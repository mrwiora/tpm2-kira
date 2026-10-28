package admin

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base32"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/internal/totp"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
	"github.com/mrwiora/tpm2-kira/internal/untrusted"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Seal creates a new TOTP key inside the TPM and approves the current PCR
// values for it (see internal/nvslot/policy.go).
func Seal(tpmPath, pcrsStr string, nvramIndex uint32, pubKeyPath, privKeyPath string, debug bool, hashAlgo measure.PCRHashAlgo, verifyUKI bool) error {
	// Fall back to default key paths when not provided by the user
	if pubKeyPath == "" {
		pubKeyPath = signing.DefaultPublicKeyPath
	}
	if privKeyPath == "" {
		privKeyPath = signing.DefaultPrivateKeyPath
	}

	// Parse PCR specs first to display them
	specs, err := measure.ParsePCRSpecs(pcrsStr)
	if err != nil {
		return fmt.Errorf("invalid PCRs: %w", err)
	}

	// The signing keys come from 'setup', which seal never runs on its own.
	for _, keyPath := range []string{privKeyPath, pubKeyPath} {
		if _, err := os.Stat(keyPath); errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("cannot seal: no signing key at %s.\n"+
				"  Run 'tpm2-kira setup' first to create the signing keys,\n"+
				"  or pass --privkey and --pubkey to use your own", keyPath)
		}
	}

	// Both key files are checked (mode 0400, trusted owner and directory, no
	// symlink) on the descriptor they are read from, so what is parsed is
	// what was checked. The private key must be usable before anything is
	// generated or written: without it the PolicySigned NV write cannot be
	// authorized.
	keyData, err := signing.ReadSigningKeyFile(privKeyPath)
	if err != nil {
		return fmt.Errorf("cannot seal: %w", err)
	}
	pubData, err := signing.ReadSigningKeyFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("cannot seal: %w", err)
	}
	signer, err := signing.ParseSigningPrivateKey(keyData, privKeyPath)
	if err != nil {
		return fmt.Errorf("cannot seal: signing private key is not usable: %w", err)
	}
	pubKey, err := signing.ParseSigningPublicKeyPEM(pubData, pubKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load signing public key: %w", err)
	}

	// The public key goes into the policy and the private key authorizes
	// the NV writes; a mismatch would only surface once the TPM refuses a
	// write, after the index has been replaced.
	if err := signing.VerifyKeyPairMatch(pubKey, signer); err != nil {
		return fmt.Errorf("cannot seal: %s and %s are not a key pair: %w", pubKeyPath, privKeyPath, err)
	}
	keyLocation := ""
	if desc, ok := signing.YubiKeyDescription(signer); ok {
		keyLocation = fmt.Sprintf("\nSigning Key Location: %s (the token and its PIN are needed now)", desc)
	}

	// Display which PCRs are being used
	fmt.Println("=== Sealing Configuration ===")
	fmt.Printf("Hash Algorithm: %s (%d-byte PCR digests)\n", hashAlgo.DisplayString(), hashAlgo.DigestSize())
	fmt.Printf("PCRs used for sealing: %s\n", measure.PCRSpecsToString(specs))
	fmt.Printf("Signing Key: %s (%s, fingerprint: %s)%s\n", pubKeyPath, signing.PublicKeyDescription(pubKey), signing.PublicKeyFingerprint(pubKey), keyLocation)
	fmt.Printf("Authentication: PolicyAuthorize (PCR values + generation, approved by the signing key)\n")
	fmt.Println()
	for _, spec := range specs {
		fmt.Printf("  PCR%-2d (%s): %s\n", spec.Index, spec.Source.String(), measure.GetPCRDescription(spec.Index))
	}
	fmt.Println()

	// The fallback slot is sealed to 0 and 7 alone by design (default_pcrs.go).
	if !(pcrsStr == FallbackPCRSelection && nvramIndex == nvslot.ResolveNVRAMIndex(FallbackSlot)) {
		measure.WarnAboutPCRSelection(specs)
	}
	measure.WarnAboutHashAlgo(hashAlgo)

	if err := nvslot.ValidateBlobIndex(nvramIndex); err != nil {
		return fmt.Errorf("cannot seal: %w", err)
	}

	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	tpmdev.Cleanup(tpmDev, debug)

	// A key on a token must be able to sign before anything is created.
	if err := signing.PrepareSigningKey(signer); err != nil {
		return fmt.Errorf("cannot seal: %w", err)
	}

	// Sealing a slot again replaces its TOTP key, not its phones: their
	// enrolment lives in the same blob and is carried over - if this
	// signing key wrote it. Somebody else's entries are not signed anew.
	// The boot key in it is bound to the slot's policy by the policy
	// reference, which is kept. A slot with phones gets no TOTP key: the
	// phones check its boots (SealedBlobPayload).
	var kept *nvslot.Attestation
	var policyRef []byte
	if oldRaw, old, err := phonegate.ReadSlot(tpmDev, nvramIndex); err == nil && old.Payload.Attestation != nil {
		if nvslot.VerifyBlobSignature(oldRaw, old, signer.Public()) == nil {
			kept, policyRef = old.Payload.Attestation, old.Payload.PolicyRef
			if kept.Phone.Enabled() {
				fmt.Printf("Phone enrolment: kept (%d phone(s) enrolled for this slot)\n", len(kept.Phone.Verifiers))
			}
			if kept.Vault.Enabled() {
				fmt.Printf("Vault enrolment: kept (%s)\n", kept.Vault.URL)
			}
			fmt.Println()
		} else {
			fmt.Println("WARNING: this slot carries a phone enrolment that another signing key wrote.")
			fmt.Println("  It is not carried over. Enrol the phone again: tpm2-kira phone enrol")
			fmt.Println()
		}
	}

	blob, err := newSlot(tpmDev, pubKey, policyRef)
	if err != nil {
		return err
	}
	blob.Payload.Attestation = kept
	var key []byte
	var alg tpm2.TPMAlgID
	if !blob.PhoneAttested() {
		if key, alg, err = newTOTPSecret(tpmDev); err != nil {
			return fmt.Errorf("cannot seal: %w", err)
		}
		defer clear(key)
		if alg != tpm2.TPMAlgSHA1 {
			fmt.Println("NOTE: this TPM has no SHA-1, so the TOTP key uses HMAC-SHA256 instead of the")
			fmt.Println("  usual HMAC-SHA1. The QR code says so (algorithm=SHA256), but some")
			fmt.Println("  authenticator apps ignore that and then show codes that never match.")
			fmt.Println("  Check that your app's first code matches 'tpm2-kira reveal' before you rely on it.")
			fmt.Println()
		}
		if err := addTOTPKey(tpmDev, blob, key, alg); err != nil {
			return err
		}
	}

	if err := approveAndWrite(tpmDev, nvramIndex, blob, specs, hashAlgo, verifyUKI, signer, debug); err != nil {
		return err
	}
	if key == nil {
		fmt.Println()
		fmt.Printf("Slot %d is attested by its phone(s): it has no TOTP code while a phone is enrolled.\n", nvslot.SlotNumber(nvramIndex))
		fmt.Println("The new PCR values are approved for the phone's check at boot.")
		return nil
	}
	showTOTPSecret(key, alg, nvramIndex, measure.PCRSpecsToString(specs))
	return nil
}

// newSlot returns a blob with the slot's policy parameters, not yet
// approved for any PCR state and without a TOTP key (addTOTPKey).
//
// Every key of the slot is created under PolicyAuthorize by pubKey,
// qualified by policyRef: whatever pubKey approves for this policyRef can
// use them. A fresh policyRef is made unless the slot's existing one is
// passed in, which keeps the slot's other keys (the boot key, the release
// key) under the same approvals.
func newSlot(tpmDev transport.TPM, pubKey crypto.PublicKey, policyRef []byte) (*nvslot.SealedBlob, error) {
	// Loading the key checks that this TPM can verify its signatures.
	loadRsp, err := signing.LoadExternalPublicKey(tpmDev, pubKey)
	if err != nil {
		return nil, fmt.Errorf("signing key incompatible with this TPM: %w", err)
	}
	tpmdev.FlushHandle(tpmDev, loadRsp.ObjectHandle)

	signingPublic, _, err := signing.PublicKeyToTPM2BPublic(pubKey)
	if err != nil {
		return nil, err
	}
	if len(policyRef) == 0 {
		if policyRef, err = nvslot.NewPolicyRef(); err != nil {
			return nil, err
		}
	}
	return &nvslot.SealedBlob{
		Version: nvslot.CurrentBlobVersion,
		Payload: nvslot.SealedBlobPayload{PolicyRef: policyRef, SigningPublic: signingPublic.Bytes()},
	}, nil
}

// addTOTPKey creates the TOTP key object for key under the slot's policy
// and puts it into blob.
func addTOTPKey(tpmDev transport.TPM, blob *nvslot.SealedBlob, key []byte, alg tpm2.TPMAlgID) error {
	policy, err := blob.SlotPolicy()
	if err != nil {
		return err
	}
	primary, err := tpmdev.CreatePrimaryKey(tpmDev)
	if err != nil {
		return err
	}
	defer tpmdev.FlushHandle(tpmDev, primary.ObjectHandle)
	obj, err := totp.CreateKey(tpmDev, primary, key, alg, policy)
	if err != nil {
		return err
	}
	blob.Payload.Public, blob.Payload.Private, blob.Payload.TOTPAlgorithm = obj.Public, obj.Private, alg
	return nil
}

// newTOTPSecret makes a TOTP key for this TPM: its HMAC algorithm (SHA-1,
// or SHA-256 on a TPM without it) and random bytes of the matching size.
func newTOTPSecret(tpmDev transport.TPM) ([]byte, tpm2.TPMAlgID, error) {
	alg, err := totp.ChooseAlgorithm(tpmDev)
	if err != nil {
		return nil, 0, err
	}
	key := make([]byte, totp.KeySize(alg))
	if _, err := rand.Read(key); err != nil {
		return nil, 0, fmt.Errorf("failed to generate the TOTP key: %w", err)
	}
	return key, alg, nil
}

// showTOTPSecret prints a new TOTP key once, with its QR code for the
// authenticator.
func showTOTPSecret(key []byte, alg tpm2.TPMAlgID, nvramIndex uint32, pcrs string) {
	totpSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
	fmt.Println()
	fmt.Println("=== TOTP Secret Generated ===")
	fmt.Println("The key is now inside the TPM, which computes every code; it is shown here")
	fmt.Println("once, for your authenticator, and cannot be read back later.")
	fmt.Printf("Secret: %s (HMAC-%s)\n", totpSecret, nvslot.TOTPAlgorithmName(alg))
	fmt.Println()
	fmt.Println("Scan QR Code with authenticator app:")
	fmt.Println()
	totp.DisplayQRCode(totpSecret, nvramIndex, pcrs, alg)
	fmt.Println()
	fmt.Println("To generate TOTP codes:")
	fmt.Printf("   tpm2-kira reveal --nvram 0x%08X\n", nvramIndex)
}

// ErrGenerationRaised marks a failure after the slot's generation was raised:
// the previous approval is revoked, so no code is shown until a reseal
// completes. Such a failure is never reported as a harmless skip.
var ErrGenerationRaised = errors.New("the slot's generation was raised")

// checkBlobFits fails with a BlobTooLargeError when blob, with the given
// PCR values and generation and signatures of the largest size pub makes,
// would not fit this TPM's NV index.
func checkBlobFits(tpmDev transport.TPM, nvramIndex uint32, blob *nvslot.SealedBlob, pcrDigests []nvslot.PCRDigestPair, measurePoint bool, gen uint64, pub crypto.PublicKey) error {
	limit := nvslot.NvIndexLimit(tpmDev)
	if limit == 0 {
		return nil
	}
	approvalMax, blobSigMax, err := signatureSizes(pub)
	if err != nil {
		return err
	}
	trial := *blob
	trial.Version = nvslot.CurrentBlobVersion
	trial.Payload.PCRDigests = pcrDigests
	trial.Payload.MeasurePointApplied = measurePoint
	trial.Payload.Generation = gen
	trial.Payload.ApprovalSignature = make([]byte, approvalMax)
	unsigned, err := trial.Marshal()
	if err != nil {
		return err
	}
	if size := len(unsigned) + 2 + blobSigMax; size > limit {
		return &nvslot.BlobTooLargeError{Index: nvramIndex, Size: size, Limit: limit}
	}
	return nil
}

// signatureSizes returns the largest approval (a TPMT_SIGNATURE) and blob
// signature (PKCS #1 v1.5, or ASN.1 DER for ECDSA) the key pub makes.
func signatureSizes(pub crypto.PublicKey) (approval, blob int, err error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		n := k.Size()
		return 2 + 2 + 2 + n, n, nil
	case *ecdsa.PublicKey:
		c := (k.Curve.Params().BitSize + 7) / 8
		// r and s, each an INTEGER of up to c+1 bytes, in a SEQUENCE.
		body := 2 * (2 + c + 1)
		header := 2
		if body > 127 {
			header = 3
		}
		return 2 + 2 + 2*(2+c), header + body, nil
	default:
		return 0, 0, fmt.Errorf("unsupported signing key type %T", pub)
	}
}

// approveAndWrite approves the PCR values for specs and writes the blob.
//
// It raises the slot's generation, which revokes every earlier approval for
// the slot, signs PolicyPCR(values) + PolicyNV(generation) with signer, and
// writes the signed blob. The key object in blob is not touched: only its
// approval changes, so the TOTP key never has to leave the TPM.
func approveAndWrite(tpmDev transport.TPM, nvramIndex uint32, blob *nvslot.SealedBlob, specs []measure.PCRSpec, hashAlgo measure.PCRHashAlgo, verifyUKI bool, signer crypto.Signer, debug bool) error {
	if len(specs) == 0 {
		return fmt.Errorf("no PCRs specified")
	}
	if signer == nil {
		return fmt.Errorf("no signing private key provided")
	}
	if err := nvslot.ValidateBlobIndex(nvramIndex); err != nil {
		return err
	}

	// The display checks the key's policy before the OS separator runs, so
	// PCRs the separator touches are read from the event log even when
	// given as register source (the registers already carry the separator
	// by the time anything can seal); the blob records the source used.
	readResult, err := measure.ReadPCRValues(tpmDev, specs, hashAlgo, measure.MeasurePointModeSetting, measure.MeasurePointBeforeSeparator, debug)
	if err != nil {
		return err
	}
	specs = readResult.Specs
	if readResult.AfterSeparator != "" {
		fmt.Println()
		fmt.Println("WARNING: the event log cannot be used for this TPM, so PCRs 0-7, 9, 12-14 are sealed to")
		fmt.Println("         their register values, which already carry systemd's os-separator. The key's policy")
		fmt.Println("         then holds only after the separator: codes are computed live while the initrd")
		fmt.Println("         runs instead of before the separator, and the display says so. Reason:")
		fmt.Printf("         %s\n", readResult.AfterSeparator)
		fmt.Println()
	}
	// Reseal runs right after an initramfs rebuild, where the image on disk is
	// expected to differ from the booted one, so only seal can check this.
	if verifyUKI {
		if err := measure.VerifyUKISpecsAgainstEventlog(specs, hashAlgo, debug); err != nil {
			return err
		}
	}

	pcrPolicy, err := measure.ComputePolicyDigestFromPCRValues(tpmDev, measure.PCRSpecIndices(specs), readResult.Values, hashAlgo)
	if err != nil {
		return fmt.Errorf("failed to compute the PCR policy: %w", err)
	}

	pcrDigests := make([]nvslot.PCRDigestPair, len(specs))
	for i, spec := range specs {
		pcrDigests[i] = nvslot.PCRDigestPair{
			Index:   spec.Index,
			Source:  spec.Source,
			Command: spec.Command,
			Digest:  tpm2.TPM2BDigest{Buffer: readResult.Values[spec.Index]},
		}
	}
	measurePoint := readResult.EventlogInfo != nil && readResult.EventlogInfo.MeasurePointExtends != ""
	gen := blob.Payload.Generation + 1

	// Raising the generation revokes the slot's approval, so a blob this
	// TPM cannot store must be found before that, not by the write.
	if err := checkBlobFits(tpmDev, nvramIndex, blob, pcrDigests, measurePoint, gen, signer.Public()); err != nil {
		return err
	}

	genName, err := nvslot.WriteGeneration(tpmDev, nvslot.GenerationIndex(nvramIndex), gen, signer.Public(), signer)
	if err != nil {
		return err
	}
	raised := func(err error) error { return fmt.Errorf("%w (to generation %d): %w", ErrGenerationRaised, gen, err) }

	approved := nvslot.ApprovedPolicy(pcrPolicy.Buffer, genName, gen)
	approval, err := nvslot.SignApproval(signer, approved, blob.Payload.PolicyRef)
	if err != nil {
		return raised(err)
	}

	blob.Version = nvslot.CurrentBlobVersion
	blob.Payload.PCRDigests = pcrDigests
	blob.Payload.MeasurePointApplied = measurePoint
	blob.Payload.Generation = gen
	blob.Payload.ApprovalSignature = approval

	if debug {
		fmt.Println("=== Policy Details ===")
		fmt.Printf("PCR policy:       %x\n", pcrPolicy.Buffer)
		fmt.Printf("Generation:       %d (index 0x%08X)\n", gen, nvslot.GenerationIndex(nvramIndex))
		fmt.Printf("Approved policy:  %x\n", approved)
		fmt.Printf("Policy reference: %x\n", blob.Payload.PolicyRef)
		for _, spec := range specs {
			sourceLabel := spec.Source.String()
			if spec.Source == measure.PCRSourceUKI {
				sourceLabel = fmt.Sprintf("uki [%s]", untrusted.Quote(spec.Command))
			}
			fmt.Printf("  PCR%-2d (%s): %x\n", spec.Index, sourceLabel, readResult.Values[spec.Index])
		}
		fmt.Println()
	}

	unsignedBlob, err := blob.Marshal()
	if err != nil {
		return raised(fmt.Errorf("failed to marshal sealed data: %w", err))
	}
	// The signature covers Version + PayloadLen + all payload fields.
	data, err := nvslot.SignBlobPayload(unsignedBlob, signer)
	if err != nil {
		return raised(fmt.Errorf("failed to sign sealed blob: %w", err))
	}
	if err := nvslot.WriteToNVRAM(tpmDev, nvramIndex, data, signer.Public(), signer); err != nil {
		return raised(fmt.Errorf("failed to write to NVRAM: %w", err))
	}
	return nil
}
