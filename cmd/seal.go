package cmd

import (
	"crypto"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Seal creates a new TOTP key inside the TPM and approves the current PCR
// values for it (see cmd/totpkey.go).
func Seal(tpmPath, pcrsStr string, nvramIndex uint32, pubKeyPath, privKeyPath string, debug bool, hashAlgo PCRHashAlgo, verifyUKI bool) error {
	// Fall back to default key paths when not provided by the user
	if pubKeyPath == "" {
		pubKeyPath = DefaultPublicKeyPath
	}
	if privKeyPath == "" {
		privKeyPath = DefaultPrivateKeyPath
	}

	// Parse PCR specs first to display them
	specs, err := ParsePCRSpecs(pcrsStr)
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
	keyData, err := ReadSigningKeyFile(privKeyPath)
	if err != nil {
		return fmt.Errorf("cannot seal: %w", err)
	}
	pubData, err := ReadSigningKeyFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("cannot seal: %w", err)
	}
	signer, err := parseSigningPrivateKey(keyData, privKeyPath)
	if err != nil {
		return fmt.Errorf("cannot seal: signing private key is not usable: %w", err)
	}
	pubKey, err := parseSigningPublicKeyPEM(pubData, pubKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load signing public key: %w", err)
	}

	// The public key goes into the policy and the private key authorizes
	// the NV writes; a mismatch would only surface once the TPM refuses a
	// write, after the index has been replaced.
	if err := verifyKeyPairMatch(pubKey, signer); err != nil {
		return fmt.Errorf("cannot seal: %s and %s are not a key pair: %w", pubKeyPath, privKeyPath, err)
	}
	keyLocation := ""
	if desc, ok := YubiKeyDescription(signer); ok {
		keyLocation = fmt.Sprintf("\nSigning Key Location: %s (the token and its PIN are needed now)", desc)
	}

	// Display which PCRs are being used
	fmt.Println("=== Sealing Configuration ===")
	fmt.Printf("Hash Algorithm: %s (%d-byte PCR digests)\n", hashAlgo.DisplayString(), hashAlgo.DigestSize())
	fmt.Printf("PCRs used for sealing: %s\n", PCRSpecsToString(specs))
	fmt.Printf("Signing Key: %s (%s, fingerprint: %s)%s\n", pubKeyPath, PublicKeyDescription(pubKey), PublicKeyFingerprint(pubKey), keyLocation)
	fmt.Printf("Authentication: PolicyAuthorize (PCR values + generation, approved by the signing key)\n")
	fmt.Println()
	for _, spec := range specs {
		fmt.Printf("  PCR%-2d (%s): %s\n", spec.Index, spec.Source.String(), GetPCRDescription(spec.Index))
	}
	fmt.Println()

	WarnAboutPCRSelection(specs)
	WarnAboutHashAlgo(hashAlgo)

	if err := ValidateBlobIndex(nvramIndex); err != nil {
		return fmt.Errorf("cannot seal: %w", err)
	}

	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	CleanupTPM(tpmDev, debug)

	// A key on a token must be able to sign before anything is created.
	if err := PrepareSigningKey(signer); err != nil {
		return fmt.Errorf("cannot seal: %w", err)
	}

	alg, err := ChooseTOTPAlgorithm(tpmDev)
	if err != nil {
		return fmt.Errorf("cannot seal: %w", err)
	}
	if alg != tpm2.TPMAlgSHA1 {
		fmt.Println("NOTE: this TPM has no SHA-1, so the TOTP key uses HMAC-SHA256 instead of the")
		fmt.Println("  usual HMAC-SHA1. The QR code says so (algorithm=SHA256), but some")
		fmt.Println("  authenticator apps ignore that and then show codes that never match.")
		fmt.Println("  Check that your app's first code matches 'tpm2-kira reveal' before you rely on it.")
		fmt.Println()
	}

	key := make([]byte, totpKeySize(alg))
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate the TOTP key: %w", err)
	}
	defer clear(key)

	blob, err := newKeyObject(tpmDev, key, alg, pubKey)
	if err != nil {
		return err
	}
	blob.Payload.PublicKeyPath = pubKeyPath
	blob.Payload.PrivateKeyPath = privKeyPath

	// Sealing a slot again replaces its TOTP key, not its phones: their
	// enrolment lives in the same blob and is carried over - if this
	// signing key wrote it. Somebody else's entries are not signed anew.
	if oldRaw, old, err := readSlot(tpmDev, nvramIndex); err == nil && old.Payload.Attestation != nil {
		if VerifyBlobSignature(oldRaw, old, signer.Public()) == nil {
			blob.Payload.Attestation = old.Payload.Attestation
			fmt.Printf("Phone enrolment: kept (%d phone(s) enrolled for this slot)\n\n", len(old.Payload.Attestation.Phone.Verifiers))
		} else {
			fmt.Println("WARNING: this slot carries a phone enrolment that another signing key wrote.")
			fmt.Println("  It is not carried over. Enrol the phone again: tpm2-kira attest enrol")
			fmt.Println()
		}
	}

	if err := approveAndWrite(tpmDev, nvramIndex, blob, specs, hashAlgo, verifyUKI, signer, debug); err != nil {
		return err
	}

	// Display TOTP information
	totpSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
	fmt.Println()
	fmt.Println("=== TOTP Secret Generated ===")
	fmt.Println("The key is now inside the TPM, which computes every code; it is shown here")
	fmt.Println("once, for your authenticator, and cannot be read back later.")
	fmt.Printf("Secret: %s (HMAC-%s)\n", totpSecret, totpAlgorithmName(alg))
	fmt.Println()
	fmt.Println("Scan QR Code with authenticator app:")
	fmt.Println()
	displayTOTPQRCode(totpSecret, nvramIndex, PCRSpecsToString(specs), alg)

	fmt.Println()
	fmt.Println("To generate TOTP codes:")
	fmt.Printf("   tpm2-kira reveal --nvram 0x%08X\n", nvramIndex)

	return nil
}

// newKeyObject creates the TOTP key object for key and returns a blob with
// the object and its policy parameters, not yet approved for any PCR state.
//
// The object's policy is PolicyAuthorize by pubKey, qualified by a fresh
// policyRef: whatever pubKey approves for this policyRef can use the key.
func newKeyObject(tpmDev transport.TPM, key []byte, alg tpm2.TPMAlgID, pubKey crypto.PublicKey) (*SealedBlob, error) {
	// Loading the key checks that this TPM can verify its signatures, and
	// yields the Name the TPM will see in PolicyAuthorize.
	loadRsp, err := LoadExternalPublicKey(tpmDev, pubKey)
	if err != nil {
		return nil, fmt.Errorf("signing key incompatible with this TPM: %w", err)
	}
	keyName := loadRsp.Name.Buffer
	FlushHandle(tpmDev, loadRsp.ObjectHandle)

	signingPublic, _, err := PublicKeyToTPM2BPublic(pubKey)
	if err != nil {
		return nil, err
	}
	policyRef, err := newPolicyRef()
	if err != nil {
		return nil, err
	}

	primary, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, primary.ObjectHandle)
	obj, err := CreateTOTPKey(tpmDev, primary, key, alg, policyAuthorizeDigest(keyName, policyRef))
	if err != nil {
		return nil, err
	}

	return &SealedBlob{
		Version: CurrentBlobVersion,
		Payload: SealedBlobPayload{
			Public:        obj.Public,
			Private:       obj.Private,
			TOTPAlgorithm: alg,
			PolicyRef:     policyRef,
			SigningPublic: signingPublic.Bytes(),
		},
	}, nil
}

// ErrGenerationRaised marks a failure after the slot's generation was raised:
// the previous approval is revoked, so no code is shown until a reseal
// completes. Such a failure is never reported as a harmless skip.
var ErrGenerationRaised = errors.New("the slot's generation was raised")

// approveAndWrite approves the PCR values for specs and writes the blob.
//
// It raises the slot's generation, which revokes every earlier approval for
// the slot, signs PolicyPCR(values) + PolicyNV(generation) with signer, and
// writes the signed blob. The key object in blob is not touched: only its
// approval changes, so the TOTP key never has to leave the TPM.
func approveAndWrite(tpmDev transport.TPM, nvramIndex uint32, blob *SealedBlob, specs []PCRSpec, hashAlgo PCRHashAlgo, verifyUKI bool, signer crypto.Signer, debug bool) error {
	if len(specs) == 0 {
		return fmt.Errorf("no PCRs specified")
	}
	if signer == nil {
		return fmt.Errorf("no signing private key provided")
	}
	if err := ValidateBlobIndex(nvramIndex); err != nil {
		return err
	}

	// The display checks the key's policy before the OS separator runs, so
	// PCRs the separator touches are read from the event log even when
	// given as register source (the registers already carry the separator
	// by the time anything can seal); the blob records the source used.
	readResult, err := ReadPCRValues(tpmDev, specs, hashAlgo, MeasurePointModeSetting, MeasurePointBeforeSeparator, debug)
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
		if err := VerifyUKISpecsAgainstEventlog(specs, hashAlgo, debug); err != nil {
			return err
		}
	}

	pcrPolicy, err := ComputePolicyDigestFromPCRValues(tpmDev, PCRSpecIndices(specs), readResult.Values, hashAlgo)
	if err != nil {
		return fmt.Errorf("failed to compute the PCR policy: %w", err)
	}

	gen := blob.Payload.Generation + 1
	genName, err := writeGeneration(tpmDev, GenerationIndex(nvramIndex), gen, signer.Public(), signer)
	if err != nil {
		return err
	}
	raised := func(err error) error { return fmt.Errorf("%w (to generation %d): %w", ErrGenerationRaised, gen, err) }

	approved := ApprovedPolicy(pcrPolicy.Buffer, genName, gen)
	approval, err := signApproval(signer, approved, blob.Payload.PolicyRef)
	if err != nil {
		return raised(err)
	}

	pcrDigests := make([]PCRDigestPair, len(specs))
	for i, spec := range specs {
		pcrDigests[i] = PCRDigestPair{
			Index:   spec.Index,
			Source:  spec.Source,
			Command: spec.Command,
			Digest:  tpm2.TPM2BDigest{Buffer: readResult.Values[spec.Index]},
		}
	}
	blob.Version = CurrentBlobVersion
	blob.Payload.AppVersion = AppVersion
	blob.Payload.PCRDigests = pcrDigests
	blob.Payload.EventlogInfo = readResult.EventlogInfo
	blob.Payload.Generation = gen
	blob.Payload.ApprovalSignature = approval

	if debug {
		fmt.Println("=== Policy Details ===")
		fmt.Printf("PCR policy:       %x\n", pcrPolicy.Buffer)
		fmt.Printf("Generation:       %d (index 0x%08X)\n", gen, GenerationIndex(nvramIndex))
		fmt.Printf("Approved policy:  %x\n", approved)
		fmt.Printf("Policy reference: %x\n", blob.Payload.PolicyRef)
		for _, spec := range specs {
			sourceLabel := spec.Source.String()
			if spec.Source == PCRSourceUKI {
				sourceLabel = fmt.Sprintf("uki [%s]", quoteUntrusted(spec.Command))
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
	data, err := SignBlobPayload(unsignedBlob, signer)
	if err != nil {
		return raised(fmt.Errorf("failed to sign sealed blob: %w", err))
	}
	if err := WriteToNVRAM(tpmDev, nvramIndex, data, signer.Public(), signer); err != nil {
		return raised(fmt.Errorf("failed to write to NVRAM: %w", err))
	}
	return nil
}
