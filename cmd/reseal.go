package cmd

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// ResealCommand is the top-level entry point for the reseal CLI command.
// When nvramIndex is 0 it scans every default slot and reseals each one;
// otherwise it reseals only the requested index.
func ResealCommand(tpmPath string, nvramIndex uint32, pcrsStr, pubKeyPath, privKeyPath string, debug bool) error {
	if nvramIndex != 0 {
		// Single-slot mode – same behaviour as before
		err := Reseal(tpmPath, pcrsStr, nvramIndex, pubKeyPath, privKeyPath, debug)
		var skip *ResealSkippedError
		if errors.As(err, &skip) {
			fmt.Println()
			PrintResealSkipped(os.Stdout, []*ResealSkippedError{skip})
		}
		return err
	}

	// Multi-slot mode – discover populated slots, then reseal each one
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	slots := FindPopulatedSlots(tpmDev, debug)
	tpmDev.Close()

	if len(slots) == 0 {
		return fmt.Errorf("no sealed secrets found in NVRAM slots 0x%08X - 0x%08X", NVRAMSlotStart, NVRAMSlotEnd)
	}

	fmt.Printf("Found %d sealed slot(s) to reseal\n\n", len(slots))

	var failed []uint32
	var skipped []*ResealSkippedError
	for i, slotIdx := range slots {
		slotNum := SlotNumber(slotIdx)
		fmt.Printf("── Slot #%d (0x%08X) ─────────────────────────\n", slotNum, slotIdx)

		err := Reseal(tpmPath, pcrsStr, slotIdx, pubKeyPath, privKeyPath, debug)
		var skip *ResealSkippedError
		switch {
		case errors.As(err, &skip):
			fmt.Printf("Slot #%d (0x%08X) skipped: %v\n", slotNum, slotIdx, skip.Cause)
			skipped = append(skipped, skip)
		case err != nil:
			fmt.Printf("Error resealing slot #%d (0x%08X): %v\n", slotNum, slotIdx, err)
			failed = append(failed, slotIdx)
		}

		if i < len(slots)-1 {
			fmt.Println()
		}
	}

	if len(skipped) > 0 {
		fmt.Println()
		PrintResealSkipped(os.Stdout, skipped)
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d of %d slot(s) failed to reseal", len(failed), len(slots))
	}
	if len(skipped) > 0 {
		return fmt.Errorf("%w: %d of %d slot(s)", ErrResealSkipped, len(skipped), len(slots))
	}
	return nil
}

// ErrResealSkipped marks a reseal that did not happen because the signing
// key was unavailable. Nothing was written: the old blob is intact and still
// opens through PolicySigned once the key is back.
var ErrResealSkipped = errors.New("reseal skipped")

// ResealSkippedError reports one slot whose reseal was skipped.
type ResealSkippedError struct {
	NVIndex    uint32
	KeyFile    string
	Cause      *TokenUnavailableError
	SealedPCRs []PCRSpec
}

func (e *ResealSkippedError) Error() string {
	return fmt.Sprintf("reseal of slot 0x%08X skipped: %v", e.NVIndex, e.Cause)
}

func (e *ResealSkippedError) Unwrap() []error { return []error{ErrResealSkipped, e.Cause} }

// asResealSkipped turns an error into a skip when, and only when, the
// signing key was unavailable and the NVRAM index was not touched. A failure
// after the index was replaced is never a skip, whatever caused it.
func asResealSkipped(err error, nvIndex uint32, keyFile string, blob *SealedBlob) error {
	var cause *TokenUnavailableError
	if err == nil || errors.Is(err, ErrNVIndexReplaced) || errors.Is(err, ErrGenerationRaised) || !errors.As(err, &cause) {
		return err
	}
	return &ResealSkippedError{NVIndex: nvIndex, KeyFile: keyFile, Cause: cause, SealedPCRs: blob.GetPCRSpecs()}
}

// PrintResealSkipped prints the SKIPPED block. Its first line is the marker
// the initramfs hooks look for.
func PrintResealSkipped(w io.Writer, skipped []*ResealSkippedError) {
	first := skipped[0]
	var slots []string
	for _, s := range skipped {
		slots = append(slots, fmt.Sprintf("#%d", SlotNumber(s.NVIndex)))
	}
	fmt.Fprintln(w, "tpm2-kira: SKIPPED: resealing did not happen — the signing key was not available.")
	fmt.Fprintf(w, "  Key file:      %s (%s)\n", first.KeyFile, first.Cause.Token)
	fmt.Fprintf(w, "  Reason:        %s\n", indentContinuation(first.Cause.Reason, "                 "))
	fmt.Fprintf(w, "  Slots:         %s (nothing was written; the sealed secrets are intact)\n", strings.Join(slots, ", "))
	fmt.Fprintf(w, "  Sealed PCRs:   %s\n", PCRSpecsToString(first.SealedPCRs))
	fmt.Fprintln(w, "  Consequence:   the sealed policy still binds the PCR values of the last seal.")
	fmt.Fprintln(w, "                 If they have changed — as they do after a kernel or initramfs")
	fmt.Fprintln(w, "                 update — the next boot reports a PCR MISMATCH and shows no")
	fmt.Fprintln(w, "                 TOTP code. That is expected here; it is not evidence of tampering.")
	fmt.Fprintln(w, "  To fix:        plug in the YubiKey and run, with the PIN typed when asked")
	fmt.Fprintf(w, "                 or set in %s:\n", PINEnvVar)
	fmt.Fprintln(w, "                     sudo tpm2-kira reseal")
}

func indentContinuation(s, indent string) string {
	return strings.ReplaceAll(s, "\n", "\n"+indent)
}

// Reseal unseals data from TPM NVRAM and reseals with current PCR values.
//
// Nothing is unsealed: the TOTP key stays in the TPM. reseal raises the
// slot's generation, which revokes the old approval, and has the signing key
// approve the PCR values for the next boot.
//
// The signing key is --privkey, or the default key from setup; key paths
// stored in the blob are never used to find it (see resolveResealKeys). The
// public key for the NEW sealed blob is --pubkey, which must belong to that
// private key, or else derived from it.
func Reseal(tpmPath, pcrsStr string, nvramIndex uint32, pubKeyPath, privKeyPath string, debug bool) error {
	// Parse PCRs if provided (we'll use original PCRs if not explicitly overridden)
	var userProvidedSpecs []PCRSpec
	var userSpecifiedPCRs bool
	var err error
	if pcrsStr != "" {
		userProvidedSpecs, err = ParsePCRSpecs(pcrsStr)
		if err != nil {
			return fmt.Errorf("invalid PCRs: %w", err)
		}
		userSpecifiedPCRs = true
	}

	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	CleanupTPM(tpmDev, debug)

	sealedData, err := ReadFromNVRAM(tpmDev, nvramIndex)
	if err != nil {
		return HandleNVRAMNotFoundError(err, debug)
	}
	sealedBlob, err := UnmarshalSealedBlob(sealedData)
	if err != nil {
		if bve, ok := IsBlobVersionError(err); ok {
			return fmt.Errorf(
				"cannot reseal: the stored blob is version %d but this build writes version %d.\n"+
					"reseal preserves the existing blob, so it cannot upgrade the format.\n"+
					"Seal again to replace it (this generates a NEW TOTP secret, so re-enrol your authenticator):\n"+
					"    tpm2-kira seal --nvram 0x%08X",
				bve.FoundVersion, bve.RequiredVersion, nvramIndex)
		}
		return fmt.Errorf("failed to unmarshal sealed data: %w", err)
	}

	// ── Resolve the signing key and verify the blob with it ──
	keys, err := resolveResealKeys(sealedData, sealedBlob, privKeyPath, pubKeyPath, debug)
	if err != nil {
		return err
	}
	signer := keys.signer

	// The key object only accepts approvals from the key it was created
	// for. Another key may have verified the blob only if it was sealed
	// with a key pair that was later replaced; its approvals would be
	// refused by the TPM, so say so now.
	if err := checkObjectSigningKey(sealedBlob, signer.Public()); err != nil {
		return fmt.Errorf("cannot reseal: %w", err)
	}

	// ── Make sure the key can sign before anything is changed ──
	// For a key on a token this finds an absent token or a missing PIN now,
	// while the slot is untouched, and reports a skip rather than a failure.
	if err := PrepareSigningKey(signer); err != nil {
		if skip := asResealSkipped(err, nvramIndex, keys.privKeyPath, sealedBlob); skip != err {
			return skip
		}
		return fmt.Errorf("cannot reseal: %w", err)
	}

	var specsToUse []PCRSpec
	if userSpecifiedPCRs {
		specsToUse = userProvidedSpecs
		fmt.Printf("\nResealing with user-specified PCRs: %s\n", PCRSpecsToString(specsToUse))
	} else {
		specsToUse = sealedBlob.GetPCRSpecs()
		fmt.Printf("\nPreserving original PCR selection: %s\n", PCRSpecsToString(specsToUse))
	}

	hashAlgo := sealedBlob.GetHashAlgo()
	fmt.Printf("Hash algorithm: %s (%d-byte PCR digests)\n", hashAlgo.DisplayString(), hashAlgo.DigestSize())

	WarnAboutPCRSelection(specsToUse)
	WarnAboutHashAlgo(hashAlgo)
	printResealSources(specsToUse, sealedBlob)

	pub := signer.Public()
	fmt.Printf("Signing key: %s (%s, fingerprint: %s)\n", keys.privKeyPath, PublicKeyDescription(pub), PublicKeyFingerprint(pub))

	// Record the paths in use, for info. They are never used to find a key.
	sealedBlob.Payload.PrivateKeyPath = keys.privKeyPath
	sealedBlob.Payload.PublicKeyPath = pubKeyPath
	if pubKeyPath == "" && keys.privKeyPath == DefaultPrivateKeyPath {
		sealedBlob.Payload.PublicKeyPath = DefaultPublicKeyPath
	}

	if err := approveAndWrite(tpmDev, nvramIndex, sealedBlob, specsToUse, hashAlgo, false, signer, debug); err != nil {
		return asResealSkipped(fmt.Errorf("failed to reseal: %w", err), nvramIndex, keys.privKeyPath, sealedBlob)
	}

	fmt.Printf("\nSuccessfully resealed with PCRs: %s\n", PCRSpecsToString(specsToUse))
	fmt.Printf("Generation: %d (every earlier approval for this slot is revoked)\n", sealedBlob.Payload.Generation)
	fmt.Printf("Authentication: PolicyAuthorize (PCR values + generation, approved by the signing key)\n")

	return nil
}

// checkObjectSigningKey fails unless pub is the key the blob's key object
// accepts approvals from.
func checkObjectSigningKey(blob *SealedBlob, pub crypto.PublicKey) error {
	want, _, err := PublicKeyToTPM2BPublic(pub)
	if err != nil {
		return err
	}
	if !bytes.Equal(want.Bytes(), blob.Payload.SigningPublic) {
		return fmt.Errorf("the TOTP key in this slot accepts approvals only from the signing key it was sealed with,\n" +
			"  and that is not the key in use. Changing the signing key means sealing again")
	}
	return nil
}

func printResealSources(specs []PCRSpec, blob *SealedBlob) {
	for _, spec := range specs {
		fmt.Printf("  PCR%-2d (%s): %s\n", spec.Index, spec.Source.String(), GetPCRDescription(spec.Index))
		switch spec.Source {
		case PCRSourceEventlog:
			if info := blob.Payload.EventlogInfo; info != nil {
				fmt.Printf("         previously from %s, %s\n", quoteUntrusted(info.EventlogPath), quoteUntrusted(info.CalculationTime))
			}
		case PCRSourceUKI:
			fmt.Printf("         recomputed from the unified kernel image %s\n", quoteUntrusted(spec.Command))
		}
	}
}

// resealKeys is the signing key reseal works with, resolved without
// consulting the blob.
type resealKeys struct {
	signer      crypto.Signer
	privKeyPath string
	pubKey      crypto.PublicKey // from --pubkey; nil when derived from signer
}

// resolveResealKeys loads the signing key and verifies the blob with it.
//
// The blob is not trusted until its signature is verified, and anyone with
// TPM access can replace it (SECURITY-BACKGROUND §9). The key that verifies
// it therefore comes from --privkey or the default location, never from a
// path the blob names: a planted blob would name a key its author holds and
// pass its own check. Blob paths are only compared afterwards.
func resolveResealKeys(sealedData []byte, sealedBlob *SealedBlob, privKeyPath, pubKeyPath string, debug bool) (*resealKeys, error) {
	keys := &resealKeys{privKeyPath: privKeyPath}
	if keys.privKeyPath == "" {
		keys.privKeyPath = DefaultPrivateKeyPath
	}
	if _, err := os.Lstat(keys.privKeyPath); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("cannot reseal: no signing private key at %s.\n"+
			"  The key verifies the blob and authorizes the NV write, so reseal needs it.\n"+
			"  Pass --privkey <path>, or create the default key pair with 'tpm2-kira setup'.%s",
			keys.privKeyPath, blobKeyPathHint(sealedBlob, keys.privKeyPath))
	}

	// Loaded from a checked file (mode 0400, trusted owner and directory,
	// no symlink). A key that fails to load is an error, not a reason to
	// skip the signature check.
	signer, err := LoadCheckedSigningPrivateKey(keys.privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot reseal: %w", err)
	}
	keys.signer = signer

	// An explicit --pubkey is checked the same way, and must belong to the
	// private key: the policy is built from it and the NV write is signed
	// with the private key, so a mismatch would only surface once the TPM
	// refuses the write, after the old index was undefined.
	if pubKeyPath != "" {
		pub, err := LoadCheckedSigningPublicKey(pubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("cannot reseal: %w", err)
		}
		if err := verifyKeyPairMatch(pub, signer); err != nil {
			return nil, fmt.Errorf("cannot reseal: %s and %s are not a key pair: %w", pubKeyPath, keys.privKeyPath, err)
		}
		keys.pubKey = pub
	}

	// The signature MUST be verified BEFORE any blob field is acted on, so a
	// tampered blob cannot steer reseal via its stored PCR specs or key paths.
	if err := VerifyBlobSignature(sealedData, sealedBlob, signer.Public()); err != nil {
		return nil, fmt.Errorf("blob integrity check failed — the NVRAM blob may have been tampered with: %w%s",
			err, blobKeyPathHint(sealedBlob, keys.privKeyPath))
	}
	if debug {
		fmt.Println("Blob signature verified successfully")
	}

	// The blob is trusted from here on; its stored path is only compared.
	if p := sealedBlob.Payload.PrivateKeyPath; p != "" && p != keys.privKeyPath {
		fmt.Printf("Note: the blob was sealed with key file %s; using %s, which verified it.\n",
			quoteUntrusted(p), keys.privKeyPath)
	}
	return keys, nil
}

// blobKeyPathHint names the key file a blob claims to have been sealed with,
// when it differs from the one in use. The path is unverified: it is quoted,
// never opened, and the user is told to pass it only if they recognise it.
func blobKeyPathHint(blob *SealedBlob, used string) string {
	p := blob.Payload.PrivateKeyPath
	if p == "" || p == used {
		return ""
	}
	return fmt.Sprintf("\n  The blob says it was sealed with key file %s (unverified).\n"+
		"  Only if you sealed it with that key yourself, rerun with: --privkey %s",
		quoteUntrusted(p), quoteUntrusted(p))
}

// IsTPMAuthError checks if an error is a TPM authentication/authorization failure
func IsTPMAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "tpm_rc_auth_fail") ||
		strings.Contains(errStr, "tpm_rc_bad_auth") ||
		strings.Contains(errStr, "authorization failure") ||
		strings.Contains(errStr, "auth fail") ||
		strings.Contains(errStr, "bad auth")
}
