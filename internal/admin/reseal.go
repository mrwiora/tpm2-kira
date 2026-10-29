package admin

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
	"github.com/mrwiora/tpm2-kira/internal/untrusted"

	"github.com/mrwiora/tpm2-kira/internal/machineid"
	"github.com/tpm2-trust/assh/hostkey"
)

// ResealCommand is the top-level entry point for the reseal CLI command.
// When nvramIndex is 0 it scans every default slot and reseals each one;
// otherwise it reseals only the requested index.
func ResealCommand(tpmPath string, nvramIndex uint32, pcrsStr, pubKeyPath, privKeyPath string, debug bool) error {
	if nvramIndex != 0 {
		// Single-slot mode – same behaviour as before
		err := Reseal(tpmPath, pcrsStr, nvramIndex, pubKeyPath, privKeyPath, debug)
		if nvramIndex == machineid.Slot {
			keepMachineIDAt(tpmPath)
		}
		var skip *ResealSkippedError
		if errors.As(err, &skip) {
			fmt.Println()
			PrintResealSkipped(os.Stdout, []*ResealSkippedError{skip})
		}
		return err
	}

	// Multi-slot mode – discover populated slots, then reseal each one
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	slots := nvslot.FindPopulatedSlots(tpmDev, debug)
	tpmDev.Close()

	controlPath := controlConfigPath()
	if len(slots) == 0 {
		if conf, _ := loadSSHConf(sshConfPath(controlPath), controlPath); fileExistsCA(conf.CA) {
			return resealSSHCA(controlPath, tpmPath, privKeyPath)
		}
		return fmt.Errorf("no sealed secrets found in NVRAM slots 0x%08X - 0x%08X", nvslot.NVRAMSlotStart, nvslot.NVRAMSlotEnd)
	}
	slotsErr := resealSlots(tpmPath, slots, pcrsStr, pubKeyPath, privKeyPath, debug)
	keepMachineIDAt(tpmPath)
	return joinReseal(slotsErr, resealSSHCA(controlPath, tpmPath, privKeyPath))
}

// joinReseal is the slots' and the SSH CA's outcome: a failure of either
// wins over a skip of the other, which was reported already.
func joinReseal(slots, sshCA error) error {
	skip := func(err error) bool { return errors.Is(err, ErrResealSkipped) }
	switch {
	case slots != nil && sshCA != nil && skip(slots) && !skip(sshCA):
		return sshCA
	case slots != nil && sshCA != nil && skip(sshCA) && !skip(slots):
		return slots
	}
	return errors.Join(slots, sshCA)
}

// resealSlots reseals each of slots.
func resealSlots(tpmPath string, slots []uint32, pcrsStr, pubKeyPath, privKeyPath string, debug bool) error {
	fmt.Printf("Found %d sealed slot(s) to approve\n\n", len(slots))

	var failed []uint32
	var skipped []*ResealSkippedError
	for i, slotIdx := range slots {
		slotNum := nvslot.SlotNumber(slotIdx)
		fmt.Printf("── Slot #%d (0x%08X) ─────────────────────────\n", slotNum, slotIdx)

		err := Reseal(tpmPath, pcrsStr, slotIdx, pubKeyPath, privKeyPath, debug)
		var skip *ResealSkippedError
		switch {
		case errors.As(err, &skip):
			fmt.Printf("Slot #%d (0x%08X) skipped: %v\n", slotNum, slotIdx, skip.Cause)
			skipped = append(skipped, skip)
		case err != nil:
			fmt.Printf("Error approving slot #%d (0x%08X): %v\n", slotNum, slotIdx, err)
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
		return fmt.Errorf("%d of %d slot(s) failed to approve", len(failed), len(slots))
	}
	if len(skipped) > 0 {
		return fmt.Errorf("%w: %d of %d slot(s)", ErrResealSkipped, len(skipped), len(slots))
	}
	return nil
}

// resealSSHCA approves the next boot's values in every slot of the SSH CA
// of the assh.conf beside the control.conf at controlPath - its slots made
// those of the file first - with the signing key, when one is not approved
// yet: after an image rebuild, slot 0's PCR 11 (or 8 and 9) has moved. No
// CA is nothing to do. A token that is not at hand is a skip, as for the
// slots.
func resealSSHCA(controlPath, tpmPath, privKeyPath string) error {
	conf, confErr := loadSSHConf(sshConfPath(controlPath), controlPath)
	path := conf.CA
	if !fileExistsCA(path) {
		return nil
	}
	fmt.Printf("\n── SSH CA (%s) ─────────────────────────\n", path)
	if confErr != nil {
		return fmt.Errorf("SSH CA: %w", confErr)
	}
	if changed, err := syncSSHCASlots(conf); err != nil {
		return fmt.Errorf("SSH CA: %w", err)
	} else if changed {
		fmt.Printf("SSH CA: its slots are %s's now\n", sshConfPath(controlPath))
	}
	st := readSSHCA(conf, tpmPath)
	if st.CA == nil || st.Values == nil {
		return fmt.Errorf("SSH CA: %s", st.Err)
	}
	if len(st.Unapproved()) == 0 {
		fmt.Println("SSH CA: every slot is approved for the next boot already")
		return nil
	}
	if privKeyPath == "" {
		privKeyPath = signing.DefaultPrivateKeyPath
	}
	signer, err := signing.LoadCheckedSigningPrivateKey(privKeyPath)
	if err != nil {
		return fmt.Errorf("SSH CA: %w", err)
	}
	if !samePublicKey(st.CA.AuthorityKey(), signer.Public()) {
		return fmt.Errorf("SSH CA: its authority is another key than %s: control creates the CA again", privKeyPath)
	}
	if err := signing.PrepareSigningKey(signer); err != nil {
		var cause *signing.TokenUnavailableError
		if errors.As(err, &cause) {
			fmt.Printf("tpm2-kira: SKIPPED: the SSH CA is not approved for the next boot - the signing key was not available.\n  Reason: %s\n  The next boot serves a temporary host key unless slot 1 still fits; run 'sudo tpm2-kira slot approve' with the key at hand.\n", cause.Reason)
			return fmt.Errorf("%w: the SSH CA", ErrResealSkipped)
		}
		return fmt.Errorf("SSH CA: %w", err)
	}
	ca, err := approveSSHCA(conf, tpmPath, signer)
	if err != nil {
		return fmt.Errorf("SSH CA: %w", err)
	}
	fmt.Printf("Successfully approved the SSH CA %s for the next boot in %d slot(s)\n", ca.Fingerprint(), len(ca.Slots))
	return nil
}

// fileExistsCA reports whether there is a CA at path, a file or an EFI
// variable.
func fileExistsCA(path string) bool {
	_, err := hostkey.LoadCA(path)
	return !os.IsNotExist(err)
}

// samePublicKey reports whether a and b are the same key.
func samePublicKey(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

// ErrResealSkipped marks a reseal that did not happen because the signing
// key was unavailable. Nothing was written: the old blob is intact and still
// opens through PolicySigned once the key is back.
var ErrResealSkipped = errors.New("approval skipped")

// ResealSkippedError reports one slot whose reseal was skipped.
type ResealSkippedError struct {
	NVIndex    uint32
	KeyFile    string
	Cause      *signing.TokenUnavailableError
	SealedPCRs []measure.PCRSpec
}

func (e *ResealSkippedError) Error() string {
	return fmt.Sprintf("approval of slot 0x%08X skipped: %v", e.NVIndex, e.Cause)
}

func (e *ResealSkippedError) Unwrap() []error { return []error{ErrResealSkipped, e.Cause} }

// asResealSkipped turns an error into a skip when, and only when, the
// signing key was unavailable and the NVRAM index was not touched. A failure
// after the index was replaced is never a skip, whatever caused it.
func asResealSkipped(err error, nvIndex uint32, keyFile string, blob *nvslot.SealedBlob) error {
	var cause *signing.TokenUnavailableError
	if err == nil || errors.Is(err, nvslot.ErrNVIndexReplaced) || errors.Is(err, ErrGenerationRaised) || !errors.As(err, &cause) {
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
		slots = append(slots, fmt.Sprintf("#%d", nvslot.SlotNumber(s.NVIndex)))
	}
	fmt.Fprintln(w, "tpm2-kira: SKIPPED: the approval did not happen — the signing key was not available.")
	fmt.Fprintf(w, "  Key file:      %s (%s)\n", first.KeyFile, first.Cause.Token)
	fmt.Fprintf(w, "  Reason:        %s\n", indentContinuation(first.Cause.Reason, "                 "))
	fmt.Fprintf(w, "  Slots:         %s (nothing was written; the sealed secrets are intact)\n", strings.Join(slots, ", "))
	fmt.Fprintf(w, "  Sealed PCRs:   %s\n", measure.PCRSpecsToString(first.SealedPCRs))
	fmt.Fprintln(w, "  Consequence:   the sealed policy still binds the PCR values of the last seal.")
	fmt.Fprintln(w, "                 If they have changed — as they do after a kernel or initramfs")
	fmt.Fprintln(w, "                 update — the next boot reports a PCR MISMATCH and shows no")
	fmt.Fprintln(w, "                 TOTP code. That is expected here; it is not evidence of tampering.")
	fmt.Fprintln(w, "  To fix:        plug in the YubiKey and run, with the PIN typed when asked")
	fmt.Fprintf(w, "                 or set in %s:\n", signing.PINEnvVar)
	fmt.Fprintln(w, "                     sudo tpm2-kira slot approve")
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
// The signing key is --privkey, or the default key from setup (see
// resolveResealKeys); the blob names no key file. The public key for the NEW sealed blob is --pubkey, which must belong to that
// private key, or else derived from it.
func Reseal(tpmPath, pcrsStr string, nvramIndex uint32, pubKeyPath, privKeyPath string, debug bool) error {
	// Parse PCRs if provided (we'll use original PCRs if not explicitly overridden)
	var userProvidedSpecs []measure.PCRSpec
	var userSpecifiedPCRs bool
	var err error
	if pcrsStr != "" {
		userProvidedSpecs, err = measure.ParsePCRSpecs(pcrsStr)
		if err != nil {
			return fmt.Errorf("invalid PCRs: %w", err)
		}
		userSpecifiedPCRs = true
	}

	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	tpmdev.Cleanup(tpmDev, debug)

	sealedData, err := tpmdev.ReadFromNVRAM(tpmDev, nvramIndex)
	if err != nil {
		return tpmdev.HandleNVRAMNotFoundError(err, debug)
	}
	sealedBlob, err := nvslot.UnmarshalSealedBlob(sealedData)
	if err != nil {
		if bve, ok := nvslot.IsBlobVersionError(err); ok {
			return fmt.Errorf(
				"cannot approve: the stored blob is version %d but this build writes version %d.\n"+
					"slot approve preserves the existing blob, so it cannot upgrade the format.\n"+
					"Seal again to replace it (this generates a NEW TOTP secret, so re-enrol your authenticator):\n"+
					"    tpm2-kira slot add --nvram 0x%08X",
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
		return fmt.Errorf("cannot approve: %w", err)
	}

	// ── Make sure the key can sign before anything is changed ──
	// For a key on a token this finds an absent token or a missing PIN now,
	// while the slot is untouched, and reports a skip rather than a failure.
	if err := signing.PrepareSigningKey(signer); err != nil {
		if skip := asResealSkipped(err, nvramIndex, keys.privKeyPath, sealedBlob); skip != err {
			return skip
		}
		return fmt.Errorf("cannot approve: %w", err)
	}

	var specsToUse []measure.PCRSpec
	if userSpecifiedPCRs {
		specsToUse = userProvidedSpecs
		fmt.Printf("\nResealing with user-specified PCRs: %s\n", measure.PCRSpecsToString(specsToUse))
	} else {
		specsToUse = sealedBlob.GetPCRSpecs()
		fmt.Printf("\nPreserving original PCR selection: %s\n", measure.PCRSpecsToString(specsToUse))
	}

	hashAlgo := sealedBlob.GetHashAlgo()
	fmt.Printf("Hash algorithm: %s (%d-byte PCR digests)\n", hashAlgo.DisplayString(), hashAlgo.DigestSize())

	measure.WarnAboutPCRSelection(specsToUse)
	measure.WarnAboutHashAlgo(hashAlgo)
	printResealSources(specsToUse)

	pub := signer.Public()
	fmt.Printf("Signing key: %s (%s, fingerprint: %s)\n", keys.privKeyPath, signing.PublicKeyDescription(pub), signing.PublicKeyFingerprint(pub))

	if err := approveAndWrite(tpmDev, nvramIndex, sealedBlob, specsToUse, hashAlgo, false, signer, debug); err != nil {
		return asResealSkipped(fmt.Errorf("failed to approve: %w", err), nvramIndex, keys.privKeyPath, sealedBlob)
	}

	fmt.Printf("\nSuccessfully approved the boot state with PCRs: %s\n", measure.PCRSpecsToString(specsToUse))
	fmt.Printf("Generation: %d (every earlier approval for this slot is revoked)\n", sealedBlob.Payload.Generation)
	fmt.Printf("Authentication: PolicyAuthorize (PCR values + generation, approved by the signing key)\n")

	return nil
}

// checkObjectSigningKey fails unless pub is the key the blob's key object
// accepts approvals from.
func checkObjectSigningKey(blob *nvslot.SealedBlob, pub crypto.PublicKey) error {
	want, _, err := signing.PublicKeyToTPM2BPublic(pub)
	if err != nil {
		return err
	}
	if !bytes.Equal(want.Bytes(), blob.Payload.SigningPublic) {
		return fmt.Errorf("the TOTP key in this slot accepts approvals only from the signing key it was sealed with,\n" +
			"  and that is not the key in use. Changing the signing key means sealing again")
	}
	return nil
}

func printResealSources(specs []measure.PCRSpec) {
	for _, spec := range specs {
		fmt.Printf("  PCR%-2d (%s): %s\n", spec.Index, spec.Source.String(), measure.GetPCRDescription(spec.Index))
		if spec.Source == measure.PCRSourceUKI {
			fmt.Printf("         recomputed from the unified kernel image %s\n", untrusted.Quote(spec.Command))
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
// it therefore comes from --privkey or tpm2-kira's default location; the
// blob names no key file.
func resolveResealKeys(sealedData []byte, sealedBlob *nvslot.SealedBlob, privKeyPath, pubKeyPath string, debug bool) (*resealKeys, error) {
	keys := &resealKeys{privKeyPath: privKeyPath}
	if keys.privKeyPath == "" {
		keys.privKeyPath = signing.DefaultPrivateKeyPath
	}
	if _, err := os.Lstat(keys.privKeyPath); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("cannot approve: no signing private key at %s.\n"+
			"  The key verifies the blob and authorizes the NV write, so slot approve needs it.\n"+
			"  Pass --privkey <path>, or create the default key pair with 'tpm2-kira setup'.",
			keys.privKeyPath)
	}

	// Loaded from a checked file (mode 0400, trusted owner and directory,
	// no symlink). A key that fails to load is an error, not a reason to
	// skip the signature check.
	signer, err := signing.LoadCheckedSigningPrivateKey(keys.privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot approve: %w", err)
	}
	keys.signer = signer

	// An explicit --pubkey is checked the same way, and must belong to the
	// private key: the policy is built from it and the NV write is signed
	// with the private key, so a mismatch would only surface once the TPM
	// refuses the write, after the old index was undefined.
	if pubKeyPath != "" {
		pub, err := signing.LoadCheckedSigningPublicKey(pubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("cannot approve: %w", err)
		}
		if err := signing.VerifyKeyPairMatch(pub, signer); err != nil {
			return nil, fmt.Errorf("cannot approve: %s and %s are not a key pair: %w", pubKeyPath, keys.privKeyPath, err)
		}
		keys.pubKey = pub
	}

	// The signature MUST be verified BEFORE any blob field is acted on, so a
	// tampered blob cannot steer reseal via its stored PCR specs.
	if err := nvslot.VerifyBlobSignature(sealedData, sealedBlob, signer.Public()); err != nil {
		return nil, fmt.Errorf("blob integrity check failed — the NVRAM blob may have been tampered with: %w", err)
	}
	if debug {
		fmt.Println("Blob signature verified successfully")
	}
	return keys, nil
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
