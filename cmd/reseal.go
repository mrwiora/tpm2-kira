package cmd

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"
)

// ResealCommand is the top-level entry point for the reseal CLI command.
// When nvramIndex is 0 it scans every default slot and reseals each one;
// otherwise it reseals only the requested index.
func ResealCommand(tpmPath string, nvramIndex uint32, pcrsStr, pubKeyPath, privKeyPath string, debug bool) error {
	if nvramIndex != 0 {
		// Single-slot mode – same behaviour as before
		return Reseal(tpmPath, pcrsStr, nvramIndex, pubKeyPath, privKeyPath, debug)
	}

	// Multi-slot mode – discover populated slots, then reseal each one
	tpmDev, err := transport.OpenTPM(tpmPath)
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
	for i, slotIdx := range slots {
		slotNum := SlotNumber(slotIdx)
		fmt.Printf("── Slot #%d (0x%08X) ─────────────────────────\n", slotNum, slotIdx)

		if err := Reseal(tpmPath, pcrsStr, slotIdx, pubKeyPath, privKeyPath, debug); err != nil {
			fmt.Printf("Error resealing slot #%d (0x%08X): %v\n", slotNum, slotIdx, err)
			failed = append(failed, slotIdx)
		}

		if i < len(slots)-1 {
			fmt.Println()
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("%d of %d slot(s) failed to reseal", len(failed), len(slots))
	}
	return nil
}

// Reseal unseals data from TPM NVRAM and reseals with current PCR values.
//
// Authentication is handled entirely by the TPM via PolicyOR:
//   - If PCR values match: the TPM authorizes unseal via the PCR branch. No private key needed.
//   - If PCR values changed: the TPM requires PolicySigned proof. The private key signs a
//     nonce and the TPM verifies it against the public key baked into the policy.
//
// The signing public key for the NEW sealed blob is determined by:
//  1. --pubkey flag (explicit override)
//  2. Derived from --privkey (if provided)
//  3. The public key stored in the existing blob (default, preserves key identity)
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

	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	// Note: No defer here - we'll close it manually before calling sealDataWithSpecs

	// Cleanup TPM memory
	CleanupTPM(tpmDev, debug)

	// Read sealed blob from NVRAM
	sealedData, err := ReadFromNVRAM(tpmDev, nvramIndex)
	if err != nil {
		tpmDev.Close()
		return HandleNVRAMNotFoundError(err, debug)
	}

	// Unmarshal sealed blob
	sealedBlob, err := UnmarshalSealedBlob(sealedData)
	if err != nil {
		tpmDev.Close()
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

	// Verify the blob has a signed branch digest
	if len(sealedBlob.Payload.SignedBranchDigest) == 0 {
		tpmDev.Close()
		return fmt.Errorf("sealed blob does not contain a signed branch digest. Re-seal with current version: tpm2-kira seal")
	}

	// ── Resolve key paths: CLI flags take priority, then blob paths ──
	// The blob stores the filesystem paths used at seal time so that reseal
	// can locate the keys automatically when the user doesn't override them.
	effectivePrivKeyPath := privKeyPath
	effectivePubKeyPath := pubKeyPath

	if effectivePrivKeyPath == "" && !sealedBlob.Payload.PrivateKeyRef.IsZero() {
		effectivePrivKeyPath = sealedBlob.Payload.PrivateKeyRef.String()
		if debug {
			fmt.Printf("Using private key path from blob: %s\n", effectivePrivKeyPath)
		}
	}
	if effectivePubKeyPath == "" && sealedBlob.Payload.PublicKeyRef.Kind == KeyRefFile && sealedBlob.Payload.PublicKeyRef.Path != "" {
		effectivePubKeyPath = sealedBlob.Payload.PublicKeyRef.Path
		if debug {
			fmt.Printf("Using public key path from blob: %s\n", effectivePubKeyPath)
		}
	}

	// Fallback: try the well-known default key paths if nothing was
	// resolved from the CLI flags or the blob.  This covers the common
	// case where a slot was sealed with only --pubkey (no --privkey) but
	// the default key pair created by 'setup' is still on disk.
	if effectivePrivKeyPath == "" {
		if _, err := os.Stat(DefaultPrivateKeyPath); err == nil {
			effectivePrivKeyPath = DefaultPrivateKeyPath
			if debug {
				fmt.Printf("Using default private key path: %s\n", effectivePrivKeyPath)
			}
		}
	}
	if effectivePubKeyPath == "" {
		if _, err := os.Stat(DefaultPublicKeyPath); err == nil {
			effectivePubKeyPath = DefaultPublicKeyPath
			if debug {
				fmt.Printf("Using default public key path: %s\n", effectivePubKeyPath)
			}
		}
	}

	// ── Resolve the signing key ──
	// Every reseal needs it, not only a recovery: the NV index's write policy
	// is PolicySigned, so even an unchanged-PCR reseal cannot write the new
	// blob without a signature. Resolving it first means an absent token or a
	// missing key file is reported before any work is done, and nothing in
	// the TPM has been disturbed.
	keyRef, err := ParseKeyRef(effectivePrivKeyPath)
	if err != nil {
		tpmDev.Close()
		return err
	}

	signingKey, keyErr := OpenSigningKey(keyRef, NewPINProvider(PINFileSetting), debug)
	if keyErr != nil {
		tpmDev.Close()

		if IsKeyUnavailable(keyErr) && !RequireKeySetting {
			return reportResealSkipped(nvramIndex, keyRef, sealedBlob, keyErr)
		}
		return keyErr
	}
	defer signingKey.Close()

	// ── Check the key is the one this blob was sealed against ──
	// Advisory, but it turns the commonest mistake — the wrong token plugged
	// in — into a sentence naming it, instead of a blob signature failure
	// that reads like tampering.
	if err := checkKeyIdentity(signingKey, sealedBlob); err != nil {
		tpmDev.Close()
		return err
	}

	// ── Verify blob integrity signature ──
	// The signature MUST be verified BEFORE any blob field is acted on, so a
	// tampered blob cannot steer reseal via its stored PCR specs or key refs.
	//
	// The verification key is the signing key's own public half — the trust
	// anchor. The blob's stored PublicKeyPath is NOT trusted for this purpose.
	if sigErr := VerifyBlobSignature(sealedData, sealedBlob, signingKey.Public()); sigErr != nil {
		tpmDev.Close()
		return fmt.Errorf("blob integrity check failed — the NVRAM blob may have been tampered with: %w", sigErr)
	}
	if debug {
		fmt.Println("Blob signature verified successfully")
	}

	// ── Unseal: let the TPM decide which branch to use ──
	// Try the PCR branch first. If PCRs match, the TPM authorizes it directly.
	// If PCRs changed, fall back to PolicySigned where the TPM verifies the signature.
	result, err := UnsealWorkflow(tpmDev, nvramIndex, debug)
	if err != nil {
		// Check if it's a PCR mismatch - we can handle this with PolicySigned recovery
		if pcrErr, ok := err.(*PCRMismatchError); ok {
			fmt.Printf("PCR values changed - using PolicySigned recovery (signing key authentication)\n\n")

			// Show PCR mismatch details (blob vs current register values)
			PrintKIRAError(pcrErr)

			// Use PolicySigned branch for unsealing - the TPM verifies the signature
			result, err = UnsealWithSignedBranchFromBlob(tpmDev, nvramIndex, signingKey, debug)
			if err != nil {
				tpmDev.Close()
				return fmt.Errorf("failed to unseal with signing key: %w", err)
			}
		} else if IsTPMPolicyFailure(err) {
			// TPM policy failure - show PCR comparison and use PolicySigned recovery
			fmt.Printf("TPM policy verification failed - using PolicySigned recovery\n")
			fmt.Printf("This typically happens when PCR values change during the unsealing process\n")
			fmt.Println()

			// Show PCR details using centralized helper function
			ShowPCRDetails(tpmDev, nvramIndex, debug)

			// Use PolicySigned branch for unsealing - the TPM verifies the signature
			result, err = UnsealWithSignedBranchFromBlob(tpmDev, nvramIndex, signingKey, debug)
			if err != nil {
				tpmDev.Close()
				return fmt.Errorf("failed to unseal with signing key: %w", err)
			}
		} else {
			tpmDev.Close()
			return fmt.Errorf("failed to unseal data: %w", err)
		}
	}

	unsealedData := result.UnsealedData
	sealedBlob = result.SealedBlob

	// Close TPM device before calling sealDataWithSpecs (which will open it again)
	tpmDev.Close()

	// ── Determine the public key for re-sealing ──
	// Priority: --pubkey > blob pubkey path > derived from --privkey > blob privkey path
	// The signing public key must come from the filesystem; the blob stores only
	// a path hint, which is not trusted.
	var resealPubKey crypto.PublicKey
	var resealPubKeySource string
	var resealPubKeyPathForBlob string
	var resealPrivKeyPathForBlob string

	if effectivePubKeyPath != "" {
		// Explicit --pubkey (or blob path): load from the filesystem. This is
		// how the signing key is changed, so it takes priority.
		var loadedPubKey crypto.PublicKey
		loadedPubKey, _, err = LoadSigningPublicKeyFromPEM(effectivePubKeyPath)
		if err != nil {
			if pubKeyPath != "" {
				// The user named this file, so failing to read it is their
				// error to see rather than something to work around.
				return fmt.Errorf("failed to load signing public key from %s: %w", effectivePubKeyPath, err)
			}

			// The path came from the blob, where it is only a hint. The
			// signing key already resolved above has the same public half,
			// so a moved or missing file is not a reason to stop.
			fmt.Printf("Note: the public key file recorded in the blob is unreadable (%v);\n", err)
			fmt.Printf("      using the public half of the signing key instead.\n")
			effectivePubKeyPath = ""
		} else {
			resealPubKey = loadedPubKey
			resealPubKeySource = effectivePubKeyPath
			resealPubKeyPathForBlob = effectivePubKeyPath
		}
	}

	if resealPubKey == nil {
		// The public half of the key already resolved above. No file to
		// read and, for a token, no second card session.
		resealPubKey = signingKey.Public()
		resealPubKeySource = fmt.Sprintf("(from %s)", keyRef)
	}

	// Preserve the key reference for the new blob
	resealPrivKeyPathForBlob = keyRef.String()

	// ── Display configuration and re-seal ──
	// Determine which PCR specs to use for resealing
	var specsToUse []PCRSpec

	if userSpecifiedPCRs {
		// User explicitly provided PCRs - use those
		specsToUse = userProvidedSpecs
		fmt.Printf("\nResealing data with user-specified PCRs: %s\n", PCRSpecsToString(specsToUse))
	} else {
		// No PCRs specified - preserve original PCR selection and per-PCR sources
		specsToUse = sealedBlob.GetPCRSpecs()
		fmt.Printf("\nPreserving original PCR selection: %s\n", PCRSpecsToString(specsToUse))
	}

	// Detect hash algorithm from the original blob
	hashAlgo := sealedBlob.GetHashAlgo()
	fmt.Printf("Hash algorithm: %s (%d-byte PCR digests)\n", hashAlgo.DisplayString(), hashAlgo.DigestSize())

	WarnAboutPCRSelection(specsToUse)
	WarnAboutHashAlgo(hashAlgo)

	// Display per-PCR source information
	hasEventlog := false
	hasRegister := false
	hasUKI := false
	for _, spec := range specsToUse {
		switch spec.Source {
		case PCRSourceEventlog:
			hasEventlog = true
		case PCRSourceUKI:
			hasUKI = true
		default:
			hasRegister = true
		}
	}

	sourceCount := 0
	if hasEventlog {
		sourceCount++
	}
	if hasRegister {
		sourceCount++
	}
	if hasUKI {
		sourceCount++
	}

	if sourceCount > 1 {
		fmt.Println("PCR sources: mixed (eventlog, uki, and/or register)")
	} else if hasEventlog {
		fmt.Println("PCR sources: all eventlog-based")
	} else if hasUKI {
		fmt.Println("PCR sources: all computed from the unified kernel image")
	} else {
		fmt.Println("PCR sources: all register-based")
	}

	for _, spec := range specsToUse {
		fmt.Printf("  PCR%-2d (%s): %s\n", spec.Index, spec.Source.String(), GetPCRDescription(spec.Index))
	}

	if hasEventlog {
		fmt.Println("Note: Eventlog will be re-read to calculate current PCR values")
		if sealedBlob.Payload.EventlogInfo != nil {
			fmt.Printf("Previous eventlog info:\n")
			fmt.Printf("  Eventlog path: %s\n", sealedBlob.Payload.EventlogInfo.EventlogPath)
			fmt.Printf("  Sealed at: %s\n", sealedBlob.Payload.EventlogInfo.CalculationTime)
			fmt.Printf("  Events processed: %d/%d\n", sealedBlob.Payload.EventlogInfo.ProcessedEvents, sealedBlob.Payload.EventlogInfo.TotalEvents)
		}
	}
	if hasUKI {
		for _, spec := range specsToUse {
			if spec.Source == PCRSourceUKI {
				fmt.Printf("Note: PCR %d will be recomputed from the unified kernel image: %s\n", spec.Index, spec.Command)
			}
		}
	}

	fmt.Printf("Signing key: %s (%s, fingerprint: %s)\n", resealPubKeySource, PublicKeyDescription(resealPubKey), PublicKeyFingerprint(resealPubKey))

	// Reseal the data with the determined specs, preserving the original hash algorithm
	if err := sealDataWithSpecs(tpmPath, specsToUse, nvramIndex, unsealedData, resealPubKey, resealPubKeyPathForBlob, resealPrivKeyPathForBlob, debug, hashAlgo, false, signingKey); err != nil {
		return fmt.Errorf("failed to reseal data: %w", err)
	}

	fmt.Printf("\nSuccessfully resealed data with PCRs: %s\n", PCRSpecsToString(specsToUse))
	fmt.Printf("Data size: %d bytes\n", len(unsealedData))
	fmt.Printf("Authentication: PolicyOR (PCR branch + PolicySigned branch)\n")

	return nil
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

// RequireKeySetting turns the graceful skip below into a hard failure. It is
// set by --require-key, for callers that must not quietly do nothing.
var RequireKeySetting bool

// ResealSkippedMarker is the fixed prefix the initramfs hooks grep for. It is
// deliberately distinct from both the success line and the FAILED marker: the
// reseal did not happen, but nothing is broken and nothing was lost.
const ResealSkippedMarker = "tpm2-kira: SKIPPED:"

// reportResealSkipped explains that no reseal took place because the signing
// key was not available, and what the user will see at the next boot.
//
// It returns nil. Nothing was attempted and nothing was damaged — the sealed
// blob in NVRAM is exactly as it was — so this is not a failure. What it is
// instead is a state the user has to know about, because the next boot will
// show a PCR mismatch and no TOTP code.
func reportResealSkipped(nvramIndex uint32, ref KeyRef, blob *SealedBlob, cause error) error {
	reason := cause.Error()
	hint := ""
	if kue, ok := AsKeyUnavailable(cause); ok {
		reason = kue.Reason
		hint = kue.Hint
	}

	var out strings.Builder

	fmt.Fprintf(&out, "\n%s resealing did not happen — the signing key was not available.\n", ResealSkippedMarker)
	fmt.Fprintf(&out, "  NVRAM slot:    0x%08X (slot #%d)\n", nvramIndex, SlotNumber(nvramIndex))
	if !ref.IsZero() {
		fmt.Fprintf(&out, "  Key reference: %s\n", ref)
	}
	fmt.Fprintf(&out, "  Reason:        %s\n", reason)
	fmt.Fprintf(&out, "  Consequence:   the sealed policy still binds the PCR values from before this\n")
	fmt.Fprintf(&out, "                 change. At the next boot tpm2-kira will report a PCR MISMATCH\n")
	fmt.Fprintf(&out, "                 and show no TOTP code. That is expected here — it is not\n")
	fmt.Fprintf(&out, "                 evidence of tampering.\n")

	if pcrs := describeSealedPCRs(blob); pcrs != "" {
		fmt.Fprintf(&out, "  Affected PCRs: %s\n", pcrs)
	}

	fmt.Fprintf(&out, "  Nothing was changed: the sealed secret in NVRAM is untouched.\n")
	fmt.Fprintf(&out, "  To fix:        make the key available and run:\n")
	if ref.Kind == KeyRefYubiKey {
		fmt.Fprintf(&out, "                     export %s=...\n", PINEnvVar)
	}
	fmt.Fprintf(&out, "                     sudo tpm2-kira reseal --nvram 0x%08X\n", nvramIndex)
	if hint != "" {
		fmt.Fprintf(&out, "  Hint:          %s\n", hint)
	}

	fmt.Fprint(os.Stderr, out.String())

	return nil
}

// describeSealedPCRs lists the PCRs in the sealed policy, which are exactly the
// ones that will be reported as mismatching.
func describeSealedPCRs(blob *SealedBlob) string {
	if blob == nil || len(blob.Payload.PCRDigests) == 0 {
		return ""
	}

	parts := make([]string, 0, len(blob.Payload.PCRDigests))
	for _, pair := range blob.Payload.PCRDigests {
		parts = append(parts, fmt.Sprintf("%d (%s)", pair.Index, pair.Source.String()))
	}

	return strings.Join(parts, ", ")
}

// checkKeyIdentity compares the resolved signing key against what the blob
// records about the key it was sealed with.
//
// The blob signature is the authoritative check and runs straight after this
// one; the point here is only to produce a better sentence when the two differ
// for an ordinary reason. A blob with nothing recorded — sealed by a build
// before this was stored — is not an error.
func checkKeyIdentity(key SigningKey, blob *SealedBlob) error {
	if len(blob.Payload.KeyFingerprint) == 0 {
		return nil
	}

	fingerprint, err := KeyFingerprint(key.Public())
	if err != nil {
		return err
	}

	if bytes.Equal(fingerprint, blob.Payload.KeyFingerprint) {
		return nil
	}

	msg := fmt.Sprintf("the signing key is not the one this slot was sealed against.\n"+
		"  Sealed with: fingerprint %x", blob.Payload.KeyFingerprint[:8])

	if blob.Payload.TokenSerial != 0 {
		msg += fmt.Sprintf(" on YubiKey %d", blob.Payload.TokenSerial)
	}
	if !blob.Payload.PrivateKeyRef.IsZero() {
		msg += fmt.Sprintf(" (%s)", blob.Payload.PrivateKeyRef)
	}

	msg += fmt.Sprintf("\n  Offered:     fingerprint %x (%s)", fingerprint[:8], key.Description())
	msg += "\n  Resealing with this key would fail inside the TPM: the sealed object's\n" +
		"  PolicySigned branch is bound to the other key's name."

	return errors.New(msg)
}
