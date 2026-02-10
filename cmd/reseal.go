package cmd

import (
	"crypto"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// FindPopulatedSlots probes the default slot range and returns the NVRAM
// indices that contain data.  The check is lightweight – it only reads the
// NV public area (no unsealing).
func FindPopulatedSlots(tpmDev transport.TPM, debug bool) []uint32 {
	var populated []uint32
	for idx := uint32(NVRAMSlotStart); idx <= uint32(NVRAMSlotEnd); idx++ {
		readPublic := tpm2.NVReadPublic{
			NVIndex: tpm2.TPMHandle(idx),
		}
		resp, err := readPublic.Execute(tpmDev)
		if err != nil {
			// Slot does not exist – skip
			continue
		}
		nvPub, err := resp.NVPublic.Contents()
		if err != nil || nvPub.DataSize == 0 {
			continue
		}
		if debug {
			fmt.Printf("Found populated slot 0x%08X (%d bytes)\n", idx, nvPub.DataSize)
		}
		populated = append(populated, idx)
	}
	return populated
}

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
		slotNum := int(slotIdx - NVRAMSlotStart)
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
		return fmt.Errorf("failed to unmarshal sealed data: %w", err)
	}

	// Verify the blob has a signed branch digest (v5 format)
	if len(sealedBlob.SignedBranchDigest) == 0 {
		tpmDev.Close()
		return fmt.Errorf("sealed blob does not contain a signed branch digest. Re-seal with current version: tpm2-kira seal")
	}

	// ── Resolve key paths: CLI flags take priority, then blob paths ──
	// The blob stores the filesystem paths used at seal time so that reseal
	// can locate the keys automatically when the user doesn't override them.
	effectivePrivKeyPath := privKeyPath
	effectivePubKeyPath := pubKeyPath

	if effectivePrivKeyPath == "" && sealedBlob.PrivateKeyPath != "" {
		effectivePrivKeyPath = sealedBlob.PrivateKeyPath
		if debug {
			fmt.Printf("Using private key path from blob: %s\n", effectivePrivKeyPath)
		}
	}
	if effectivePubKeyPath == "" && sealedBlob.PublicKeyPath != "" {
		effectivePubKeyPath = sealedBlob.PublicKeyPath
		if debug {
			fmt.Printf("Using public key path from blob: %s\n", effectivePubKeyPath)
		}
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

			// Private key is required for PolicySigned recovery
			if effectivePrivKeyPath == "" {
				tpmDev.Close()
				return fmt.Errorf("PCR values have changed. The signing private key is required for recovery.\n" +
					"  Provide it with --privkey <path>")
			}

			// Use PolicySigned branch for unsealing - the TPM verifies the signature
			result, err = UnsealWithSignedBranchFromBlob(tpmDev, nvramIndex, effectivePrivKeyPath, debug)
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

			// Private key is required for PolicySigned recovery
			if effectivePrivKeyPath == "" {
				tpmDev.Close()
				return fmt.Errorf("TPM policy verification failed. The signing private key is required for recovery.\n" +
					"  Provide it with --privkey <path>")
			}

			// Use PolicySigned branch for unsealing - the TPM verifies the signature
			result, err = UnsealWithSignedBranchFromBlob(tpmDev, nvramIndex, effectivePrivKeyPath, debug)
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
	// The blob no longer stores the public key PEM; a key source on the filesystem is required.
	var resealPubKey crypto.PublicKey
	var resealPubKeySource string
	var resealPubKeyPathForBlob string
	var resealPrivKeyPathForBlob string

	if effectivePubKeyPath != "" {
		// Explicit --pubkey (or blob path): load from the filesystem
		var loadedPubKey crypto.PublicKey
		loadedPubKey, _, err = LoadSigningPublicKeyFromPEM(effectivePubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load signing public key from %s: %w", effectivePubKeyPath, err)
		}
		resealPubKey = loadedPubKey
		resealPubKeySource = effectivePubKeyPath
		resealPubKeyPathForBlob = effectivePubKeyPath
	} else if effectivePrivKeyPath != "" {
		// No --pubkey but --privkey was given: derive public key from it
		privKey, loadErr := LoadSigningPrivateKeyFromPEM(effectivePrivKeyPath)
		if loadErr != nil {
			return fmt.Errorf("failed to load private key to derive public key: %w", loadErr)
		}
		resealPubKey = privKey.Public()
		resealPubKeySource = fmt.Sprintf("(derived from %s)", effectivePrivKeyPath)
	} else {
		// Neither --pubkey nor --privkey available: cannot reseal
		return fmt.Errorf("cannot reseal: no signing key available.\n" +
			"  Provide --pubkey <path> or --privkey <path>, or ensure the key paths\n" +
			"  stored in the blob are accessible on the filesystem")
	}

	// Preserve the private key path for the new blob
	if effectivePrivKeyPath != "" {
		resealPrivKeyPathForBlob = effectivePrivKeyPath
	}

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

	// Display per-PCR source information
	hasEventlog := false
	hasRegister := false
	hasPredict := false
	for _, spec := range specsToUse {
		switch spec.Source {
		case PCRSourceEventlog:
			hasEventlog = true
		case PCRSourcePredict:
			hasPredict = true
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
	if hasPredict {
		sourceCount++
	}

	if sourceCount > 1 {
		fmt.Println("PCR sources: mixed (eventlog, predict, and/or register)")
	} else if hasEventlog {
		fmt.Println("PCR sources: all eventlog-based")
	} else if hasPredict {
		fmt.Println("PCR sources: all predict-based (external command)")
	} else {
		fmt.Println("PCR sources: all register-based")
	}

	for _, spec := range specsToUse {
		fmt.Printf("  PCR%-2d (%s): %s\n", spec.Index, spec.Source.String(), GetPCRDescription(spec.Index))
	}

	if hasEventlog {
		fmt.Println("Note: Eventlog will be re-read to calculate current PCR values")
		if sealedBlob.EventlogInfo != nil {
			fmt.Printf("Previous eventlog info:\n")
			fmt.Printf("  Eventlog path: %s\n", sealedBlob.EventlogInfo.EventlogPath)
			fmt.Printf("  Sealed at: %s\n", sealedBlob.EventlogInfo.CalculationTime)
			fmt.Printf("  Events processed: %d/%d\n", sealedBlob.EventlogInfo.ProcessedEvents, sealedBlob.EventlogInfo.TotalEvents)
		}
	}
	if hasPredict {
		for _, spec := range specsToUse {
			if spec.Source == PCRSourcePredict {
				fmt.Printf("Note: PCR %d will be re-predicted via command: %s\n", spec.Index, spec.Command)
			}
		}
	}

	fmt.Printf("Signing key: %s (%s, fingerprint: %s)\n", resealPubKeySource, PublicKeyDescription(resealPubKey), PublicKeyFingerprint(resealPubKey))

	// Reseal the data with the determined specs, preserving the original hash algorithm
	if err := sealDataWithSpecs(tpmPath, specsToUse, nvramIndex, unsealedData, resealPubKey, resealPubKeyPathForBlob, resealPrivKeyPathForBlob, debug, hashAlgo); err != nil {
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
