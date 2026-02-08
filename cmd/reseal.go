package cmd

import (
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Reseal unseals data from TPM NVRAM and reseals it with current PCR values
// Automatically preserves per-PCR source modes (register vs eventlog) from the original blob
func Reseal(tpmPath, pcrsStr string, nvramIndex uint32, password string, debug bool) error {
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

	// Resealing requires password for recovery
	if !sealedBlob.HasPassword {
		tpmDev.Close()
		return fmt.Errorf("resealing requires a password for recovery. The sealed data was created without a password, so resealing would risk permanent lockout after future PCR changes. To reseal, first extract the data and seal it again with a password")
	}

	if password == "" {
		tpmDev.Close()
		return fmt.Errorf("resealing requires a password to ensure recovery is possible after future PCR changes")
	}

	// Password validation is now done by TPM during unseal (no more Argon2 pre-check)

	// Perform unsealing workflow using the same logic as reveal/run commands
	result, err := UnsealWorkflow(tpmDev, nvramIndex, debug)
	if err != nil {
		// Check if it's a PCR mismatch - we can handle this with password
		if pcrErr, ok := err.(*PCRMismatchError); ok {
			fmt.Printf("PCR values changed - using password authentication\n")
			fmt.Println("\n=== PCR Mismatch Details ===")

			// Convert byte slices to TPM2BDigest format
			expectedDigests := make([]tpm2.TPM2BDigest, len(pcrErr.ExpectedDigests))
			for i, digest := range pcrErr.ExpectedDigests {
				expectedDigests[i] = tpm2.TPM2BDigest{Buffer: digest}
			}
			currentDigests := make([]tpm2.TPM2BDigest, len(pcrErr.CurrentDigests))
			for i, digest := range pcrErr.CurrentDigests {
				currentDigests[i] = tpm2.TPM2BDigest{Buffer: digest}
			}

			DisplayPCRMismatch(pcrErr.PCRIndices, expectedDigests, currentDigests)
			fmt.Println()

			// Use password authentication for unsealing (TPM validates the password)
			result, err = UnsealWithPassword(tpmDev, nvramIndex, password, debug)
			if err != nil {
				tpmDev.Close()
				// Convert TPM auth errors to user-friendly message
				if IsTPMAuthError(err) {
					return fmt.Errorf("incorrect password")
				}
				return fmt.Errorf("failed to unseal with password: %w", err)
			}
		} else if IsTPMPolicyFailure(err) {
			// TPM policy failure - show PCR comparison and use password authentication
			fmt.Printf("TPM policy verification failed - using password authentication\n")
			fmt.Printf("This typically happens when PCR values change during the unsealing process\n")
			fmt.Println()

			// Show PCR details using centralized helper function
			ShowPCRDetails(tpmDev, nvramIndex, debug)

			// Use password authentication for unsealing (TPM validates the password)
			result, err = UnsealWithPassword(tpmDev, nvramIndex, password, debug)
			if err != nil {
				tpmDev.Close()
				// Convert TPM auth errors to user-friendly message
				if IsTPMAuthError(err) {
					return fmt.Errorf("incorrect password")
				}
				return fmt.Errorf("failed to unseal with password: %w", err)
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
	for _, spec := range specsToUse {
		if spec.Source == PCRSourceEventlog {
			hasEventlog = true
		} else {
			hasRegister = true
		}
	}

	if hasEventlog && hasRegister {
		fmt.Println("PCR sources: mixed (some eventlog, some register)")
	} else if hasEventlog {
		fmt.Println("PCR sources: all eventlog-based")
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

	// Reseal the data with the determined specs, preserving the original hash algorithm
	if err := sealDataWithSpecs(tpmPath, specsToUse, nvramIndex, unsealedData, password, debug, hashAlgo); err != nil {
		return fmt.Errorf("failed to reseal data: %w", err)
	}

	fmt.Printf("\nSuccessfully resealed data with PCRs: %s\n", PCRSpecsToString(specsToUse))
	fmt.Printf("Data size: %d bytes\n", len(unsealedData))

	return nil
}

// UnsealWithPassword performs unsealing using password authentication when PCRs don't match
// Password validation is done solely by the TPM - no software pre-validation
func UnsealWithPassword(tpmDev transport.TPM, nvramIndex uint32, password string, debug bool) (*UnsealWorkflowResult, error) {
	// Read sealed blob from NVRAM
	sealedData, err := ReadFromNVRAM(tpmDev, nvramIndex)
	if err != nil {
		return nil, HandleNVRAMNotFoundError(err, debug)
	}

	// Unmarshal sealed blob
	sealedBlob, err := UnmarshalSealedBlob(sealedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sealed data: %w", err)
	}

	// Check if password protection was enabled during sealing
	if !sealedBlob.HasPassword {
		return nil, fmt.Errorf("sealed data has no password fallback configured")
	}

	// Create primary key
	primaryKey, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, primaryKey.ObjectHandle)

	// Load sealed object
	loadedObject, err := LoadSealedObject(tpmDev, primaryKey, sealedBlob)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, loadedObject.ObjectHandle)

	// Unseal the data using password authentication (not PCR policy)
	// The TPM validates the password directly - no software pre-validation needed
	unsealedData, err := UnsealData(tpmDev, loadedObject, sealedBlob, password, false)
	if err != nil {
		// Check if this is an authentication error and provide clearer message
		if IsTPMAuthError(err) {
			return nil, fmt.Errorf("TPM rejected password: incorrect password")
		}
		return nil, err
	}

	return &UnsealWorkflowResult{
		UnsealedData: unsealedData,
		SealedBlob:   sealedBlob,
		UsedPassword: true,
	}, nil
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
