package cmd

import (
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"
)

// Reseal unseals data from TPM NVRAM using PolicySigned recovery and reseals with current PCR values.
// When PCR values have changed, the signing private key is required to authenticate via the PolicySigned branch.
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

	// Load the signing public key for resealing
	pubKey, pubKeyPEM, err := LoadSigningPublicKeyFromPEM(pubKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load signing public key from %s: %w", pubKeyPath, err)
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

	// Verify the blob has a signing key (v4 format)
	if len(sealedBlob.SigningKeyPEM) == 0 {
		tpmDev.Close()
		return fmt.Errorf("sealed blob does not contain a signing key. Re-seal with current version: tpm2-kira seal")
	}

	// Perform unsealing workflow using the same logic as reveal/run commands
	result, err := UnsealWorkflow(tpmDev, nvramIndex, debug)
	if err != nil {
		// Check if it's a PCR mismatch - we can handle this with PolicySigned recovery
		if pcrErr, ok := err.(*PCRMismatchError); ok {
			fmt.Printf("PCR values changed - using PolicySigned recovery (signing key authentication)\n\n")

			// Show PCR mismatch details (blob vs current register values)
			PrintKIRAError(pcrErr)

			// Use PolicySigned branch for unsealing
			result, err = UnsealWithSignedBranchFromBlob(tpmDev, nvramIndex, privKeyPath, debug)
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

			// Use PolicySigned branch for unsealing
			result, err = UnsealWithSignedBranchFromBlob(tpmDev, nvramIndex, privKeyPath, debug)
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

	fmt.Printf("Signing key: %s (%s, fingerprint: %s)\n", pubKeyPath, PublicKeyDescription(pubKey), PublicKeyFingerprint(pubKey))

	// Reseal the data with the determined specs, preserving the original hash algorithm
	if err := sealDataWithSpecs(tpmPath, specsToUse, nvramIndex, unsealedData, pubKey, pubKeyPEM, debug, hashAlgo); err != nil {
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
