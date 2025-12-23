package cmd

import (
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2/transport"
)

// Reveal unseals the TOTP secret from TPM NVRAM and generates a TOTP code
func Reveal(tpmPath, pcrsStr string, nvramIndex uint32, debug bool) {
	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		PrintKIRAError(fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err))
		os.Exit(0)
	}
	defer tpmDev.Close()

	// Cleanup TPM memory
	CleanupTPM(tpmDev, debug)

	// Perform unsealing workflow
	result, err := UnsealWorkflow(tpmDev, nvramIndex, debug)
	if err != nil {
		// Check if it's a TPM policy failure and show PCR details if possible
		if IsTPMPolicyFailure(err) {
			// Read sealed blob to show PCR comparison
			if sealedData, readErr := ReadFromNVRAM(tpmDev, nvramIndex); readErr == nil {
				if blob, unmarshalErr := UnmarshalSealedBlob(sealedData); unmarshalErr == nil {
					if currentPCRs, pcrErr := GetCurrentPCRValues(tpmDev, blob, debug); pcrErr == nil {
						fmt.Println(FormatKIRAError(err))
						fmt.Println()
						fmt.Println("=== PCR Mismatch Details ===")
						DisplayPCRMismatch(blob.GetPCRIndices(), blob.GetPCRDigestValues(), currentPCRs)
						fmt.Println()
						fmt.Println("To fix this, run: tpm2-kira reseal")
						fmt.Println("(Make sure you have the password that was set during initial sealing)")
						os.Exit(0)
					}
				}
			}
		}
		PrintKIRAError(err)
		os.Exit(0)
	}

	// Get the unsealed TOTP secret
	secret := string(result.UnsealedData)

	// Generate TOTP code
	code, _, err := generateTOTPCode(secret)
	if err != nil {
		PrintKIRAError(fmt.Errorf("failed to generate TOTP code (invalid TOTP secret): %w", err))
		os.Exit(0)
	}

	// Display with colored KIRA format
	PrintKIRAOutput(code)
}

// RevealPlain unseals the TOTP secret from TPM NVRAM and generates a plain TOTP code
func RevealPlain(tpmPath, pcrsStr string, nvramIndex uint32, debug bool) {
	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		PrintKIRAError(fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err))
		os.Exit(0)
	}
	defer tpmDev.Close()

	// Cleanup TPM memory
	CleanupTPM(tpmDev, debug)

	// Perform unsealing workflow
	result, err := UnsealWorkflow(tpmDev, nvramIndex, debug)
	if err != nil {
		// Check if it's a TPM policy failure and show PCR details if possible
		if IsTPMPolicyFailure(err) {
			// Read sealed blob to show PCR comparison
			if sealedData, readErr := ReadFromNVRAM(tpmDev, nvramIndex); readErr == nil {
				if blob, unmarshalErr := UnmarshalSealedBlob(sealedData); unmarshalErr == nil {
					if currentPCRs, pcrErr := GetCurrentPCRValues(tpmDev, blob, debug); pcrErr == nil {
						fmt.Println(FormatKIRAError(err))
						fmt.Println()
						fmt.Println("=== PCR Mismatch Details ===")
						DisplayPCRMismatch(blob.GetPCRIndices(), blob.GetPCRDigestValues(), currentPCRs)
						fmt.Println()
						fmt.Println("To fix this, run: tpm2-kira reseal")
						fmt.Println("(Make sure you have the password that was set during initial sealing)")
						os.Exit(0)
					}
				}
			}
		}
		PrintKIRAError(err)
		os.Exit(0)
	}

	// Get the unsealed TOTP secret
	secret := string(result.UnsealedData)

	// Generate TOTP code
	code, _, err := generateTOTPCode(secret)
	if err != nil {
		PrintKIRAError(fmt.Errorf("failed to generate TOTP code (invalid TOTP secret): %w", err))
		os.Exit(0)
	}

	// Display only the 6-digit TOTP code
	fmt.Println(code)
}
