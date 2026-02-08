package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// InfoWithFormat displays information with optional JSON output
func InfoWithFormat(tpmPath, pcrsStr string, nvramIndex uint32, debug bool, jsonOutput bool) error {
	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	// Read NVRAM public area
	nvIndex := tpm2.TPMHandle(nvramIndex)
	readPublic := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}

	readPublicResp, err := readPublic.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to read NVRAM index 0x%08X (may not exist): %w", nvramIndex, err)
	}

	nvPublic, err := readPublicResp.NVPublic.Contents()
	if err != nil {
		return fmt.Errorf("failed to parse NVRAM public area: %w", err)
	}

	// Read sealed blob from NVRAM
	sealedData, err := ReadFromNVRAM(tpmDev, nvramIndex)
	if err != nil {
		return fmt.Errorf("failed to read from NVRAM: %w", err)
	}

	// Unmarshal sealed blob
	sealedBlob, err := UnmarshalSealedBlob(sealedData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal sealed data: %w", err)
	}

	// Display information
	if jsonOutput {
		// Output the SealedBlob structure as JSON
		output, err := json.MarshalIndent(sealedBlob, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(output))
	} else {
		// Human-readable output
		fmt.Printf("Sealed Blob Information:\n")
		fmt.Printf("========================\n")
		fmt.Printf("TPM NVRAM Index: 0x%08X\n", nvramIndex)
		fmt.Printf("Total NVRAM Size: %d bytes\n\n", nvPublic.DataSize)

		hashAlgo := sealedBlob.GetHashAlgo()
		fmt.Printf("Blob Format:\n")
		fmt.Printf("  Version: %d\n", sealedBlob.Version)
		fmt.Printf("  App Version: %s\n", sealedBlob.AppVersion)
		fmt.Printf("  Hash Algorithm: %s (%d-byte PCR digests)\n\n", hashAlgo.DisplayString(), hashAlgo.DigestSize())

		fmt.Printf("NVRAM Attributes:\n")
		fmt.Printf("  Owner Write: %v\n", nvPublic.Attributes.OwnerWrite)
		fmt.Printf("  Owner Read: %v\n", nvPublic.Attributes.OwnerRead)
		fmt.Printf("  Auth Write: %v\n", nvPublic.Attributes.AuthWrite)
		fmt.Printf("  Auth Read: %v\n", nvPublic.Attributes.AuthRead)
		fmt.Printf("  Written: %v\n", nvPublic.Attributes.Written)
		fmt.Printf("\n")

		fmt.Printf("PCR Configuration:\n")
		fmt.Printf("  PCR Indices: %v\n", sealedBlob.GetPCRIndices())
		fmt.Printf("  Number of PCRs: %d\n\n", len(sealedBlob.PCRDigests))

		fmt.Printf("PCR Descriptions:\n")
		for _, pcrDigest := range sealedBlob.PCRDigests {
			fmt.Printf("  PCR%-2d (%s): %s\n", pcrDigest.Index, pcrDigest.Source.String(), GetPCRDescription(pcrDigest.Index))
		}
		fmt.Printf("\n")

		fmt.Printf("Password Fallback:\n")
		if sealedBlob.HasPassword {
			fmt.Printf("  Enabled: Yes\n")
			fmt.Printf("  Validation: TPM-based (no hash stored in NVRAM)\n")
		} else {
			fmt.Printf("  Enabled: No\n")
		}
		fmt.Printf("\n")

		fmt.Printf("TPM Objects:\n")
		fmt.Printf("  Public Blob Size: %d bytes\n", len(sealedBlob.Public))
		fmt.Printf("  Private Blob Size: %d bytes\n\n", len(sealedBlob.Private))

		fmt.Printf("Eventlog Information:\n")
		if sealedBlob.HasEventlogPCRs() {
			fmt.Printf("  Eventlog PCRs: %v\n", sealedBlob.GetEventlogPCRIndices())
			if sealedBlob.EventlogInfo != nil {
				fmt.Printf("  Eventlog Path: %s\n", sealedBlob.EventlogInfo.EventlogPath)
				fmt.Printf("  Eventlog Hash: %s...\n", sealedBlob.EventlogInfo.EventlogHash[:min(16, len(sealedBlob.EventlogInfo.EventlogHash))])
				fmt.Printf("  Calculation Time: %s\n", sealedBlob.EventlogInfo.CalculationTime)
				fmt.Printf("  Total Events: %d\n", sealedBlob.EventlogInfo.TotalEvents)
				fmt.Printf("  Processed Events: %d\n", sealedBlob.EventlogInfo.ProcessedEvents)
			}
		} else {
			fmt.Printf("  No eventlog-based PCRs (all from TPM registers)\n")
		}
		if len(sealedBlob.GetRegisterPCRIndices()) > 0 {
			fmt.Printf("  Register PCRs: %v\n", sealedBlob.GetRegisterPCRIndices())
		}
		fmt.Printf("\n")

		fmt.Printf("PCR Digest Values:\n")
		for _, pcrDigest := range sealedBlob.PCRDigests {
			fmt.Printf("  PCR %d (%s): (%d bytes)\n", pcrDigest.Index, pcrDigest.Source.String(), len(pcrDigest.Digest.Buffer))
			fmt.Printf("    Value: %x\n", pcrDigest.Digest.Buffer)
		}

		fmt.Println("\nSealed Data Content:")
		fmt.Println("===================")
		fmt.Println("Type: TOTP Secret")
		fmt.Println("\nNote: For security reasons, the 'info' command does not display secrets.")
		fmt.Println("Use 'tpm2-kira reveal' to generate TOTP codes.")
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
