package cmd

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Seal generates and seals a TOTP secret to TPM NVRAM with PCR policy and optional password
func Seal(tpmPath, pcrsStr string, nvramIndex uint32, password string, debug bool) error {
	// Parse PCR specs first to display them
	specs, err := ParsePCRSpecs(pcrsStr)
	if err != nil {
		return fmt.Errorf("invalid PCRs: %w", err)
	}

	// Display which PCRs are being used
	fmt.Println("=== Sealing Configuration ===")
	fmt.Printf("PCRs used for sealing: %s\n", PCRSpecsToString(specs))
	fmt.Println()
	for _, spec := range specs {
		fmt.Printf("  PCR%-2d (%s): %s\n", spec.Index, spec.Source.String(), GetPCRDescription(spec.Index))
	}
	fmt.Println()

	// Generate TOTP secret
	fmt.Println("Generating TOTP secret...")
	dataToSeal, err := generateTOTPSecret()
	if err != nil {
		return fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Seal the generated TOTP secret
	if err := sealDataWithSpecs(tpmPath, specs, nvramIndex, dataToSeal, password, debug); err != nil {
		return err
	}

	// Display TOTP information
	fmt.Println()
	fmt.Println("=== TOTP Secret Generated ===")
	totpSecret := string(dataToSeal)
	fmt.Printf("Secret: %s\n", totpSecret)
	fmt.Println()
	fmt.Println("Scan QR Code with authenticator app:")
	fmt.Println()

	// Display QR code with slot and PCR information
	displayTOTPQRCode(totpSecret, nvramIndex, PCRSpecsToString(specs))

	fmt.Println()
	fmt.Println("To generate TOTP codes:")
	fmt.Printf("   tpm2-kira reveal --nvram 0x%08X\n", nvramIndex)
	if password != "" {
		fmt.Println("   (password fallback enabled for recovery)")
	} else {
		fmt.Println("   (WARNING: no password fallback - reseal will not be possible)")
	}

	return nil
}

// sealData seals the provided data to TPM NVRAM with PCR policy and password.
// Parses the pcrsStr to determine per-PCR sources (register vs eventlog).
func sealData(tpmPath, pcrsStr string, nvramIndex uint32, dataToSeal []byte, password string, debug bool) error {
	specs, err := ParsePCRSpecs(pcrsStr)
	if err != nil {
		return fmt.Errorf("invalid PCRs: %w", err)
	}
	return sealDataWithSpecs(tpmPath, specs, nvramIndex, dataToSeal, password, debug)
}

// sealDataWithSpecs seals data using explicit PCR specs with per-PCR source (register or eventlog)
func sealDataWithSpecs(tpmPath string, specs []PCRSpec, nvramIndex uint32, dataToSeal []byte, password string, debug bool) error {
	if len(specs) == 0 {
		return fmt.Errorf("no PCRs specified")
	}

	if len(dataToSeal) == 0 {
		return fmt.Errorf("no data to seal")
	}

	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	// Cleanup TPM memory
	CleanupTPM(tpmDev, debug)

	// Separate PCRs by source
	var eventlogPCRIndices []int
	var registerPCRIndices []int
	for _, spec := range specs {
		if spec.Source == PCRSourceEventlog {
			eventlogPCRIndices = append(eventlogPCRIndices, spec.Index)
		} else {
			registerPCRIndices = append(registerPCRIndices, spec.Index)
		}
	}

	// Collect all PCR values from their respective sources
	pcrValues := make(map[int][]byte)
	var eventlogInfo *EventlogInfo

	// Calculate eventlog-based PCR values
	if len(eventlogPCRIndices) > 0 {
		calc := NewEventlogPCRCalculator(tpmDev, eventlogPCRIndices, debug)

		// Validate eventlog access first
		if err := ValidateEventlogAccess(tpmDev); err != nil {
			return fmt.Errorf("eventlog validation failed: %w", err)
		}

		// Calculate PCR values from eventlog
		calculatedPCRs, info, err := calc.CalculatePCRsFromEventlog()
		if err != nil {
			return fmt.Errorf("failed to calculate PCRs from eventlog: %w", err)
		}
		eventlogInfo = info

		for idx, val := range calculatedPCRs {
			pcrValues[idx] = val
		}

		if debug {
			fmt.Println("Eventlog-calculated PCR values:")
			for _, idx := range eventlogPCRIndices {
				fmt.Printf("  PCR%d: %x\n", idx, pcrValues[idx])
			}
		}
	}

	// Read register-based PCR values from TPM
	if len(registerPCRIndices) > 0 {
		pcrRead := tpm2.PCRRead{
			PCRSelectionIn: CreatePCRSelection(registerPCRIndices),
		}

		pcrReadResp, err := pcrRead.Execute(tpmDev)
		if err != nil {
			return fmt.Errorf("failed to read PCRs: %w", err)
		}

		for i, pcrIndex := range registerPCRIndices {
			pcrValues[pcrIndex] = pcrReadResp.PCRValues.Digests[i].Buffer
		}

		if debug {
			fmt.Println("Register-read PCR values:")
			for _, idx := range registerPCRIndices {
				fmt.Printf("  PCR%d: %x\n", idx, pcrValues[idx])
			}
		}
	}

	// Build ordered list of all PCR indices (preserving spec order)
	allPCRIndices := PCRSpecIndices(specs)

	// Compute policy digest from all collected PCR values
	policyDigest, err := ComputePolicyDigestFromPCRValues(tpmDev, allPCRIndices, pcrValues)
	if err != nil {
		return fmt.Errorf("failed to compute policy digest from PCR values: %w", err)
	}

	// Create PCRDigestPair structures with per-PCR source
	pcrDigests := make([]PCRDigestPair, len(specs))
	for i, spec := range specs {
		pcrDigests[i] = PCRDigestPair{
			Index:  spec.Index,
			Source: spec.Source,
			Digest: tpm2.TPM2BDigest{
				Buffer: pcrValues[spec.Index],
			},
		}
	}

	// Create primary key in owner hierarchy
	primaryKey, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return err
	}
	defer FlushHandle(tpmDev, primaryKey.ObjectHandle)

	// Create sealed object
	createRsp, err := CreateSealedObject(tpmDev, primaryKey, dataToSeal, policyDigest, password)
	if err != nil {
		return err
	}

	// Prepare sealed blob (Version 3: per-PCR source tracking)
	sealedBlob := &SealedBlob{
		Version:      3,
		AppVersion:   AppVersion,
		Public:       createRsp.Public,
		Private:      createRsp.Private,
		PCRDigests:   pcrDigests,
		HasPassword:  password != "",
		EventlogInfo: eventlogInfo,
	}

	// Marshal to bytes
	data, err := sealedBlob.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal sealed data: %w", err)
	}

	// Write to TPM NVRAM
	if err := WriteToNVRAM(tpmDev, nvramIndex, data); err != nil {
		return fmt.Errorf("failed to write to NVRAM: %w", err)
	}

	if debug {
		fmt.Printf("Successfully sealed TOTP secret to TPM NVRAM index 0x%08X\n", nvramIndex)
		fmt.Printf("PCRs used: %s\n", PCRSpecsToString(specs))
		fmt.Printf("Secret size: %d bytes\n", len(dataToSeal))
		fmt.Printf("Total NVRAM size: %d bytes\n", len(data))
		if len(eventlogPCRIndices) > 0 {
			fmt.Printf("Eventlog PCRs: %v\n", eventlogPCRIndices)
			if eventlogInfo != nil {
				fmt.Printf("Eventlog path: %s\n", eventlogInfo.EventlogPath)
				fmt.Printf("Total events: %d\n", eventlogInfo.TotalEvents)
			}
		}
		if len(registerPCRIndices) > 0 {
			fmt.Printf("Register PCRs: %v\n", registerPCRIndices)
		}
		if password != "" {
			fmt.Printf("Password fallback: enabled (TPM-validated)\n")
		} else {
			fmt.Printf("Password fallback: disabled\n")
		}
	}

	return nil
}

// generateTOTPSecret generates a TOTP-compatible secret
// Returns a 32-byte (256-bit) random secret encoded in Base32
func generateTOTPSecret() ([]byte, error) {
	// Generate 32 bytes of random data (256 bits)
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to Base32 (standard for TOTP secrets)
	// Remove padding as it's optional for TOTP
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)

	return []byte(secret), nil
}
