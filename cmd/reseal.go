package cmd

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Reseal unseals data from TPM NVRAM and reseals it with current PCR values
// Automatically preserves eventlog-based PCR calculation if the original blob was eventlog-based
func Reseal(tpmPath, pcrsStr string, nvramIndex uint32, password string, debug bool) error {
	// Parse PCRs if provided (we'll use original PCRs if not explicitly overridden)
	var userProvidedPCRs []int
	var userSpecifiedPCRs bool
	var err error
	if pcrsStr != "" {
		userProvidedPCRs, err = ParsePCRs(pcrsStr)
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
	// Note: No defer here - we'll close it manually before calling sealData

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

	// Read current PCR values
	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: CreatePCRSelection(sealedBlob.GetPCRIndices()),
	}

	pcrReadResp, err := pcrRead.Execute(tpmDev)
	if err != nil {
		tpmDev.Close()
		return fmt.Errorf("failed to read PCRs: %w", err)
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

	// Always verify the password for reseal operations
	if !VerifyPasswordArgon2(password, sealedBlob.PasswordHash, sealedBlob.PasswordSalt) {
		tpmDev.Close()
		return fmt.Errorf("incorrect password")
	}

	// Determine which authentication method to use for unsealing
	pcrMatch := VerifyPCRValues(sealedBlob.GetPCRDigestValues(), pcrReadResp.PCRValues.Digests)
	usePassword := false

	if !pcrMatch {
		// PCRs don't match - use password authentication
		usePassword = true
		fmt.Printf("PCR values changed - using password authentication\n")

		// Always display PCR mismatch information
		fmt.Println("\n=== PCR Mismatch Details ===")
		DisplayPCRMismatch(sealedBlob.GetPCRIndices(), sealedBlob.GetPCRDigestValues(), pcrReadResp.PCRValues.Digests)
		fmt.Println()
	}

	// Create primary key
	primaryKey, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		tpmDev.Close()
		return err
	}

	// Load sealed object
	loadedObject, err := LoadSealedObject(tpmDev, primaryKey, sealedBlob)
	if err != nil {
		FlushHandle(tpmDev, primaryKey.ObjectHandle)
		tpmDev.Close()
		return err
	}

	// Unseal the data
	usePCRPolicy := !usePassword
	unsealedData, err := UnsealData(tpmDev, loadedObject, sealedBlob, password, usePCRPolicy)
	if err != nil {
		FlushHandle(tpmDev, loadedObject.ObjectHandle)
		FlushHandle(tpmDev, primaryKey.ObjectHandle)
		tpmDev.Close()
		return err
	}

	// Flush all handles to free TPM object memory before closing device
	FlushHandle(tpmDev, loadedObject.ObjectHandle)
	FlushHandle(tpmDev, primaryKey.ObjectHandle)

	// Close TPM device before calling sealData (which will open it again)
	tpmDev.Close()

	// Check if original blob was eventlog-based
	useEventlog := sealedBlob.EventlogBased

	if useEventlog {
		fmt.Println("\nResealing data with eventlog-based PCR calculation (preserving original mode)...")
		if sealedBlob.EventlogInfo != nil {
			fmt.Printf("Original eventlog info:\n")
			fmt.Printf("  Eventlog path: %s\n", sealedBlob.EventlogInfo.EventlogPath)
			fmt.Printf("  Sealed at: %s\n", sealedBlob.EventlogInfo.CalculationTime)
			fmt.Printf("  Events processed: %d/%d\n", sealedBlob.EventlogInfo.ProcessedEvents, sealedBlob.EventlogInfo.TotalEvents)
		}
	} else {
		fmt.Println("\nResealing data with current PCR values...")
	}

	// Determine which PCRs to use for resealing
	var pcrsToUse []int
	var pcrsStrToUse string

	if userSpecifiedPCRs {
		// User explicitly provided PCRs - use those
		pcrsToUse = userProvidedPCRs
		pcrsStrToUse = pcrsStr
		fmt.Printf("Using user-specified PCRs: %v\n", pcrsToUse)
	} else {
		// No PCRs specified - preserve original PCR selection
		pcrsToUse = sealedBlob.GetPCRIndices()
		// Convert PCR slice to string format for sealData
		pcrsStrToUse = ""
		for i, pcr := range pcrsToUse {
			if i > 0 {
				pcrsStrToUse += ","
			}
			pcrsStrToUse += fmt.Sprintf("%d", pcr)
		}
		fmt.Printf("Preserving original PCR selection: %v\n", pcrsToUse)
	}

	if useEventlog {
		fmt.Printf("PCR calculation mode: eventlog-based (automatically preserved)\n")
		fmt.Printf("Note: Eventlog will be re-read to calculate current PCR values\n")
	} else {
		fmt.Printf("PCR calculation mode: current values\n")
	}

	// Reseal the data with appropriate mode (eventlog-based or current values)
	if err := sealDataWithMode(tpmPath, pcrsStrToUse, nvramIndex, unsealedData, password, debug, useEventlog); err != nil {
		return fmt.Errorf("failed to reseal data: %w", err)
	}

	if useEventlog {
		fmt.Printf("\nSuccessfully resealed data with eventlog-based PCRs: %v\n", pcrsToUse)
	} else {
		fmt.Printf("\nSuccessfully resealed data with current PCRs: %v\n", pcrsToUse)
	}
	fmt.Printf("Data size: %d bytes\n", len(unsealedData))

	return nil
}
