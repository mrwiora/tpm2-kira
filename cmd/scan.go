package cmd

import (
	"fmt"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
)

const (
	// NVRAM slot range for multi-slot support
	NVRAMSlotStart = 0x01803010
	NVRAMSlotEnd   = 0x0180301F
)

// NVRAMSlot represents a TOTP secret stored in an NVRAM slot
type NVRAMSlot struct {
	SlotNumber int
	Index      uint32
	Code       string
	Secret     string
	Error      error // Error encountered during unsealing (if any)
	Available  bool  // Whether the slot has data (even if unsealing failed)
}

// ScanAndReveal scans NVRAM slots, displays PCR mismatches, and returns valid slots with codes
// If nvramIndex is 0, scans all slots in the default range
// Otherwise, scans only the specified nvramIndex
func ScanAndReveal(tpmPath string, nvramIndex uint32, debug bool) ([]NVRAMSlot, map[int]string, error) {
	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	// Cleanup TPM memory
	CleanupTPM(tpmDev, debug)

	// Determine if we should scan all slots or just one
	var slots []NVRAMSlot
	if nvramIndex == 0 {
		// Scan all slots in the default range when nvramIndex is 0
		slots = ScanNVRAMSlots(tpmDev, debug)
		if len(slots) == 0 {
			return nil, nil, fmt.Errorf("no TOTP secrets found in NVRAM slots 0x%08X - 0x%08X", NVRAMSlotStart, NVRAMSlotEnd)
		}
	} else {
		// Scan only the specified index
		slots = ScanNVRAMSlot(tpmDev, nvramIndex, debug)
		if len(slots) == 0 {
			return nil, nil, fmt.Errorf("no TOTP secret found at NVRAM index 0x%08X", nvramIndex)
		}
	}

	// Check if we have any valid slots (without PCR mismatches)
	if !HasValidSlots(slots) {
		return slots, nil, fmt.Errorf("TOTP secrets found but all have PCR mismatches (see details above)")
	}

	// Generate TOTP codes for all slots
	codes, err := GenerateTOTPCodesForSlots(slots)
	if err != nil {
		return slots, nil, err
	}

	return slots, codes, nil
}

// ScanNVRAMSlots scans all NVRAM indices from 0x01803010 to 0x0180301F
// and returns a list of slots containing valid TOTP secrets
func ScanNVRAMSlots(tpmDev transport.TPM, debug bool) []NVRAMSlot {
	return ScanNVRAMSlotsRange(tpmDev, NVRAMSlotStart, NVRAMSlotEnd, debug)
}

// ScanNVRAMSlot scans a single NVRAM index and returns it as a slot if valid
func ScanNVRAMSlot(tpmDev transport.TPM, nvramIndex uint32, debug bool) []NVRAMSlot {
	return ScanNVRAMSlotsRange(tpmDev, nvramIndex, nvramIndex, debug)
}

// ScanNVRAMSlotsRange scans NVRAM indices from startIndex to endIndex
// and returns a list of slots containing valid TOTP secrets
func ScanNVRAMSlotsRange(tpmDev transport.TPM, startIndex, endIndex uint32, debug bool) []NVRAMSlot {
	var slots []NVRAMSlot

	for i := startIndex; i <= endIndex; i++ {
		// Calculate slot number: if in default range, use offset from start
		// For custom indices, use offset from startIndex (0 for single slot)
		var slotNumber int
		if i >= NVRAMSlotStart && i <= NVRAMSlotEnd {
			slotNumber = int(i - NVRAMSlotStart)
		} else {
			slotNumber = int(i - startIndex)
		}

		if debug {
			fmt.Printf("Scanning NVRAM slot %d (0x%08X)...\n", slotNumber, i)
		}

		// Cleanup TPM state before each unseal attempt
		CleanupTPM(tpmDev, debug)

		// In debug mode, peek at the raw NVRAM data before attempting full unseal
		if debug {
			rawData, peekErr := ReadFromNVRAM(tpmDev, i)
			if peekErr == nil {
				peek := PeekBlobVersion(rawData)
				fmt.Printf("  Slot %d: NVRAM data found (%d bytes), blob version: %d", slotNumber, peek.DataSize, peek.Version)
				if peek.AppVersion != "" {
					fmt.Printf(", app version: %s", peek.AppVersion)
				}
				fmt.Println()
			} else if debug {
				fmt.Printf("  Slot %d: no NVRAM data (%v)\n", slotNumber, peekErr)
			}
			// Re-cleanup after the peek read
			CleanupTPM(tpmDev, debug)
		}

		// Try to unseal from this slot
		result, err := UnsealWorkflow(tpmDev, i, debug)
		if err != nil {
			// Check if this is a blob version incompatibility (slot has data but wrong version)
			if bve, ok := IsBlobVersionError(err); ok {
				if debug {
					fmt.Printf("  Slot %d: incompatible blob version (found v%d, requires v%d)\n", slotNumber, bve.FoundVersion, bve.RequiredVersion)
				}

				// Mark slot as available but with the version error
				slots = append(slots, NVRAMSlot{
					SlotNumber: slotNumber,
					Index:      i,
					Available:  true,
					Error:      err,
				})
				continue
			}

			// Check if this is a PCR policy failure (slot exists but PCRs don't match)
			if IsTPMPolicyFailure(err) {
				if debug {
					fmt.Printf("  Slot %d: PCR policy failure - slot exists but PCRs don't match\n", slotNumber)
				}

				// Mark slot as available but with error
				slots = append(slots, NVRAMSlot{
					SlotNumber: slotNumber,
					Index:      i,
					Available:  true,
					Error:      err,
				})
				continue
			}

			// Check if it's a PCR mismatch error with detailed information
			if _, ok := err.(*PCRMismatchError); ok {
				if debug {
					fmt.Printf("  Slot %d: PCR mismatch detected\n", slotNumber)
				}

				// Mark slot as available but with error
				slots = append(slots, NVRAMSlot{
					SlotNumber: slotNumber,
					Index:      i,
					Available:  true,
					Error:      err,
				})
				continue
			}

			// Before dropping the slot, check whether NVRAM actually has data.
			// If it does, the slot exists but unsealing failed for an
			// unexpected reason (e.g. TPM resource exhaustion). We must still
			// report it so the user sees all populated slots.
			CleanupTPM(tpmDev, debug)
			if rawData, peekErr := ReadFromNVRAM(tpmDev, i); peekErr == nil && len(rawData) > 0 {
				if debug {
					fmt.Printf("  Slot %d: NVRAM data present but unsealing failed (%v)\n", slotNumber, err)
				}
				slots = append(slots, NVRAMSlot{
					SlotNumber: slotNumber,
					Index:      i,
					Available:  true,
					Error:      err,
				})
				continue
			}

			if debug {
				fmt.Printf("  Slot %d: not available (%v)\n", slotNumber, err)
			}
			continue
		}

		// Get the unsealed TOTP secret
		secret := string(result.UnsealedData)

		// Generate TOTP code
		code, _, err := generateTOTPCode(secret)
		if err != nil {
			if debug {
				fmt.Printf("  Slot %d: contains data but not a valid TOTP secret\n", slotNumber)
			}
			continue
		}

		if debug {
			fmt.Printf("  Slot %d: valid TOTP secret found, code: %s\n", slotNumber, code)
		}

		slots = append(slots, NVRAMSlot{
			SlotNumber: slotNumber,
			Index:      i,
			Code:       code,
			Secret:     secret,
			Available:  true,
		})
	}

	return slots
}

// GenerateTOTPCodesForSlots generates fresh TOTP codes for all slots
// Returns a map of slot numbers to TOTP codes and any error encountered
func GenerateTOTPCodesForSlots(slots []NVRAMSlot) (map[int]string, error) {
	codes := make(map[int]string)

	for _, slot := range slots {
		// Skip slots that have errors (e.g., PCR mismatch)
		if slot.Error != nil {
			continue
		}

		code, _, err := generateTOTPCode(slot.Secret)
		if err != nil {
			return nil, fmt.Errorf("failed to generate TOTP code for slot %d: %w", slot.SlotNumber, err)
		}
		codes[slot.SlotNumber] = code
	}

	return codes, nil
}

// PrintKIRASlots prints TOTP codes in the unified KIRA format with timestamps and PCR details
func PrintKIRASlots(tpmDev transport.TPM, slots []NVRAMSlot, codes map[int]string) {
	now := time.Now().UTC()
	timestamp := now.Format("15:04:05")

	// Yellow color for KIRA
	fmt.Printf("[ \033[1;33mKIRA\033[0m ] Time UTC %s\n", timestamp)

	for _, slot := range slots {
		if slot.Error != nil {
			// Check if this is a version incompatibility error
			if bve, ok := IsBlobVersionError(slot.Error); ok {
				fmt.Printf("\033[0;31m#%d\033[0m: Incompatible blob version (found v%d, requires v%d) - re-seal with: tpm2-kira seal\n", slot.SlotNumber, bve.FoundVersion, bve.RequiredVersion)
				continue
			}

			// This slot has a PCR mismatch or policy failure - red slot number
			fmt.Printf("\033[0;31m#%d\033[0m: PCR Mismatch\n", slot.SlotNumber)

			// Try to read the sealed blob to get PCR details
			// Read the sealed blob and current register values for comparison
			sealedData, err := ReadFromNVRAM(tpmDev, slot.Index)
			if err == nil {
				sealedBlob, err := UnmarshalSealedBlob(sealedData)
				if err == nil {
					// Read current PCR values from TPM registers only
					// (no eventlog or predict dependency)
					currentPCRValues, err := GetCurrentPCRValuesFromRegisters(tpmDev, sealedBlob, false)
					if err == nil {
						pcrIndices := sealedBlob.GetPCRIndices()
						expectedDigests := sealedBlob.GetPCRDigestValues()

						for idx, pcrIndex := range pcrIndices {
							if idx >= len(expectedDigests) || idx >= len(currentPCRValues) {
								break
							}

							expected := expectedDigests[idx].Buffer
							current := currentPCRValues[idx].Buffer

							match := true
							if len(expected) != len(current) {
								match = false
							} else {
								for j := range expected {
									if expected[j] != current[j] {
										match = false
										break
									}
								}
							}

							status := "✓ MATCH"
							if !match {
								status = "✗ CHANGED"
							}

							source := sealedBlob.PCRDigests[idx].Source
							fmt.Printf("  PCR%-2d (%s): %s - %s\n", pcrIndex, source.String(), GetPCRDescription(pcrIndex), status)
							fmt.Printf("    Expected (blob):    %x\n", expected)
							fmt.Printf("    Current (register): %x\n", current)
						}
					}
				}
			}
		} else if code, exists := codes[slot.SlotNumber]; exists {
			// Green slot number for successful reveal
			fmt.Printf("\033[0;32m#%d\033[0m: %s\n", slot.SlotNumber, code)
		}
	}
}

// PrintPlainSlots prints TOTP codes in plain format (no KIRA header)
func PrintPlainSlots(slots []NVRAMSlot, codes map[int]string) {
	for _, slot := range slots {
		if slot.Error != nil {
			// Check if this is a version incompatibility error
			if bve, ok := IsBlobVersionError(slot.Error); ok {
				fmt.Printf("#%d: Incompatible blob version (found v%d, requires v%d) - re-seal with: tpm2-kira seal\n", slot.SlotNumber, bve.FoundVersion, bve.RequiredVersion)
				continue
			}
			// For plain output with errors, show slot number
			fmt.Printf("#%d: PCR Mismatch\n", slot.SlotNumber)
		} else if code, exists := codes[slot.SlotNumber]; exists {
			// For plain output with codes, only show the code without prefix if single slot
			if len(slots) == 1 {
				fmt.Printf("%s\n", code)
			} else {
				fmt.Printf("#%d: %s\n", slot.SlotNumber, code)
			}
		}
	}
}

// HasValidSlots returns true if there are any slots with valid TOTP codes
func HasValidSlots(slots []NVRAMSlot) bool {
	for _, slot := range slots {
		if slot.Error == nil && slot.Secret != "" {
			return true
		}
	}
	return false
}

// RevealCommand implements the reveal command functionality
func RevealCommand(tpmPath string, nvramIndex uint32, debug bool, plain bool) {
	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		PrintKIRAError(fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err))
		return
	}
	defer tpmDev.Close()

	// Cleanup TPM memory
	CleanupTPM(tpmDev, debug)

	// Determine if we should scan all slots or just one
	var slots []NVRAMSlot
	if nvramIndex == 0 {
		// Scan all slots in the default range when nvramIndex is 0
		slots = ScanNVRAMSlots(tpmDev, debug)
		if len(slots) == 0 {
			PrintKIRAError(fmt.Errorf("no TOTP secrets found in NVRAM slots 0x%08X - 0x%08X", NVRAMSlotStart, NVRAMSlotEnd))
			return
		}
	} else {
		// Scan only the specified index
		slots = ScanNVRAMSlot(tpmDev, nvramIndex, debug)
		if len(slots) == 0 {
			PrintKIRAError(fmt.Errorf("no TOTP secret found at NVRAM index 0x%08X", nvramIndex))
			return
		}
	}

	// Generate TOTP codes for valid slots
	codes, _ := GenerateTOTPCodesForSlots(slots)

	// Display codes (including slots with PCR mismatches)
	if plain {
		PrintPlainSlots(slots, codes)
	} else {
		PrintKIRASlots(tpmDev, slots, codes)
	}
}

// RunCommand implements the run command functionality (continuous display)
func RunCommand(tpmPath string, nvramIndex uint32, debug bool) {
	var lastCodes map[int]string
	var lastError error
	var lastErrorTime time.Time
	firstRun := true

	lastCodes = make(map[int]string)

	for {
		// Open TPM
		tpmDev, err := transport.OpenTPM(tpmPath)
		if err != nil {
			currentTime := time.Now()
			newError := fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)

			// Show error message if it's new or 30 seconds have passed
			if lastError == nil || lastError.Error() != newError.Error() || currentTime.Sub(lastErrorTime) >= 30*time.Second {
				PrintKIRAError(newError)
				lastError = newError
				lastErrorTime = currentTime
			}

			// Wait 30 seconds before retrying
			time.Sleep(30 * time.Second)
			continue
		}

		// Cleanup TPM memory
		CleanupTPM(tpmDev, debug)

		// Determine if we should scan all slots or just one
		var slots []NVRAMSlot
		if nvramIndex == 0 {
			// Scan all slots in the default range when nvramIndex is 0
			slots = ScanNVRAMSlots(tpmDev, debug)
		} else {
			// Scan only the specified index
			slots = ScanNVRAMSlot(tpmDev, nvramIndex, debug)
		}
		tpmDev.Close()

		if len(slots) == 0 {
			currentTime := time.Now()
			var newError error
			if nvramIndex == 0 {
				newError = fmt.Errorf("no TOTP secrets found in NVRAM slots 0x%08X - 0x%08X", NVRAMSlotStart, NVRAMSlotEnd)
			} else {
				newError = fmt.Errorf("no TOTP secret found at NVRAM index 0x%08X", nvramIndex)
			}

			// Show error message if it's new or 30 seconds have passed
			if lastError == nil || lastError.Error() != newError.Error() || currentTime.Sub(lastErrorTime) >= 30*time.Second {
				PrintKIRAError(newError)
				lastError = newError
				lastErrorTime = currentTime
			}

			// Wait 30 seconds before retrying
			time.Sleep(30 * time.Second)
			continue
		}

		// Generate TOTP codes for valid slots
		newCodes, _ := GenerateTOTPCodesForSlots(slots)

		// Check if any code has changed or it's the first run
		hasNewCodes := firstRun
		if !firstRun {
			for slotNum, code := range newCodes {
				if lastCodes[slotNum] != code {
					hasNewCodes = true
					break
				}
			}
		}

		// Always display: on first run, when codes change, or when we have slots (even with errors)
		shouldDisplay := firstRun || hasNewCodes || len(slots) > 0

		if shouldDisplay {
			// Open TPM again for display (needed for PCR details)
			tpmDev2, err := transport.OpenTPM(tpmPath)
			if err == nil {
				// Display with colored KIRA format
				PrintKIRASlots(tpmDev2, slots, newCodes)
				tpmDev2.Close()
			} else {
				// Fallback: display without TPM access (no PCR details)
				fmt.Printf("[ \033[1;33mKIRA\033[0m ] Time UTC %s\n", time.Now().UTC().Format("15:04:05"))
				for _, slot := range slots {
					if slot.Error != nil {
						if bve, ok := IsBlobVersionError(slot.Error); ok {
							fmt.Printf("\033[0;31m#%d\033[0m: Incompatible blob version (found v%d, requires v%d) - re-seal with: tpm2-kira seal\n", slot.SlotNumber, bve.FoundVersion, bve.RequiredVersion)
						} else {
							fmt.Printf("\033[0;31m#%d\033[0m: PCR Mismatch\n", slot.SlotNumber)
						}
					} else if code, exists := newCodes[slot.SlotNumber]; exists {
						fmt.Printf("\033[0;32m#%d\033[0m: %s\n", slot.SlotNumber, code)
					}
				}
			}

			// Add newline after each output in run mode
			fmt.Println()

			// Update last codes
			lastCodes = newCodes
			lastError = nil // Clear any previous error since we're successful
			firstRun = false
		}

		// Calculate time to next TOTP window (30 second boundaries: :00 and :30)
		now := time.Now()
		currentSecond := now.Second()
		var secondsToWait int

		if currentSecond < 30 {
			// Wait until :30
			secondsToWait = 30 - currentSecond
		} else {
			// Wait until next :00
			secondsToWait = 60 - currentSecond
		}

		// Sleep until the next TOTP window boundary
		time.Sleep(time.Duration(secondsToWait) * time.Second)
	}
}
