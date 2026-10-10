package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/go-tpm/tpm2"
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
	Code       string // TOTP code for the time of the scan, computed in the TPM
	Error      error  // Why no code could be computed (if any)
	Available  bool   // Whether the slot has data (even if no code could be computed)

	// AfterSeparator marks a slot that got its first code only after the
	// boot display released the boot (tpm2-kira run), i.e. a blob whose
	// policy holds after the OS separator: its codes are computed live for
	// as long as the policy holds, and the display says so.
	AfterSeparator bool

	// Phone marks a slot attested by its phones: it has no TOTP key, so
	// no code, and the display shows the phone's state instead.
	Phone bool
}

// phoneSlotDefault is a phone slot's line where no gate reports on it.
const phoneSlotDefault = "mobile attestation (a phone is enrolled; no TOTP code)"

// NVRAMIndexExists performs a lightweight check whether the given NVRAM index
// is defined and contains data.  It only reads the NV public area — no
// unsealing or authorization is attempted.
func NVRAMIndexExists(tpmDev transport.TPM, index uint32) bool {
	readPublic := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(index),
	}
	resp, err := readPublic.Execute(tpmDev)
	if err != nil {
		return false
	}
	nvPub, err := resp.NVPublic.Contents()
	if err != nil {
		return false
	}
	return nvPub.DataSize > 0
}

// FindPopulatedSlotsInRange probes every index from startIndex to endIndex
// (inclusive) and returns those that contain data.  The check is lightweight —
// it only reads the NV public area (no unsealing).
func FindPopulatedSlotsInRange(tpmDev transport.TPM, startIndex, endIndex uint32, debug bool) []uint32 {
	var populated []uint32
	for idx := startIndex; idx <= endIndex; idx++ {
		if !NVRAMIndexExists(tpmDev, idx) {
			continue
		}
		if debug {
			fmt.Printf("Found populated slot #%d (0x%08X)\n", SlotNumber(idx), idx)
		}
		populated = append(populated, idx)
	}
	return populated
}

// FindPopulatedSlots is a convenience wrapper that scans the default slot
// range (NVRAMSlotStart – NVRAMSlotEnd).
func FindPopulatedSlots(tpmDev transport.TPM, debug bool) []uint32 {
	return FindPopulatedSlotsInRange(tpmDev, NVRAMSlotStart, NVRAMSlotEnd, debug)
}

// MaxSlotNumber is the highest valid slot shorthand (0-based).
const MaxSlotNumber = NVRAMSlotEnd - NVRAMSlotStart // 15

// ResolveNVRAMIndex translates a user-supplied --nvram value into a full
// NVRAM index.  Values 0–15 are treated as slot shorthands and mapped to
// NVRAMSlotStart + value.  Everything else is returned unchanged.
func ResolveNVRAMIndex(value uint32) uint32 {
	if value <= MaxSlotNumber {
		return NVRAMSlotStart + value
	}
	return value
}

// SlotNumber returns a human-friendly slot number for the given NVRAM index.
// Indices inside the default range are numbered as offsets from NVRAMSlotStart;
// indices outside the range are returned as-is (cast to int).
func SlotNumber(index uint32) int {
	if index >= NVRAMSlotStart && index <= NVRAMSlotEnd {
		return int(index - NVRAMSlotStart)
	}
	// Outside the shorthand range there is no slot number; the raw index would
	// be indistinguishable from a real one.
	return -1
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
// and returns a list of slots containing valid TOTP secrets.
// A lightweight existence check is performed first so that empty indices
// are skipped without incurring the cost of a full unseal attempt.
func ScanNVRAMSlotsRange(tpmDev transport.TPM, startIndex, endIndex uint32, debug bool) []NVRAMSlot {
	// Pre-filter: discover which indices actually hold data.
	populated := FindPopulatedSlotsInRange(tpmDev, startIndex, endIndex, debug)
	if len(populated) == 0 {
		return nil
	}

	var slots []NVRAMSlot

	for _, i := range populated {
		slotNumber := SlotNumber(i)

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
				fmt.Printf("  Slot %d: NVRAM data found (%d bytes), blob version: %d\n", slotNumber, peek.DataSize, peek.Version)
			} else if debug {
				fmt.Printf("  Slot %d: no NVRAM data (%v)\n", slotNumber, peekErr)
			}
			// Re-cleanup after the peek read
			CleanupTPM(tpmDev, debug)
		}

		code, _, err := SlotCode(tpmDev, i, time.Now(), debug)
		if errors.Is(err, ErrPhoneSlot) {
			slots = append(slots, NVRAMSlot{SlotNumber: slotNumber, Index: i, Available: true, Phone: true})
			continue
		}
		if err != nil {
			if debug {
				fmt.Printf("  Slot %d: no code (%v)\n", slotNumber, err)
			}
			// The slot was confirmed to exist by the pre-filter, so it
			// is reported with the reason, whatever it is.
			slots = append(slots, NVRAMSlot{SlotNumber: slotNumber, Index: i, Available: true, Error: err})
			continue
		}
		if debug {
			fmt.Printf("  Slot %d: code computed\n", slotNumber)
		}
		slots = append(slots, NVRAMSlot{SlotNumber: slotNumber, Index: i, Code: code, Available: true})
	}

	return slots
}

// GenerateTOTPCodesForSlots collects the codes of the slots that have one,
// keyed by slot number. The codes were computed by the TPM during the scan.
func GenerateTOTPCodesForSlots(slots []NVRAMSlot) (map[int]string, error) {
	codes := make(map[int]string)
	for _, slot := range slots {
		if slot.Error == nil && slot.Code != "" {
			codes[slot.SlotNumber] = slot.Code
		}
	}
	return codes, nil
}

// slotErrorLine describes why a slot has no code, for the boot console.
// It returns "" for a PCR mismatch, which is shown with its details.
func slotErrorLine(err error) string {
	var genErr *GenerationMismatchError
	switch {
	case errors.Is(err, ErrCodesLocked):
		return "Locked until reboot (codes are only shown before the disk is unlocked)"
	case errors.Is(err, ErrSeparatorLocked):
		return "Locked until the next boot (the OS separator ran after the measure point)"
	case errors.As(err, &genErr):
		if genErr.IndexMissing {
			return "Generation index missing - reseal"
		}
		return fmt.Sprintf("Approval revoked (blob generation %d, slot at %d) - reseal", genErr.BlobGeneration, genErr.IndexGeneration)
	}
	if bve, ok := IsBlobVersionError(err); ok {
		return fmt.Sprintf("Incompatible blob version (found v%d, requires v%d) - re-seal with: tpm2-kira seal", bve.FoundVersion, bve.RequiredVersion)
	}
	if _, ok := err.(*PCRMismatchError); ok || IsTPMPolicyFailure(err) {
		return ""
	}
	return fmt.Sprintf("No code: %v", err)
}

// PrintKIRASlots prints TOTP codes in the unified KIRA format with timestamps and PCR details
func PrintKIRASlots(tpmDev transport.TPM, slots []NVRAMSlot, codes map[int]string) {
	now := time.Now().UTC()
	timestamp := now.Format("15:04:05")

	// Yellow color for KIRA
	fmt.Printf("[ \033[1;33mKIRA\033[0m ] Time UTC %s\n", timestamp)

	for _, slot := range slots {
		if slot.Error != nil {
			if line := slotErrorLine(slot.Error); line != "" {
				fmt.Printf("\033[0;31m#%d\033[0m: %s\n", slot.SlotNumber, line)
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
					// (no eventlog or UKI dependency)
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

							status := PCRStatus(expected, current)

							source := sealedBlob.Payload.PCRDigests[idx].Source
							fmt.Printf("  PCR%-2d (%s): %s - %s\n", pcrIndex, source.String(), GetPCRDescription(pcrIndex), status)
							fmt.Printf("    Expected (blob):    %x\n", expected)
							fmt.Printf("    Current (register): %x\n", current)
						}
					}
				}
			}
		} else if slot.Phone {
			fmt.Printf("\033[0;33m#%d\033[0m: %s\n", slot.SlotNumber, phoneSlotText(codes, slot))
		} else if code, exists := codes[slot.SlotNumber]; exists {
			// Green slot number for successful reveal
			fmt.Printf("\033[0;32m#%d\033[0m: %s", slot.SlotNumber, code)
			if slot.AfterSeparator {
				fmt.Print("  (computed after the boot was released: reseal to lock it before the OS separator)")
			}
			fmt.Println()
		}
	}
}

// phoneSlotText is a phone slot's line: what the boot screen put in codes
// for it, or phoneSlotDefault.
func phoneSlotText(codes map[int]string, slot NVRAMSlot) string {
	if line, ok := codes[slot.SlotNumber]; ok {
		return line
	}
	return phoneSlotDefault
}

// PrintPlainSlots prints TOTP codes in plain format (no KIRA header)
func PrintPlainSlots(slots []NVRAMSlot, codes map[int]string) {
	for _, slot := range slots {
		if slot.Error != nil {
			if line := slotErrorLine(slot.Error); line != "" {
				fmt.Printf("#%d: %s\n", slot.SlotNumber, line)
				continue
			}
			// For plain output with errors, show slot number
			fmt.Printf("#%d: PCR Mismatch\n", slot.SlotNumber)
		} else if slot.Phone {
			fmt.Printf("#%d: %s\n", slot.SlotNumber, phoneSlotText(codes, slot))
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
		if slot.Error == nil && slot.Code != "" {
			return true
		}
	}
	return false
}

// RevealCommand implements the reveal command functionality
func RevealCommand(tpmPath string, nvramIndex uint32, debug bool, plain bool) {
	// Open TPM
	tpmDev, err := OpenTPM(tpmPath)
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
