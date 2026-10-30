package nvslot

import (
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
)

const (
	// NVRAM slot range for multi-slot support
	NVRAMSlotStart = 0x01803010
	NVRAMSlotEnd   = 0x0180301F
)

// FindPopulatedSlotsInRange returns the slots from startIndex to endIndex
// (inclusive) that are set up: whose generation index is defined
// (SlotExists). Their records may still be missing, which a reader finds
// as ErrNoRecord. The check is lightweight: one NV public area each.
func FindPopulatedSlotsInRange(tpmDev transport.TPM, startIndex, endIndex uint32, debug bool) []uint32 {
	var populated []uint32
	for idx := startIndex; idx <= endIndex; idx++ {
		if !SlotExists(tpmDev, idx) {
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
