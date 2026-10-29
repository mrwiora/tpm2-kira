package nvslot

// What tpm2-kira keeps in the TPM is removed one way, aSSH's persist's,
// like everything aSSH keeps there:
//
//   - A removal takes only an index that has the public area tpm2-kira
//     defines at that place (Ours: a blob's, a generation index's, a record
//     counter's), never whatever sits at a handle of its range; anything
//     else is left, and named (persist.ErrNotOurs).
//   - Absent is not an error: a removal reports what went.
//   - A write at one of tpm2-kira's own places replaces what is there,
//     whatever it is (replaceAt): the range is tpm2-kira's, and a stale or
//     planted index at it must not stop a slot from being written.

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/persist"
)

// Ours is what tpm2-kira defines at index, told by its place: the record
// counters, the generation indices above them, and below those the blobs
// (the slots' and the boot settings'). Outside the range nothing is ours.
func Ours(index uint32) persist.Owned {
	switch {
	case ValidateNVRAMIndex(index) != nil:
		return func(*tpm2.TPMSNVPublic, tpm2.TPM2BName) bool { return false }
	case index >= AttestCounterStart && index <= AttestCounterIndex(NVRAMSlotEnd):
		return persist.Shaped(AttestCounterPublic(index))
	case index >= AppNVRAMStart+GenerationIndexOffset:
		return persist.Shaped(generationIndexPublic(index, tpm2.TPM2BDigest{}))
	default:
		return persist.Shaped(blobPublic(index, tpm2.TPM2BDigest{}, 0))
	}
}

// RemoveIndex removes tpm2-kira's index at index, when it is there and
// has its shape. It reports whether it removed one.
func RemoveIndex(tpmDev transport.TPM, index uint32) (bool, error) {
	if err := ValidateNVRAMIndex(index); err != nil {
		return false, err
	}
	return persist.RemoveNV(tpmDev, tpm2.TPMHandle(index), Ours(index))
}

// Removed is one index a removal took.
type Removed struct {
	Index uint32
	What  string
}

// RemoveSlot removes the slot at blobIndex from the TPM, whole: its blob
// (the TOTP key, the phones, the vault's part), then its generation index
// and its record counter. Every part is tried even when another fails; it
// gives what went, and the failures together.
func RemoveSlot(tpmDev transport.TPM, blobIndex uint32) ([]Removed, error) {
	if err := ValidateBlobIndex(blobIndex); err != nil {
		return nil, err
	}
	var removed []Removed
	var errs []error
	for _, part := range []Removed{
		{blobIndex, "the blob (TOTP key and phones)"},
		{GenerationIndex(blobIndex), "the generation index"},
		{AttestCounterIndex(blobIndex), "the record counter"},
	} {
		ok, err := RemoveIndex(tpmDev, part.Index)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s (0x%08X): %w", part.What, part.Index, err))
			continue
		}
		if ok {
			removed = append(removed, part)
		}
	}
	return removed, errors.Join(errs...)
}

// replaceAt clears tpm2-kira's own place index for a write: what is
// there goes, whatever its shape.
func replaceAt(tpmDev transport.TPM, index uint32) error {
	if err := ValidateNVRAMIndex(index); err != nil {
		return err
	}
	if _, err := persist.RemoveNV(tpmDev, tpm2.TPMHandle(index), func(*tpm2.TPMSNVPublic, tpm2.TPM2BName) bool { return true }); err != nil {
		return fmt.Errorf("clearing 0x%08X for the write: %w", index, err)
	}
	return nil
}
