package nvslot

// What tpm2-kira keeps in the TPM is removed one way, aSSH's persist's,
// like everything aSSH keeps there:
//
//   - A removal takes an index that has the public area tpm2-kira defines at
//     that place (Ours: a blob's, a generation index's, a record counter's),
//     never whatever sits at a handle of its range on its own; anything else
//     is left, and named (persist.ErrNotOurs).
//   - An index of another shape at one of tpm2-kira's own places (OwnPlace)
//     goes when a person saw it and said so (TakeForeign, persist.Any), and
//     nowhere else: a place can be stale, and only a person can tell.
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

// definedAt is the public area tpm2-kira defines at index, told by its
// place: the record counters, the generation indices above them, and below
// those the boot settings. The size of 0 is any, the policy not compared.
func definedAt(index uint32) tpm2.TPMSNVPublic {
	switch {
	case index >= AttestCounterStart && index <= AttestCounterIndex(NVRAMSlotEnd):
		return AttestCounterPublic(index)
	case index >= AppNVRAMStart+GenerationIndexOffset:
		return generationIndexPublic(index, tpm2.TPM2BDigest{})
	default:
		return blobPublic(index, tpm2.TPM2BDigest{}, 0)
	}
}

// Ours is what tpm2-kira defines at index. Outside the range nothing is ours.
func Ours(index uint32) persist.Owned {
	if ValidateNVRAMIndex(index) != nil {
		return func(*tpm2.TPMSNVPublic, tpm2.TPM2BName) bool { return false }
	}
	return persist.Shaped(definedAt(index))
}

// OwnPlace says whether index is a place tpm2-kira itself defines an index
// at: the boot settings, a slot's generation index or record counter. The
// rest of the range is only reserved for it.
func OwnPlace(index uint32) bool {
	return index == BootSettingsIndex ||
		(index >= GenerationIndex(NVRAMSlotStart) && index <= GenerationIndex(NVRAMSlotEnd)) ||
		(index >= AttestCounterIndex(NVRAMSlotStart) && index <= AttestCounterIndex(NVRAMSlotEnd))
}

// Foreign is an index at one of tpm2-kira's own places without the public
// area tpm2-kira defines there.
type Foreign struct {
	Index  uint32
	Public tpm2.TPMSNVPublic // what is there
	Name   tpm2.TPM2BName
	Want   tpm2.TPMSNVPublic // what tpm2-kira defines there
}

// ForeignAt is the index of another shape at index, or nil: none there, it is
// tpm2-kira's, the place is not one of its own, or it cannot be read (the
// removal then says why).
func ForeignAt(tpmDev transport.TPM, index uint32) *Foreign {
	if !OwnPlace(index) {
		return nil
	}
	pub, name, err := persist.ReadNVPublic(tpmDev, tpm2.TPMHandle(index))
	if err != nil || Ours(index)(pub, name) {
		return nil
	}
	return &Foreign{Index: index, Public: *pub, Name: name, Want: definedAt(index)}
}

// TakeForeign is a person's word on an index of another shape, having been
// shown it: true removes it. nil is No, without asking.
type TakeForeign func(Foreign) (bool, error)

// RemoveIndex removes tpm2-kira's index at index, when it is there and has
// its shape, or one of another shape at an own place that take says yes to.
// It reports whether it removed one.
func RemoveIndex(tpmDev transport.TPM, index uint32, take TakeForeign) (bool, error) {
	if err := ValidateNVRAMIndex(index); err != nil {
		return false, err
	}
	owned := Ours(index)
	if f := ForeignAt(tpmDev, index); f != nil && take != nil {
		yes, err := take(*f)
		if err != nil {
			return false, fmt.Errorf("NV index 0x%08X: %w", index, err)
		}
		if yes {
			owned = persist.Any
		}
	}
	return removeAt(tpmDev, index, owned)
}

// removeAt is the one removal, persist's, with what the TPM's refusal means
// for the person reading it.
func removeAt(tpmDev transport.TPM, index uint32, owned persist.Owned) (bool, error) {
	ok, err := persist.RemoveNV(tpmDev, tpm2.TPMHandle(index), owned)
	switch {
	case errors.Is(err, tpm2.TPMRCBadAuth), errors.Is(err, tpm2.TPMRCAuthFail):
		return ok, fmt.Errorf("NV index 0x%08X: the TPM's owner hierarchy has a password, and tpm2-kira presents the empty one throughout: remove the password (tpm2_changeauth -c owner -p PASSWORD) and do this again (%w)", index, err)
	case errors.Is(err, tpm2.TPMRCNVAuthorization):
		return ok, fmt.Errorf("NV index 0x%08X: the platform's firmware defined it, and only the platform can remove it: neither tpm2-kira nor the TPM's owner can (%w)", index, err)
	case errors.Is(err, tpm2.TPMRCAttributes):
		return ok, fmt.Errorf("NV index 0x%08X: it is defined to go by its own policy alone (TPM2_NV_UndefineSpaceSpecial, with the platform): the TPM's owner cannot remove it (%w)", index, err)
	}
	return ok, err
}

// Removed is one index a removal took.
type Removed struct {
	Index uint32
	What  string
}

// RemoveSlot removes the slot at blobIndex whole: its record (the EFI
// variable), then its generation index and record counter in the TPM, take
// deciding on either if it has another shape. Every part is tried even when
// another fails; it gives what went, and the failures together.
func RemoveSlot(tpmDev transport.TPM, blobIndex uint32, take TakeForeign) ([]Removed, error) {
	if err := ValidateBlobIndex(blobIndex); err != nil {
		return nil, err
	}
	var removed []Removed
	var errs []error
	if ok, err := RemoveRecord(blobIndex); err != nil {
		errs = append(errs, fmt.Errorf("the record (KIRAslot%d): %w", SlotNumber(blobIndex), err))
	} else if ok {
		removed = append(removed, Removed{blobIndex, fmt.Sprintf("the record (EFI variable KIRAslot%d)", SlotNumber(blobIndex))})
	}
	for _, part := range []Removed{
		{GenerationIndex(blobIndex), "the generation index"},
		{AttestCounterIndex(blobIndex), "the record counter"},
	} {
		ok, err := RemoveIndex(tpmDev, part.Index, take)
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
	if _, err := removeAt(tpmDev, index, func(*tpm2.TPMSNVPublic, tpm2.TPM2BName) bool { return true }); err != nil {
		return fmt.Errorf("clearing 0x%08X for the write: %w", index, err)
	}
	return nil
}
