package nvslot

// A slot's record - its signed blob (blob.go) - lives in an EFI variable
// of its own, KIRAslotN, not in the TPM: nothing in it needs the TPM to
// keep it. Its integrity is the signing key's signature, its freshness the
// record counter (counter.go), and nothing in it is secret in clear: the
// private parts are wrapped by this TPM's storage key, the factors for its
// EK. The TPM keeps only what its policies read: the slot's generation
// index (policy.go) - which also says that the slot exists - and its record
// counter.
//
// What the variable changes against an NV index: root can replace it
// (refused by the signature and the counter) or delete it (the slot's
// methods fail, the fallbacks unlock); a TPM clear leaves it behind; a
// firmware reset may take it. Its size is bounded by MaxRecordSize, not by
// TPM2_PT_NV_INDEX_MAX.

import (
	"errors"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/persist"

	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// VarGUID is the vendor GUID of tpm2-kira's EFI variables.
const VarGUID = "67f474ef-94a1-4412-88df-d62349d430a9"

// MaxRecordSize bounds a slot's record: firmware variable stores are small
// (some fail when nearly full), so a record stays a few KB.
const MaxRecordSize = 8 * 1024

// ErrNoRecord: the slot has no record in its EFI variable.
var ErrNoRecord = errors.New("no record (not set up: 'tpm2-kira slot add'; what is left of a slot: 'tpm2-kira control')")

// RecordVar is the EFI variable of the slot at index: KIRAslotN.
func RecordVar(index uint32) (string, error) {
	if err := ValidateBlobIndex(index); err != nil {
		return "", err
	}
	return fmt.Sprintf("%sKIRAslot%d-%s", persist.VarPrefix, SlotNumber(index), VarGUID), nil
}

// ReadRecord is the slot's record as it is stored; ErrNoRecord when its
// variable is not there. It is not verified: UnmarshalSealedBlob and
// VerifyBlobSignature are the reader's.
func ReadRecord(index uint32) ([]byte, error) {
	v, err := RecordVar(index)
	if err != nil {
		return nil, err
	}
	data, err := persist.ReadVar(v)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("slot %d: %w", SlotNumber(index), ErrNoRecord)
	case err != nil:
		return nil, fmt.Errorf("slot %d's record: %w", SlotNumber(index), err)
	case len(data) == 0:
		return nil, fmt.Errorf("slot %d: %w (an empty variable)", SlotNumber(index), ErrNoRecord)
	case len(data) > MaxRecordSize:
		return nil, fmt.Errorf("slot %d's record is %d bytes, more than the %d a record may have", SlotNumber(index), len(data), MaxRecordSize)
	}
	return data, nil
}

// WriteRecord replaces the slot's record: the firmware takes the whole
// variable or none of it, and the old one stays until the new one is
// there. The record is signed by the caller (SignBlobPayload).
func WriteRecord(index uint32, data []byte) error {
	v, err := RecordVar(index)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("refusing to write an empty record for slot %d", SlotNumber(index))
	}
	if len(data) > MaxRecordSize {
		return &RecordTooLargeError{Slot: SlotNumber(index), Size: len(data)}
	}
	if err := persist.WriteVar(v, data); err != nil {
		return fmt.Errorf("slot %d's record: %w", SlotNumber(index), err)
	}
	back, err := persist.ReadVar(v)
	if err != nil || string(back) != string(data) {
		return fmt.Errorf("slot %d's record was written, but does not read back as written (%v)", SlotNumber(index), err)
	}
	return nil
}

// RemoveRecord removes the slot's record and reports whether there was
// one.
func RemoveRecord(index uint32) (bool, error) {
	v, err := RecordVar(index)
	if err != nil {
		return false, err
	}
	return persist.RemoveVar(v)
}

// RecordTooLargeError: a record over MaxRecordSize; nothing was written.
type RecordTooLargeError struct {
	Slot int
	Size int // the record, signed
}

func (e *RecordTooLargeError) Error() string {
	return fmt.Sprintf("slot %d's record would be %d bytes, more than the %d a record may have; nothing was written", e.Slot, e.Size, MaxRecordSize)
}

// SlotExists reports whether the slot at index is set up: its generation
// index is defined. Its record may still be missing (removed, or a
// firmware reset), which a reader finds as ErrNoRecord.
func SlotExists(tpmDev transport.TPM, index uint32) bool {
	return ValidateBlobIndex(index) == nil && tpmdev.NVRAMIndexExists(tpmDev, GenerationIndex(index))
}

// SlotState is what is there of a slot: in the TPM, in its variable.
type SlotState struct {
	Index   uint32
	Indices bool // the generation index is defined
	Record  bool // the variable is there
}

// Orphaned says what of the slot is left without the rest: a record whose
// slot is gone from the TPM (a TPM clear, a slot deleted elsewhere) or a
// slot whose record is gone (removed, a firmware reset); "" when whole or
// absent.
func (s SlotState) Orphaned() string {
	switch {
	case s.Record && !s.Indices:
		return "a record without its slot in the TPM (the TPM was cleared, or the slot removed without it)"
	case s.Indices && !s.Record:
		return "a slot in the TPM without its record (the EFI variable was removed, or the firmware reset)"
	}
	return ""
}

// SlotStates is the state of every slot of which anything is there.
func SlotStates(tpmDev transport.TPM) []SlotState {
	var out []SlotState
	for idx := uint32(NVRAMSlotStart); idx <= NVRAMSlotEnd; idx++ {
		s := SlotState{Index: idx, Indices: SlotExists(tpmDev, idx)}
		if v, err := RecordVar(idx); err == nil {
			_, rerr := persist.ReadVar(v)
			s.Record = rerr == nil
		}
		if s.Indices || s.Record {
			out = append(out, s)
		}
	}
	return out
}
