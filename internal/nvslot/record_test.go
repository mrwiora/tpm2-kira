package nvslot

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tpm2-trust/assh/persist"
)

// useVarDir points persist at a directory of the test's own.
func useVarDir(t *testing.T) string {
	t.Helper()
	old := persist.VarDir
	persist.VarDir = t.TempDir()
	t.Cleanup(func() { persist.VarDir = old })
	return persist.VarDir
}

// A slot's record is KIRAslotN under tpm2-kira's GUID, for the 16 slots
// and nothing else.
func TestRecordVar(t *testing.T) {
	for n, want := range map[uint32]string{0: "efi:KIRAslot0-" + VarGUID, 15: "efi:KIRAslot15-" + VarGUID} {
		if got, err := RecordVar(NVRAMSlotStart + n); err != nil || got != want {
			t.Errorf("slot %d: %q %v", n, got, err)
		}
	}
	for _, idx := range []uint32{NVRAMSlotStart - 1, NVRAMSlotEnd + 1, GenerationIndex(NVRAMSlotStart), 0} {
		if v, err := RecordVar(idx); err == nil {
			t.Errorf("0x%08X has a record: %s", idx, v)
		}
	}
}

// Written whole, read back as written, removed; a missing or empty
// variable is ErrNoRecord, an oversized one is neither written nor read.
func TestRecordStorage(t *testing.T) {
	dir := useVarDir(t)
	const slot = NVRAMSlotStart + 3
	if _, err := ReadRecord(slot); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("no variable: %v", err)
	}
	rec := bytes.Repeat([]byte{0x5a}, 3000) // more than an NV index of 2048
	if err := WriteRecord(slot, rec); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "KIRAslot3-"+VarGUID)
	raw, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(raw[:4], []byte{7, 0, 0, 0}) || !bytes.Equal(raw[4:], rec) {
		t.Fatalf("the variable: %d bytes, %v", len(raw), err)
	}
	if got, err := ReadRecord(slot); err != nil || !bytes.Equal(got, rec) {
		t.Fatalf("read back: %d bytes, %v", len(got), err)
	}
	newer := []byte("the next record")
	if err := WriteRecord(slot, newer); err != nil {
		t.Fatal(err)
	}
	if got, _ := ReadRecord(slot); !bytes.Equal(got, newer) {
		t.Fatalf("replaced: %q", got)
	}

	var tooLarge *RecordTooLargeError
	if err := WriteRecord(slot, make([]byte, MaxRecordSize+1)); !errors.As(err, &tooLarge) || tooLarge.Slot != 3 {
		t.Fatalf("an oversized record: %v", err)
	}
	if got, _ := ReadRecord(slot); !bytes.Equal(got, newer) {
		t.Fatal("an oversized record replaced the one there")
	}
	if err := WriteRecord(slot, nil); err == nil {
		t.Fatal("an empty record was written")
	}
	os.WriteFile(file, append([]byte{7, 0, 0, 0}, make([]byte, MaxRecordSize+1)...), 0o644)
	if _, err := ReadRecord(slot); err == nil || errors.Is(err, ErrNoRecord) || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("an oversized variable: %v", err)
	}
	os.WriteFile(file, []byte{7, 0, 0, 0}, 0o644)
	if _, err := ReadRecord(slot); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("an empty variable: %v", err)
	}

	if ok, err := RemoveRecord(slot); !ok || err != nil {
		t.Fatalf("remove: %v %v", ok, err)
	}
	if ok, err := RemoveRecord(slot); ok || err != nil {
		t.Fatalf("remove again: %v %v", ok, err)
	}
	if _, err := ReadRecord(slot); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("after remove: %v", err)
	}
	if err := WriteRecord(GenerationIndex(slot), newer); err == nil {
		t.Fatal("a record written for a generation index")
	}
}

func TestSlotStateOrphaned(t *testing.T) {
	for _, c := range []struct {
		s    SlotState
		want string
	}{
		{SlotState{Indices: true, Record: true}, ""},
		{SlotState{}, ""},
		{SlotState{Record: true}, "without its slot in the TPM"},
		{SlotState{Indices: true}, "without its record"},
	} {
		if got := c.s.Orphaned(); (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%+v: %q", c.s, got)
		}
	}
}
