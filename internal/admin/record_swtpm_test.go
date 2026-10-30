//go:build integration

package admin

import (
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/persist"

	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
)

// A slot is there when its generation index is; its record is its EFI
// variable. What is left of one without the other is named.
func TestSlotStates(t *testing.T) {
	old := persist.VarDir
	persist.VarDir = t.TempDir()
	t.Cleanup(func() { persist.VarDir = old })

	sock := startSWTPM(t)
	const sealed, foreign = nvslot.NVRAMSlotStart, nvslot.NVRAMSlotStart + 5
	privPath, pubPath := signingKeyFiles(t)
	if err := Seal(sock, "23", sealed, pubPath, privPath, false, measure.PCRHashAlgoSHA256, false, true); err != nil {
		t.Fatal(err)
	}
	if err := nvslot.WriteRecord(foreign, []byte("a record of a TPM cleared since")); err != nil {
		t.Fatal(err)
	}
	tpmDev, err := transport.OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tpmDev.Close()

	if !nvslot.SlotExists(tpmDev, sealed) || nvslot.SlotExists(tpmDev, foreign) || nvslot.SlotExists(tpmDev, nvslot.NVRAMSlotStart+1) {
		t.Fatal("SlotExists does not follow the generation index")
	}
	states := map[uint32]nvslot.SlotState{}
	for _, s := range nvslot.SlotStates(tpmDev) {
		states[s.Index] = s
	}
	if len(states) != 2 || !states[sealed].Indices || !states[foreign].Record || states[foreign].Indices {
		t.Fatalf("states: %+v", states)
	}
	if states[foreign].Orphaned() == "" {
		t.Error("a record without its slot is not named")
	}
	// The sealed slot is whole: its record and its generation index.
	if s := states[sealed]; !s.Record || s.Orphaned() != "" {
		t.Errorf("the sealed slot: %+v %q", s, s.Orphaned())
	}
	// Its record removed (by hand, a firmware reset): named.
	if _, err := nvslot.RemoveRecord(sealed); err != nil {
		t.Fatal(err)
	}
	for _, s := range nvslot.SlotStates(tpmDev) {
		if s.Index == sealed && (s.Record || s.Orphaned() == "") {
			t.Errorf("the slot without its record: %+v %q", s, s.Orphaned())
		}
	}
}
