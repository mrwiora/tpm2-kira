//go:build integration

package admin

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// DeleteSlot on a software TPM: the record and the generation index go in
// one act; a slot whose record alone was taken by hand is dirty, and the
// deletion takes the rest.
//
//	go test -tags integration -count=1 -run TestDeleteSlotOnSWTPM ./internal/admin/
func TestDeleteSlotOnSWTPM(t *testing.T) {
	sock := startSWTPM(t)
	tpm, err := tpmdev.Open(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	extendPCR(tpm, 0, "firmware")
	extendPCR(tpm, 7, "secure boot")
	pubPath, privPath := writeTestKeyPair(t)

	oldList := listLuksDevices
	defer func() { listLuksDevices = oldList }()
	useTestVars(t)
	listLuksDevices = func() ([]string, error) { return nil, nil }

	const idx = nvslot.NVRAMSlotStart + 1
	if err := Seal(sock, "0,7", idx, pubPath, privPath, false, measure.PCRHashAlgoSHA256, false, true); err != nil {
		t.Fatalf("seal: %v", err)
	}

	var out bytes.Buffer
	if err := DeleteSlot(DeleteSlotOptions{TPMPath: sock, Slot: 1, Out: &out}); err != nil {
		t.Fatalf("delete: %v\n%s", err, out.String())
	}
	if tpmdev.NVRAMIndexExists(tpm, nvslot.GenerationIndex(idx)) {
		t.Error("the generation index is still there")
	}
	if _, err := nvslot.ReadRecord(idx); !errors.Is(err, nvslot.ErrNoRecord) {
		t.Errorf("the record is still there: %v", err)
	}
	if !strings.Contains(out.String(), "deleted whole") || !strings.Contains(out.String(), "authenticator") {
		t.Errorf("output:\n%s", out.String())
	}
	if err := DeleteSlot(DeleteSlotOptions{TPMPath: sock, Slot: 1, Out: &out}); err == nil || !strings.Contains(err.Error(), "nothing to delete") {
		t.Fatalf("an empty slot: %v", err)
	}

	// The record taken by hand leaves the generation index: the slot is
	// dirty, and the deletion takes the rest.
	if err := Seal(sock, "0,7", idx, pubPath, privPath, false, measure.PCRHashAlgoSHA256, false, true); err != nil {
		t.Fatalf("seal again: %v", err)
	}
	if _, err := nvslot.RemoveRecord(idx); err != nil {
		t.Fatal(err)
	}
	dirt := collectDirt(sock, nil)
	if len(dirt) != 1 || dirt[0].Slot != 1 || !dirt[0].Generation || dirt[0].Record {
		t.Fatalf("dirt: %+v", dirt)
	}
	out.Reset()
	if err := DeleteSlot(DeleteSlotOptions{TPMPath: sock, Slot: 1, Out: &out}); err != nil {
		t.Fatalf("cleanup: %v\n%s", err, out.String())
	}
	if dirt := collectDirt(sock, nil); len(dirt) != 0 {
		t.Fatalf("still dirty: %+v", dirt)
	}
}
