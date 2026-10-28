//go:build integration

package admin

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// DeleteSlot on a software TPM: the blob, its generation index and the
// recovery blob go in one act; a slot whose blob alone was taken by hand
// is dirty, and the deletion takes the rest.
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

	oldDir, oldList := nvslot.NVRAMRecoveryDir, listLuksDevices
	defer func() { nvslot.NVRAMRecoveryDir, listLuksDevices = oldDir, oldList }()
	nvslot.NVRAMRecoveryDir = t.TempDir()
	listLuksDevices = func() ([]string, error) { return nil, nil }

	const idx = nvslot.NVRAMSlotStart + 1
	if err := Seal(sock, "0,7", idx, pubPath, privPath, false, measure.PCRHashAlgoSHA256, false); err != nil {
		t.Fatalf("seal: %v", err)
	}
	stash := filepath.Join(nvslot.NVRAMRecoveryDir, fmt.Sprintf("slot-0x%08X-1759823456.blob", uint32(idx)))
	os.WriteFile(stash, []byte("x"), 0o600)

	var out bytes.Buffer
	if err := DeleteSlot(DeleteSlotOptions{TPMPath: sock, Slot: 1, Out: &out}); err != nil {
		t.Fatalf("delete: %v\n%s", err, out.String())
	}
	for _, i := range []uint32{idx, nvslot.GenerationIndex(idx)} {
		if tpmdev.NVRAMIndexExists(tpm, i) {
			t.Errorf("0x%08X is still there", i)
		}
	}
	if _, err := os.Stat(stash); !os.IsNotExist(err) {
		t.Error("the recovery blob is still there")
	}
	if !strings.Contains(out.String(), "deleted whole") || !strings.Contains(out.String(), "authenticator") {
		t.Errorf("output:\n%s", out.String())
	}
	if err := DeleteSlot(DeleteSlotOptions{TPMPath: sock, Slot: 1, Out: &out}); err == nil || !strings.Contains(err.Error(), "nothing to delete") {
		t.Fatalf("an empty slot: %v", err)
	}

	// The blob taken by hand leaves the generation index: the slot is
	// dirty, and the deletion takes the rest.
	if err := Seal(sock, "0,7", idx, pubPath, privPath, false, measure.PCRHashAlgoSHA256, false); err != nil {
		t.Fatalf("seal again: %v", err)
	}
	if err := tpmdev.UndefineIndex(tpm, idx); err != nil {
		t.Fatal(err)
	}
	dirt := collectDirt(sock, nil)
	if len(dirt) != 1 || dirt[0].Slot != 1 || !dirt[0].Generation || dirt[0].Blob {
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
