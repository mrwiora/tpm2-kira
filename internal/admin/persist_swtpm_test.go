//go:build integration

package admin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/tpm2-trust/assh/hostkey"
	"github.com/tpm2-trust/assh/persist"

	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// A removal takes only what has tpm2-kira's shape: an index of another
// kind at a slot's handle is left and named, the slot's own indices go
// whole, and none there is no error of the primitive.
func TestRemovalTakesOnlyOurs(t *testing.T) {
	sock := startSWTPM(t)
	tpm, err := tpmdev.Open(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	key := testSigner(t)
	mine, foreign := uint32(nvslot.NVRAMSlotStart+2), uint32(nvslot.NVRAMSlotStart+3)
	writeTestSlot(t, tpm, mine, key)
	if _, err := nvslot.WriteGeneration(tpm, nvslot.GenerationIndex(mine), 1, key.Public(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := nvslot.BumpAttestCounter(tpm, nvslot.AttestCounterIndex(mine)); err != nil {
		t.Fatal(err)
	}
	other := tpm2.TPMSNVPublic{NVIndex: tpm2.TPMHandle(foreign), NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{NT: tpm2.TPMNTOrdinary, OwnerWrite: true, OwnerRead: true, NoDA: true}, DataSize: 16}
	if _, err := (tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, PublicInfo: tpm2.New2B(other)}).Execute(tpm); err != nil {
		t.Fatal(err)
	}

	removed, err := nvslot.RemoveSlot(tpm, foreign)
	if len(removed) != 0 || !errors.Is(err, persist.ErrNotOurs) || !strings.Contains(err.Error(), "0x01803013") {
		t.Fatalf("another's index at slot 3: %v %v", removed, err)
	}
	if !tpmdev.NVRAMIndexExists(tpm, foreign) {
		t.Fatal("another's index was removed")
	}
	removed, err = nvslot.RemoveSlot(tpm, mine)
	if err != nil || len(removed) != 3 {
		t.Fatalf("slot 2 whole: %+v %v", removed, err)
	}
	for _, idx := range []uint32{mine, nvslot.GenerationIndex(mine), nvslot.AttestCounterIndex(mine)} {
		if tpmdev.NVRAMIndexExists(tpm, idx) {
			t.Errorf("0x%08X left", idx)
		}
	}
	if removed, err := nvslot.RemoveSlot(tpm, mine); len(removed) != 0 || err != nil {
		t.Fatalf("slot 2 again: %v %v", removed, err)
	}
	// The command says so for a slot that is not there.
	tpm.Close()
	if err := NVRAMDelete(sock, mine, false); err == nil || !strings.Contains(err.Error(), "nothing to delete") {
		t.Fatalf("slot delete of an empty slot: %v", err)
	}
}

// slot delete without --nvram is everything of tpm2-kira: the slots and
// the SSH CA that assh.conf names, with its public key.
func TestSlotDeleteTakesTheSSHCA(t *testing.T) {
	sock := startSWTPM(t)
	tpm, err := tpmdev.Open(sock)
	if err != nil {
		t.Fatal(err)
	}
	key := testSigner(t)
	writeTestSlot(t, tpm, nvslot.NVRAMSlotStart, key)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca")
	ca, err := hostkey.CreateCA(tpm, key.Public(), hostkey.CAOptions{Type: hostkey.P256, Bank: hostkey.SHA256, PCRs: []int{7, 15}, Window: 15, PolicyRef: []byte(sshCARef)})
	if err != nil {
		t.Fatal(err)
	}
	if err := saveSSHCA(ca, caPath); err != nil {
		t.Fatal(err)
	}
	tpm.Close()
	conf := filepath.Join(dir, "control.conf")
	if err := os.WriteFile(conf, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sshConfPath(conf), []byte("ASSH_CA="+caPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TPM2_KIRA_CONTROL_CONF", conf)

	if err := NVRAMDeleteCommand(sock, 0, true, false); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{caPath, caPath + ".pub"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s left: %v", p, err)
		}
	}
	if err := NVRAMDeleteCommand(sock, 0, true, false); err == nil || !strings.Contains(err.Error(), "nothing of tpm2-kira") {
		t.Fatalf("again: %v", err)
	}
}
