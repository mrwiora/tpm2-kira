//go:build integration

package admin

import (
	"os"
	"strings"
	"testing"

	"github.com/tpm2-trust/assh/persist"

	"github.com/mrwiora/tpm2-kira/internal/machineid"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// The machine-id sealed under slot 0's policy: slot add seals it, the boot
// releases it while the slot's policy holds and not after a PCR of the
// slot moved, slot approve keeps it current when /etc/machine-id changes,
// and deleting slot 0 takes it.
func TestSealedMachineID(t *testing.T) {
	sock := startSWTPM(t)
	old := persist.VarDir
	persist.VarDir = t.TempDir() // the suite's other tests seal slot 0 too
	t.Cleanup(func() { persist.VarDir = old })
	if _, err := machineid.Load(); !os.IsNotExist(err) {
		t.Fatalf("a variable before slot 0: %v", err)
	}
	sealRealSlot(t, sock, machineid.Slot) // seals it, as slot add does
	s, err := machineid.Load()
	if err != nil {
		t.Fatalf("slot add sealed nothing: %v", err)
	}

	// The boot: released into the run and etc files.
	os.Remove(machineid.RunPath)
	if err := os.WriteFile(machineid.RunPath, []byte("00000000000000000000000000000001\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	released, err := machineid.Boot(sock)
	if err != nil || !released {
		t.Fatalf("not released while slot 0's policy holds: %v %v", released, err)
	}
	want, _ := machineid.ReadID(machineid.EtcPath)
	if got, _ := machineid.ReadID(machineid.RunPath); got != want {
		t.Fatalf("released %q, the system's is %q", got, want)
	}

	// /etc/machine-id changed: slot approve seals the new one.
	if err := os.WriteFile(machineid.EtcPath, []byte("fedcba9876543210fedcba9876543210\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(machineid.EtcPath, []byte("0123456789abcdef0123456789abcdef\n"), 0o644)
	keepMachineIDAt(sock)
	s2, err := machineid.Load()
	if err != nil || string(s2.IDHash) == string(s.IDHash) {
		t.Fatalf("not sealed again for the new machine-id: %v", err)
	}

	// A PCR of slot 0 moved (a boot state nobody approved): no release.
	tpm, err := tpmdev.Open(sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := extendPCR(tpm, 23, "tampered"); err != nil {
		t.Fatal(err)
	}
	tpm.Close()
	if released, err := machineid.Boot(sock); released || err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("released in another boot state: %v %v", released, err)
	}

	// slot 0 deleted: the variable with it.
	if err := NVRAMDelete(sock, machineid.Slot, false); err != nil {
		t.Fatal(err)
	}
	if _, err := machineid.Load(); !os.IsNotExist(err) {
		t.Fatalf("the sealed machine-id outlived slot 0: %v", err)
	}
	if released, err := machineid.Boot(sock); released || err != nil {
		t.Fatalf("nothing sealed: %v %v", released, err)
	}
}
