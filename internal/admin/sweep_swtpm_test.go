//go:build integration

package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/tpm2-trust/assh/persist"
	"github.com/tpm2-trust/tpm2-kira/internal/efivars"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"
)

// What an earlier version (or another program) left at tpm2-kira's places: slot
// delete --yes shows it and leaves it, and names --sweep; --sweep takes it whatever
// its shape. What is not at tpm2-kira's places stays.
func TestSweepTakesWhatIsLeftAtTpm2KirasPlaces(t *testing.T) {
	sock, tpm := foreignTPM(t)
	old := efivars.Dir
	efivars.SetDir(t.TempDir())
	t.Cleanup(func() { efivars.SetDir(old) })
	vars := map[string]bool{
		"KIRAattestOld-" + efivars.GUIDText:             true,  // an earlier version's variable: swept
		"KIRAasshCA-" + persist.VarGUID:                 true,  // the SSH CA's: swept
		"Boot0001-8be4df61-93ca-11d2-aa0d-00e098032b8c": false, // the firmware's: stays
		"OtherApp-" + persist.VarGUID:                   false, // aSSH's GUID, not tpm2-kira's name: stays
	}
	for name := range vars {
		if err := os.WriteFile(filepath.Join(efivars.Dir, name), []byte{7, 0, 0, 0, 1}, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const oldAttest, middle, window, outside = uint32(0x01803020), uint32(0x01803500), uint32(0x01802915), uint32(0x01500010)
	attrs := tpm2.TPMANV{OwnerWrite: true, OwnerRead: true, AuthRead: true, NoDA: true}
	for _, idx := range []uint32{oldAttest, middle, window, outside} {
		defineAt(t, tpm, idx, attrs)
	}

	var err error
	out := captureStdout(t, func() { err = NVRAMDeleteCommand(sock, 0, true, false, false, false) })
	for _, want := range []string{"0x01803020", "0x01803500", "0x01802915", "KIRAattestOld-", "KIRAasshCA-", "left (--sweep takes them)"} {
		if !strings.Contains(out, want) {
			t.Errorf("the listing lacks %q:\n%s", want, out)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "--sweep") || !tpmdev.NVRAMIndexExists(tpm, middle) {
		t.Fatalf("without --sweep: %v, the index there %v", err, tpmdev.NVRAMIndexExists(tpm, middle))
	}

	out = captureStdout(t, func() { err = NVRAMDeleteCommand(sock, 0, true, false, true, false) })
	if err != nil {
		t.Fatalf("--sweep: %v\n%s", err, out)
	}
	for _, idx := range []uint32{oldAttest, middle, window} {
		if _, _, rerr := persist.ReadNVPublic(tpm, tpm2.TPMHandle(idx)); rerr == nil {
			t.Errorf("0x%08X is still there:\n%s", idx, out)
		}
	}
	if _, _, rerr := persist.ReadNVPublic(tpm, tpm2.TPMHandle(outside)); rerr != nil {
		t.Errorf("0x%08X, outside tpm2-kira's places, went", outside)
	}
	for name, swept := range vars {
		_, serr := os.Stat(filepath.Join(efivars.Dir, name))
		if swept != os.IsNotExist(serr) {
			t.Errorf("%s: swept %v, there %v", name, swept, serr == nil)
		}
	}
	// Nothing left: the sweep finds nothing, and says so.
	if err = NVRAMDeleteCommand(sock, 0, true, false, true, false); err == nil || !strings.Contains(err.Error(), "nothing of tpm2-kira") {
		t.Fatalf("again: %v", err)
	}
}
