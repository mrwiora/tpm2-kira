package admin

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/tpm2-trust/assh/persist"

	"github.com/mrwiora/tpm2-kira/internal/machineid"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
)

// The tests make key directories and files with the modes they state;
// a looser umask than 022 (Debian gives users 002) would turn a private
// temporary directory into a group-writable one, which the signing-key
// checks rightly refuse. The umask is not what is under test.
func TestMain(m *testing.M) {
	// The phone's radio worker that 'run' starts (TestCoordinatorAndWorker).
	if len(os.Args) > 1 && os.Args[1] == "gate-child" {
		os.Exit(phonegate.RadioWorkerMain(false))
	}
	syscall.Umask(0o22)
	// The EFI variables and the machine-id the tests seal are theirs: never
	// the host's efivarfs or /etc/machine-id.
	dir, err := os.MkdirTemp("", "tpm2-kira-admin-tests-")
	if err != nil {
		panic(err)
	}
	persist.VarDir = filepath.Join(dir, "efivars")
	os.MkdirAll(persist.VarDir, 0o755)
	seedFirmwareVars(persist.VarDir)
	machineid.EtcPath = filepath.Join(dir, "machine-id")
	machineid.RunPath = filepath.Join(dir, "run-machine-id")
	os.WriteFile(machineid.EtcPath, []byte("0123456789abcdef0123456789abcdef\n"), 0o644)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
