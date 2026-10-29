package admin

import (
	"os"
	"syscall"
	"testing"

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
	os.Exit(m.Run())
}
