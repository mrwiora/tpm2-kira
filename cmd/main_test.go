package cmd

import (
	"os"
	"syscall"
	"testing"
)

// The tests make key directories and files with the modes they state;
// a looser umask than 022 (Debian gives users 002) would turn a private
// temporary directory into a group-writable one, which the signing-key
// checks rightly refuse. The umask is not what is under test.
func TestMain(m *testing.M) {
	// The SSH server's unprivileged half, when a test starts this binary
	// as 'remote serve' (remote_ssh_test.go).
	if os.Getenv("TPM2_KIRA_TEST_SERVE") == "1" {
		if err := RemoteServeCommand(); err != nil {
			os.Stderr.WriteString("remote serve: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	syscall.Umask(0o22)
	os.Exit(m.Run())
}
