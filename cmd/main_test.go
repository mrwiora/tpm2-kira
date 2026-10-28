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
	syscall.Umask(0o22)
	os.Exit(m.Run())
}
