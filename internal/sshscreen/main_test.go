package sshscreen

import (
	"os"
	"testing"
)

// TestMain is also the SSH server's unprivileged half, when a test starts
// this binary as 'ssh-child' (server_test.go).
func TestMain(m *testing.M) {
	if os.Getenv("TPM2_KIRA_TEST_SERVE") == "1" {
		if err := SSHChildCommand(); err != nil {
			os.Stderr.WriteString("ssh-child: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
