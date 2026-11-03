// Package memlock is tpm2-kira's use of aSSH's sandbox.LockMemory: a command on
// the installed system stops without the lock, a boot goes on without it.
package memlock

import (
	"fmt"
	"os"

	"github.com/tpm2-trust/assh/sandbox"
)

// Command is the first thing a command does that handles a passphrase, a salt, a
// derived key, a TOTP key, a signing key's file or a YubiKey's PIN: nothing of them
// reaches swap or a core file. An error stops the command, before anything is asked
// or read.
//
// The test suite runs the binary as a user, with a user's limit on locked memory:
// TPM2_KIRA_UNPRIVILEGED=1, which is nothing to root, lets such a run go on.
func Command() error {
	err := sandbox.LockMemory()
	if err == nil || (os.Geteuid() != 0 && os.Getenv("TPM2_KIRA_UNPRIVILEGED") != "") {
		return nil
	}
	return fmt.Errorf("nothing was asked or read, because it could reach swap: %w", err)
}

// Boot is the same at boot, for the process that holds what is typed: never a
// stop (no enforced mode). The line it returns is the boot's log. The initrd has
// no swap, so what the lock adds there is a guard against one being set up.
func Boot() string {
	if err := sandbox.LockMemory(); err != nil {
		return fmt.Sprintf("tpm2-kira: the boot goes on: %v", err)
	}
	return "tpm2-kira: memory locked, not dumpable"
}
