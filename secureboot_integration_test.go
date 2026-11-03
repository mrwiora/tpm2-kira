//go:build integration

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Secure Boot's state, in the commands of the installed system: said once in a
// command however many slots it goes through, whatever the selection, and nothing
// stops; said by the image's plan to its hook; silent with Secure Boot on. A state
// that cannot be read is said too.
func TestSecureBootWarningPlaces(t *testing.T) {
	testDir := os.Getenv("TPM2_KIRA_TEST_DIR")
	vars := filepath.Join(testDir, "efivars")
	removeVars := func() {
		for _, name := range []string{"SecureBoot", "SetupMode"} {
			os.Remove(filepath.Join(vars, name+"-8be4df61-93ca-11d2-aa0d-00e098032b8c"))
		}
	}
	removeVars()
	t.Cleanup(removeVars)

	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()
	keys := []string{"--tpm", tpmPath, "--pubkey", testPubKeyPath, "--privkey", testPrivKeyPath}
	once := func(what, stdout, stderr, want string, n int) {
		t.Helper()
		out := stdout + stderr
		if strings.Count(out, "Secure Boot") < n {
			t.Errorf("%s: no Secure Boot:\n%s", what, out)
		}
		if strings.Count(out, "WARNING: Secure Boot") != n || (n > 0 && !strings.Contains(out, want)) {
			t.Errorf("%s: %q %d time(s) wanted, got %d:\n%s", what, want, n, strings.Count(out, "WARNING: Secure Boot"), out)
		}
	}

	// Two slots, no state to read: the state is unknown.
	out, errOut, code := kira(t, nil, append([]string{"slot", "add", "--totp"}, keys...)...)
	if code != 0 {
		t.Fatalf("slot add: %d\n%s%s", code, out, errOut)
	}
	once("slot add, unreadable", out, errOut, "could not be read", 1)

	writeSecureBootVars(t, testDir, 0, 1)
	const setup = "WARNING: Secure Boot is in Setup Mode"
	out, errOut, _ = kira(t, nil, append([]string{"slot", "approve"}, keys...)...)
	if !strings.Contains(out, "Successfully approved") {
		t.Fatalf("Setup Mode stops the approval:\n%s%s", out, errOut)
	}
	once("slot approve", out, errOut, setup, 1)
	out, errOut, _ = kira(t, nil, append([]string{"slot", "approve", "--if-moved"}, keys...)...)
	once("slot approve --if-moved", out, errOut, setup, 1)
	out, errOut, _ = kira(t, nil, "status", "--tpm", tpmPath, "--pubkey", testPubKeyPath)
	once("status", out, errOut, setup, 1)

	buildroot := t.TempDir()
	out, errOut, code = kira(t, nil, "initramfs", "plan", "--tpm", tpmPath, "--buildroot", buildroot, "--format", "mkinitcpio")
	if code != 0 || !strings.Contains(out, "warning Secure Boot is in Setup Mode") {
		t.Errorf("the image's plan: %d\n%s%s", code, out, errOut)
	}

	writeSecureBootVars(t, testDir, 0, 0)
	out, errOut, _ = kira(t, nil, append([]string{"slot", "approve"}, keys...)...)
	once("slot approve, off", out, errOut, "WARNING: Secure Boot is off", 1)

	writeSecureBootVars(t, testDir, 1, 0)
	out, errOut, _ = kira(t, nil, append([]string{"slot", "approve"}, keys...)...)
	once("slot approve, on", out, errOut, "", 0)
	out, errOut, _ = kira(t, nil, "status", "--tpm", tpmPath, "--pubkey", testPubKeyPath)
	once("status, on", out, errOut, "", 0)
	if out, _, _ = kira(t, nil, "initramfs", "plan", "--tpm", tpmPath, "--buildroot", t.TempDir(), "--format", "mkinitcpio"); strings.Contains(out, "Secure Boot") {
		t.Errorf("the image's plan, on:\n%s", out)
	}
}
