package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The boot image carries tpm2-kira-boot, and only what the boot runs:
// nothing of the administration (internal/admin), not its prompts (internal/prompt), not control's full screen (internal/tui).
func TestBootBinaryHoldsNoAdministration(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "./cmd/tpm2-kira-boot").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, bad := range []string{"github.com/tpm2-trust/tpm2-kira/internal/admin", "github.com/tpm2-trust/tpm2-kira/internal/prompt", "github.com/tpm2-trust/tpm2-kira/internal/tui"} {
			if dep == bad || strings.HasPrefix(dep, bad) {
				t.Errorf("tpm2-kira-boot depends on %s", dep)
			}
		}
	}
}

// tpm2-kira-boot links internal/signing for the public key alone. The PIN's sources stay
// out: nothing in a boot image reads a PIN, from a descriptor or a terminal.
func TestBootBinaryHoldsNoPINPath(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "tpm2-kira-boot")
	if out, err := exec.Command("go", "build", "-o", bin, "./cmd/tpm2-kira-boot").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	out, err := exec.Command("go", "tool", "nm", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("go tool nm: %v", err)
	}
	for _, sym := range strings.Split(string(out), "\n") {
		for _, bad := range []string{"internal/signing.readPIN", "internal/signing.UsePINDescriptor", "internal/signing.PromptPIN", "internal/signing.promptPINOnTTY",
			"internal/signing.readNoEcho", "internal/signing.StoredPIN", "internal/signing.pinBuffer", "internal/signing.descriptorPIN", "internal/signing.noTerminalPIN", "internal/signing.IgnorePINEnv", "internal/piv."} {
			if strings.Contains(sym, bad) {
				t.Errorf("tpm2-kira-boot holds %s", strings.TrimSpace(sym))
			}
		}
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"pin-fd", "TPM2_KIRA_PIN"} {
		if bytes.Contains(data, []byte(bad)) {
			t.Errorf("tpm2-kira-boot holds the string %q", bad)
		}
	}
}
