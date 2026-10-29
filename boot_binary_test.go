package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The boot image carries tpm2-kira-boot, and only what the boot runs:
// nothing of the administration (internal/admin) and not its terminal UI.
func TestBootBinaryHoldsNoAdministration(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "./cmd/tpm2-kira-boot").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, bad := range []string{"github.com/mrwiora/tpm2-kira/internal/admin", "charm.land/"} {
			if dep == bad || strings.HasPrefix(dep, bad) {
				t.Errorf("tpm2-kira-boot depends on %s", dep)
			}
		}
	}
}
