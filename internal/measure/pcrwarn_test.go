package measure

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tpm2-trust/go-uefi-slim/efivar"
	"github.com/tpm2-trust/tpm2-kira/internal/efivars"
)

// WarnSecureBoot says the state whatever the selection, and once in a command;
// control's switch silences it; with Secure Boot on it says nothing.
func TestWarnSecureBootOnce(t *testing.T) {
	capture := func(f func()) string {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdout
		os.Stdout = w
		defer func() { os.Stdout = old }()
		f()
		w.Close()
		var b bytes.Buffer
		b.ReadFrom(r)
		return b.String()
	}
	dir := t.TempDir()
	defer func(old string) { efivars.Dir = old }(efivars.Dir)
	efivars.Dir = dir
	set := func(name string, v byte) {
		t.Helper()
		path := filepath.Join(dir, name+"-"+efivar.GlobalVariable.String())
		if err := os.WriteFile(path, []byte{6, 0, 0, 0, v}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	defer func(old bool) { secureBootWarned = old }(secureBootWarned)

	secureBootWarned = false
	if out := capture(func() { WarnSecureBoot(); WarnSecureBoot() }); strings.Count(out, "could not be read") != 1 {
		t.Fatalf("nothing readable, twice asked: %q", out)
	}
	set("SecureBoot", 0)
	set("SetupMode", 1)
	secureBootWarned = false
	if out := capture(func() { WarnSecureBoot(); WarnSecureBoot() }); strings.Count(out, "WARNING: Secure Boot is in Setup Mode") != 1 {
		t.Fatalf("Setup Mode, twice asked: %q", out)
	}
	secureBootWarned = false
	defer func(old bool) { AdvisoryWarnings = old }(AdvisoryWarnings)
	AdvisoryWarnings = false
	if out := capture(WarnSecureBoot); out != "" {
		t.Fatalf("switched off: %q", out)
	}
	AdvisoryWarnings = true
	set("SecureBoot", 1)
	set("SetupMode", 0)
	if out := capture(WarnSecureBoot); out != "" {
		t.Fatalf("Secure Boot on: %q", out)
	}
}
