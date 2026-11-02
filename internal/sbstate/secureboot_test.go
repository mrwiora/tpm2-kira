package sbstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/efivars"
	"github.com/tpm2-trust/go-uefi-slim/efivar"
)

// vars points efivars.Dir at a directory holding the variables given, nil: absent.
func vars(t *testing.T, secureBoot, setupMode []byte) {
	t.Helper()
	dir := t.TempDir()
	old := efivars.Dir
	efivars.Dir = dir
	t.Cleanup(func() { efivars.Dir = old })
	for name, data := range map[string][]byte{"SecureBoot": secureBoot, "SetupMode": setupMode} {
		if data == nil {
			continue
		}
		path := filepath.Join(dir, name+"-"+efivar.GlobalVariable.String())
		if err := os.WriteFile(path, append([]byte{6, 0, 0, 0}, data...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStates(t *testing.T) {
	on, off := []byte{1}, []byte{0}
	for _, tc := range []struct {
		name          string
		sb, setup     []byte
		known         bool
		wantInWarning string // empty: no warning
	}{
		{"enforcing", on, off, true, ""},
		{"off", off, off, true, "Secure Boot is off"},
		{"Setup Mode", off, on, true, "Setup Mode"},
		{"Setup Mode, reported on", on, on, true, "Setup Mode"},
		{"no variables", nil, nil, false, "could not be read"},
		{"SecureBoot alone", on, nil, false, "could not be read"},
		{"SetupMode alone", nil, off, false, "could not be read"},
		{"a variable of two bytes", []byte{1, 1}, off, false, "2 bytes"},
		{"an empty variable", []byte{}, off, false, "0 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vars(t, tc.sb, tc.setup)
			s := Read()
			if s.Known != tc.known {
				t.Fatalf("known %v, want %v (%+v)", s.Known, tc.known, s)
			}
			w := s.Warning()
			switch {
			case tc.wantInWarning == "" && w != "":
				t.Fatalf("a warning: %s", w)
			case tc.wantInWarning == "":
			case !strings.HasPrefix(w, WarningPrefix) || !strings.Contains(w, tc.wantInWarning):
				t.Fatalf("warning %q, want %q in it", w, tc.wantInWarning)
			case strings.Contains(w, "\n"):
				t.Fatalf("not one line: %q", w)
			}
		})
	}
}
