package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// One file holds both parts; a key of the one part next to the other's is
// no error, and setUnlockMode leaves the rest of the file as it is.
func TestControlConfigOneFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.conf")
	os.WriteFile(path, []byte("# radio\nTPM2_KIRA_ATTEST_ADAPTER=1\nTPM2_KIRA_UNLOCK=password+salt\n"), 0o644)
	cfg, err := LoadControlConfig(path)
	if err != nil || cfg.Attest.Adapter != 1 || cfg.Unlock.Mode != UnlockPasswordSalt {
		t.Fatalf("%+v %v", cfg, err)
	}
	if err := setUnlockMode(path, UnlockPasswordRemoteSalt); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "# radio\nTPM2_KIRA_ATTEST_ADAPTER=1\nTPM2_KIRA_UNLOCK=password+remotesalt\n" {
		t.Fatalf("after setUnlockMode:\n%s", data)
	}
	missing, err := LoadControlConfig(filepath.Join(t.TempDir(), "none"))
	if err != nil || missing.Unlock.Mode != UnlockSkip || missing.Attest.AdapterWait == 0 {
		t.Fatalf("missing file: %+v %v", missing, err)
	}
}
