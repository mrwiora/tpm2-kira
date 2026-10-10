package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// One file holds the radio and the PIN; setAttestBluetooth leaves the
// rest of the file as it is, and a missing file is the defaults.
func TestControlConfigOneFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.conf")
	os.WriteFile(path, []byte("# radio\nTPM2_KIRA_ATTEST_ADAPTER=1\n"), 0o644)
	cfg, err := LoadControlConfig(path)
	if err != nil || cfg.Attest.Adapter != 1 || cfg.Attest.Bluetooth != "auto" {
		t.Fatalf("%+v %v", cfg, err)
	}
	if err := setAttestBluetooth(path, "always"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "# radio\nTPM2_KIRA_ATTEST_ADAPTER=1\nTPM2_KIRA_ATTEST_BLUETOOTH=always\n" {
		t.Fatalf("after setAttestBluetooth:\n%s", data)
	}
	if cfg, err := LoadControlConfig(path); err != nil || cfg.Attest.Bluetooth != "always" {
		t.Fatalf("always not read back: %+v %v", cfg, err)
	}
	if _, err := ParseControlConfig([]byte("TPM2_KIRA_ATTEST_BLUETOOTH=sometimes\n")); err == nil {
		t.Fatal("an unknown bluetooth policy parsed")
	}
	if err := setControlGuide(path, "guided"); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadControlConfig(path); err != nil || cfg.Control != "guided" {
		t.Fatalf("the guide choice: %+v %v", cfg, err)
	}
	if _, err := ParseControlConfig([]byte("TPM2_KIRA_CONTROL=wizard\n")); err == nil {
		t.Fatal("an unknown guide mode parsed")
	}
	missing, err := LoadControlConfig(filepath.Join(t.TempDir(), "none"))
	if err != nil || missing.Attest.Bluetooth != "auto" {
		t.Fatalf("missing file: %+v %v", missing, err)
	}
}
