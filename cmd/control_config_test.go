package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrwiora/tpm2-kira/internal/signing"
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
	if _, err := ParseControlConfig([]byte("TPM2_KIRA_CONTROL=guided\n")); err == nil || !strings.Contains(err.Error(), "Remove the line") {
		t.Fatalf("the guided/manual choice that is gone: %v", err)
	}
	missing, err := LoadControlConfig(filepath.Join(t.TempDir(), "none"))
	if err != nil || missing.Attest.Bluetooth != "auto" {
		t.Fatalf("missing file: %+v %v", missing, err)
	}
}

// The PIN has a file of its own: the PIN alone, root's alone; a file
// others can read gives it as loose. A PIN line in control.conf is an
// error that never quotes it.
func TestPINFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TPM2_KIRA_CONTROL_CONF", filepath.Join(dir, "control.conf"))
	path := signing.PINPath()
	if path != filepath.Join(dir, "pin") {
		t.Fatalf("the PIN file is %s", path)
	}
	if pin, _ := signing.StoredPIN(path); pin != "" {
		t.Fatalf("no file: %q", pin)
	}
	if err := signing.StorePIN(path, "12\n34"); err == nil {
		t.Fatal("a newline in the PIN was stored")
	}
	os.WriteFile(path, []byte("old"), 0o644)
	if err := signing.StorePIN(path, "123456"); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("the PIN file is %v", st.Mode().Perm())
	}
	if pin, loose := signing.StoredPIN(path); pin != "123456" || loose {
		t.Fatalf("read back %q loose %v", pin, loose)
	}
	os.Chmod(path, 0o640)
	if stored, loose := signing.PINStored(path); !stored || !loose {
		t.Fatalf("readable by the group: stored %v loose %v", stored, loose)
	}
	_, err := ParseControlConfig([]byte("TPM2_KIRA_PIN='secret-1234'\n"))
	if err == nil || !strings.Contains(err.Error(), "file of its own") || strings.Contains(err.Error(), "secret-1234") {
		t.Fatalf("a PIN line: %v", err)
	}
}

// control writes control.conf only when a value changes: its time says
// when the image is out of date.
func TestSetControlValueKeepsAnUnchangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.conf")
	if err := setControlValue(path, "TPM2_KIRA_NET", "dhcp"); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	os.Chtimes(path, past, past)
	if err := setControlValue(path, "TPM2_KIRA_NET", "dhcp"); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); !st.ModTime().Equal(past) {
		t.Fatal("the same value written again")
	}
	setControlValue(path, "TPM2_KIRA_NET", "off")
	if st, _ := os.Stat(path); st.ModTime().Equal(past) {
		t.Fatal("a new value not written")
	}
}

// control checks control.conf before anything else: every line that does
// not load, with its number and what to do, and then it quits - nothing
// asked, nothing written. The PIN is never quoted.
func TestControlStopsOnAConfigThatDoesNotLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.conf")
	t.Setenv("TPM2_KIRA_CONTROL_CONF", path)
	os.WriteFile(path, []byte("TPM2_KIRA_NET=dhcp\nTPM2_KIRA_ATTEST_TIMEOUT=0\nTPM2_KIRA_PIN='secret-1234'\nTPM2_KIRA_ATTEST_DEBUG=1\n"), 0o600)
	before, _ := os.ReadFile(path)

	var out bytes.Buffer
	err := Control(ControlOptions{TPMPath: filepath.Join(t.TempDir(), "no-tpm"), Out: &out})
	got := out.String()
	if err == nil || !strings.Contains(err.Error(), "does not load") {
		t.Fatalf("control went on: %v\n%s", err, got)
	}
	for _, want := range []string{"line 2: TPM2_KIRA_ATTEST_TIMEOUT is gone", "line 3: the YubiKey's PIN has a file of its own", "line 4: TPM2_KIRA_ATTEST_DEBUG is gone", "Remove the line"} {
		if !strings.Contains(got, want) {
			t.Errorf("the output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "secret-1234") || strings.Contains(got, "Looking at this machine") || strings.Contains(got, "Step 1 of 2") {
		t.Errorf("control said too much, or went on:\n%s", got)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("control wrote the file")
	}

	// Fixed, control goes on, and the settings in the file are taken.
	os.WriteFile(path, []byte("TPM2_KIRA_NET=dhcp\n"), 0o600)
	out.Reset()
	if err := Control(ControlOptions{TPMPath: filepath.Join(t.TempDir(), "no-tpm"), Out: &out}); err != nil || !strings.Contains(out.String(), "Step 2 of 2") ||
		!strings.Contains(out.String(), "Boot network Network at boot: DHCP") {
		t.Fatalf("a good file: %v\n%s", err, out.String())
	}
	if problems := ControlConfigProblems([]byte("TPM2_KIRA_CONTROL=guided\nx\n")); len(problems) != 2 {
		t.Fatalf("problems %v", problems)
	}
}
