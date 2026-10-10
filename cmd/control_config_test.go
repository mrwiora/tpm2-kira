package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

// The PIN is read from its own line, in the parser's line syntax, whatever
// the other lines say; the last line wins; nothing else of the file counts.
func TestPINLine(t *testing.T) {
	for content, want := range map[string]string{
		"TPM2_KIRA_PIN='123456'\n":                                       "123456",
		"TPM2_KIRA_PIN = \"654321\"\n":                                   "654321",
		"  TPM2_KIRA_PIN=111111\n":                                       "111111",
		"# TPM2_KIRA_PIN='000000'\nTPM2_KIRA_PIN=222222\n":               "222222",
		"TPM2_KIRA_PIN=1\nTPM2_KIRA_PIN=2\n":                             "2",
		"TPM2_KIRA_ATTEST_DEBUG=1\nTPM2_KIRA_PIN='333333'\njust words\n": "333333",
		"TPM2_KIRA_PINX='9'\n":                                           "",
		"TPM2_KIRA_PIN=''\n":                                             "",
		"":                                                               "",
	} {
		got, ok := pinLine([]byte(content))
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v, want %q", content, got, ok, want)
		}
	}
}

// An image build reads its two settings leniently: a file that does not
// load gives the defaults and says why.
func TestBuildSettingsDoNotStopTheBuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.conf")
	os.WriteFile(path, []byte("TPM2_KIRA_ATTEST_ADAPTER=hci2\nTPM2_KIRA_ATTEST_BLUETOOTH=always\n"), 0o600)
	if cfg, w := buildSettings(path); cfg.Adapter != 2 || cfg.Bluetooth != "always" || w != "" {
		t.Fatalf("%+v %q", cfg, w)
	}
	os.WriteFile(path, []byte("TPM2_KIRA_ATTEST_ADAPTER=hci2\nTPM2_KIRA_ATTEST_TIMEOUT=0\n"), 0o600)
	if cfg, w := buildSettings(path); cfg.Adapter != 0 || cfg.Bluetooth != "auto" || !strings.Contains(w, "does not load") {
		t.Fatalf("%+v %q", cfg, w)
	}
}

// control checks control.conf before anything else: every line that does
// not load, with its number and what to do, and then it quits - nothing
// asked (the guided/manual choice read as "not made" asked every time),
// nothing written. The PIN is never quoted.
func TestControlStopsOnAConfigThatDoesNotLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.conf")
	t.Setenv("TPM2_KIRA_CONTROL_CONF", path)
	os.WriteFile(path, []byte("TPM2_KIRA_CONTROL=guided\nTPM2_KIRA_ATTEST_TIMEOUT=0\nTPM2_KIRA_PIN='secret-1234'\nTPM2_KIRA_ATTEST_DEBUG=1\n"), 0o600)
	before, _ := os.ReadFile(path)

	var out bytes.Buffer
	err := Control(ControlOptions{TPMPath: filepath.Join(t.TempDir(), "no-tpm"), Out: &out})
	got := out.String()
	if err == nil || !strings.Contains(err.Error(), "does not load") {
		t.Fatalf("control went on: %v\n%s", err, got)
	}
	for _, want := range []string{"line 2: TPM2_KIRA_ATTEST_TIMEOUT is gone", "line 4: TPM2_KIRA_ATTEST_DEBUG is gone", "Remove the line", "the PIN\nincluded, stays"} {
		if !strings.Contains(got, want) {
			t.Errorf("the output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "secret-1234") || strings.Contains(got, "Looking at this machine") || strings.Contains(got, "Protections") {
		t.Errorf("control said too much, or went on:\n%s", got)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("control wrote the file")
	}

	// Fixed, control goes on, and the choice in the file is taken.
	os.WriteFile(path, []byte("TPM2_KIRA_CONTROL=guided\nTPM2_KIRA_PIN='secret-1234'\n"), 0o600)
	out.Reset()
	if err := Control(ControlOptions{TPMPath: filepath.Join(t.TempDir(), "no-tpm"), Out: &out}); err != nil || !strings.Contains(out.String(), "Protections") {
		t.Fatalf("a good file: %v\n%s", err, out.String())
	}
	if problems := ControlConfigProblems([]byte("TPM2_KIRA_CONTROL=wizard\nx\n")); len(problems) != 2 {
		t.Fatalf("problems %v", problems)
	}
}
