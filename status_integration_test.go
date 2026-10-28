//go:build integration
// +build integration

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/cmd"
)

// The binary as it is run on a machine: the root gate, 'slot add' without
// arguments, 'status' and its notes, 'initramfs plan' on control.conf.
// The TPM is swtpm; the LUKS headers are not read (no root), so the notes
// tested here are the ones across the slots and the configuration file.

// kira runs the binary with args as given, with env added to the
// environment, and returns stdout, stderr and the exit code.
func kira(t *testing.T, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	c := exec.Command("./tpm2-kira", args...)
	c.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	err := c.Run()
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("tpm2-kira %v: %v", args, err)
	}
	return out.String(), errb.String(), code
}

// writeConf writes a control.conf for a test and returns its path.
func writeConf(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// statusJSON runs 'status --json' and decodes the report.
func statusJSON(t *testing.T, tpmPath, privKey, conf string) cmd.StatusReport {
	t.Helper()
	stdout, stderr, code := kira(t, nil, "status", "--json", "--tpm", tpmPath, "--privkey", privKey, "--conf", conf)
	if code != 0 {
		t.Fatalf("status --json exit %d: %s%s", code, stdout, stderr)
	}
	var r cmd.StatusReport
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("status --json: %v\n%s", err, stdout)
	}
	return r
}

func hasNote(notes []string, substr string) bool {
	for _, n := range notes {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}

// Without root the commands refuse with the line to run; help, version and
// pcrtips answer. TPM2_KIRA_UNPRIVILEGED, which the suite sets for itself,
// is taken away for this test.
func TestRootIsRequired(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the gate is open")
	}
	unprivileged := "TPM2_KIRA_UNPRIVILEGED="
	for _, args := range [][]string{{"status"}, {"slot", "add", "--pcrs", "0"}, {"slot", "list"}, {"slot", "info"}, {"phone", "status"}, {"luks", "status"}} {
		stdout, stderr, code := kira(t, []string{unprivileged}, args...)
		want := "tpm2-kira " + args[0] + ": root is needed - sudo tpm2-kira " + strings.Join(args, " ")
		if code != 1 || !strings.Contains(stderr, want) || stdout != "" {
			t.Errorf("%v as a user: exit %d, stdout %q, stderr %q; want exit 1 and %q", args, code, stdout, stderr, want)
		}
	}
	// control without a terminal says it in one line too.
	_, stderr, code := kira(t, []string{unprivileged}, "control")
	if code != 1 || !strings.Contains(stderr, "tpm2-kira control: root is needed - sudo tpm2-kira control") {
		t.Errorf("control as a user: exit %d, stderr %q", code, stderr)
	}
	for _, args := range [][]string{{"help"}, {"help", "slot"}, {"version"}, {"pcrtips"}} {
		stdout, stderr, code := kira(t, []string{unprivileged}, args...)
		if code != 0 || stdout == "" || strings.Contains(stderr, "root is needed") {
			t.Errorf("%v as a user: exit %d, stdout %d bytes, stderr %q; want an answer", args, code, len(stdout), stderr)
		}
	}
}

// 'slot add' without --nvram and --pcrs seals slot 0 to what the machine can
// vouch for and slot 1 to the fallback; without an event log (swtpm) both
// are read from the registers, so the policy can be satisfied and the
// codes show. 'status' then reports both slots signed, the fallback marked,
// and nothing to do.
func TestSealDefaultsAndStatus(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	stdout, stderr, code := kira(t, nil, "slot", "add", "--tpm", tpmPath, "--pubkey", testPubKeyPath, "--privkey", testPrivKeyPath)
	if code != 0 {
		t.Fatalf("seal: exit %d\n%s%s", code, stdout, stderr)
	}
	for _, want := range []string{"PCRs: 0,2,7 (", "Slot 1: the fallback, sealed to PCRs 0,7 alone"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("seal without arguments: %q missing in\n%s", want, stdout)
		}
	}
	for _, slot := range []string{"0", "1"} {
		if code, out := revealPlainCode(t, tpmPath, slot); code == "" {
			t.Errorf("reveal-plain slot %s after the default seal gives no code:\n%s", slot, out)
		}
	}

	conf := writeConf(t, "TPM2_KIRA_ATTEST_ADAPTER=0\n")
	r := statusJSON(t, tpmPath, testPrivKeyPath, conf)
	if r.TPMError != "" || len(r.Slots) != 2 {
		t.Fatalf("status: tpm_error %q, %d slots: %+v", r.TPMError, len(r.Slots), r)
	}
	for i, want := range []struct {
		pcrs     string
		fallback bool
	}{{"0,2,7", false}, {"0,7", true}} {
		s := r.Slots[i]
		if s.Slot != i || s.PCRs != want.pcrs || s.Fallback != want.fallback || !s.Signed || !strings.HasSuffix(s.GenState, "(matches)") {
			t.Errorf("slot %d: %+v; want pcrs %s, fallback %v, signed, generation matching", i, s, want.pcrs, want.fallback)
		}
	}
	if r.Config != conf || r.ConfigError != "" {
		t.Errorf("config: %q (%q); want %s", r.Config, r.ConfigError, conf)
	}

	// The plain report says the same.
	stdout, _, code = kira(t, nil, "status", "--tpm", tpmPath, "--privkey", testPrivKeyPath, "--conf", conf)
	for _, want := range []string{"slot 0   sealed to 0,2,7;", "slot 1   sealed to 0,7 (the fallback);", "signed by this machine's key", "Disk unlock (how a key is made is in each device's LUKS header)"} {
		if code != 0 || !strings.Contains(stdout, want) {
			t.Errorf("status: %q missing in\n%s", want, stdout)
		}
	}
}

// The notes name what does not fit: a slot not signed by the key given, a
// missing fallback, a mode without the phone salt it needs, and a file
// that does not parse.
func TestStatusNotes(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	empty := writeConf(t, "")
	r := statusJSON(t, tpmPath, testPrivKeyPath, empty)
	if len(r.Slots) != 0 || !hasNote(r.Notes, "no slot is sealed: tpm2-kira slot add") {
		t.Errorf("nothing sealed, an empty file: %d slots, notes %q", len(r.Slots), r.Notes)
	}

	// Slot 0 alone, to a selection that is not the fallback.
	if _, stderr, code := kira(t, nil, "slot", "add", "--tpm", tpmPath, "--nvram", "0", "--pcrs", "0,23", "--pubkey", testPubKeyPath, "--privkey", testPrivKeyPath); code != 0 {
		t.Fatalf("seal: exit %d: %s", code, stderr)
	}
	r = statusJSON(t, tpmPath, testPrivKeyPath, empty)
	if len(r.Slots) != 1 || !r.Slots[0].Signed || r.Slots[0].Fallback {
		t.Fatalf("slots: %+v", r.Slots)
	}
	if !hasNote(r.Notes, "no fallback slot (PCRs 0e,7e alone)") || !hasNote(r.Notes, "tpm2-kira slot add --nvram 1 --pcrs 0e,7e") {
		t.Errorf("no fallback: notes %q", r.Notes)
	}

	// Checked with another key: not signed, and the note says what that means.
	otherPub, otherPriv := filepath.Join(t.TempDir(), "pub.pem"), filepath.Join(t.TempDir(), "priv.pem")
	if err := generateTestKeys(otherPub, otherPriv); err != nil {
		t.Fatal(err)
	}
	r = statusJSON(t, tpmPath, otherPriv, empty)
	if r.Slots[0].Signed || r.Slots[0].SignReason == "" {
		t.Errorf("another key: %+v", r.Slots[0])
	}
	if !hasNote(r.Notes, "slot 0 is not signed by this machine's key") || !hasNote(r.Notes, "the hooks will not approve it") {
		t.Errorf("another key: notes %q", r.Notes)
	}

	// A line it does not know: the error names it.
	bad := writeConf(t, "TPM2_KIRA_NOSUCH=password+salt\n")
	r = statusJSON(t, tpmPath, testPrivKeyPath, bad)
	if !strings.Contains(r.ConfigError, "unknown key") {
		t.Errorf("bad file: error %q", r.ConfigError)
	}
	stdout, _, _ := kira(t, nil, "status", "--tpm", tpmPath, "--privkey", testPrivKeyPath, "--conf", bad)
	if !strings.Contains(stdout, "unknown key") {
		t.Errorf("bad file, plain: %s", stdout)
	}

	// Without the TPM the slots are an error and the rest still shows.
	r = statusJSON(t, filepath.Join(t.TempDir(), "no-tpm"), testPrivKeyPath, empty)
	if r.TPMError == "" || hasNote(r.Notes, "no slot") {
		t.Errorf("no TPM: error %q, notes %q", r.TPMError, r.Notes)
	}
}

// 'initramfs plan' is what the initramfs hooks run to build an image, and
// it reads control.conf: the file as control writes it loads, a missing
// file is the defaults, and a line that cannot be used names itself - and
// never stops the build: the plan is made with the defaults.
func TestInitramfsPlanReadsTheConfig(t *testing.T) {
	good := writeConf(t, "# written by control\nTPM2_KIRA_ATTEST_ADAPTER=hci1\n")
	stdout, stderr, code := kira(t, nil, "initramfs", "plan", "--conf", good)
	if code != 0 || strings.Contains(stdout, "warning") || !strings.Contains(stdout, "in  Disk unlock") {
		t.Errorf("a good file: exit %d, %q %q", code, stdout, stderr)
	}
	missing := filepath.Join(t.TempDir(), "none")
	if stdout, _, code := kira(t, nil, "initramfs", "plan", "--conf", missing); code != 0 || strings.Contains(stdout, "warning") {
		t.Errorf("a missing file is the defaults: exit %d, %q", code, stdout)
	}
	for content, reason := range map[string]string{
		"TPM2_KIRA_NOSUCH=skip\n":           "line 1: unknown key",
		"\nTPM2_KIRA_ATTEST_ADAPTER=eth0\n": "line 2: invalid adapter",
		"just words\n":                      "line 1: expected KEY=VALUE",
	} {
		path := writeConf(t, content)
		stdout, stderr, code := kira(t, nil, "initramfs", "plan", "--conf", path)
		if code != 0 || !strings.Contains(stdout, "warning: control.conf does not load") || !strings.Contains(stdout, reason) {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want exit 0 and %q", content, code, stdout, stderr, reason)
		}
	}
}
