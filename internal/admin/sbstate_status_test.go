package admin

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tpm2-trust/tpm2-kira/internal/sbstate"
)

// Status: the Secure Boot warning first, once, in a pipe without colour; in JSON too.
// Control's notes come from the same place and do not say it: it has its own line.
func TestStatusSaysSecureBoot(t *testing.T) {
	r := StatusReport{TPM: "tpm", Version: "v", Slots: []StatusSlot{{Slot: 4, Signed: true}},
		SecureBootWarning: sbstate.State{Known: true, SetupMode: true}.Warning()}
	r.Notes = statusNotes(r)
	if strings.Contains(strings.Join(r.Notes, "\n"), "WARNING: Secure Boot") {
		t.Errorf("Secure Boot in the notes, which control shows under its own line: %v", r.Notes)
	}
	out := captureStdout(t, func() { printStatus(r) })
	if !strings.Contains(out, "WARNING: Secure Boot is in Setup Mode") || strings.Index(out, "WARNING: Secure Boot") > strings.Index(out, "Slots (") {
		t.Errorf("Secure Boot's line:\n%s", out)
	}
	if strings.Count(out, "WARNING: Secure Boot") != 1 {
		t.Errorf("said more than once:\n%s", out)
	}
	if strings.Contains(out, "\033[") {
		t.Errorf("colour into a pipe:\n%q", out)
	}
	b, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(b), `"secure_boot_warning":"WARNING: Secure Boot is in Setup Mode`) {
		t.Errorf("JSON: %v %s", err, b)
	}
	r.SecureBootWarning = sbstate.State{Known: true, Enabled: true}.Warning()
	if out := captureStdout(t, func() { printStatus(r) }); strings.Contains(out, "WARNING: Secure Boot") {
		t.Errorf("with Secure Boot on:\n%s", out)
	}
}

// The boot chain's prerequisites: every bad state in red, and none of them stops anything.
func TestPrereqsShowSecureBootRed(t *testing.T) {
	for _, state := range []sbstate.State{{Known: true}, {Known: true, SetupMode: true}, {Why: "no efivars"}} {
		c := &controller{out: &strings.Builder{}}
		c.facts.SecureBoot = state
		line := ""
		for _, l := range strings.Split(c.prereqText(), "\n") {
			if strings.Contains(l, "Secure Boot") {
				line = l
			}
		}
		if !strings.Contains(line, "\033[0;31m") || !strings.Contains(line, "risk:") {
			t.Errorf("%+v: %q", state, line)
		}
		for _, p := range c.prereqs() {
			if strings.Contains(p.text, "Secure Boot") && p.state == prereqNot {
				t.Errorf("%+v counts as not met: nothing is enforced", state)
			}
		}
	}
}
