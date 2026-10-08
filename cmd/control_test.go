package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// The steps are judged from the facts: done, possible, or blocked with
// the reason, in the order they build on each other.
func TestControlSteps(t *testing.T) {
	zero := 0
	c := &controller{facts: machineFacts{TPM: "/dev/tpmrm0", SHA256Bank: true, LogSHA256: true, PCRs: "0e,2e,7e,11u"}}
	steps := c.steps()
	if len(steps) != 5 || steps[0].Done != "" || steps[1].Blocked != "needs the signing key" || steps[2].Blocked != "needs the TOTP seal" {
		t.Fatalf("a bare machine: %+v", steps)
	}

	c.facts.Keys = "local key files"
	c.facts.Status.Slots = []StatusSlot{{Slot: 0, PCRs: "0e,2e,7e,11u", Signed: true}, {Slot: 1, PCRs: "0e,7e", Fallback: true, Signed: true}}
	steps = c.steps()
	if steps[1].Done == "" || steps[2].Blocked != "no Bluetooth adapter on this machine" || steps[3].Blocked == "" {
		t.Fatalf("sealed, no adapter, no LUKS: %+v", steps)
	}

	c.facts.Adapter = "hci0"
	c.facts.Status.Devices = []LuksDeviceStatus{{Device: "/dev/sda2", Keyslots: []KeyslotStatus{{Keyslot: 0}}}}
	steps = c.steps()
	if steps[2].Blocked != "" || steps[2].Done != "" || steps[3].Blocked != "" || steps[4].Blocked != "needs the attestation by phone" {
		t.Fatalf("adapter and a device: %+v", steps)
	}

	c.facts.Phone = true
	c.facts.Status.Slots[0].Phones = []string{"Pixel"}
	c.facts.Status.Devices[0].Keyslots = append(c.facts.Status.Devices[0].Keyslots, KeyslotStatus{Keyslot: 1, Token: &LuksToken{Mode: LuksModePasswordRemoteSalt, Slot: &zero}})
	c.facts.Status.UnlockMode = UnlockPasswordRemoteSalt
	steps = c.steps()
	if steps[2].Done == "" || steps[4].Done == "" || steps[3].Done != "" {
		t.Fatalf("phone and a remote-salt keyslot: %+v", steps)
	}

	// The screen: the facts, the markers, the recommendation.
	var out bytes.Buffer
	c.out = &out
	c.show(steps)
	got := out.String()
	for _, want := range []string{"SHA-256 bank and event log", "hci0", "[x]", "[ ] 4", "Recommended next:", "4  Disk key from password + salt (hashpwd2)\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("the screen lacks %q:\n%s", want, got)
		}
	}
	c.facts.UseSHA1 = true
	out.Reset()
	c.show(steps)
	if !strings.Contains(out.String(), "the SHA-1 bank is used") {
		t.Errorf("SHA-1 not said:\n%s", out.String())
	}
}
