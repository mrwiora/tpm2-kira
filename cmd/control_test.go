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
	if len(steps) != 6 || steps[0].Done != "" || steps[1].Blocked != "needs the signing key" || steps[2].Blocked != "needs the TOTP seal" || steps[5].Blocked != "needs a keyslot of tpm2-kira's" {
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
	steps = c.steps()
	if steps[2].Done == "" || steps[4].Done == "" || steps[3].Done != "" {
		t.Fatalf("phone and a remote-salt keyslot: %+v", steps)
	}
	// The unlock step: the mode the keyslots call for, and the route.
	if steps[5].Done != "" || !strings.Contains(steps[5].Explain, "Open: TPM2_KIRA_UNLOCK=password+remotesalt (now ); /dev/sda2 not routed") {
		t.Fatalf("mode unset, device unrouted: %+v", steps[5])
	}
	c.facts.Status.UnlockMode = UnlockPasswordRemoteSalt
	c.facts.Routed = map[string]bool{"/dev/sda2": true}
	steps = c.steps()
	if steps[5].Done != "mode password+remotesalt; the key routed" {
		t.Fatalf("mode set, device routed: %+v", steps[5])
	}
	c.facts.Status.Devices[0].Keyslots[1].Token.Mode = LuksModePasswordSalt
	if got := c.wantedUnlockMode(); got != UnlockPasswordSalt {
		t.Fatalf("a typed-salt keyslot alone wants %q", got)
	}
	c.facts.Status.Devices[0].Keyslots[1].Token.Mode = LuksModePasswordRemoteSalt

	// The screen: the facts, the markers, the recommendation.
	var out bytes.Buffer
	c.out = &out
	c.show(steps)
	got := out.String()
	for _, want := range []string{"SHA-256 bank and event log", "hci0", "[x]", "[ ] 4", "Recommended next:", "4  Disk key from password + salt (hashpwd2)\n", "6  Unlock at boot (unlock.conf, the key's route, the initramfs)  - mode password+remotesalt; the key routed"} {
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

func TestNoteTextEscapesMarkupAndDropsIndent(t *testing.T) {
	got := noteText("  TPM         /dev/tpm_rm0 *x*\n  Boot        a\\b\n")
	want := "TPM         /dev/tpm\\_rm0 \\*x\\*\nBoot        a\\\\b\n"
	if got != want {
		t.Fatalf("noteText:\n%q\nwant\n%q", got, want)
	}
}
