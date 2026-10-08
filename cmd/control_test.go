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
	for _, want := range []string{"SHA-256 bank and event log", "hci0", "[x]", "[ ] 4", "Recommended next:", "4  Disk key from password + salt (hashpwd2)\n", "6  Unlock at boot (control.conf, the key's route, the initramfs)  - mode password+remotesalt; the key routed"} {
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

// The risks: what weakens the protections, judged from the facts.
func TestControlRisks(t *testing.T) {
	f := machineFacts{SecureBoot: SecureBootState{Known: true, Enabled: true}, EKBy: "Infineon"}
	f.Status.Slots = []StatusSlot{{Slot: 0, PCRs: "0e,2e,7e,11u"}, {Slot: 1, PCRs: "0e,7e", Fallback: true}}
	if r := risks(&f); len(r) != 0 {
		t.Fatalf("a sound machine has risks: %v", r)
	}
	f.UseSHA1 = true
	f.SecureBoot = SecureBootState{Known: true, SetupMode: true}
	f.Status.Slots[0].PCRs = "0,2,7"
	f.EKBy, f.EKNote, f.Phone = "", "the TPM has no vendor certificate for its endorsement key", true
	f.PINLoose = true
	r := risks(&f)
	for i, want := range []string{"SHA-1 bank", "Setup Mode", "slot 0 is sealed to PCRs 0,2,7", "no known vendor vouches", "holds the YubiKey PIN"} {
		if i >= len(r) || !strings.Contains(r[i], want) {
			t.Errorf("risk %d lacks %q: %v", i, want, r)
		}
	}
	if !strings.Contains(r[3], "enrolled phone pinned it on first use") {
		t.Errorf("the phone's trust not said: %s", r[3])
	}
	f.SecureBoot = SecureBootState{Known: true}
	if r := risks(&f); !strings.Contains(r[1], "Secure Boot is disabled") {
		t.Errorf("disabled: %v", r)
	}
	f.SecureBoot = SecureBootState{}
	if r := risks(&f); !strings.Contains(r[1], "cannot be read") {
		t.Errorf("unknown: %v", r)
	}
	// On the screens.
	f.Risks = risks(&f)
	c := &controller{facts: f}
	var out bytes.Buffer
	c.out = &out
	c.show(c.steps())
	if !strings.Contains(out.String(), "Risks") || !strings.Contains(out.String(), "  ! the SHA-1 bank") {
		t.Errorf("the plain screen lacks the risks:\n%s", out.String())
	}
	if d := c.noteDescription(); !strings.Contains(d, "*Risks*\n! the SHA-1 bank") {
		t.Errorf("the note lacks the risks:\n%s", d)
	}
}

// The signing key step with a YubiKey: done only with the PIN stored.
func TestControlYubiKeyPINStep(t *testing.T) {
	c := &controller{facts: machineFacts{Keys: "YubiKey 123 slot 9a", YubiKey: true}}
	s := c.steps()[0]
	if s.Done != "" || !strings.Contains(s.Explain, "Its PIN, stored in") {
		t.Fatalf("without the PIN: %+v", s)
	}
	c.facts.PINStored = true
	if s := c.steps()[0]; !strings.Contains(s.Done, "its PIN in") {
		t.Fatalf("with the PIN: %+v", s)
	}
	c.facts.YubiKey = false
	if s := c.steps()[0]; s.Done != "YubiKey 123 slot 9a" {
		t.Fatalf("no PIN wanted: %+v", s)
	}
}
