package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// The overview is a tree judged from the facts: the signing key, the
// standard sealing guided while a slot of the pair is missing, then every
// slot a line of its own with the strong slot's options under it, the
// typed-salt keyslot independent of the slots, and the unlock greyed until
// a keyslot of ours exists.
func TestControlSteps(t *testing.T) {
	c := &controller{facts: machineFacts{TPM: "/dev/tpmrm0", SHA256Bank: true, LogSHA256: true, PCRs: "0e,2e,7e,11u"}}
	steps := c.steps()
	if len(steps) != 4 || steps[0].Done != "" || steps[1].Key != "seal" || steps[1].Blocked != "needs the signing key" ||
		steps[2].Key != "luks-salt" || steps[2].Blocked == "" || steps[3].Key != "unlock" || steps[3].Blocked != "no slot is sealed yet" {
		t.Fatalf("a bare machine: %+v", steps)
	}

	// With the key the sealing of the standard pair is the recommendation:
	// no slot-specific option shows before a slot exists.
	c.facts.Keys = "local key files"
	steps = c.steps()
	if steps[1].Blocked != "" || recommended(steps) != 1 || !strings.Contains(steps[1].Explain, "The standard pair") {
		t.Fatalf("no slot yet: %+v", steps[1])
	}

	// Both slots sealed: the tree replaces the seal step; the strong slot
	// carries the options, each slot's line removes it.
	c.facts.Status.Slots = []StatusSlot{{Slot: 0, PCRs: "0e,2e,7e,11u", Signed: true}, {Slot: 1, PCRs: "0e,7e", Fallback: true, Signed: true}}
	c.facts.Status.Devices = []LuksDeviceStatus{{Device: "/dev/sda2", Keyslots: []KeyslotStatus{{Keyslot: 0}}}}
	steps = c.steps()
	if len(steps) != 7 || steps[1].Key != "slot:0" || steps[2].Key != "attest" || steps[3].Key != "luks-remote" ||
		steps[4].Key != "slot:1" || steps[5].Key != "luks-salt" || steps[6].Key != "unlock" {
		t.Fatalf("the tree: %+v", steps)
	}
	if steps[1].Done != "sealed to 0e,2e,7e,11u" || !steps[1].Optional || !steps[1].SelfConfirm ||
		steps[4].Done != "the fallback, sealed to 0e,7e" {
		t.Fatalf("the slot lines: %+v %+v", steps[1], steps[4])
	}
	if !steps[2].Child || !steps[3].Child || steps[2].Blocked != "no Bluetooth adapter on this machine" ||
		steps[3].Blocked != "needs the attestation by phone" {
		t.Fatalf("the strong slot's options: %+v %+v", steps[2], steps[3])
	}
	if steps[6].Blocked != "needs a keyslot of tpm2-kira's (the remote salt under slot 0, or the typed salt)" {
		t.Fatalf("unlock without a keyslot: %+v", steps[6])
	}

	// A phone and a remote-salt keyslot bound to slot 0, read from the
	// LUKS header: the options under slot 0 are done.
	c.facts.Adapter = "hci0"
	c.facts.Phone = true
	c.facts.Status.Slots[0].Phones = []string{"Pixel"}
	c.facts.Status.Devices[0].Keyslots = append(c.facts.Status.Devices[0].Keyslots, KeyslotStatus{Keyslot: 1, Token: &LuksToken{Mode: LuksModePasswordRemoteSalt, Slot: 0}})
	steps = c.steps()
	if steps[2].Done != `phone "Pixel"` || steps[3].Done != "keyslot 1 of /dev/sda2" {
		t.Fatalf("phone and remote-salt keyslot: %+v %+v", steps[2], steps[3])
	}
	// The unlock step: the mode the keyslots call for, and the route.
	if steps[6].Done != "" || !strings.Contains(steps[6].Explain, "Open: TPM2_KIRA_UNLOCK=password+remotesalt (now ); /dev/sda2 not routed") {
		t.Fatalf("mode unset, device unrouted: %+v", steps[6])
	}
	c.facts.Status.UnlockMode = UnlockPasswordRemoteSalt
	c.facts.Routed = map[string]bool{"/dev/sda2": true}
	steps = c.steps()
	if steps[6].Done != "mode password+remotesalt; the key routed" {
		t.Fatalf("mode set, device routed: %+v", steps[6])
	}
	c.facts.Status.Devices[0].Keyslots[1].Token.Mode = LuksModePasswordSalt
	if got := c.wantedUnlockMode(); got != UnlockPasswordSalt {
		t.Fatalf("a typed-salt keyslot alone wants %q", got)
	}
	c.facts.Status.Devices[0].Keyslots[1].Token.Mode = LuksModePasswordRemoteSalt

	// The screen: the status, the markers, the tree, the recommendation.
	var out bytes.Buffer
	c.out = &out
	c.show(steps)
	got := out.String()
	for _, want := range []string{"SHA-256 bank and event log", "hci0", "[x]", "Slot 0  - sealed to 0e,2e,7e,11u",
		"  Attestation by phone", "Recommended next:", "6  Disk key from password + salt (hashpwd2)\n",
		"7  Unlock at boot (control.conf, the key's route, the initramfs)  - mode password+remotesalt; the key routed"} {
		if !strings.Contains(got, want) {
			t.Errorf("the screen lacks %q:\n%s", want, got)
		}
	}

	// A half-gone slot is a line of its own, dirty and recommended first.
	c.facts.Dirt = []SlotContents{{Slot: 2, Index: NVRAMSlotStart + 2, Counter: true}}
	dirty := c.steps()
	if dirty[5].Key != "slot:2" || dirty[5].Dirty != "dirty: the record counter left" || recommended(dirty) != 5 {
		t.Fatalf("a dirty slot: %+v", dirty[5])
	}
	out.Reset()
	c.show(dirty)
	if got := out.String(); !strings.Contains(got, "[!]") || !strings.Contains(got, "Slot 2  - dirty: the record counter left") {
		t.Fatalf("the dirty screen:\n%s", got)
	}
	c.facts.Dirt = nil

	// A missing half of the standard pair brings the seal step back, for
	// exactly the missing slot.
	c.facts.Status.Slots = c.facts.Status.Slots[:1]
	steps = c.steps()
	if steps[1].Key != "seal" || !strings.Contains(steps[1].Explain, "Slot 1, the fallback, is missing") || steps[2].Key != "slot:0" {
		t.Fatalf("fallback missing: %+v", steps[1])
	}
	c.facts.Status.Slots = []StatusSlot{{Slot: 1, PCRs: "0e,7e", Fallback: true, Signed: true}}
	steps = c.steps()
	if steps[1].Key != "seal" || !strings.Contains(steps[1].Explain, "Slot 0 is missing") {
		t.Fatalf("slot 0 missing: %+v", steps[1])
	}
}

func TestNoteTextEscapesMarkupAndDropsIndent(t *testing.T) {
	got := noteText("  TPM         /dev/tpm_rm0 *x*\n  Boot        a\\b\n")
	want := "TPM         /dev/tpm\\_rm0 \\*x\\*\nBoot        a\\\\b\n"
	if got != want {
		t.Fatalf("noteText:\n%q\nwant\n%q", got, want)
	}
}

// The status on top judges line by line: green what is good, red what is
// not with the risk in brackets; there is no separate risks list.
func TestControlStatusJudgement(t *testing.T) {
	f := machineFacts{TPM: "/dev/tpmrm0", LogSHA256: true, Keys: "local key files",
		SecureBoot: SecureBootState{Known: true, Enabled: true}, EKBy: "Infineon", Initramfs: "mkinitcpio"}
	f.Status.Slots = []StatusSlot{{Slot: 0, PCRs: "0e,2e,7e,11u"}, {Slot: 1, PCRs: "0e,7e", Fallback: true}}
	c := &controller{facts: f}
	got := c.factsText()
	for _, want := range []string{
		good("/dev/tpmrm0, SHA-256 bank and event log"),
		good("Infineon vouches for the endorsement key"),
		good("enabled"),
		good("0 (0e,2e,7e,11u), 1 (0e,7e, the fallback)"),
		good("local key files"),
		good("mkinitcpio"),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the sound machine lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "risk:") || strings.Contains(got, "\033[0;31m") {
		t.Errorf("a sound machine shows red:\n%s", got)
	}

	c.facts.UseSHA1, c.facts.SHA1Why = true, "no SHA-256 bank"
	c.facts.SecureBoot = SecureBootState{Known: true, SetupMode: true}
	c.facts.Status.Slots[0].PCRs = "0,2,7"
	c.facts.EKBy, c.facts.EKNote, c.facts.Phone = "", "the TPM has no vendor certificate for its endorsement key", true
	c.facts.PINLoose = true
	c.facts.Initramfs = ""
	got = c.factsText()
	for _, want := range []string{
		"the SHA-1 bank is used (risk: SHA-1 collisions are practical",
		"Setup Mode (risk: any root user can replace the keys",
		"slot 0 leaves the kernel, the initrd or the command line unmeasured (risk: a replaced initrd",
		"none vouches for the endorsement key: the TPM has no vendor certificate for its endorsement key (risk: the enrolled phone pinned it on first use",
		"holds the PIN, but other users can read it",
		"neither mkinitcpio nor initramfs-tools found (risk: no code screen at boot",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the status lacks %q:\n%s", want, got)
		}
	}
	c.facts.SecureBoot = SecureBootState{Known: true}
	if got := c.factsText(); !strings.Contains(got, "disabled (risk: the boot loader and the kernel run unsigned") {
		t.Errorf("disabled: %s", got)
	}
	c.facts.SecureBoot = SecureBootState{}
	if got := c.factsText(); !strings.Contains(got, "state unknown, no efivars (risk:") {
		t.Errorf("unknown: %s", got)
	}
	if d := c.noteDescription(); strings.Contains(d, "Risks") {
		t.Errorf("a separate risks list remains:\n%s", d)
	}
	// The plain screen carries the judged status and the version header.
	var out bytes.Buffer
	c.out = &out
	c.show(c.steps())
	if !strings.Contains(out.String(), "control unknown - the protections") || !strings.Contains(out.String(), "the SHA-1 bank is used (risk:") {
		t.Errorf("the plain screen:\n%s", out.String())
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
