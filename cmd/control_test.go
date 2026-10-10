package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

// The overview is gated: until the signing key exists and the boot
// integration is wired, it is those two steps and Quit - only a dirty
// slot shows through. Then the tree: the standard sealing while a slot of
// the pair is missing, every slot a line of its own with the strong
// slot's options under it, the typed-salt keyslot independent of the
// slots, and the unlock greyed until a keyslot of ours exists.
func TestControlSteps(t *testing.T) {
	c := &controller{facts: machineFacts{TPM: "/dev/tpmrm0", SHA256Bank: true, LogSHA256: true, PCRs: "0e,2e,7e,11u"}}
	steps := c.steps()
	if len(steps) != 2 || steps[0].Key != "setup" || steps[1].Key != "initramfs" ||
		!strings.Contains(steps[1].Blocked, "neither mkinitcpio nor initramfs-tools") {
		t.Fatalf("a bare machine: %+v", steps)
	}

	// The key alone is not enough: the boot integration gates too, and a
	// dirty slot still shows through the gate.
	c.facts.Keys = "local key files"
	c.facts.Initramfs, c.facts.HookState = "mkinitcpio", "sd-tpm2-kira is not in HOOKS of /etc/mkinitcpio.conf - add it next to sd-encrypt, then rebuild"
	c.facts.Dirt = []SlotContents{{Slot: 2, Index: NVRAMSlotStart + 2, Counter: true}}
	steps = c.steps()
	if len(steps) != 3 || steps[1].Key != "initramfs" || steps[1].Done != "" || steps[1].Title != "mkinitcpio configuration" ||
		steps[2].Key != "slot:2" || steps[2].Dirty == "" {
		t.Fatalf("gated with dirt: %+v", steps)
	}
	if recommended(steps) != 2 { // dirt first, then the open gate steps
		t.Fatalf("recommended %d", recommended(steps))
	}
	c.facts.Dirt = nil
	if steps = c.steps(); len(steps) != 2 || recommended(steps) != 1 {
		t.Fatalf("gated: %+v", steps)
	}

	// Wired: the sealing of the standard pair is the recommendation; no
	// slot-specific option shows before a slot exists, the unlock is grey.
	c.facts.HookState = ""
	steps = c.steps()
	if len(steps) != 5 || steps[1].Done != "sd-tpm2-kira in HOOKS of "+mkinitcpioConf+", the image rebuilt" ||
		steps[2].Key != "seal" || steps[3].Key != "luks-salt" || steps[4].Key != "unlock" {
		t.Fatalf("wired, no slot: %+v", steps)
	}
	if recommended(steps) != 2 || !strings.Contains(steps[2].Explain, "The standard pair") ||
		steps[4].Blocked != "no slot is sealed yet" {
		t.Fatalf("no slot yet: %+v", steps[2])
	}

	// Both slots sealed: the tree replaces the seal step; the strong slot
	// carries the options, each slot's line removes it.
	c.facts.Status.Slots = []StatusSlot{{Slot: 0, PCRs: "0e,2e,7e,11u", Signed: true}, {Slot: 1, PCRs: "0e,7e", Fallback: true, Signed: true}}
	c.facts.Status.Devices = []LuksDeviceStatus{{Device: "/dev/sda2", Keyslots: []KeyslotStatus{{Keyslot: 0}}}}
	steps = c.steps()
	if len(steps) != 8 || steps[2].Key != "slot:0" || steps[3].Key != "attest" || steps[4].Key != "luks-remote" ||
		steps[5].Key != "slot:1" || steps[6].Key != "luks-salt" || steps[7].Key != "unlock" {
		t.Fatalf("the tree: %+v", steps)
	}
	if steps[2].Done != "sealed to 0e,2e,7e,11u" || !steps[2].Optional || !steps[2].SelfConfirm ||
		steps[5].Done != "the fallback, sealed to 0e,7e" {
		t.Fatalf("the slot lines: %+v %+v", steps[2], steps[5])
	}
	if !steps[3].Child || !steps[4].Child || steps[3].Blocked != "no Bluetooth adapter on this machine" ||
		steps[4].Blocked != "needs the attestation by phone" {
		t.Fatalf("the strong slot's options: %+v %+v", steps[3], steps[4])
	}
	if steps[7].Blocked != "needs a keyslot of tpm2-kira's (the remote salt under slot 0, or the typed salt)" {
		t.Fatalf("unlock without a keyslot: %+v", steps[7])
	}

	// A phone and a remote-salt keyslot bound to slot 0, read from the
	// LUKS header: the options under slot 0 are done, and the unlock
	// waits only for the route.
	c.facts.Adapter = "hci0"
	c.facts.Phone = true
	c.facts.Status.Slots[0].Phones = []string{"Pixel"}
	zero := 0
	c.facts.Status.Devices[0].Keyslots = append(c.facts.Status.Devices[0].Keyslots, KeyslotStatus{Keyslot: 1, Token: &LuksToken{Mode: LuksModePasswordRemoteSalt, Slot: &zero}})
	steps = c.steps()
	if steps[3].Done != `phone "Pixel"` || steps[4].Done != "keyslot 1 of /dev/sda2" {
		t.Fatalf("phone and remote-salt keyslot: %+v %+v", steps[3], steps[4])
	}
	if steps[7].Done != "" || !strings.Contains(steps[7].Explain, "Open: /dev/sda2 not routed through tpm2-kira") {
		t.Fatalf("device unrouted: %+v", steps[7])
	}
	c.facts.Routed = map[string]bool{"/dev/sda2": true}
	steps = c.steps()
	if steps[7].Done != "the key routed" {
		t.Fatalf("device routed: %+v", steps[7])
	}

	// The screen: the status, the markers, the tree, the recommendation.
	var out bytes.Buffer
	c.out = &out
	c.show(steps)
	got := out.String()
	for _, want := range []string{"SHA-256 bank and event log", "hci0", "[x]", "Slot 0  - sealed to 0e,2e,7e,11u",
		"  Attestation by phone", "Recommended next:", "7  Disk key from password + salt (hashpwd2)\n",
		"8  Unlock at boot (the key's route, the initramfs)  - the key routed"} {
		if !strings.Contains(got, want) {
			t.Errorf("the screen lacks %q:\n%s", want, got)
		}
	}

	// A half-gone slot is a line of its own, dirty and recommended first.
	c.facts.Dirt = []SlotContents{{Slot: 2, Index: NVRAMSlotStart + 2, Counter: true}}
	dirty := c.steps()
	if dirty[6].Key != "slot:2" || dirty[6].Dirty != "dirty: the record counter left" || recommended(dirty) != 6 {
		t.Fatalf("a dirty slot: %+v", dirty[6])
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
	if steps[2].Key != "seal" || !strings.Contains(steps[2].Explain, "Slot 1, the fallback, is missing") || steps[3].Key != "slot:0" {
		t.Fatalf("fallback missing: %+v", steps[2])
	}
	c.facts.Status.Slots = []StatusSlot{{Slot: 1, PCRs: "0e,7e", Fallback: true, Signed: true}}
	steps = c.steps()
	if steps[2].Key != "seal" || !strings.Contains(steps[2].Explain, "Slot 0 is missing") {
		t.Fatalf("slot 0 missing: %+v", steps[2])
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
		good("mkinitcpio, sd-tpm2-kira in HOOKS"),
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
	c.facts.Initramfs, c.facts.HookState = "mkinitcpio", "sd-tpm2-kira is not in HOOKS of /etc/mkinitcpio.conf - add it next to sd-encrypt, then rebuild"
	if got := c.factsText(); !strings.Contains(got, "mkinitcpio, but sd-tpm2-kira is not in HOOKS") || !strings.Contains(got, "(risk: the next boot shows no code screen and serves no key)") {
		t.Errorf("the unwired hook is not marked:\n%s", got)
	}
	c.facts.Initramfs, c.facts.HookState = "", ""
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

// The boot integration is wired only when the hook files are installed
// and, with mkinitcpio, sd-tpm2-kira is in the HOOKS that mkinitcpio
// would use - the conf and its drop-ins, the last assignment winning.
func TestInitramfsHookState(t *testing.T) {
	dir := t.TempDir()
	defer func(conf, hook, pre string) { mkinitcpioConf, mkinitcpioHook, debianPremount = conf, hook, pre }(mkinitcpioConf, mkinitcpioHook, debianPremount)
	mkinitcpioConf = dir + "/mkinitcpio.conf"
	mkinitcpioHook = dir + "/sd-tpm2-kira"
	debianPremount = dir + "/premount"

	if s := initramfsHookState("mkinitcpio"); !strings.Contains(s, "hook is not installed") {
		t.Fatalf("no hook files: %q", s)
	}
	os.WriteFile(mkinitcpioHook, []byte("#!/bin/bash\n"), 0o644)
	os.WriteFile(mkinitcpioConf, []byte("# comment, not an assignment:\n#HOOKS=(base sd-tpm2-kira)\nHOOKS=(base systemd block\n       sd-encrypt filesystems)\n"), 0o644)
	if s := initramfsHookState("mkinitcpio"); !strings.Contains(s, "is not in HOOKS of "+mkinitcpioConf) {
		t.Fatalf("missing from HOOKS: %q", s)
	}
	os.WriteFile(mkinitcpioConf, []byte("HOOKS=(base systemd block sd-tpm2-kira sd-encrypt filesystems) # trailing\n"), 0o644)
	if s := initramfsHookState("mkinitcpio"); s != "" {
		t.Fatalf("wired, yet: %q", s)
	}
	// A drop-in overrides the conf, as mkinitcpio reads them.
	os.MkdirAll(dir+"/mkinitcpio.conf.d", 0o755)
	os.WriteFile(dir+"/mkinitcpio.conf.d/10-override.conf", []byte(`HOOKS="base systemd sd-encrypt"`+"\n"), 0o644)
	if s := initramfsHookState("mkinitcpio"); !strings.Contains(s, "is not in HOOKS") {
		t.Fatalf("the drop-in did not win: %q", s)
	}
	os.WriteFile(dir+"/mkinitcpio.conf.d/20-ours.conf", []byte("HOOKS=('base' 'systemd' 'sd-tpm2-kira' 'sd-encrypt')\n"), 0o644)
	if s := initramfsHookState("mkinitcpio"); s != "" {
		t.Fatalf("the later drop-in did not win: %q", s)
	}

	if s := initramfsHookState("initramfs-tools"); !strings.Contains(s, "boot scripts are not installed") {
		t.Fatalf("no Debian scripts: %q", s)
	}
	os.WriteFile(debianPremount, []byte("#!/bin/sh\n"), 0o644)
	if s := initramfsHookState("initramfs-tools"); s != "" {
		t.Fatalf("Debian wired, yet: %q", s)
	}
	if s := initramfsHookState(""); s != "" {
		t.Fatalf("no initramfs at all judges nothing: %q", s)
	}
}

// Adopting the HOOKS: the line as it should read, written only on request,
// before sd-encrypt; and the rebuild check from the timestamps.
func TestAdoptHookAndRebuildPending(t *testing.T) {
	dir := t.TempDir()
	defer func(c, p string) { mkinitcpioConf, mkinitcpioPresetDir = c, p }(mkinitcpioConf, mkinitcpioPresetDir)
	mkinitcpioConf = dir + "/mkinitcpio.conf"
	mkinitcpioPresetDir = dir + "/mkinitcpio.d"
	os.WriteFile(mkinitcpioConf, []byte("MODULES=()\nHOOKS=(base systemd block sd-encrypt filesystems)\n"), 0o644)

	file, oldLine, newLine, err := AdoptHookLine(mkinitcpioConf)
	if err != nil || file != mkinitcpioConf ||
		oldLine != "HOOKS=(base systemd block sd-encrypt filesystems)" ||
		newLine != "HOOKS=(base systemd block sd-tpm2-kira sd-encrypt filesystems)" {
		t.Fatalf("%q %q %q %v", file, oldLine, newLine, err)
	}
	if _, line, err := AdoptHook(mkinitcpioConf); err != nil || line != newLine {
		t.Fatalf("adopt: %q %v", line, err)
	}
	data, _ := os.ReadFile(mkinitcpioConf)
	if string(data) != "MODULES=()\nHOOKS=(base systemd block sd-tpm2-kira sd-encrypt filesystems)\n" {
		t.Fatalf("the file after adopting:\n%s", data)
	}
	if s := initramfsHookState("mkinitcpio"); strings.Contains(s, "HOOKS") { // the hook files are the host's business here
		t.Fatalf("not wired after adopting: %q", s)
	}
	// Without sd-encrypt the hook goes after systemd; without either it is
	// not an editing matter.
	os.WriteFile(mkinitcpioConf, []byte("HOOKS=(base systemd autodetect block filesystems)\n"), 0o644)
	if _, _, newLine, err := AdoptHookLine(mkinitcpioConf); err != nil || newLine != "HOOKS=(base systemd sd-tpm2-kira autodetect block filesystems)" {
		t.Fatalf("after systemd: %q %v", newLine, err)
	}
	os.WriteFile(mkinitcpioConf, []byte("HOOKS=(base udev encrypt filesystems)\n"), 0o644)
	if _, _, _, err := AdoptHookLine(mkinitcpioConf); err == nil || !strings.Contains(err.Error(), "systemd-based initramfs") {
		t.Fatalf("a busybox initramfs: %v", err)
	}

	// The rebuild check: an image older than the HOOKS file is pending.
	os.WriteFile(mkinitcpioConf, []byte("HOOKS=(base systemd sd-tpm2-kira sd-encrypt)\n"), 0o644)
	os.MkdirAll(mkinitcpioPresetDir, 0o755)
	img := dir + "/initramfs-linux.img"
	os.WriteFile(dir+"/mkinitcpio.d/linux.preset", []byte("PRESETS=('default')\ndefault_image=\""+img+"\"\n"), 0o644)
	if p := rebuildPending(mkinitcpioConf); p != "" { // no image yet: nothing to tell
		t.Fatalf("no image: %q", p)
	}
	os.WriteFile(img, []byte("img"), 0o644)
	old := time.Now().Add(-time.Hour)
	os.Chtimes(img, old, old)
	if p := rebuildPending(mkinitcpioConf); !strings.Contains(p, "was built before") {
		t.Fatalf("stale image: %q", p)
	}
	now := time.Now().Add(time.Minute)
	os.Chtimes(img, now, now)
	if p := rebuildPending(mkinitcpioConf); p != "" {
		t.Fatalf("fresh image: %q", p)
	}
}
