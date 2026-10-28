package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

// Step 1, the boot chain: the hook, the route, and the way on to step 2,
// which opens once both are in place.
func TestControlBootChain(t *testing.T) {
	c := &controller{facts: machineFacts{TPM: "/dev/tpmrm0", SHA256Bank: true, LogSHA256: true, PCRs: "0e,2e,7e,11u"}}
	steps := c.chainSteps()
	if len(steps) != 3 || steps[0].Key != "initramfs" || !strings.Contains(steps[0].Blocked, "neither mkinitcpio nor initramfs-tools") ||
		steps[2].Key != "continue" || steps[2].Blocked == "" || chainDone(&c.facts) {
		t.Fatalf("a bare machine: %+v", steps)
	}
	if got := c.prereqText(); !strings.Contains(got, "Initramfs: neither mkinitcpio nor initramfs-tools found") || !strings.Contains(got, "not met") {
		t.Fatalf("the prerequisites of a bare machine:\n%s", got)
	}

	// mkinitcpio, the hook files installed, not yet in HOOKS: the adoption
	// is the recommendation.
	c.facts.Initramfs, c.facts.HookInstalled = "mkinitcpio", true
	c.facts.Hooks = []string{"base", "systemd", "block", "sd-encrypt", "filesystems"}
	c.facts.HookState = "sd-tpm2-kira is not in HOOKS of /etc/mkinitcpio.conf - add it next to sd-encrypt, then rebuild"
	c.facts.Status.Devices = []LuksDeviceStatus{{Device: "/dev/sda2", Keyslots: []KeyslotStatus{{Keyslot: 0}}}}
	steps = c.chainSteps()
	if steps[0].Title != "mkinitcpio adoption" || steps[0].Blocked != "" || steps[0].Done != "" ||
		!strings.Contains(steps[2].Blocked, "mkinitcpio adoption") || recommended(steps) != 0 {
		t.Fatalf("not in HOOKS: %+v", steps)
	}
	// A busybox initramfs: no adoption possible, and the prerequisite says so.
	c.facts.Hooks = []string{"base", "udev", "encrypt"}
	if s := c.chainSteps()[0]; !strings.Contains(s.Blocked, "not systemd-based") || !strings.Contains(c.prereqText(), "HOOKS lack systemd") {
		t.Fatalf("busybox: %+v", s)
	}
	c.facts.Hooks = []string{"base", "systemd", "sd-tpm2-kira", "sd-encrypt"}

	// In HOOKS, the route open: the way on waits for the route alone - the
	// image is built when control is left, not in a step.
	c.facts.HookState, c.facts.Rebuild = "", "the image was built before sd-tpm2-kira was in HOOKS"
	steps = c.chainSteps()
	if steps[0].Done == "" || steps[1].Done != "" || steps[1].Blocked != "" ||
		!strings.Contains(steps[2].Blocked, "Kernel command line adoption") || strings.Contains(steps[2].Blocked, "mkinitcpio") {
		t.Fatalf("hook in, unrouted: %+v", steps)
	}
	// Routed: step 2 opens, the way on is the recommendation, the image
	// out of date or not.
	c.facts.Routed = map[string]bool{"/dev/sda2": true}
	steps = c.chainSteps()
	if !chainDone(&c.facts) || steps[2].Blocked != "" || recommended(steps) != 2 || steps[2].Menu != "hub" {
		t.Fatalf("in place: %+v", steps)
	}

	// Without a LUKS device the route has nothing to do and holds nothing up.
	c.facts.Status.Devices = nil
	if s := c.chainSteps()[1]; s.Blocked == "" || !chainDone(&c.facts) {
		t.Fatalf("no LUKS: %+v", s)
	}
}

// The prerequisites judge the recovery passphrase and an empty one.
func TestControlPrerequisites(t *testing.T) {
	c := &controller{facts: machineFacts{TPM: "/dev/tpmrm0", Initramfs: "mkinitcpio", HookInstalled: true,
		Hooks: []string{"systemd", "sd-encrypt"}, SecureBoot: SecureBootState{Known: true, Enabled: true}}}
	c.facts.Status.Devices = []LuksDeviceStatus{{Device: "/dev/sda2", Keyslots: []KeyslotStatus{{Keyslot: 0}}}}
	if got := c.prereqText(); !strings.Contains(got, "All prerequisites are met") || strings.Contains(got, "\033[0;31m") {
		t.Fatalf("a sound machine:\n%s", got)
	}
	c.facts.EmptyPass = []string{"keyslot 0 of /dev/sda2"}
	c.facts.NoRecovery = []string{"/dev/sdb1"}
	got := c.prereqText()
	for _, want := range []string{"keyslot 0 of /dev/sda2 opens with an empty passphrase (risk: anybody with the disk opens it",
		"Recovery passphrase: none on /dev/sdb1", "2 not met"} {
		if !strings.Contains(got, want) {
			t.Errorf("the prerequisites lack %q:\n%s", want, got)
		}
	}
	if got := c.factsText(); !strings.Contains(got, "\033[0;31mkeyslot 0 of /dev/sda2 opens with an empty passphrase (risk:") {
		t.Errorf("the status does not flag the empty passphrase:\n%s", got)
	}
}

// wired is a machine whose boot chain is in place, with a LUKS device and
// its recovery passphrase.
func wired() *controller {
	c := &controller{facts: machineFacts{TPM: "/dev/tpmrm0", SHA256Bank: true, LogSHA256: true, PCRs: "0e,2e,7e,11u",
		Initramfs: "mkinitcpio", HookInstalled: true, Hooks: []string{"systemd", "sd-tpm2-kira", "sd-encrypt"},
		Wired: 1, Remote: DefaultRemoteConfig()}}
	c.facts.Status.Devices = []LuksDeviceStatus{{Device: "/dev/sda2", Keyslots: []KeyslotStatus{{Keyslot: 0}}}}
	c.facts.Routed = map[string]bool{"/dev/sda2": true}
	return c
}

// Step 2: a line per submenu, each summing its options up; the options
// are greyed with the reason this machine cannot have them.
func TestControlHub(t *testing.T) {
	c := wired()
	steps := c.hubSteps()
	if len(steps) != 6 || steps[0].Key != "chain" || steps[0].Done != "in place" || steps[1].Key != "menu:keys" ||
		steps[2].Key != "menu:phone" || steps[3].Key != "menu:disk" || steps[4].Key != "menu:remote" || steps[5].Key != "debug" {
		t.Fatalf("step 2: %+v", steps)
	}
	if recommended(steps) != 1 || steps[1].Optional || !steps[2].Optional {
		t.Fatalf("the keys lead: %d", recommended(steps))
	}
	// Nothing of a phone without an adapter; no disk key without a slot
	// but the typed salt; the network possible.
	if !strings.Contains(steps[2].Blocked, "no Bluetooth adapter") || steps[3].Blocked != "" || steps[4].Blocked != "" {
		t.Fatalf("the submenus: %+v", steps[2:5])
	}
	keys := c.menuSteps("keys")
	if keys[0].Key != "setup" || keys[1].Key != "seal" || keys[1].Blocked != "needs the signing key" {
		t.Fatalf("keys: %+v", keys)
	}
	disk := c.menuSteps("disk")
	if disk[0].Blocked != "" || !strings.Contains(disk[1].Blocked, "needs slot 0") || !strings.Contains(disk[2].Blocked, "needs the signing key") {
		t.Fatalf("disk: %+v", disk)
	}

	// Step 1 not in place: every submenu waits for it. An image built
	// before the hook was in HOOKS is not that: it is rebuilt on leaving.
	c.facts.Rebuild = "the image was built before sd-tpm2-kira was in HOOKS"
	if steps := c.hubSteps(); steps[0].Done != "in place" {
		t.Fatalf("an old image holds step 1 open: %+v", steps[0])
	}
	c.facts.Rebuild = ""
	c.facts.Routed = map[string]bool{}
	if steps := c.hubSteps(); steps[0].Done != "" || recommended(steps) != 0 || steps[1].Blocked != "needs step 1, the boot chain" {
		t.Fatalf("chain open: %+v", steps)
	}
	c.facts.Routed = map[string]bool{"/dev/sda2": true}

	// The key and both slots: the keys are done, the slot lines remove.
	c.facts.Keys = "local key files"
	c.facts.Status.Slots = []StatusSlot{{Slot: 0, PCRs: "0e,2e,7e,11u", Signed: true}, {Slot: 1, PCRs: "0e,7e", Fallback: true, Signed: true}}
	keys = c.menuSteps("keys")
	if len(keys) != 3 || keys[1].Key != "slot:0" || keys[1].Done != "sealed to 0e,2e,7e,11u" || keys[2].Done != "the fallback, sealed to 0e,7e" {
		t.Fatalf("sealed: %+v", keys)
	}
	if st := c.hubSteps()[2]; st.Key != "menu:keys" || st.Done != "Signing key, Slot 0, Slot 1" {
		t.Fatalf("the keys' line: %+v", st)
	}
	// A slot of another signing key (setup made a new one) is not done:
	// reseal cannot approve it. Its line and the submenu say so.
	c.facts.Status.Slots[0].Signed, c.facts.Status.Slots[0].SignReason = false, "another key signed it"
	if keys := c.menuSteps("keys"); keys[1].Done != "" || !strings.Contains(keys[1].Dirty, "not signed by this machine's signing key (another key signed it)") {
		t.Fatalf("a slot of another key: %+v", keys[1])
	}
	if st := c.hubSteps()[2]; st.Dirty == "" {
		t.Fatalf("the keys' line with a slot of another key: %+v", st)
	}
	// Without a signing key the key's line is what is open: the slots
	// are not judged.
	keysDesc := c.facts.Keys
	c.facts.Keys = ""
	if keys := c.menuSteps("keys"); keys[1].Dirty != "" {
		t.Fatalf("a slot judged without a signing key: %+v", keys[1])
	}
	c.facts.Keys = keysDesc
	c.facts.Status.Slots[0].Signed = true
	// A slot sealed, this boot not through the image: reboot leads.
	if steps := c.hubSteps(); steps[0].Key != "reboot" {
		t.Fatalf("uncapped: %+v", steps[0])
	}

	// The phone: an adapter, the boot capped; the phone salt waits for it.
	c.facts.Adapter, c.facts.Capped = "hci0", true
	phone := c.menuSteps("phone")
	if phone[0].Blocked != "" || phone[0].Done != "" || phone[1].Blocked != "" {
		t.Fatalf("phone possible: %+v", phone)
	}
	if disk := c.menuSteps("disk"); !strings.Contains(disk[1].Blocked, "needs an enrolled phone") {
		t.Fatalf("phone salt without a phone: %+v", disk[1])
	}
	c.facts.NewImage = "/boot/initramfs-linux.img was rebuilt after this boot started"
	if phone := c.menuSteps("phone"); !strings.Contains(phone[0].Blocked, "rebuilt after this boot started") {
		t.Fatalf("new image: %+v", phone[0])
	}
	c.facts.NewImage = ""
	c.facts.Phone, c.facts.Status.Slots[0].Phones = true, 1
	zero := 0
	c.facts.Status.Devices[0].Keyslots = append(c.facts.Status.Devices[0].Keyslots, KeyslotStatus{Keyslot: 1, Token: &LuksToken{Mode: LuksModePasswordPhoneSalt, Slot: &zero}})
	if disk := c.menuSteps("disk"); disk[1].Done != "keyslot 1 of /dev/sda2" {
		t.Fatalf("phone salt enrolled: %+v", disk[1])
	}
	if keys := c.menuSteps("keys"); !strings.Contains(keys[1].Done, "attested by 1 phone") || !strings.Contains(keys[1].Done, "keyslot 1 of /dev/sda2") {
		t.Fatalf("slot 0's line: %+v", keys[1])
	}

	// No recovery passphrase: no disk key can be authorised.
	c.facts.NoRecovery = []string{"/dev/sda2"}
	if disk := c.menuSteps("disk"); !strings.Contains(disk[0].Blocked, "needs a recovery passphrase") {
		t.Fatalf("no recovery: %+v", disk[0])
	}
	c.facts.NoRecovery = nil
	// Unrouted: the disk keys wait for the route.
	c.facts.Routed = map[string]bool{}
	if disk := c.menuSteps("disk"); !strings.Contains(disk[0].Blocked, "needs the key's route") {
		t.Fatalf("unrouted: %+v", disk[0])
	}
}

// The vault: possible with slot 0 and a wired interface; enrolled, its
// line says whether it answers and knows this device, red when not.
func TestControlVault(t *testing.T) {
	c := wired()
	c.facts.Keys = "local key files"
	c.facts.Status.Slots = []StatusSlot{{Slot: 0, PCRs: "0e,2e,7e,11u", Signed: true}}
	if v := c.menuSteps("disk")[2]; v.Key != "luks-vault" || v.Blocked != "" || v.Done != "" {
		t.Fatalf("vault possible: %+v", v)
	}
	c.facts.Wired = 0
	if v := c.menuSteps("disk")[2]; !strings.Contains(v.Blocked, "no wired interface") {
		t.Fatalf("no wired interface: %+v", v)
	}
	c.facts.Wired = 1

	zero := 0
	c.facts.Status.Slots[0].Vault = "https://vault:8443"
	c.facts.Status.Devices[0].Keyslots = append(c.facts.Status.Devices[0].Keyslots, KeyslotStatus{Keyslot: 1, Token: &LuksToken{Mode: LuksModeTPMVault, Slot: &zero}})
	c.facts.Remote.Net.Mode = "dhcp"
	c.facts.Vaults = map[int]vaultCheck{0: {Answers: true, Knows: true}}
	if v := c.menuSteps("disk")[2]; !strings.Contains(v.Done, "the vault answers and knows this device") || !strings.Contains(v.Done, "keyslot 1 of /dev/sda2") {
		t.Fatalf("vault enrolled: %+v", v)
	}
	if got := c.factsText(); !strings.Contains(got, "\033[0;32mslot 0: https://vault:8443 answers") {
		t.Fatalf("the status:\n%s", got)
	}
	c.facts.Vaults[0] = vaultCheck{Problem: "not reachable (connection refused)"}
	v := c.menuSteps("disk")[2]
	if !strings.Contains(v.Dirty, "not reachable") {
		t.Fatalf("vault unreachable: %+v", v)
	}
	if st := c.hubSteps(); recommended(st) < 0 || st[recommended(st)].Key != "menu:disk" {
		t.Fatalf("the unreachable vault leads: %+v", st)
	}
	if got := c.factsText(); !strings.Contains(got, "(risk: the disk does not open unattended") {
		t.Fatalf("the status:\n%s", got)
	}
	c.facts.Vaults[0] = vaultCheck{Answers: true, Knows: true}
	c.facts.Remote.Net.Mode = "off"
	if v := c.menuSteps("disk")[2]; !strings.Contains(v.Dirty, "no network to reach the vault") {
		t.Fatalf("vault without network: %+v", v)
	}
}

// Network and SSH: SSH offers the network on the way; an SSH server
// nobody can log in to is red.
func TestControlRemote(t *testing.T) {
	c := wired()
	r := c.menuSteps("remote")
	if r[0].Key != "net" || r[0].Blocked != "" || r[0].Done != "" || r[1].Key != "ssh" || r[1].Blocked != "" {
		t.Fatalf("both possible: %+v", r)
	}
	c.facts.Wired = 0
	if r := c.menuSteps("remote"); !strings.Contains(r[0].Blocked, "no wired network interface") || !strings.Contains(r[1].Blocked, "no wired interface") {
		t.Fatalf("no wired interface: %+v", r)
	}
	c.facts.Wired = 1
	c.facts.Remote.Net.Mode, c.facts.Remote.SSH.On = "dhcp", true
	c.facts.SSHKeys = 0
	if r := c.menuSteps("remote"); !strings.Contains(r[0].Done, "DHCP") || !strings.Contains(r[1].Dirty, "nobody can log in") {
		t.Fatalf("no key: %+v", r)
	}
	c.facts.SSHKeys = 2
	c.facts.SSHCA = sshCAState{Err: "no SSH CA: tpm2-kira control creates it in the TPM"}
	if r := c.menuSteps("remote"); !strings.Contains(r[1].Dirty, "no SSH CA") {
		t.Fatalf("no CA: %+v", r[1])
	}
	c.facts.SSHCA = testSSHCA(t, false)
	if r := c.menuSteps("remote"); !strings.Contains(r[1].Done, "approved when you quit control") {
		t.Fatalf("a CA not approved: %+v", r[1])
	}
	c.facts.SSHCA = testSSHCA(t, true)
	if r := c.menuSteps("remote"); !strings.Contains(r[1].Done, "port 22") || !strings.Contains(r[1].Done, "2 key(s)") || !strings.Contains(r[1].Done, "SSH CA SHA256:") || strings.Contains(r[1].Done, "quit") {
		t.Fatalf("ssh: %+v", r[1])
	}
	// A CA made for another signing key: not done, and picking it makes it again.
	c.facts.SSHCAOtherKey = true
	if r := c.menuSteps("remote"); r[1].Done != "" || !strings.Contains(r[1].Dirty, "made for another signing key") {
		t.Fatalf("a CA of another key: %+v", r[1])
	}
	c.facts.SSHCAOtherKey = false
	// With SSH on, the typed disk keys say they are typed there too.
	if d := c.menuSteps("disk"); !strings.Contains(d[0].Explain, "typed in the SSH session") {
		t.Fatalf("typed over SSH: %+v", d[0])
	}
}

// The plain screen: both steps, the submenus' options under their line,
// the recommendation down to the option.
func TestControlShow(t *testing.T) {
	c := wired()
	var out bytes.Buffer
	c.out = &out
	c.show()
	got := out.String()
	for _, want := range []string{"Step 1 of 2: the boot chain", "All prerequisites are met", "[x]\033[0m mkinitcpio adoption",
		"Step 2 of 2: what this machine combines", "Signing key and TOTP codes", "    Signing key", "    Password + salt (Argon2id)",
		"Recommended next:\033[0m Signing key and TOTP codes > Signing key"} {
		if !strings.Contains(got, want) {
			t.Errorf("the screen lacks %q:\n%s", want, got)
		}
	}
	// The way to step 2 is the menu's: step 2 follows on this screen.
	if strings.Contains(got, "Continue to step 2") {
		t.Errorf("a way to step 2 on the plain screen:\n%s", got)
	}
	// A half-gone slot is red and recommended first.
	c.facts.Keys = "local key files"
	c.facts.Dirt = []SlotContents{{Slot: 2, Index: NVRAMSlotStart + 2, Counter: true}}
	out.Reset()
	c.show()
	if got := out.String(); !strings.Contains(got, "[!]") || !strings.Contains(got, "Slot 2  - dirty: the record counter left") ||
		!strings.Contains(got, "Recommended next:\033[0m Signing key and TOTP codes > Slot 2") {
		t.Fatalf("the dirty screen:\n%s", got)
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
	c.show()
	if !strings.Contains(out.String(), "control unknown - the protections") || !strings.Contains(out.String(), "the SHA-1 bank is used (risk:") {
		t.Errorf("the plain screen:\n%s", out.String())
	}
}

// The signing key step with a YubiKey: done only with the PIN stored.
func TestControlYubiKeyPINStep(t *testing.T) {
	c := &controller{facts: machineFacts{Keys: "YubiKey 123 slot 9a", YubiKey: true}}
	s := c.keysSteps()[0]
	if s.Done != "" || !strings.Contains(s.Explain, "Its PIN, stored in") {
		t.Fatalf("without the PIN: %+v", s)
	}
	c.facts.PINStored = true
	if s := c.keysSteps()[0]; !strings.Contains(s.Done, "its PIN in") {
		t.Fatalf("with the PIN: %+v", s)
	}
	c.facts.YubiKey = false
	if s := c.keysSteps()[0]; s.Done != "YubiKey 123 slot 9a" {
		t.Fatalf("no PIN wanted: %+v", s)
	}
}

// The boot integration is wired only when the hook files are installed
// and, with mkinitcpio, sd-tpm2-kira is in the HOOKS that mkinitcpio
// would use - the conf and its drop-ins, the last assignment winning.
func TestInitramfsHookState(t *testing.T) {
	dir := t.TempDir()
	defer func(conf string, hooks, pre []string) {
		mkinitcpioConf, mkinitcpioHookFiles, debianPremounts = conf, hooks, pre
	}(mkinitcpioConf, mkinitcpioHookFiles, debianPremounts)
	mkinitcpioConf = dir + "/mkinitcpio.conf"
	mkinitcpioHookFiles = []string{dir + "/etc-sd-tpm2-kira", dir + "/sd-tpm2-kira"}
	debianPremounts = []string{dir + "/etc-premount", dir + "/premount"}

	if s := initramfsHookState("mkinitcpio"); !strings.Contains(s, "hook is not installed") {
		t.Fatalf("no hook files: %q", s)
	}
	// make install-mkinitcpio's place (/etc); the package's counts the same.
	os.WriteFile(mkinitcpioHookFiles[0], []byte("#!/bin/bash\n"), 0o644)
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
	// make install-initramfs-tools' place (/etc); the package's counts the same.
	os.WriteFile(debianPremounts[0], []byte("#!/bin/sh\n"), 0o644)
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

// An image rebuilt after the boot started is found by the timestamps:
// what a phone pins now, the next boot cannot match.
func TestImageNewerThanBoot(t *testing.T) {
	dir := t.TempDir()
	defer func(p, u string) { mkinitcpioPresetDir, uptimePath = p, u }(mkinitcpioPresetDir, uptimePath)
	mkinitcpioPresetDir = dir
	uptimePath = dir + "/uptime"
	img := dir + "/initramfs-linux.img"
	os.WriteFile(dir+"/linux.preset", []byte("default_image=\""+img+"\"\n"), 0o644)
	os.WriteFile(uptimePath, []byte("3600.00 7200.00\n"), 0o644)

	if got := imageNewerThanBoot(); got != "" { // no image at all
		t.Fatalf("no image: %q", got)
	}
	os.WriteFile(img, []byte("img"), 0o644) // written now: after the boot an hour ago
	if got := imageNewerThanBoot(); !strings.Contains(got, "rebuilt after this boot started") {
		t.Fatalf("fresh image: %q", got)
	}
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(img, old, old)
	if got := imageNewerThanBoot(); got != "" {
		t.Fatalf("an image older than the boot: %q", got)
	}
}
