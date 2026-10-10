package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/mrwiora/tpm2-kira/attest"
	"golang.org/x/sys/unix"
)

// 'tpm2-kira control' is the guided way through the protections, for a
// person rather than a script: it first looks at what the machine has (a
// TPM and its banks, the event log, how it booted, a Bluetooth adapter, the
// LUKS devices, the initramfs kind), then at what is configured already
// (the keys, the slots, the phone, the keyslots, the unlock mode, the
// route), shows both on one screen, recommends the next step, and runs
// the step the person picks with the same functions the expert commands
// use. Run again, it shows the state and what is left. Nothing here is a
// third way of doing things: every step is one of setup, seal, attest
// enrol, luks enrol.

// ControlOptions is what control takes.
type ControlOptions struct {
	TPMPath string
	Debug   bool
	Out     io.Writer // default stdout
}

// machineFacts is what the analysis found.
type machineFacts struct {
	TPM        string
	TPMErr     string
	SHA256Bank bool
	SHA1Bank   bool
	LogRead    bool // the event log can be read
	LogSHA256  bool // and carries SHA-256 digests
	UseSHA1    bool // the only way on this machine (SHA1Why says why)
	SHA1Why    string
	PCRs       string
	PCRsWhy    string
	Keys       string // "" when setup has not run; else what the key is
	YubiKey    bool   // the key is on a YubiKey that wants a PIN
	PINStored  bool   // control.conf holds the PIN, root's alone
	PINLoose   bool   // control.conf holds the PIN, but others can read it
	EKBy       string // the vendor whose chain vouches for this TPM's EK; "" when none does
	EKNote     string // why none does
	SecureBoot SecureBootState
	Initramfs  string // mkinitcpio, initramfs-tools, or ""
	HookState  string // why the boot integration would not run; "" when wired
	Rebuild    string // mkinitcpio: why the image still lacks the hook; "" when it carries it
	Adapter    string // hciN, or ""
	AttestConf string // "" when control.conf loads; else the reason

	Status   StatusReport   // the slots, the unlock mode, the LUKS devices, the notes
	Dirt     []SlotContents // slots whose blob is gone but of which parts remain
	Phone    bool           // a phone is enrolled for some slot
	Salt     bool           // a remote salt is enrolled for some slot
	BTAlways bool           // Bluetooth is packed into every image (control.conf)
	Routed   map[string]bool
}

// collectFacts is the analysis.
func collectFacts(tpmPath string, debug bool) machineFacts {
	f := machineFacts{TPM: tpmPath, Routed: map[string]bool{}}

	if tpmDev, err := OpenTPM(tpmPath); err != nil {
		f.TPMErr = err.Error()
	} else {
		f.SHA256Bank = TPMHasPCRBank(tpmDev, PCRHashAlgoSHA256)
		f.SHA1Bank = TPMHasPCRBank(tpmDev, PCRHashAlgoSHA1)
		tpmDev.Close()
	}
	if _, err := readRawEventLogFromPath(DefaultEventlogPath); err == nil {
		f.LogRead = true
		if d, err := EventDigestsForPCR(DefaultEventlogPath, 0, PCRHashAlgoSHA256); err == nil && len(d) > 0 {
			f.LogSHA256 = true
		}
	}
	// The SHA-1 bank is for a TPM without a SHA-256 bank, and for a
	// firmware whose event log measures into the SHA-1 bank alone (then
	// the SHA-256 registers hold nothing the boot put there). Without a
	// log to read the registers decide, and SHA-256 is what seal reads.
	switch {
	case f.TPMErr != "" || !f.SHA1Bank:
	case !f.SHA256Bank:
		f.UseSHA1, f.SHA1Why = true, "no SHA-256 bank"
	case f.LogRead && !f.LogSHA256:
		f.UseSHA1, f.SHA1Why = true, "the event log has no SHA-256 digests"
	}
	algo := PCRHashAlgoSHA256
	if f.UseSHA1 {
		algo = PCRHashAlgoSHA1
	}
	f.PCRs, f.PCRsWhy = DefaultPCRSelection("", algo)

	if _, err := os.Stat(DefaultPrivateKeyPath); err == nil {
		f.Keys = "local key files in " + DefaultKeysDir
		if k, err := LoadCheckedSigningPrivateKey(DefaultPrivateKeyPath); err == nil {
			if desc, ok := YubiKeyDescription(k); ok {
				f.Keys = desc
				f.YubiKey = yubiKeyWantsPIN(k)
			}
		}
	}
	if pin, loose := configPIN(controlConfigPath()); pin != "" {
		f.PINStored, f.PINLoose = !loose, loose
	}
	f.SecureBoot = ReadSecureBootState()
	if f.TPMErr == "" {
		f.EKBy, f.EKNote = ekVerdict(tpmPath, debug)
	}
	switch {
	case fileExists(mkinitcpioConf):
		f.Initramfs = "mkinitcpio"
	case isDebianInitramfs():
		f.Initramfs = "initramfs-tools"
	}
	f.HookState = initramfsHookState(f.Initramfs)
	if f.Initramfs == "mkinitcpio" && f.HookState == "" {
		f.Rebuild = rebuildPending(mkinitcpioConf)
	}
	if m, _ := filepath.Glob("/sys/class/bluetooth/hci*"); len(m) > 0 {
		f.Adapter = filepath.Base(m[0])
	}
	if cfg, err := LoadAttestConfig(controlConfigPath()); err != nil {
		f.AttestConf = err.Error()
	} else {
		f.BTAlways = cfg.Bluetooth == "always"
	}

	f.Status = collectStatus(StatusOptions{TPMPath: tpmPath, ConfigPath: controlConfigPath(), Debug: debug})
	if f.TPMErr == "" {
		f.Dirt = collectDirt(tpmPath, f.Status.Devices)
	}
	for _, s := range f.Status.Slots {
		f.Phone = f.Phone || len(s.Phones) > 0
		f.Salt = f.Salt || s.RemoteSalt
	}
	var devices []string
	for _, d := range f.Status.Devices {
		devices = append(devices, d.Device)
	}
	if len(devices) > 0 {
		if findings, err := RouteFindings(devices, nil, ""); err == nil {
			for _, r := range findings {
				if r.Routed {
					f.Routed[r.Device] = true
				}
			}
		}
	}
	return f
}

// weakSlots are the slots whose selection leaves the kernel, the initrd
// or the command line unmeasured (the fallback is weak by design and not
// counted).
func weakSlots(f *machineFacts) []int {
	var weak []int
	for _, s := range f.Status.Slots {
		if s.Fallback {
			continue
		}
		specs, err := ParsePCRSpecs(s.PCRs)
		if err != nil {
			continue
		}
		if kernelInitrd, cmdline := bootChainCoverage(PCRSpecIndices(specs)); !kernelInitrd || !cmdline {
			weak = append(weak, s.Slot)
		}
	}
	return weak
}

// ekVerdict is what a phone concludes about this TPM's endorsement key:
// the vendor whose certificate chain vouches for it, or why none does.
func ekVerdict(tpmPath string, debug bool) (by, note string) {
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return "", err.Error()
	}
	defer tpmDev.Close()
	defer CleanupTPM(tpmDev, debug)
	alg, ek, pub, err := pickCertifiedEK(tpmDev)
	if err != nil {
		return "", err.Error()
	}
	FlushHandle(tpmDev, ek.handle)
	by, err = attest.VerifyEKCertificate(pub, readEKCert(tpmDev, alg), readEKCertChain(tpmDev), time.Now())
	if err != nil {
		return "", attest.EKCertNote(err)
	}
	return by, ""
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// A step of the protection, as the menu shows it. The overview is a tree:
// every populated slot is a line of its own, the options that build on a
// slot (the attestation, the remote salt) are indented under it (Child),
// and picking a slot's own line removes the slot whole (SelfConfirm: the
// step asks before it acts, so no "run it again?" stands in front).
type controlStep struct {
	Key         string
	Title       string
	Explain     string // one or two lines on what it does
	Done        string // "" when not done; else how it is
	Blocked     string // "" when it can be done; else why not
	Dirty       string // "" when nothing is half-gone; else what and where
	Optional    bool   // not a protection: never the recommendation on its own
	Child       bool   // indented under the slot line above it
	SelfConfirm bool   // Run confirms by itself; picked straight even when Done
	Run         func(c *controller) error
}

// The one colour language of the overview: green is good and done, orange
// is open - possible and still to do - and red is dirty, a half-gone slot.
// Blocked stays grey.
func (s controlStep) marker() string {
	switch {
	case s.Dirty != "":
		return "\033[0;31m[!]\033[0m"
	case s.Done != "":
		return "\033[0;32m[x]\033[0m"
	case s.Blocked != "":
		return "\033[0;90m[-]\033[0m"
	}
	return "\033[0;33m[ ]\033[0m"
}

// controller holds one run of the control command.
type controller struct {
	o     ControlOptions
	out   io.Writer
	tty   bool
	facts machineFacts
	ran   bool // a step ran: the initramfs is to be rebuilt
}

// steps are the overview: the signing key, then the slots as a tree - the
// standard sealing (slots 0 and 1) guided while one of them is missing,
// each populated slot a line of its own that removes the slot whole when
// picked, with the options that build on the strong slot indented under it
// - then the keyslot from a typed salt (independent of the slots) and the
// unlock, greyed until a keyslot of ours exists.
func (c *controller) steps() []controlStep {
	f := &c.facts
	var slot0, strong *StatusSlot
	fallback := false
	for i := range f.Status.Slots {
		s := &f.Status.Slots[i]
		if s.Slot == 0 {
			slot0 = s
		}
		if !s.Fallback && strong == nil {
			strong = s // the strong slot carries the options: slot 0 normally
		}
		fallback = fallback || s.Fallback
	}
	hasSalt := false
	boundTo := map[int][]string{} // slot -> "keyslot N of /dev/x": the remote-salt keyslots, from the LUKS headers
	for _, d := range f.Status.Devices {
		for _, ks := range d.Keyslots {
			if ks.Token == nil {
				continue
			}
			if ks.Token.Mode == LuksModePasswordSalt {
				hasSalt = true
			}
			if ks.Token.Mode == LuksModePasswordRemoteSalt && ks.Token.Slot != nil {
				boundTo[*ks.Token.Slot] = append(boundTo[*ks.Token.Slot], fmt.Sprintf("keyslot %d of %s", ks.Keyslot, d.Device))
			}
		}
	}
	luksDevices := len(f.Status.Devices) > 0 && f.Status.DevicesError == ""

	keys := controlStep{Key: "setup", Title: "Signing key",
		Explain: "The key that approves boot states and authorises every write to the TPM: local files, or a key on a YubiKey.",
		Run:     (*controller).runSetup}
	switch {
	case f.Keys == "":
	case f.YubiKey && f.PINStored:
		keys.Done = f.Keys + "; its PIN in " + controlConfigPath()
	case f.YubiKey:
		// The key is there, the PIN not: the hooks' reseal after a kernel
		// update is skipped until it is. The step stores it.
		keys.Explain = f.Keys + ". Its PIN, stored in " + controlConfigPath() + " (readable by root alone, left out of the initramfs), lets the hooks reseal unattended after a kernel or initramfs update; without it that reseal is skipped and the next boot shows a PCR mismatch."
	default:
		keys.Done = f.Keys
	}
	// The boot integration is the second foundation: without the hook in
	// the image there is no code screen, no gate and no key at boot, so
	// everything else waits behind it.
	boot := controlStep{Key: "initramfs", Run: (*controller).runInitramfs}
	switch f.Initramfs {
	case "mkinitcpio":
		boot.Title = "mkinitcpio configuration"
		switch {
		case f.HookState != "":
			boot.Explain = "The code screen, the gate and the key provider enter the boot image through the sd-tpm2-kira hook: " + mkinitcpioConf + " must carry it in HOOKS, next to sd-encrypt. The step shows the line as it should read and writes it when you say so - editing the file yourself works just as well - and then offers the rebuild (mkinitcpio -P)."
		case f.Rebuild != "":
			boot.Explain = f.Rebuild + ". The step offers to run mkinitcpio -P."
		default:
			boot.Done = "sd-tpm2-kira in HOOKS of " + mkinitcpioConf + ", the image rebuilt"
		}
	case "initramfs-tools":
		boot.Title = "initramfs-tools integration"
		if f.HookState == "" {
			boot.Done = "the boot scripts are in place"
		} else {
			boot.Explain = "The .deb installs the boot scripts into /usr/share/initramfs-tools; nothing is configured by hand."
		}
	default:
		boot.Title = "Initramfs integration"
		boot.Blocked = "neither mkinitcpio nor initramfs-tools found: no code screen at boot"
	}

	steps := []controlStep{keys, boot}

	// Until the signing key exists and the boot integration is wired, the
	// overview is these two steps and Quit: everything else builds on
	// them. Only a dirty slot shows through, so a cleanup is never hidden.
	if keys.Done == "" || boot.Done == "" {
		for _, d := range f.Dirt {
			steps = append(steps, dirtyLine(d))
		}
		return steps
	}

	// The standard sealing, slots 0 and 1: the step guides to it while one
	// of the two is missing and seals exactly what lacks; with both in
	// place the tree below shows them and the step disappears ('tpm2-kira
	// seal' stays for sealing anew by hand).
	if slot0 == nil || !fallback {
		seal := controlStep{Key: "seal", Title: "TOTP codes at boot (slot 0, and slot 1 the fallback)",
			Run: (*controller).runSeal}
		switch {
		case f.TPMErr != "":
			seal.Blocked = "no TPM: " + f.TPMErr
		case f.Keys == "":
			seal.Blocked = "needs the signing key"
		case slot0 == nil && !fallback:
			seal.Explain = "The standard pair: a TOTP key sealed into slot 0 - to " + f.PCRs + ", evaluated for this machine and put up as the recommendation to acknowledge, or custom PCRs instead - and one sealed to PCRs 0 and 7 alone into slot 1, the fallback for a boot whose kernel changed unpredicted. Pair both with your authenticator."
		case slot0 == nil:
			seal.Explain = "Slot 0 is missing: seals a TOTP key into it - to " + f.PCRs + ", evaluated for this machine and put up as the recommendation to acknowledge, or custom PCRs instead. Slot 1, the fallback, stays as it is."
		default:
			seal.Explain = "Slot 1, the fallback, is missing: seals a TOTP key to PCRs 0 and 7 alone into it, the code for a boot whose kernel changed unpredicted. Slot 0 stays as it is."
		}
		steps = append(steps, seal)
	}

	// The tree: every populated slot, and every dirty one, is a line of
	// its own; picking the line removes the slot whole, dirt included.
	lines := map[int]controlStep{}
	var order []int
	for i := range f.Status.Slots {
		s := f.Status.Slots[i]
		desc := "sealed to " + s.PCRs
		if s.Fallback {
			desc = "the fallback, " + desc
		}
		if strong == nil || s.Slot != strong.Slot {
			// The strong slot's phones and keyslots are its children's
			// lines; every other slot carries them on its own line.
			if len(s.Phones) > 0 {
				desc += ", phone " + quoted(s.Phones)
			}
			for _, name := range boundTo[s.Slot] {
				desc += ", " + name
			}
		}
		n := s.Slot
		lines[n] = controlStep{Key: fmt.Sprintf("slot:%d", n), Title: fmt.Sprintf("Slot %d", n),
			Done: desc, Optional: true, SelfConfirm: true,
			Explain: "Picking a slot deletes it whole: the TOTP key (its codes in the authenticator), the phones, the remote salt, the LUKS keyslots bound to it, the recovery blobs. Keyslots that are not tpm2-kira's - the recovery passphrase - stay.",
			Run:     func(c *controller) error { return c.runRemoveSlot(n) }}
		order = append(order, n)
	}
	for _, d := range f.Dirt {
		lines[d.Slot] = dirtyLine(d)
		order = append(order, d.Slot)
	}
	sort.Ints(order)
	for _, n := range order {
		steps = append(steps, lines[n])
		if strong == nil || n != strong.Slot {
			continue
		}
		// The options that build on the strong slot, under its line.
		attest := controlStep{Key: "attest", Child: true, Title: "Attestation by phone (Marify, Bluetooth LE)",
			Explain: "The phone checks the boot state against what it pinned and shows a code the machine must show too; it replaces Enter at the code screen.",
			Run:     (*controller).runAttest}
		switch {
		case f.Adapter == "":
			attest.Blocked = "no Bluetooth adapter on this machine"
		case f.AttestConf != "":
			attest.Blocked = controlConfigPath() + ": " + f.AttestConf
		case len(strong.Phones) > 0:
			attest.Done = "phone " + quoted(strong.Phones)
		}
		luksRemote := controlStep{Key: "luks-remote", Child: true, Title: "Disk key from password + remote salt (the phone)",
			Explain: "A LUKS keyslot whose key is derived from your password and the salt the phone hands back after it attested the boot: the disk needs the phone, this TPM in an approved boot, and your password.",
			Run:     func(c *controller) error { return c.runLuks(LuksModePasswordRemoteSalt) }}
		switch {
		case !luksDevices:
			luksRemote.Blocked = "no LUKS device found (root for the headers)"
		case attest.Done == "":
			luksRemote.Blocked = "needs the attestation by phone"
		case len(boundTo[strong.Slot]) > 0:
			luksRemote.Done = strings.Join(boundTo[strong.Slot], ", ")
		}
		steps = append(steps, attest, luksRemote)
	}

	// The keyslot from a typed salt: independent of the slots - no TPM is
	// in its key, no slot binding in its token, and deleting a slot leaves
	// it untouched. It coexists with the remote-salt keyslot: at boot the
	// phone's salt is tried first, the typed salt is the fallback.
	luksSalt := controlStep{Key: "luks-salt", Title: "Disk key from password + salt (hashpwd2)",
		Explain: "A LUKS keyslot whose key is derived at boot from a password and a salt you type (Argon2id, 1 GiB); the recovery passphrase stays in its own keyslot. Bound to no slot - deleting a slot leaves it untouched - and it coexists with the remote-salt keyslot, as the typed fallback when the phone is not there.",
		Run:     func(c *controller) error { return c.runLuks(LuksModePasswordSalt) }}
	switch {
	case !luksDevices:
		luksSalt.Blocked = "no LUKS device found (root for the headers)"
	case hasSalt:
		luksSalt.Done = "a keyslot is enrolled"
	}

	// The disk unlock's one prerequisite left: every device with a keyslot
	// of ours takes its key from tpm2-kira (the route). How the key is
	// made, the boot reads from the LUKS header itself - nothing is
	// configured. Greyed until a keyslot of ours exists.
	unlock := controlStep{Key: "unlock", Title: "Unlock at boot (the key's route, the initramfs)",
		Explain: "A device gets its key from tpm2-kira when its rd.luks.key= (crypttab on Debian) names tpm2-kira's socket; how the key is made, the boot reads from the device's own LUKS header.",
		Run:     (*controller).runUnlock}
	anyKeyslot := false
	var unrouted []string
	for _, d := range f.Status.Devices {
		if d.Error != "" {
			continue
		}
		for _, ks := range d.Keyslots {
			if ks.Token != nil {
				anyKeyslot = true
				if !f.Routed[d.Device] {
					unrouted = append(unrouted, d.Device)
				}
				break
			}
		}
	}
	switch {
	case !anyKeyslot && len(f.Status.Slots) == 0:
		unlock.Blocked = "no slot is sealed yet"
	case !anyKeyslot:
		unlock.Blocked = "needs a keyslot of tpm2-kira's (the remote salt under slot 0, or the typed salt)"
	case len(unrouted) == 0:
		unlock.Done = "the key routed"
	default:
		unlock.Explain += "\nOpen: " + strings.Join(unrouted, ", ") + " not routed through tpm2-kira."
	}

	return append(steps, luksSalt, unlock)
}

// runUnlock advises the route for the devices that lack it (the kernel
// command line and crypttab are the person's to change). How the key is
// made needs no setting: the boot reads it from the LUKS header itself.
func (c *controller) runUnlock() error {
	for _, d := range c.facts.Status.Devices {
		if d.Error != "" || c.facts.Routed[d.Device] {
			continue
		}
		for _, ks := range d.Keyslots {
			if ks.Token != nil {
				fmt.Fprint(c.out, RouteAdvice(d.Device))
				break
			}
		}
	}
	return nil
}

// ControlNeedsRoot is control's answer when it is not root: its screen,
// or a line without a terminal.
func ControlNeedsRoot() {
	text := "Everything control looks at and sets is root's: the TPM, the keys in /etc/tpm2-kira, the LUKS headers, the initramfs.\n\n    sudo tpm2-kira control"
	if !isTerminal(os.Stdin) {
		fmt.Fprintln(os.Stderr, "tpm2-kira control: root is needed - sudo tpm2-kira control")
		return
	}
	c := &controller{out: os.Stdout}
	fmt.Fprint(c.out, clearScreen)
	c.form(huh.NewNote().Title("[ KIRA ] control needs root").Description(noteText(text)).Next(true).NextLabel("Quit")).Run()
}

// header is the one line on top of every overview: the tag, the version,
// what this is. Printed once per screen, outside the form, so a redraw of
// the form cannot double it.
func (c *controller) header() string {
	v := AppVersion
	if v == "" {
		v = "unknown"
	}
	return fmt.Sprintf("%s control %s - the protections of this machine, step by step", kiraTag(tagYellow), v)
}

// Control runs the guided workflow.
func Control(o ControlOptions) error {
	c := &controller{o: o, out: o.Out}
	if c.out == nil {
		c.out = os.Stdout
	}
	c.tty = isTerminal(os.Stdin)
	// The overview judges the risks itself, in red on the status, so the
	// steps run without the commands' advisory warnings: nothing is said
	// twice. Run by hand, seal and reseal keep them.
	defer func(old bool) { AdvisoryWarnings = old }(AdvisoryWarnings)
	AdvisoryWarnings = false
	for {
		if c.tty { // the overview is a page of its own: what the last step printed was read before "back to the overview?"
			fmt.Fprint(c.out, clearScreen+"\n\033[2mLooking at this machine ...\033[0m\n")
		}
		c.facts = collectFacts(o.TPMPath, o.Debug)
		steps := c.steps()
		if !c.tty {
			c.show(steps)
			return nil // the analysis and the recommendation, for a script
		}
		fmt.Fprint(c.out, clearScreen+"\n"+c.header()+"\n\n")
		key, err := c.pick(steps)
		if err != nil || key == "" {
			c.leave(steps)
			return nil
		}
		var s controlStep
		for _, st := range steps {
			if st.Key == key {
				s = st
			}
		}
		if s.Done != "" && !s.SelfConfirm {
			again, err := c.confirm(s.Title+" is done", s.Done+". Run it again?")
			if err != nil || !again {
				continue
			}
		}
		fmt.Fprintf(c.out, "\n\033[1m%s\033[0m\n%s\n\n", s.Title, s.Explain)
		if err := s.Run(c); err != nil {
			fmt.Fprintf(c.out, "\n\033[0;31mNot done:\033[0m %v\n", err)
		} else {
			c.ran = true
		}
		// One button: whatever happened, the overview follows (Esc leaves).
		if err := c.form(huh.NewNote().Title("Back to the overview").Next(true).NextLabel("OK")).Run(); err != nil {
			c.leave(steps)
			return nil
		}
	}
}

// clearScreen is the terminal cleared, the cursor at the top.
const clearScreen = "\033[H\033[2J"

// The forms (charm.land/huh v2): the overview with the step to pick, a
// yes/no, a device. They render inline, so what a step prints stays on
// the screen above the next form. Esc or Ctrl-C leaves.

// theme is the base theme in this machine's colours, the same on a light
// and a dark background. (huh v2, charm.land: its bubbletea asks the
// terminal for the background colour inside the program, where the reply
// is read as a reply; v1 asked at process start and a reply that came a
// moment late was read by the form as keystrokes.)
func (c *controller) theme() huh.Theme {
	return huh.ThemeFunc(func(bool) *huh.Styles {
		t := huh.ThemeBase(true)
		yellow, grey := lipgloss.Color("3"), lipgloss.Color("8")
		t.Focused.Title = t.Focused.Title.Foreground(yellow).Bold(true)
		t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(yellow)
		t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(yellow).Bold(true)
		t.Focused.Description = t.Focused.Description.Foreground(lipgloss.Color("7"))
		t.Focused.ErrorMessage = t.Focused.ErrorMessage.Foreground(lipgloss.Color("1"))
		for _, s := range []*lipgloss.Style{&t.Help.Ellipsis, &t.Help.ShortKey, &t.Help.ShortDesc, &t.Help.ShortSeparator,
			&t.Help.FullKey, &t.Help.FullDesc, &t.Help.FullSeparator} {
			*s = lipgloss.NewStyle().Foreground(grey)
		}
		t.Blurred.Title, t.Blurred.Description = t.Focused.Title, t.Focused.Description
		return t
	})
}

func (c *controller) form(fields ...huh.Field) *huh.Form {
	km := huh.NewDefaultKeyMap()
	km.Select.Filter.SetEnabled(false) // a handful of entries: no filter
	return huh.NewForm(huh.NewGroup(fields...)).WithTheme(c.theme()).WithKeyMap(km).WithShowHelp(true).WithAccessible(os.Getenv("ACCESSIBLE") != "")
}

// pick is the overview: the facts as a note, the steps as a select with
// their state, the recommendation in the description. A blocked step
// cannot be picked; the reason is shown instead. "" is leave.
func (c *controller) pick(steps []controlStep) (string, error) {
	blocked := map[string]string{}
	var opts []huh.Option[string]
	for _, s := range steps {
		indent := ""
		if s.Child {
			indent = "   "
		}
		// The same colours as the status: red the dirty, green the done,
		// orange the open; the blocked grey. Only the mark is coloured,
		// so the selection's own styling stays readable.
		var label string
		switch {
		case s.Dirty != "":
			label = indent + bad("!") + " " + s.Title + "  - " + s.Dirty
		case s.Done != "":
			label = indent + good("✓") + " " + s.Title + "  - " + s.Done
		case s.Blocked != "":
			label = indent + "\033[0;90m-\033[0m " + s.Title + "  - " + s.Blocked
			blocked[s.Key] = s.Blocked
		default:
			label = indent + amber("•") + " " + s.Title
		}
		opts = append(opts, huh.NewOption(label, s.Key))
	}
	opts = append(opts, huh.NewOption("  Quit", ""))
	// The status, the recommendation and the notes are the note's, plain;
	// the select holds the selectable lines alone, so only they carry the
	// focused group's mark.
	head := "Every protection this machine can have is in place."
	if n := recommended(steps); n >= 0 {
		head = "Recommended next: " + steps[n].Title + "\n" + steps[n].Explain
	}
	if notes := c.facts.Status.Notes; len(notes) > 0 {
		head += "\n\nNotes:"
		for _, n := range notes {
			head += "\n- " + n
		}
	}
	// Quit is preselected, on entering and on every return to the
	// overview: Enter alone never runs a step, the recommendation is
	// named in the text and picked by hand.
	choice := ""
	err := c.form(
		huh.NewNote().Description(c.noteDescription()+"\n*Protections*\n"+noteText(head)),
		huh.NewSelect[string]().Options(opts...).Value(&choice).
			Validate(func(k string) error {
				if why, ok := blocked[k]; ok {
					return errors.New(why)
				}
				return nil
			}),
	).Run()
	if err != nil {
		return "", err
	}
	return choice, nil
}

func (c *controller) confirm(title, description string) (bool, error) {
	yes := false
	err := c.form(huh.NewConfirm().Title(title).Description(description).Affirmative("Yes").Negative("No").Value(&yes)).Run()
	return yes, err
}

func (c *controller) choose(title string, items []string) (int, error) {
	if len(items) == 0 {
		return 0, errors.New("nothing to choose from")
	}
	var opts []huh.Option[int]
	for i, it := range items {
		opts = append(opts, huh.NewOption(it, i))
	}
	n := 0
	if err := c.form(huh.NewSelect[int]().Title(title).Options(opts...).Value(&n)).Run(); err != nil {
		return 0, err
	}
	return n, nil
}

// noteDescription is the overview note: the status, judged line by line.
func (c *controller) noteDescription() string {
	return "*What this machine has*\n" + noteText(c.factsText())
}

// noteText is text for a note's description: huh's note reads \, _ and
// * as markup, and its wrapping drops the spaces a line begins with.
func noteText(s string) string {
	s = strings.NewReplacer(`\`, `\\`, "_", `\_`, "*", `\*`).Replace(s)
	return strings.ReplaceAll("\n"+s, "\n  ", "\n")[1:]
}

// The status is judged line by line: green is good, red is not good and
// says why - the risk in brackets. What is neither (plain information)
// stays uncoloured.
func good(s string) string  { return "\033[0;32m" + s + "\033[0m" }
func bad(s string) string   { return "\033[0;31m" + s + "\033[0m" }
func amber(s string) string { return "\033[0;33m" + s + "\033[0m" }

// factsText is "What this machine has", one line per fact, each marked
// green when it is as it should be and red with the risk in brackets
// when it is not.
func (c *controller) factsText() string {
	f := &c.facts
	var w strings.Builder
	switch {
	case f.TPMErr != "":
		fmt.Fprintf(&w, "  TPM         %s\n", bad(fmt.Sprintf("none usable (%s)", f.TPMErr)))
	case f.UseSHA1:
		fmt.Fprintf(&w, "  TPM         %s\n", bad(fmt.Sprintf("%s - %s; the SHA-1 bank is used (risk: SHA-1 collisions are practical, a measured boot can in principle be forged)", f.TPM, f.SHA1Why)))
	case f.LogSHA256:
		fmt.Fprintf(&w, "  TPM         %s\n", good(f.TPM+", SHA-256 bank and event log"))
	default:
		fmt.Fprintf(&w, "  TPM         %s, SHA-256 bank; no event log to read, the registers as they are\n", f.TPM)
	}
	if f.TPMErr == "" {
		switch {
		case f.EKBy != "":
			fmt.Fprintf(&w, "  Vendor      %s\n", good(f.EKBy+" vouches for the endorsement key"))
		default:
			phone := "a phone trusts it on first use, as it would a software TPM"
			if f.Phone {
				phone = "the enrolled phone pinned it on first use, as it would a software TPM"
			}
			fmt.Fprintf(&w, "  Vendor      %s\n", bad(fmt.Sprintf("none vouches for the endorsement key: %s (risk: %s)", f.EKNote, phone)))
		}
	}
	switch {
	case !f.SecureBoot.Known:
		fmt.Fprintf(&w, "  Secure Boot %s\n", bad("state unknown, no efivars (risk: whether PCR 7 attests an enforced policy is unknown)"))
	case f.SecureBoot.SetupMode:
		fmt.Fprintf(&w, "  Secure Boot %s\n", bad("Setup Mode (risk: any root user can replace the keys, PCR 7 attests a policy that can be rewritten)"))
	case f.SecureBoot.Enabled:
		fmt.Fprintf(&w, "  Secure Boot %s\n", good("enabled"))
	default:
		fmt.Fprintf(&w, "  Secure Boot %s\n", bad("disabled (risk: the boot loader and the kernel run unsigned, and PCR 7 records only that)"))
	}
	fmt.Fprintf(&w, "  Boot        %s: PCRs %s\n", f.PCRsWhy, f.PCRs)
	if f.TPMErr == "" {
		var parts []string
		for _, s := range f.Status.Slots {
			p := fmt.Sprintf("%d (%s)", s.Slot, s.PCRs)
			if s.Fallback {
				p = fmt.Sprintf("%d (%s, the fallback)", s.Slot, s.PCRs)
			}
			parts = append(parts, p)
		}
		switch weak := weakSlots(f); {
		case len(parts) == 0:
			fmt.Fprintln(&w, "  Slots       none sealed")
		case len(weak) > 0:
			fmt.Fprintf(&w, "  Slots       %s\n", bad(fmt.Sprintf("%s - slot %s leaves the kernel, the initrd or the command line unmeasured (risk: a replaced initrd or an edited command line still shows a valid code - reseal with 11u, or 8e,9e)",
				strings.Join(parts, ", "), joinInts(weak))))
		default:
			fmt.Fprintf(&w, "  Slots       %s\n", good(strings.Join(parts, ", ")))
		}
	}
	keyDesc := f.Keys
	if keyDesc == "" {
		keyDesc = "none yet (setup makes it)"
	}
	switch {
	case f.PINLoose: // a disclosed PIN is a risk whatever key the files describe
		fmt.Fprintf(&w, "  Key         %s\n", bad(fmt.Sprintf("%s (risk: %s holds the PIN, but other users can read it, or root does not own it - chown root:, chmod 600, consider a new PIN)", keyDesc, controlConfigPath())))
	case f.Keys == "":
		fmt.Fprintf(&w, "  Key         %s\n", keyDesc)
	default:
		fmt.Fprintf(&w, "  Key         %s\n", good(f.Keys))
	}
	switch {
	case f.Initramfs == "":
		fmt.Fprintf(&w, "  Initramfs   %s\n", bad("neither mkinitcpio nor initramfs-tools found (risk: no code screen at boot - no boot integration here)"))
	case f.HookState != "":
		fmt.Fprintf(&w, "  Initramfs   %s\n", bad(fmt.Sprintf("%s, but %s (risk: the next boot shows no code screen and serves no key)", f.Initramfs, f.HookState)))
	case f.Initramfs == "mkinitcpio":
		fmt.Fprintf(&w, "  Initramfs   %s\n", good("mkinitcpio, sd-tpm2-kira in HOOKS"))
	default:
		fmt.Fprintf(&w, "  Initramfs   %s\n", good(f.Initramfs))
	}
	if f.Adapter != "" {
		fmt.Fprintf(&w, "  Bluetooth   %s (attestation by phone possible)\n", f.Adapter)
	} else {
		fmt.Fprintln(&w, "  Bluetooth   no adapter: no attestation by phone")
	}
	switch {
	case f.Status.DevicesError != "":
		fmt.Fprintf(&w, "  LUKS        %s\n", f.Status.DevicesError)
	case len(f.Status.Devices) == 0:
		fmt.Fprintln(&w, "  LUKS        no encrypted device")
	default:
		for _, d := range f.Status.Devices {
			if d.Error != "" {
				fmt.Fprintf(&w, "  LUKS        %s: %s\n", d.Device, d.Error)
				continue
			}
			var parts []string
			for _, ks := range d.Keyslots {
				parts = append(parts, strconv.Itoa(ks.Keyslot)+" "+shortKeyslot(ks))
			}
			route := "not routed through tpm2-kira"
			if f.Routed[d.Device] {
				route = "key from tpm2-kira"
			}
			fmt.Fprintf(&w, "  LUKS        %s: keyslots %s; %s\n", d.Device, strings.Join(parts, ", "), route)
		}
	}
	return w.String()
}

func joinInts(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}

// recommended is the index of a dirty step - a half-gone slot comes before
// everything, since the protections around it cannot be judged - else of
// the first protection that can be done, or -1.
func recommended(steps []controlStep) int {
	for i, s := range steps {
		if s.Dirty != "" {
			return i
		}
	}
	for i, s := range steps {
		if !s.Optional && s.Done == "" && s.Blocked == "" {
			return i
		}
	}
	return -1
}

// show draws the one screen in plain text: the facts, the steps, the
// recommendation (a script's look, and the tests').
func (c *controller) show(steps []controlStep) {
	f := &c.facts
	w := c.out
	fmt.Fprintf(w, "\n%s\n\n", c.header())
	fmt.Fprintln(w, "\033[1mWhat this machine has\033[0m")
	fmt.Fprint(w, c.factsText())

	fmt.Fprintln(w, "\n\033[1mProtections\033[0m")
	next := recommended(steps)
	for i, s := range steps {
		indent := ""
		if s.Child {
			indent = "  "
		}
		fmt.Fprintf(w, "  %s %d  %s%s", s.marker(), i+1, indent, s.Title)
		switch {
		case s.Dirty != "":
			fmt.Fprintf(w, "  - %s", s.Dirty)
		case s.Done != "":
			fmt.Fprintf(w, "  - %s", s.Done)
		case s.Blocked != "":
			fmt.Fprintf(w, "  - %s", s.Blocked)
		}
		fmt.Fprintln(w)
	}
	if next >= 0 {
		fmt.Fprintf(w, "\n\033[1mRecommended next:\033[0m %d  %s\n  %s\n", next+1, steps[next].Title, steps[next].Explain)
	} else {
		fmt.Fprintln(w, "\n\033[1mEvery protection this machine can have is in place.\033[0m")
	}
	if notes := f.Status.Notes; len(notes) > 0 {
		fmt.Fprintln(w, "\n\033[1mNotes\033[0m")
		for _, n := range notes {
			fmt.Fprintf(w, "  - %s\n", n)
		}
	}
}

// leave says what is left to do by hand: the initramfs, the route.
func (c *controller) leave(steps []controlStep) {
	fmt.Fprintln(c.out)
	if c.ran {
		switch c.facts.Initramfs {
		case "mkinitcpio":
			fmt.Fprintln(c.out, "Rebuild the initramfs for the next boot to carry this: mkinitcpio -P")
		case "initramfs-tools":
			fmt.Fprintln(c.out, "Rebuild the initramfs for the next boot to carry this: update-initramfs -u")
		}
	}
	for _, d := range c.facts.Status.Devices {
		if d.Error != "" || c.facts.Routed[d.Device] {
			continue
		}
		for _, ks := range d.Keyslots {
			if ks.Token != nil {
				fmt.Fprintf(c.out, "%s has a keyslot of tpm2-kira's but is not routed through it: tpm2-kira luks route\n", d.Device)
				break
			}
		}
	}
}

// The steps' actions: the expert commands' functions, with the defaults
// the analysis settled.

func (c *controller) runSetup() error {
	if c.facts.Keys == "" {
		if err := Setup(SetupOptions{Debug: c.o.Debug}); err != nil {
			return err
		}
		k, err := LoadCheckedSigningPrivateKey(DefaultPrivateKeyPath)
		if err != nil {
			return err
		}
		if _, ok := YubiKeyDescription(k); !ok || !yubiKeyWantsPIN(k) {
			return nil
		}
	}
	return c.storePIN()
}

// storePIN asks the YubiKey's PIN, checks it on the token and stores it
// in control.conf for the unattended reseal.
func (c *controller) storePIN() error {
	key, err := LoadCheckedSigningPrivateKey(DefaultPrivateKeyPath)
	if err != nil {
		return err
	}
	desc, _ := YubiKeyDescription(key)
	pin := ""
	err = c.form(huh.NewInput().Title("PIN of " + desc).
		Description("Checked on the token, then stored in " + controlConfigPath() + " for the reseal the hooks run; readable by root alone, never in the initramfs.").
		EchoMode(huh.EchoModePassword).Value(&pin).
		Validate(func(s string) error {
			if s == "" {
				return errors.New("the PIN is empty")
			}
			return nil
		})).Run()
	if err != nil {
		return err
	}
	if err := VerifyYubiKeyPIN(key, pin); err != nil {
		return err
	}
	if err := setControlPIN(controlConfigPath(), pin); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "%s: %s stored, the file readable by root alone\n", controlConfigPath(), PINEnvVar)
	return nil
}

// runSeal seals what the standard pair lacks: both slots when none is
// there, else only the missing one, so the other's TOTP key (and so its
// authenticator entry) stays as it is. Slot 0's selection is the one the
// analysis evaluated, put up as a recommendation: the person acknowledges
// it, or gives custom PCRs instead (confirmPCRs).
func (c *controller) runSeal() error {
	algo := PCRHashAlgoSHA256
	if c.facts.UseSHA1 {
		algo = PCRHashAlgoSHA1
	}
	slot0, fallback := false, false
	for _, s := range c.facts.Status.Slots {
		slot0 = slot0 || s.Slot == 0
		fallback = fallback || s.Fallback
	}
	// Each slot's QR code gets a cleared screen of its own: the second
	// slot's output would otherwise scroll the first one's code away, and
	// it is shown this once. Between the two the person confirms the scan;
	// the last screen stays until "Back to the overview?" is answered.
	if slot0 && !fallback {
		fmt.Fprint(c.out, clearScreen)
		return SealFallback(c.o.TPMPath, "", "", algo, c.o.Debug)
	}
	sel, err := c.confirmPCRs()
	if err != nil {
		return err
	}
	fmt.Fprint(c.out, clearScreen)
	if err := Seal(c.o.TPMPath, sel, ResolveNVRAMIndex(0), "", "", c.o.Debug, algo, true); err != nil {
		return err
	}
	if fallback {
		return nil
	}
	if err := c.scanned("Slot 0"); err != nil {
		return err
	}
	fmt.Fprint(c.out, clearScreen)
	return SealFallback(c.o.TPMPath, "", "", algo, c.o.Debug)
}

// scanned holds a slot's QR code on the screen until the person says the
// authenticator has it.
func (c *controller) scanned(what string) error {
	return c.form(huh.NewNote().Title(what + " is sealed").
		Description("Scan the QR code above with your authenticator now: it is shown this once.").
		Next(true).NextLabel("It is in my authenticator")).Run()
}

// confirmPCRs puts the evaluated selection up as the recommendation for
// slot 0: acknowledged, it is sealed as evaluated; else the person gives
// custom PCRs, checked for form (what a selection protects, the overview
// judges afterwards). The fallback slot's selection is fixed by design.
func (c *controller) confirmPCRs() (string, error) {
	f := &c.facts
	const custom = "custom"
	choice := f.PCRs
	if err := c.form(huh.NewSelect[string]().Title("Slot 0 is sealed to these PCRs").
		Description("Evaluated for this machine: "+f.PCRsWhy+".").
		Options(
			huh.NewOption("The recommended "+f.PCRs, f.PCRs),
			huh.NewOption("Custom PCRs", custom),
		).Value(&choice)).Run(); err != nil {
		return "", err
	}
	if choice != custom {
		return choice, nil
	}
	pcrs := f.PCRs
	if err := c.form(huh.NewInput().Title("PCRs for slot 0").
		Description("Indices with a source each: none or r the register, e the event log, u the unified kernel image - such as 0e,2e,7e,11u (tpm2-kira help seal).").
		Value(&pcrs).
		Validate(func(s string) error {
			_, err := ParsePCRSpecs(s)
			return err
		})).Run(); err != nil {
		return "", err
	}
	return pcrs, nil
}

func (c *controller) runAttest() error {
	name, _ := os.Hostname()
	// The machine's own TPM was judged on the overview (the Vendor line),
	// and the phone checks it authoritatively at enrolment: no second
	// verdict and no ask here. The phone's key is still checked.
	return AttestEnrol(EnrolOptions{
		TPMPath: c.o.TPMPath, Name: name, SHA1: c.facts.UseSHA1, Timeout: 10 * time.Minute, Debug: c.o.Debug,
		VerifyTPM: CheckOff, VerifyPhone: CheckWarn,
	})
}

func (c *controller) runLuks(mode string) error {
	var devices []string
	for _, d := range c.facts.Status.Devices {
		if d.Error == "" {
			devices = append(devices, d.Device)
		}
	}
	dev := ""
	if len(devices) == 1 {
		dev = devices[0]
		if ok, err := c.confirm("The keyslot goes to "+dev+".", "Go on?"); err != nil || !ok {
			return errors.New("not confirmed")
		}
	} else {
		i, err := c.choose("Which device gets the keyslot?", devices)
		if err != nil {
			return err
		}
		dev = devices[i]
	}
	if err := LuksEnrol(LuksEnrolOptions{
		Device: dev, Mode: mode,
		Remote: FactorEnrolOptions{TPMPath: c.o.TPMPath, Timeout: 10 * time.Minute, AdapterWait: 30 * time.Second, Yes: true, Debug: c.o.Debug},
	}); err != nil {
		return err
	}
	return nil
}

// dirtyLine is a half-gone slot's line: red, recommended first, and
// picking it removes what is left.
func dirtyLine(d SlotContents) controlStep {
	n := d.Slot
	return controlStep{Key: fmt.Sprintf("slot:%d", n), Title: fmt.Sprintf("Slot %d", n),
		Dirty: "dirty: " + d.Remains() + " left", SelfConfirm: true,
		Explain: "A deletion stopped halfway, or a piece was taken by hand: picking the slot removes what is left of it.",
		Run:     func(c *controller) error { return c.runRemoveSlot(n) }}
}

// runInitramfs wires the boot integration. On mkinitcpio it shows the
// HOOKS line as it is and as it should read, and writes it when asked -
// the standing rule that control edits no file of the system has this one
// exception, asked for every time; editing by hand works just as well,
// and the step says how.
func (c *controller) runInitramfs() error {
	f := &c.facts
	switch {
	case f.Initramfs == "initramfs-tools":
		fmt.Fprintln(c.out, "The .deb installs the boot scripts; nothing is configured by hand here.")
		if f.HookState != "" {
			fmt.Fprintln(c.out, f.HookState)
		}
		return nil
	case f.Initramfs != "mkinitcpio":
		return errors.New("no initramfs system found")
	case !fileExists(mkinitcpioHook):
		return errors.New("the sd-tpm2-kira hook files are not installed: sudo make install-mkinitcpio, or the package; then run this step again")
	}
	file, oldLine, newLine, err := AdoptHookLine(mkinitcpioConf)
	if err != nil {
		return err
	}
	if oldLine == newLine {
		fmt.Fprintf(c.out, "sd-tpm2-kira is already in the HOOKS of %s.\n", file)
		return c.offerRebuild()
	}
	fmt.Fprintf(c.out, "The boot image is built from the HOOKS of %s. The line reads\n\n    %s\n\nand must carry sd-tpm2-kira next to sd-encrypt, so the code screen runs before\nthe passphrase prompt:\n\n    %s\n\nPut that line into the file yourself and rebuild (mkinitcpio -P) - or let this\nstep write it, which changes nothing else of the file.\n\n", file, oldLine, newLine)
	ok, err := c.confirm("Write the line into "+file+"?", "Only the HOOKS assignment changes; 'No' leaves the editing to you.")
	if err != nil || !ok {
		fmt.Fprintf(c.out, "Nothing was written. Put the line above into %s and rebuild (mkinitcpio -P).\n", file)
		return nil
	}
	file, line, err := AdoptHook(mkinitcpioConf)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "%s now reads: %s\n", file, line)
	c.ran = true // should the rebuild below be declined, leaving advises it
	return c.offerRebuild()
}

// offerRebuild proposes what belongs into the image before it is built -
// the Bluetooth modules, when an adapter is there, preselected and free to
// deselect - and runs mkinitcpio -P when asked.
func (c *controller) offerRebuild() error {
	if c.facts.Adapter != "" && !c.facts.BTAlways {
		ok, err := c.confirmYes("Pack Bluetooth into every boot image (~1.1 MB)?",
			"With "+c.facts.Adapter+" in the image from the start, enrolling and removing phones never changes it, and the first enrolment causes no \"changed\" verdict at the next boot. Deselect to keep the image lean: the hooks then add Bluetooth once a phone is enrolled, and that first rebuild shows \"changed\" once.")
		if err != nil {
			return err
		}
		if ok {
			if err := setAttestBluetooth(controlConfigPath(), "always"); err != nil {
				return err
			}
			fmt.Fprintf(c.out, "%s: TPM2_KIRA_ATTEST_BLUETOOTH=always\n", controlConfigPath())
			c.facts.BTAlways = true
			c.ran = true
		}
	}
	ok, err := c.confirmYes("Run mkinitcpio -P now?", "Builds every preset's image with the hook in; the output follows here.")
	if err != nil || !ok {
		fmt.Fprintln(c.out, "Not rebuilt: run mkinitcpio -P yourself before the next boot.")
		return nil
	}
	rebuild := exec.Command("mkinitcpio", "-P")
	rebuild.Stdout, rebuild.Stderr = c.out, c.out
	if err := rebuild.Run(); err != nil {
		return fmt.Errorf("mkinitcpio -P: %w", err)
	}
	c.ran = false // just rebuilt: nothing to advise on leaving
	return nil
}

// confirmYes is confirm with Yes preselected: a proposal to deselect.
func (c *controller) confirmYes(title, description string) (bool, error) {
	yes := true
	err := c.form(huh.NewConfirm().Title(title).Description(description).Affirmative("Yes").Negative("No").Value(&yes)).Run()
	return yes, err
}

// runRemoveSlot is control's one way to delete a slot, whole: the slot's
// own line in the tree runs it. What a failed part leaves behind shows as
// dirty on the overview until a run removes it.
func (c *controller) runRemoveSlot(slot int) error {
	f := &c.facts
	label := ""
	for _, s := range f.Status.Slots {
		if s.Slot != slot {
			continue
		}
		label = "sealed to " + s.PCRs
		if s.Fallback {
			label += " (the fallback)"
		}
		if len(s.Phones) > 0 {
			label += ", phone " + quoted(s.Phones)
		}
		if s.RemoteSalt {
			label += ", remote salt"
		}
		for _, d := range f.Status.Devices {
			for _, ks := range d.Keyslots {
				if ks.Token != nil && ks.Token.BoundTo(s.Slot) {
					label += fmt.Sprintf(", keyslot %d of %s", ks.Keyslot, d.Device)
				}
			}
		}
	}
	for _, d := range f.Dirt {
		if d.Slot == slot {
			label = "dirty: " + d.Remains() + " left"
		}
	}
	ok, err := c.confirm(fmt.Sprintf("Delete slot %d whole?", slot),
		"Gone for good: "+label+". The authenticator's code for it stops matching. Removing a LUKS keyslot asks for a remaining passphrase (the recovery one); keyslots that are not tpm2-kira's stay.")
	if err != nil || !ok {
		return errors.New("not confirmed")
	}
	err = DeleteSlot(DeleteSlotOptions{TPMPath: c.o.TPMPath, Slot: slot, Debug: c.o.Debug, Out: c.out})
	c.ran = true // parts may be gone even when the error says the rest is not
	return err
}

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}
