package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
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
	LogSHA256  bool // the event log carries SHA-256 digests
	UseSHA1    bool // the only way on this machine
	PCRs       string
	PCRsWhy    string
	Keys       string // "" when setup has not run; else what the key is
	Initramfs  string // mkinitcpio, initramfs-tools, or ""
	Adapter    string // hciN, or ""
	AttestConf string // "" when attest.conf loads; else the reason

	Status StatusReport // the slots, the unlock mode, the LUKS devices, the notes
	Phone  bool         // a phone is enrolled for some slot
	Salt   bool         // a remote salt is enrolled for some slot
	Routed map[string]bool
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
	if d, err := EventDigestsForPCR(DefaultEventlogPath, 0, PCRHashAlgoSHA256); err == nil && len(d) > 0 {
		f.LogSHA256 = true
	}
	f.UseSHA1 = f.TPMErr == "" && !(f.SHA256Bank && f.LogSHA256) && f.SHA1Bank
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
			}
		}
	}
	switch {
	case fileExists("/etc/mkinitcpio.conf"):
		f.Initramfs = "mkinitcpio"
	case isDebianInitramfs():
		f.Initramfs = "initramfs-tools"
	}
	if m, _ := filepath.Glob("/sys/class/bluetooth/hci*"); len(m) > 0 {
		f.Adapter = filepath.Base(m[0])
	}
	if _, err := LoadAttestConfig(DefaultAttestConfigPath); err != nil {
		f.AttestConf = err.Error()
	}

	f.Status = collectStatus(StatusOptions{TPMPath: tpmPath, UnlockConfigPath: DefaultUnlockConfigPath, Debug: debug})
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

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// A step of the protection, as the menu shows it.
type controlStep struct {
	Key     string
	Title   string
	Explain string // one or two lines on what it does
	Done    string // "" when not done; else how it is
	Blocked string // "" when it can be done; else why not
	Run     func(c *controller) error
}

func (s controlStep) marker() string {
	switch {
	case s.Done != "":
		return "\033[0;32m[x]\033[0m"
	case s.Blocked != "":
		return "\033[0;90m[-]\033[0m"
	}
	return "[ ]"
}

// controller holds one run of the control command.
type controller struct {
	o     ControlOptions
	out   io.Writer
	tty   bool
	facts machineFacts
	ran   bool // a step ran: the initramfs is to be rebuilt
}

// steps are the protections in the order they build on each other, judged
// against the facts.
func (c *controller) steps() []controlStep {
	f := &c.facts
	var slot0 *StatusSlot
	fallback := false
	for i := range f.Status.Slots {
		if f.Status.Slots[i].Slot == 0 {
			slot0 = &f.Status.Slots[i]
		}
		fallback = fallback || f.Status.Slots[i].Fallback
	}
	hasSalt, hasRemote := false, false
	for _, d := range f.Status.Devices {
		for _, ks := range d.Keyslots {
			if ks.Token != nil && ks.Token.Mode == LuksModePasswordSalt {
				hasSalt = true
			}
			if ks.Token != nil && ks.Token.Mode == LuksModePasswordRemoteSalt {
				hasRemote = true
			}
		}
	}
	luksDevices := len(f.Status.Devices) > 0 && f.Status.DevicesError == ""

	keys := controlStep{Key: "setup", Title: "Signing key",
		Explain: "The key that approves boot states and authorises every write to the TPM: local files, or a key on a YubiKey.",
		Run:     (*controller).runSetup}
	if f.Keys != "" {
		keys.Done = f.Keys
	}

	seal := controlStep{Key: "seal", Title: "TOTP code at boot",
		Explain: "A TOTP key sealed in the TPM to this boot's state (" + f.PCRs + "), shown as a code at every boot - plus a fallback slot sealed to PCRs 0 and 7 alone. Pair both with your authenticator.",
		Run:     (*controller).runSeal}
	switch {
	case f.TPMErr != "":
		seal.Blocked = "no TPM: " + f.TPMErr
	case f.Keys == "":
		seal.Blocked = "needs the signing key"
	case slot0 != nil && fallback:
		seal.Done = "slot 0 sealed to " + slot0.PCRs + "; the fallback in place"
	case slot0 != nil:
		seal.Done = "slot 0 sealed to " + slot0.PCRs + " (no fallback slot: tpm2-kira seal --nvram 1 --pcrs 0e,7e)"
	}

	attest := controlStep{Key: "attest", Title: "Attestation by phone (Marify, Bluetooth LE)",
		Explain: "The phone checks the boot state against what it pinned and shows a code the machine must show too; it replaces Enter at the code screen.",
		Run:     (*controller).runAttest}
	switch {
	case seal.Done == "":
		attest.Blocked = "needs the TOTP seal"
	case f.Adapter == "":
		attest.Blocked = "no Bluetooth adapter on this machine"
	case f.AttestConf != "":
		attest.Blocked = DefaultAttestConfigPath + ": " + f.AttestConf
	case f.Phone:
		attest.Done = "a phone is enrolled"
	}

	luksSalt := controlStep{Key: "luks-salt", Title: "Disk key from password + salt (hashpwd2)",
		Explain: "A LUKS keyslot whose key is derived at boot from a password and a salt you type (Argon2id, 1 GiB); the recovery passphrase stays in its own keyslot.",
		Run:     func(c *controller) error { return c.runLuks(LuksModePasswordSalt) }}
	switch {
	case !luksDevices:
		luksSalt.Blocked = "no LUKS device found (root for the headers)"
	case hasSalt:
		luksSalt.Done = "a keyslot is enrolled"
	}

	luksRemote := controlStep{Key: "luks-remote", Title: "Disk key from password + remote salt (the phone)",
		Explain: "As above, but the salt is kept by the phone and handed back only after it attested the boot: the disk needs the phone, this TPM in an approved boot, and your password.",
		Run:     func(c *controller) error { return c.runLuks(LuksModePasswordRemoteSalt) }}
	switch {
	case !luksDevices:
		luksRemote.Blocked = "no LUKS device found (root for the headers)"
	case attest.Done == "":
		luksRemote.Blocked = "needs the attestation by phone"
	case hasRemote:
		luksRemote.Done = "a keyslot is enrolled; unlock mode " + f.Status.UnlockMode
	}

	// The prerequisites of the disk unlock, checked together: the mode in
	// unlock.conf fits the keyslots, and every device with a keyslot of
	// ours takes its key from tpm2-kira. Control sets the mode (the
	// commands touch no configuration file); the route it advises.
	unlock := controlStep{Key: "unlock", Title: "Unlock at boot (unlock.conf, the key's route, the initramfs)",
		Explain: "The boot derives the key only in the mode set in " + DefaultUnlockConfigPath + ", and a device gets it only when its rd.luks.key= (crypttab on Debian) names tpm2-kira's socket.",
		Run:     (*controller).runUnlock}
	wanted := c.wantedUnlockMode()
	var unrouted []string
	for _, d := range f.Status.Devices {
		if d.Error != "" || f.Routed[d.Device] {
			continue
		}
		for _, ks := range d.Keyslots {
			if ks.Token != nil {
				unrouted = append(unrouted, d.Device)
				break
			}
		}
	}
	switch {
	case wanted == "":
		unlock.Blocked = "needs a keyslot of tpm2-kira's"
	case f.Status.UnlockMode == wanted && len(unrouted) == 0:
		unlock.Done = "mode " + wanted + "; the key routed"
	default:
		var open []string
		if f.Status.UnlockMode != wanted {
			open = append(open, "TPM2_KIRA_UNLOCK="+wanted+" (now "+f.Status.UnlockMode+")")
		}
		if len(unrouted) > 0 {
			open = append(open, strings.Join(unrouted, ", ")+" not routed through tpm2-kira")
		}
		unlock.Explain += "\nOpen: " + strings.Join(open, "; ") + "."
	}

	return []controlStep{keys, seal, attest, luksSalt, luksRemote, unlock}
}

// wantedUnlockMode is the mode the keyslots call for: the phone's when a
// remote-salt keyslot exists (a typed-salt one next to it is the fallback),
// else the typed salt's; "" without a keyslot of ours.
func (c *controller) wantedUnlockMode() string {
	wanted := ""
	for _, d := range c.facts.Status.Devices {
		for _, ks := range d.Keyslots {
			if ks.Token == nil {
				continue
			}
			if ks.Token.Mode == LuksModePasswordRemoteSalt {
				return UnlockPasswordRemoteSalt
			}
			if ks.Token.Mode == LuksModePasswordSalt {
				wanted = UnlockPasswordSalt
			}
		}
	}
	return wanted
}

// setMode sets the mode in unlock.conf when it differs, and says so.
func (c *controller) setMode(mode string) error {
	if c.facts.Status.UnlockMode == mode {
		return nil
	}
	if err := setUnlockMode(DefaultUnlockConfigPath, mode); err != nil {
		return fmt.Errorf("the unlock mode is not set: %w", err)
	}
	fmt.Fprintf(c.out, "%s: TPM2_KIRA_UNLOCK=%s\n", DefaultUnlockConfigPath, mode)
	c.facts.Status.UnlockMode = mode
	c.ran = true
	return nil
}

// runUnlock sets the mode the keyslots call for and advises the route for
// the devices that lack it (the kernel command line and crypttab are the
// person's to change).
func (c *controller) runUnlock() error {
	if err := c.setMode(c.wantedUnlockMode()); err != nil {
		return err
	}
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
	c.form(huh.NewNote().Title("[ KIRA ] control needs root").Description(noteText(text)).Next(true).NextLabel("Leave")).Run()
}

// Control runs the guided workflow.
func Control(o ControlOptions) error {
	c := &controller{o: o, out: o.Out}
	if c.out == nil {
		c.out = os.Stdout
	}
	c.tty = isTerminal(os.Stdin)
	for {
		if c.tty { // the overview is a page of its own: what the last step printed was read before "back to the overview?"
			fmt.Fprint(c.out, clearScreen+"\033[2mLooking at this machine ...\033[0m\n")
		}
		c.facts = collectFacts(o.TPMPath, o.Debug)
		steps := c.steps()
		if !c.tty {
			c.show(steps)
			return nil // the analysis and the recommendation, for a script
		}
		fmt.Fprint(c.out, clearScreen)
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
		if s.Done != "" {
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
		if _, err := c.confirm("Back to the overview?", ""); err != nil {
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
		var label string
		switch {
		case s.Done != "":
			label = "✓ " + s.Title + "  - " + s.Done
		case s.Blocked != "":
			label = "- " + s.Title + "  - " + s.Blocked
			blocked[s.Key] = s.Blocked
		default:
			label = "  " + s.Title
		}
		opts = append(opts, huh.NewOption(label, s.Key))
	}
	opts = append(opts, huh.NewOption("  Leave", ""))
	desc := "Every protection this machine can have is in place."
	initial := ""
	if n := recommended(steps); n >= 0 {
		desc = "Recommended next: " + steps[n].Title + "\n" + steps[n].Explain
		initial = steps[n].Key
	}
	if notes := c.facts.Status.Notes; len(notes) > 0 {
		desc += "\n\nNotes:"
		for _, n := range notes {
			desc += "\n- " + n
		}
	}
	choice := initial
	err := c.form(
		huh.NewNote().Title("[ KIRA ] control - the protections of this machine, step by step").Description("*What this machine has*\n"+noteText(c.factsText())),
		huh.NewSelect[string]().Title("Protections").Description(desc).Options(opts...).Value(&choice).
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

// noteText is text for a note's description: huh's note reads \, _ and
// * as markup, and its wrapping drops the spaces a line begins with.
func noteText(s string) string {
	s = strings.NewReplacer(`\`, `\\`, "_", `\_`, "*", `\*`).Replace(s)
	return strings.ReplaceAll("\n"+s, "\n  ", "\n")[1:]
}

// factsText is "What this machine has", one line per fact.
func (c *controller) factsText() string {
	f := &c.facts
	var w strings.Builder
	switch {
	case f.TPMErr != "":
		fmt.Fprintf(&w, "  TPM         none usable (%s)\n", f.TPMErr)
	case f.UseSHA1:
		fmt.Fprintf(&w, "  TPM         %s - no SHA-256 bank with a SHA-256 event log; the SHA-1 bank is used (--sha1), the weakness acknowledged\n", f.TPM)
	default:
		fmt.Fprintf(&w, "  TPM         %s, SHA-256 bank and event log\n", f.TPM)
	}
	fmt.Fprintf(&w, "  Boot        %s: PCRs %s\n", f.PCRsWhy, f.PCRs)
	if f.Initramfs != "" {
		fmt.Fprintf(&w, "  Initramfs   %s\n", f.Initramfs)
	} else {
		fmt.Fprintln(&w, "  Initramfs   neither mkinitcpio nor initramfs-tools found: no boot integration here")
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
	fmt.Fprintf(&w, "  Unlock      mode %s\n", f.Status.UnlockMode)
	return w.String()
}

// recommended is the index of the first step that can be done, or -1.
func recommended(steps []controlStep) int {
	for i, s := range steps {
		if s.Done == "" && s.Blocked == "" {
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
	fmt.Fprintf(w, "%s control - the protections of this machine, step by step\n\n", kiraTag(tagYellow))
	fmt.Fprintln(w, "\033[1mWhat this machine has\033[0m")
	fmt.Fprint(w, c.factsText())

	fmt.Fprintln(w, "\n\033[1mProtections\033[0m")
	next := -1
	for i, s := range steps {
		fmt.Fprintf(w, "  %s %d  %s", s.marker(), i+1, s.Title)
		switch {
		case s.Done != "":
			fmt.Fprintf(w, "  - %s", s.Done)
		case s.Blocked != "":
			fmt.Fprintf(w, "  - %s", s.Blocked)
		default:
			if next < 0 {
				next = i
			}
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
	return Setup(SetupOptions{Debug: c.o.Debug})
}

func (c *controller) runSeal() error {
	algo := PCRHashAlgoSHA256
	if c.facts.UseSHA1 {
		algo = PCRHashAlgoSHA1
	}
	return SealDefaults(c.o.TPMPath, "", "", algo, c.o.Debug)
}

func (c *controller) runAttest() error {
	name, _ := os.Hostname()
	return AttestEnrol(EnrolOptions{
		TPMPath: c.o.TPMPath, Name: name, SHA1: c.facts.UseSHA1, Timeout: 10 * time.Minute, Debug: c.o.Debug,
		VerifyTPM: CheckWarn, VerifyPhone: CheckWarn,
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
	// The mode in unlock.conf is control's to set. A typed-salt keyslot
	// next to the phone's leaves the mode: the typed salt is the fallback
	// when the phone is not there.
	if mode == LuksModePasswordSalt && c.facts.Status.UnlockMode == UnlockPasswordRemoteSalt {
		return nil
	}
	return c.setMode(mode)
}

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}
