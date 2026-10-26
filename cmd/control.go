package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/mrwiora/tpm2-kira/attest"
	"golang.org/x/sys/unix"
)

// 'tpm2-kira control' is the guided way through the protections, for a
// person rather than a script: it first looks at what the machine has (a
// TPM and its banks, the event log, how it booted, a Bluetooth adapter, the
// LUKS devices, the initramfs kind, the network interfaces), then at what
// is configured already (the keys, the slots, the phone, the keyslots, the
// route, the vault, the boot image's network and SSH server). It guides in
// two steps. Step 1, the boot chain (control_bootchain.go): the
// prerequisites, each judged, then the sd-tpm2-kira hook in the image and
// the key's route on the kernel command line, and the image built with
// them. Step 2 (control_hub.go): what the machine combines, in submenus -
// the signing key with the TOTP codes, the phone, the ways the disk is
// unlocked, the network and SSH at boot - each option greyed with the
// reason while this machine cannot have it, and an option that needs
// another one control can set up offers it on the way. Everything control
// keeps is written into control.conf by control itself. The steps run the
// same functions the expert commands use: nothing here is a third way of
// doing things.

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
	PINStored  bool   // the PIN file holds the PIN, root's alone
	PINLoose   bool   // the PIN file holds the PIN, but others can read it
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
	// BTFirmware is the adapter's firmware as the image build will find it
	// (attest_initramfs.go); empty when no log named it and none is
	// remembered, so the image may not start the adapter.
	BTFirmware []string
	// BTAuthorize is the adapter's USB device when its bus lets no new
	// device in by itself, so the image needs a rule for it; nil when not.
	BTAuthorize *USBDevice
	// BootDebug is the boot settings' debug switch (bootsettings.go).
	BootDebug bool
	// Plan is what a build of the boot image now carries (bootplan.go).
	Plan *BootPlan
	// Pending are the reasons the boot image is out of date: a file of the
	// boot chain changed after it, or a part of the plan in use now is not
	// in it, or with other settings. Empty when the image is as it should
	// be. Control rebuilds it when it is left.
	Pending []string
	// Unused are the parts the image carries that nothing uses any more:
	// no reason to rebuild, the next build leaves them out.
	Unused []string
	// ImageErr says why the image's plan could not be read.
	ImageErr string
	// HookInstalled: the hook files of the initramfs system are in place.
	HookInstalled bool
	// Hooks is mkinitcpio's HOOKS as it would build with them.
	Hooks []string
	// NoRecovery are the LUKS devices without a keyslot that is not
	// tpm2-kira's: nothing to authorise an enrolment, no way in by hand.
	NoRecovery []string
	// EmptyPass are the keyslots that open with an empty passphrase,
	// "keyslot N of /dev/x"; EmptyPassErr says why the test did not run.
	EmptyPass    []string
	EmptyPassErr string
	Wired        int // wired network interfaces: the image's network needs one
	// SSHKeys is how many keys may log in at boot (-1: the file cannot be
	// read); SSHCA the SSH CA and its approval of the next boot. Both only
	// with SSH on.
	SSHKeys int
	SSHCA   sshCAState
	// SSHCAOtherKey: the SSH CA was made for another signing key than this
	// machine's, so reseal cannot approve it.
	SSHCAOtherKey bool
	// Vaults is each vault-enrolled slot's vault, asked now.
	Vaults   map[int]vaultCheck
	Capped   bool   // 'tpm2-kira cap' ran: this boot went through the code screen
	NewImage string // an image was rebuilt after this boot started; "" when not
	Routed   map[string]bool
	Route    []RouteFinding // the route's findings, for the step that writes the fixes
	Remote   RemoteConfig   // the boot image's network and SSH server (control.conf)
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
	if stored, loose := pinStored(pinFilePath()); stored {
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
	switch f.Initramfs {
	case "mkinitcpio":
		f.HookInstalled = mkinitcpioHookInstalled()
		f.Hooks = mkinitcpioHooks(mkinitcpioConf)
		if f.HookState == "" {
			f.Rebuild = rebuildPending(mkinitcpioConf)
		}
	case "initramfs-tools":
		f.HookInstalled = debianScriptInstalled()
	}
	for _, it := range physicalInterfaces() {
		if !it.Wireless {
			f.Wired++
		}
	}
	if m, _ := filepath.Glob("/sys/class/bluetooth/hci*"); len(m) > 0 {
		f.Adapter = filepath.Base(m[0])
		if deps := adapterDeps(f.Adapter); deps != nil {
			f.BTFirmware, f.BTAuthorize = deps.Firmware, deps.Authorize
		}
	}
	if cfg, err := LoadControlConfig(controlConfigPath()); err != nil {
		f.AttestConf = err.Error()
	} else {
		f.BTAlways = cfg.Attest.Bluetooth == "always"
		f.Remote = cfg.Remote
	}
	if f.Remote.SSH.On {
		f.SSHKeys = authorizedKeyCount(f.Remote.SSH.Assh.AuthorizedKeys)
	}

	f.Status = collectStatus(StatusOptions{TPMPath: tpmPath, ConfigPath: controlConfigPath(), Debug: debug})
	if f.TPMErr == "" {
		f.BootDebug = BootDebug(tpmPath)
	}
	if f.TPMErr == "" {
		f.Dirt = collectDirt(tpmPath, f.Status.Devices)
	}
	f.NoRecovery, f.EmptyPass, f.EmptyPassErr = recoveryFacts(f.Status.Devices)
	for _, s := range f.Status.Slots {
		if s.Vault != "" {
			if f.Vaults == nil {
				f.Vaults = map[int]vaultCheck{}
			}
			f.Vaults[s.Slot] = checkVault(s.Vault, s.VaultPin, s.VaultDevice, 5*time.Second)
		}
		f.Phone = f.Phone || s.Phones > 0
		f.Salt = f.Salt || s.RemoteSalt
		f.Capped = f.Capped || strings.Contains(s.GenState, "read-locked until reboot")
	}
	if f.Initramfs == "mkinitcpio" {
		f.NewImage = imageNewerThanBoot()
	}
	f.Plan = ReadBootPlan(PlanOptions{TPMPath: tpmPath, ConfigPath: controlConfigPath(), Debug: debug})
	f.SSHCA = f.Plan.in.SSHCA
	if f.SSHCA.CA != nil && f.Plan.in.TPMErr == "" {
		// The plan needs the CA to load; control the approvals of the
		// next boot's values too.
		f.SSHCA = readSSHCA(f.Plan.in.Config.Remote.SSH.Assh, tpmPath)
	}
	if f.SSHCA.CA != nil {
		if pub, err := LoadCheckedSigningPublicKey(DefaultPublicKeyPath); err == nil {
			f.SSHCAOtherKey = !samePublicKey(f.SSHCA.CA.AuthorityKey(), pub)
		}
	}
	if f.HookState == "" {
		f.Pending, f.Unused, f.ImageErr = imageState(f.Initramfs, f.Plan)
		if f.Rebuild != "" {
			f.Pending = append([]string{f.Rebuild}, f.Pending...)
		}
	}
	var devices []string
	for _, d := range f.Status.Devices {
		devices = append(devices, d.Device)
	}
	if len(devices) > 0 {
		if findings, err := RouteFindings(devices, nil, ""); err == nil {
			f.Route = findings
			for _, r := range findings {
				if r.Routed {
					f.Routed[r.Device] = true
				}
			}
		}
	}
	return f
}

// emptyPassSeen caches the empty-passphrase test of a keyslot for this
// run, by device and the keyslot's KDF salt - a new passphrase is a new
// salt - since each test is a full key derivation.
var emptyPassSeen = map[string]bool{}

// recoveryFacts judges the keyslots that are not tpm2-kira's: the devices
// that have none (no recovery passphrase), and those that open with an
// empty passphrase (an encrypted disk anybody opens).
func recoveryFacts(devices []LuksDeviceStatus) (noRecovery, empty []string, testErr string) {
	for _, d := range devices {
		if d.Error != "" {
			continue
		}
		recovery := false
		for _, ks := range d.Keyslots {
			if ks.Token != nil {
				continue
			}
			recovery = true
			key := d.Device + "|" + strconv.Itoa(ks.Keyslot) + "|" + ks.Salt
			opens, seen := emptyPassSeen[key]
			if !seen {
				var err error
				if opens, err = emptyPassphraseOpens(d.Device, ks.Keyslot); err != nil {
					testErr = err.Error()
					continue
				}
				emptyPassSeen[key] = opens
			}
			if opens {
				empty = append(empty, fmt.Sprintf("keyslot %d of %s", ks.Keyslot, d.Device))
			}
		}
		if !recovery {
			noRecovery = append(noRecovery, d.Device)
		}
	}
	return noRecovery, empty, testErr
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
	leaf := readEKCert(tpmDev, alg)
	by, err = attest.VerifyEKCertificate(pub, leaf, readEKCertChain(tpmDev, leaf), time.Now())
	if err != nil {
		return "", attest.EKCertNote(err)
	}
	return by, ""
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// A line of a screen: a step, an option of a submenu, or a submenu's
// line on step 2 (Menu). Every populated slot is a line of its own, and
// picking it removes the slot whole (SelfConfirm: the step asks before it
// acts, so no "run it again?" stands in front).
type controlStep struct {
	Key         string
	Title       string
	Explain     string // one or two lines on what it does
	Done        string // "" when not done; else how it is
	Blocked     string // "" when it can be done; else why not
	Dirty       string // "" when nothing is half-gone; else what and where
	Optional    bool   // not a protection: never the recommendation on its own
	Check       bool   // a wiring check: pickable only while it is open
	SelfConfirm bool   // Run confirms by itself; picked straight even when Done
	Menu        string // picking opens this screen instead of running anything
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
	// screen is what the overview shows: "chain" (step 1), "hub" (step 2)
	// or one of step 2's submenus (controlMenus).
	screen string
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

// Control runs the guided workflow: step 1 until the boot chain is in
// place, then step 2 and its submenus.
func Control(o ControlOptions) error {
	c := &controller{o: o, out: o.Out}
	if c.out == nil {
		c.out = os.Stdout
	}
	c.tty = isTerminal(os.Stdin)
	// The configuration file first: control writes it, and a step taken
	// on a file that does not load would be taken on defaults it never
	// chose (a network setting read as off). Everything wrong with it, then quit.
	if problems := controlConfigProblemsText(controlConfigPath()); problems != "" {
		fmt.Fprintf(c.out, "\n%s\n\n%s", c.header(), problems)
		return fmt.Errorf("%s does not load: fix it as shown, then start control again", controlConfigPath())
	}
	// The overview judges the risks itself, in red on the status, so the
	// steps run without the commands' advisory warnings: nothing is said
	// twice. Run by hand, seal and reseal keep them.
	defer func(old bool) { AdvisoryWarnings = old }(AdvisoryWarnings)
	AdvisoryWarnings = false
	for {
		if c.tty { // the overview is a page of its own: what the last step printed was read before "Continue"
			fmt.Fprint(c.out, clearScreen+"\n\033[2mLooking at this machine ...\033[0m\n")
		}
		c.facts = collectFacts(o.TPMPath, o.Debug)
		if c.screen == "" { // the start: step 1 until the boot chain is in place
			c.screen = "hub"
			if !chainDone(&c.facts) {
				c.screen = "chain"
			}
		}
		if !c.tty {
			c.show()
			return nil // the analysis and the recommendation, for a script
		}
		steps := c.screenSteps()
		fmt.Fprint(c.out, clearScreen+"\n"+c.header()+"\n  "+c.screenTitle()+"\n\n")
		key, err := c.pick(steps)
		sub := c.screen != "chain" && c.screen != "hub"
		if err != nil && sub { // Esc in a submenu: back to step 2
			c.screen = "hub"
			continue
		}
		if err != nil || key == "" {
			c.leave()
			return nil
		}
		var s controlStep
		for _, st := range steps {
			if st.Key == key {
				s = st
			}
		}
		if s.Menu != "" {
			c.screen = s.Menu
			continue
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
		}
		// One button: whatever happened, the screen follows (Esc leaves).
		if err := c.form(huh.NewNote().Title("Back to " + c.screenTitle()).Next(true).NextLabel("OK")).Run(); err != nil {
			c.leave()
			return nil
		}
	}
}

// screenSteps are the lines of the screen shown: step 1, step 2, or a
// submenu of step 2 with its way back.
func (c *controller) screenSteps() []controlStep {
	switch c.screen {
	case "chain":
		return c.chainSteps()
	case "hub":
		return c.hubSteps()
	}
	return append(c.menuSteps(c.screen), controlStep{Key: "back", Title: "Back to step 2", Optional: true, Menu: "hub"})
}

// screenTitle names the screen, under the header.
func (c *controller) screenTitle() string {
	switch c.screen {
	case "chain":
		return "Step 1 of 2: the boot chain"
	case "hub":
		return "Step 2 of 2: what this machine combines"
	}
	return "Step 2 of 2 > " + menuByKey(c.screen).title
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
	// Esc leaves a form as Ctrl-C does: in a submenu back to step 2, in a
	// step the step ends undone.
	km.Quit = key.NewBinding(key.WithKeys("ctrl+c", "esc"), key.WithHelp("esc", "leave"))
	return huh.NewForm(huh.NewGroup(fields...)).WithTheme(c.theme()).WithKeyMap(km).WithShowHelp(true).WithAccessible(os.Getenv("ACCESSIBLE") != "")
}

// pick is the overview: the facts as a note, the steps as a select with
// their state, the recommendation in the description. A blocked step
// cannot be picked; the reason is shown instead. "" is leave.
func (c *controller) pick(steps []controlStep) (string, error) {
	blocked := map[string]string{}
	var opts []huh.Option[string]
	for _, s := range steps {
		opts = append(opts, huh.NewOption(stepLabel(s), s.Key))
		switch {
		case s.Dirty != "":
		case s.Done != "" && s.Check:
			blocked[s.Key] = "in place: " + s.Done
		case s.Done == "" && s.Blocked != "":
			blocked[s.Key] = s.Blocked
		}
	}
	if c.screen == "chain" || c.screen == "hub" {
		opts = append(opts, huh.NewOption("  Quit", ""))
	}
	// Quit (in a submenu: Back) is preselected, on entering and on every
	// return: Enter alone never runs a step, the recommendation is named
	// in the text and picked by hand.
	choice := ""
	if c.screen != "chain" && c.screen != "hub" {
		choice = "back"
	}
	err := c.form(
		huh.NewNote().Description(c.screenNote(steps)),
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

// stepLabel is a step's line in the select. The same colours as the
// status: red the dirty, green the done, orange the open, the blocked
// grey. Only the mark is coloured, so the selection's own styling stays
// readable.
func stepLabel(s controlStep) string {
	indent := ""
	switch {
	case s.Dirty != "":
		return indent + bad("!") + " " + s.Title + "  - " + s.Dirty
	case s.Done != "":
		return indent + good("✓") + " " + s.Title + "  - " + s.Done
	case s.Blocked != "":
		return indent + "\033[0;90m-\033[0m " + s.Title + "  - " + s.Blocked
	case s.Key == "back":
		return "  " + s.Title
	case s.Menu != "":
		return indent + amber("•") + " " + s.Title + "  >"
	}
	return indent + amber("•") + " " + s.Title
}

// screenNote is the text above the select: on step 1 the prerequisites,
// on step 2 the machine's status, in a submenu what it is about; then the
// recommendation, and on step 2 the status' notes.
func (c *controller) screenNote(steps []controlStep) string {
	head := c.headline(steps)
	switch c.screen {
	case "chain":
		return "*Prerequisites*\n" + noteText(c.prereqText()) + "\n*The boot chain*\n" + noteText(head)
	case "hub":
		if notes := c.facts.Status.Notes; len(notes) > 0 {
			head += "\n\nNotes:"
			for _, n := range notes {
				head += "\n- " + n
			}
		}
		return c.noteDescription() + "\n*Step 2*\n" + noteText(head)
	}
	return noteText(menuByKey(c.screen).intro + "\n\n" + head)
}

// headline is the recommendation of a screen, or what the screen offers
// when nothing is recommended.
func (c *controller) headline(steps []controlStep) string {
	if n := recommended(steps); n >= 0 {
		return "Recommended next: " + steps[n].Title + "\n" + steps[n].Explain
	}
	switch c.screen {
	case "chain":
		if chainDone(&c.facts) {
			return "The boot chain is in place."
		}
		return "Nothing of the boot chain can be done yet: the prerequisites in red say what is missing."
	case "hub":
		return "Combine what fits this machine: each entry says what it needs, and what this machine cannot have is greyed with the reason."
	}
	return "Pick what to add or change; what is not possible here says why."
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
func good(s string) string { return "\033[0;32m" + s + "\033[0m" }
func bad(s string) string  { return "\033[0;31m" + s + "\033[0m" }

// warn is orange: not a risk, but nothing to leave as it is.
func warn(s string) string  { return "\033[0;33m" + s + "\033[0m" }
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
		fmt.Fprintf(&w, "  Key         %s\n", bad(fmt.Sprintf("%s (risk: %s holds the PIN, but other users can read it, or root does not own it - chown root:, chmod 600, consider a new PIN)", keyDesc, pinFilePath())))
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
	phone := f.planHas(PartPhone)
	switch {
	case f.Adapter != "" && len(f.BTFirmware) == 0 && phone:
		// It goes into the image: without its firmware the adapter does
		// not start in the initrd. An adapter that needs none is rare.
		fmt.Fprintf(&w, "  Bluetooth   %s\n", bad(f.Adapter+", no firmware for it seen loaded (risk: the image cannot start it at boot, unless it needs none - power off, boot, then rebuild)"))
	case f.Adapter != "" && len(f.BTFirmware) == 0:
		fmt.Fprintf(&w, "  Bluetooth   %s (attestation by phone possible; no firmware seen loaded yet)\n", f.Adapter)
	case f.Adapter != "":
		fmt.Fprintf(&w, "  Bluetooth   %s (attestation by phone possible; firmware %s)\n", f.Adapter, strings.Join(f.BTFirmware, ", "))
	default:
		fmt.Fprintln(&w, "  Bluetooth   no adapter: no attestation by phone")
	}
	// The adapter's USB bus may let no new device in by itself
	// (usbcore.authorized_default=0, as USBGuard sets it): then the image
	// carries the rule that lets the adapter in.
	if phone && f.BTAuthorize != nil {
		fmt.Fprintf(&w, "  Adapter at boot  let in by tpm2-kira's rule in the image (USB %s, %s:%s); the bus blocks new devices\n", f.BTAuthorize.Port, f.BTAuthorize.Vendor, f.BTAuthorize.Product)
	}
	if line := f.imageLine(); line != "" {
		fmt.Fprintf(&w, "  Boot image  %s\n", line)
	}
	if f.BootDebug {
		fmt.Fprintf(&w, "  Debug       %s\n", warn("on at boot: the code screen and the phone check log every step, on the console too"))
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
			for _, o := range d.Orphans {
				parts = append(parts, fmt.Sprintf("token %d (%s) without a keyslot", o.ID, o.Type))
			}
			route := "not routed through tpm2-kira"
			if f.Routed[d.Device] {
				route = "key from tpm2-kira"
			}
			fmt.Fprintf(&w, "  LUKS        %s: keyslots %s; %s\n", d.Device, strings.Join(parts, ", "), route)
		}
		if len(f.EmptyPass) > 0 {
			fmt.Fprintf(&w, "  Passphrase  %s\n", bad(strings.Join(f.EmptyPass, ", ")+" opens with an empty passphrase (risk: the disk is encrypted, yet anybody with it opens it - set a passphrase: cryptsetup luksChangeKey)"))
		}
	}
	if f.Remote.Net.Mode != "off" {
		fmt.Fprintf(&w, "  Boot network %s\n", strings.Join(RemoteStatusLines(f.Remote), "; "))
	}
	for _, s := range f.Status.Slots {
		if s.Vault == "" {
			continue
		}
		switch v := f.Vaults[s.Slot]; {
		case v.Knows:
			fmt.Fprintf(&w, "  Vault       %s\n", good(fmt.Sprintf("slot %d: %s answers, with the pinned key, and knows this device", s.Slot, s.Vault)))
		default:
			fmt.Fprintf(&w, "  Vault       %s\n", bad(fmt.Sprintf("slot %d: %s - %s (risk: the disk does not open unattended; the recovery passphrase is the way in)", s.Slot, s.Vault, v.Problem)))
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

// show draws both steps in plain text, the submenus' options under their
// line of step 2: the prerequisites, the boot chain, the status, what
// the machine combines, the recommendation (a script's look, and the
// tests').
func (c *controller) show() {
	f := &c.facts
	w := c.out
	line := func(s controlStep, indent string) {
		fmt.Fprintf(w, "  %s %s%s", s.marker(), indent, s.Title)
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
	fmt.Fprintf(w, "\n%s\n\n", c.header())
	fmt.Fprintln(w, "\033[1mStep 1 of 2: the boot chain\033[0m")
	fmt.Fprint(w, c.prereqText())
	fmt.Fprintln(w)
	chain := c.chainSteps()
	for _, s := range chain {
		line(s, "")
	}

	fmt.Fprintln(w, "\n\033[1mWhat this machine has\033[0m")
	fmt.Fprint(w, c.factsText())
	fmt.Fprintln(w, "\n\033[1mStep 2 of 2: what this machine combines\033[0m")
	hub := c.hubSteps()
	for _, s := range hub {
		line(s, "")
		if s.Menu != "" && s.Menu != "chain" {
			for _, o := range c.menuSteps(s.Menu) {
				line(o, "    ")
			}
		}
	}

	rec, why := "", ""
	if n := recommended(chain); !chainDone(f) && n >= 0 {
		rec, why = "Step 1 > "+chain[n].Title, chain[n].Explain
	} else if !chainDone(f) {
		rec, why = "Step 1", "Nothing of the boot chain can be done yet: the prerequisites in red say what is missing."
	} else if n := recommended(hub); n >= 0 {
		rec, why = hub[n].Title, hub[n].Explain
		if m := hub[n].Menu; m != "" && m != "chain" {
			if sub := c.menuSteps(m); recommended(sub) >= 0 {
				o := sub[recommended(sub)]
				rec, why = hub[n].Title+" > "+o.Title, o.Explain
			}
		}
	}
	if rec != "" {
		fmt.Fprintf(w, "\n\033[1mRecommended next:\033[0m %s\n  %s\n", rec, why)
	} else {
		fmt.Fprintln(w, "\n\033[1mNothing is recommended: the rest is what this machine may combine.\033[0m")
	}
	if notes := f.Status.Notes; len(notes) > 0 {
		fmt.Fprintln(w, "\n\033[1mNotes\033[0m")
		for _, n := range notes {
			fmt.Fprintf(w, "  - %s\n", n)
		}
	}
}

// leave is the end of control: the boot image is rebuilt here, once,
// when it is out of date - after everything is set up, as a build takes
// its time - then what is left to do by hand is said: the route.
func (c *controller) leave() {
	fmt.Fprintln(c.out)
	// What changed since the image was built is looked at, not which
	// steps ran: a fresh look, as the last step may have changed it.
	f := collectFacts(c.o.TPMPath, c.o.Debug)
	// The CA's slots are assh.conf's from here on: one taken away there
	// goes now, one added is approved below.
	if f.SSHCA.CA != nil && f.Remote.SSH.On {
		if changed, err := syncSSHCASlots(f.Remote.SSH.Assh); err != nil {
			fmt.Fprintf(c.out, "\033[0;31mThe SSH CA's slots:\033[0m %v\n", err)
		} else if changed {
			fmt.Fprintf(c.out, "The SSH CA's slots are %s's now.\n", sshConfPath(controlConfigPath()))
		}
	}
	if f.SSHCA.CA != nil && f.SSHCA.Values != nil && len(f.SSHCA.Unapproved()) > 0 {
		// Approved for the image as it is; a rebuild that follows has its
		// reseal hook approve the new image's values.
		if !c.tty {
			fmt.Fprintln(c.out, "The SSH CA needs the signing key's approval of the PCRs at the next boot: run tpm2-kira control at a terminal.")
		} else if err := c.approveSSHCA(); err != nil {
			fmt.Fprintf(c.out, "\033[0;31mNot approved:\033[0m %v - the image is built without SSH\n", err)
		} else {
			f = collectFacts(c.o.TPMPath, c.o.Debug)
		}
	}
	if len(f.Pending) > 0 {
		c.facts = f
		if c.tty {
			if err := c.offerRebuild(); err != nil {
				// A build hook of the machine's own (fsck without its
				// helper, say) fails the command after the image is
				// written: what counts is whether the image is new.
				if g := collectFacts(c.o.TPMPath, c.o.Debug); len(g.Pending) == 0 {
					fmt.Fprintf(c.out, "\033[0;33mThe image is built\033[0m, and carries what control set up; %v - an error of the build's own, above.\n", err)
				} else {
					fmt.Fprintf(c.out, "\033[0;31mNot rebuilt:\033[0m %v\n", err)
				}
			}
		} else {
			fmt.Fprintf(c.out, "Rebuild the initramfs for the next boot (%s): %s\n", rebuildCommand(f.Initramfs), strings.Join(f.Pending, "; "))
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

// rebuildCommand is the build of the image the next boot starts.
func rebuildCommand(initramfs string) string {
	if initramfs == "initramfs-tools" {
		return "update-initramfs -u"
	}
	return "mkinitcpio -P"
}

// The steps' actions: the expert commands' functions, with the defaults
// the analysis settled.

func (c *controller) runSetup() error {
	if c.facts.Keys != "" {
		k, err := LoadCheckedSigningPrivateKey(DefaultPrivateKeyPath)
		if err != nil {
			return err
		}
		if _, ok := YubiKeyDescription(k); !ok {
			// setup never replaces a signing key: a new one leaves every
			// slot and the SSH CA to another key's approvals.
			fmt.Fprintf(c.out, "The signing key is %s: nothing to set again. A new signing key: move %s away, then run this step - every slot is sealed again then, and the SSH CA made again.\n", c.facts.Keys, DefaultKeysDir)
			return nil
		}
	}
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
		Description("Checked on the token, then stored in " + pinFilePath() + " for the reseal the hooks run; readable by root alone, never in the initramfs.").
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
	if err := storePIN(pinFilePath(), pin); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "%s: the PIN stored, readable by root alone\n", pinFilePath())
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
	if err := AttestEnrol(EnrolOptions{
		TPMPath: c.o.TPMPath, Name: name, SHA1: c.facts.UseSHA1, Timeout: 10 * time.Minute, Debug: c.o.Debug,
		VerifyTPM: CheckOff, VerifyPhone: CheckWarn,
	}); err != nil {
		return err
	}
	// Without the prepacked Bluetooth the first phone brings the gate's
	// modules into the image: it is rebuilt when control is left, and the
	// next boot shows "changed" once on the phone. Prepacked, the image is
	// already whole.
	if !c.facts.BTAlways && !c.facts.Phone {
		fmt.Fprintln(c.out)
		fmt.Fprintln(c.out, "The first phone brings the Bluetooth gate into the image: it is rebuilt when")
		fmt.Fprintln(c.out, "you quit control, and the next boot shows \"changed\" once on the phone - check")
		fmt.Fprintln(c.out, "and approve it there.")
	}
	return nil
}

// runLuks enrols a keyslot of the mode - or, with one enrolled already,
// offers its removal: the step is a toggle, a second enrolment is not.
func (c *controller) runLuks(mode string) error {
	type enrolled struct {
		device string
		ks     KeyslotStatus
	}
	var have []enrolled
	for _, d := range c.facts.Status.Devices {
		for _, ks := range d.Keyslots {
			if ks.Token != nil && ks.Token.Mode == mode {
				have = append(have, enrolled{d.Device, ks})
			}
		}
	}
	if len(have) > 0 {
		i := 0
		if len(have) > 1 {
			var labels []string
			for _, e := range have {
				labels = append(labels, fmt.Sprintf("keyslot %d of %s", e.ks.Keyslot, e.device))
			}
			var err error
			if i, err = c.choose("Which keyslot goes?", labels); err != nil {
				return err
			}
		}
		e := have[i]
		ok, err := c.confirm(fmt.Sprintf("Remove keyslot %d of %s?", e.ks.Keyslot, e.device),
			"This keyslot is enrolled already ("+mode+"), so picking the step offers its removal. The key opens nothing afterwards; a remaining passphrase (the recovery one) authorises it, and enrolling anew is this same step.")
		if err != nil || !ok {
			return errors.New("not confirmed")
		}
		return LuksRemove(LuksRemoveOptions{Device: e.device, Keyslot: e.ks.Keyslot})
	}
	dev, err := c.pickDevice()
	if err != nil {
		return err
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

// offerRebuild says why the image is out of date and what a build puts
// in, and runs mkinitcpio -P (update-initramfs -u) when asked. It is
// control's one rebuild, when control is left: what changes the image in
// the steps only marks it out of date.
func (c *controller) offerRebuild() error {
	f := &c.facts
	name := rebuildCommand(f.Initramfs)
	fmt.Fprintf(c.out, "\033[1mThe boot image is out of date\033[0m\n")
	for _, p := range f.Pending {
		fmt.Fprintf(c.out, "  - %s\n", p)
	}
	fmt.Fprintf(c.out, "\n\033[1mWhat %s puts in\033[0m\n%s", name, planText(f.Plan))
	if f.planHas(PartPhone) {
		fmt.Fprintln(c.out, "\n"+btImagePlan(f.Adapter))
	}
	fmt.Fprintln(c.out)
	ok, err := c.confirmYes("Run "+name+" now?", "Builds the image the next boot starts; the output follows here.")
	if err != nil || !ok {
		fmt.Fprintf(c.out, "Not rebuilt: run %s yourself before the next boot.\n", name)
		return nil
	}
	argv := strings.Fields(name)
	rebuild := exec.Command(argv[0], argv[1:]...)
	rebuild.Stdout, rebuild.Stderr = c.out, c.out
	if err := rebuild.Run(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	fmt.Fprintln(c.out)
	fmt.Fprintln(c.out, "Reboot before enrolling a phone or a remote salt: the phone pins what the")
	fmt.Fprintln(c.out, "next boot shows, and the boot key answers only in a boot through this image.")
	return nil
}

// planText is the plan, a part per line: in, or out and why.
func planText(p *BootPlan) string {
	if p == nil {
		return ""
	}
	var b strings.Builder
	for _, pt := range p.Parts {
		if pt.On {
			fmt.Fprintf(&b, "  %s %-18s %s\n", good("✓"), pt.Title(), pt.Why)
		} else {
			fmt.Fprintf(&b, "  %s %-18s %s\n", "\033[0;90m-\033[0m", pt.Title(), "\033[0;90mout: "+pt.Why+"\033[0m")
		}
	}
	return b.String()
}

// planHas says whether the plan has the part in; false without a plan.
func (f *machineFacts) planHas(name string) bool {
	return f.Plan != nil && f.Plan.Has(name)
}

// imageLine is the status' line on the boot image: what it carries, or
// why it is rebuilt when control is left.
func (f *machineFacts) imageLine() string {
	if f.Plan == nil || f.Initramfs == "" || f.HookState != "" {
		return ""
	}
	var in []string
	for _, pt := range f.Plan.Parts {
		if pt.On {
			in = append(in, pt.Title())
		}
	}
	line := "carries " + strings.Join(in, ", ")
	if len(f.Unused) > 0 {
		line += "; the next build leaves out " + strings.Join(f.Unused, ", ") + ", which nothing uses any more"
	}
	switch {
	case len(f.Pending) > 0:
		return warn("rebuilt when you quit control: " + strings.Join(f.Pending, "; "))
	case f.ImageErr != "":
		return bad("its plan cannot be read (" + f.ImageErr + ")")
	}
	return good(line)
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
		if s.Phones > 0 {
			label += ", " + phonesText(s.Phones)
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
	return err
}

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// btImagePlan says what the sd-tpm2-kira hook puts into the image for the
// adapter - the same resolution it runs (attest_initramfs.go) - so it can
// be seen before the rebuild, and checked after it.
func btImagePlan(adapter string) string {
	var n int
	if _, err := fmt.Sscanf(adapter, "hci%d", &n); err != nil {
		return ""
	}
	deps, err := ResolveBTDeps("/sys", DefaultFirmwareDir, n, append(readKernelLog(""), journalBluetoothLines()...))
	if err != nil {
		return "The sd-tpm2-kira hook adds Bluetooth for " + adapter + ": " + err.Error()
	}
	rememberedFirmware(deps, DefaultFirmwareDir)
	var b strings.Builder
	fmt.Fprintf(&b, "The sd-tpm2-kira hook adds for %s (no edit of mkinitcpio.conf):\n", adapter)
	fmt.Fprintf(&b, "  modules:   %s (with their dependencies)\n", strings.Join(deps.Modules, " "))
	if len(deps.Firmware) > 0 {
		fmt.Fprintf(&b, "  firmware:  %s\n", strings.Join(deps.Firmware, " "))
	} else {
		fmt.Fprintf(&b, "  firmware:  none known - only what the modules declare\n")
	}
	fmt.Fprintf(&b, "  and:       /%s, the gate's unit tpm2-kira-attest.service, the signing public key", btModulesLoadConf)
	if deps.Authorize != nil {
		fmt.Fprintf(&b, "\n  and:       /%s, as the adapter's USB bus lets no new device in by itself:\n             %s", BTUdevRuleFile, deps.Authorize.UdevRule())
	}
	for _, w := range deps.Warnings {
		fmt.Fprintf(&b, "\n  NOTE: %s", w)
	}
	return b.String()
}

// imageHints is step 2's hint about the boot image: when it is current
// and this boot did not go through it, reboot - picking it does. An image
// out of date is rebuilt when control is left.
func (c *controller) imageHints() []controlStep {
	f := &c.facts
	if f.Initramfs == "" || !chainDone(f) || len(f.Pending) > 0 {
		return nil
	}
	if len(f.Status.Slots) == 0 || (f.Capped && f.NewImage == "") {
		return nil
	}
	why := "the boot image is ready, and this boot did not go through it"
	if f.NewImage != "" {
		why = f.NewImage
	}
	explain := "The device is ready to be rebooted: " + why + ". At the boot, compare the code on the screen with your authenticator, press Enter and type your passphrase."
	if f.Remote.SSH.On {
		explain += " With SSH at boot, the console says where to log in to do that remotely."
	}
	if !f.Phone {
		explain += " The phone and the disk keys that need it are enrolled afterwards, in a boot through the image."
	}
	return []controlStep{{Key: "reboot", Title: "Ready to reboot", Optional: true, SelfConfirm: true,
		Explain: explain + " Picking this reboots now, after a confirmation.",
		Run: func(c *controller) error {
			ok, err := c.confirm("Reboot now?", "Unsaved work in other programs is lost.")
			if err != nil || !ok {
				return errors.New("not rebooted")
			}
			return rebootNow()
		}}}
}

// rebootNow asks systemd to reboot; a var for the tests.
var rebootNow = func() error { return exec.Command("systemctl", "reboot").Run() }

// pendingRebuild lists the files of the boot chain a boot image is built
// from that changed after the image the next boot starts was built: the
// HOOKS, the command line, crypttab. What the image carries for the
// protections is told by its plan (imageState).
func pendingRebuild(initramfs string) []string {
	var inputs []string
	switch initramfs {
	case "mkinitcpio":
		inputs = append([]string{mkinitcpioConf, "/etc/kernel/cmdline", "/etc/crypttab.initramfs"}, globs("/etc/mkinitcpio.conf.d/*.conf", "/etc/cmdline.d/*.conf")...)
	case "initramfs-tools":
		inputs = append([]string{"/etc/crypttab", "/etc/initramfs-tools/initramfs.conf", "/etc/initramfs-tools/modules"}, globs("/etc/initramfs-tools/conf.d/*")...)
	default:
		return nil
	}
	var out []string
	for _, img := range bootImages() {
		ist, err := os.Stat(img)
		if err != nil {
			continue
		}
		for _, in := range inputs {
			if st, err := os.Stat(in); err == nil && st.ModTime().After(ist.ModTime()) {
				out = append(out, fmt.Sprintf("%s changed after %s was built", in, filepath.Base(img)))
			}
		}
	}
	return out
}

// imageState compares the image the next boot starts with the plan: the
// reasons to rebuild (the boot chain's files, the parts in use and not in
// it), the parts it carries for nothing, and why its plan cannot be read.
func imageState(initramfs string, plan *BootPlan) (pending, unused []string, problem string) {
	if initramfs == "" {
		return nil, nil, ""
	}
	pending = pendingRebuild(initramfs)
	for _, img := range bootImages() {
		parts, err := imagePlan(img)
		switch {
		case os.IsNotExist(err):
			pending = append(pending, filepath.Base(img)+" is not built yet")
			continue
		case err != nil:
			problem = err.Error()
			continue
		}
		pending = append(pending, planPending(plan, parts, img)...)
		unused = append(unused, planUnused(plan, parts)...)
	}
	return pending, unused, problem
}

func globs(patterns ...string) []string {
	var out []string
	for _, p := range patterns {
		m, _ := filepath.Glob(p)
		out = append(out, m...)
	}
	return out
}

// runBootDebug switches the boot settings' debug on or off.
func (c *controller) runBootDebug() error {
	on := !c.facts.BootDebug
	title := "Switch debug at boot on?"
	if !on {
		title = "Switch debug at boot off?"
	}
	ok, err := c.confirm(title, "Takes effect at the next boot; nothing is rebuilt.")
	if err != nil || !ok {
		return errors.New("not switched")
	}
	signer, err := LoadCheckedSigningPrivateKey(DefaultPrivateKeyPath)
	if err != nil {
		return err
	}
	if err := PrepareSigningKey(signer); err != nil {
		return err
	}
	tpmDev, err := OpenTPM(c.o.TPMPath)
	if err != nil {
		return err
	}
	defer tpmDev.Close()
	if err := WriteBootSettings(tpmDev, BootSettings{Debug: on}, signer); err != nil {
		return err
	}
	c.facts.BootDebug = on
	if on {
		fmt.Fprintln(c.out, "Debug at boot is on: from the next boot the code screen and the phone check log every step, on the console too.")
	} else {
		fmt.Fprintln(c.out, "Debug at boot is off.")
	}
	return nil
}

// controlConfigProblemsText says everything that keeps control.conf from
// loading - each line, its number and what to do - or "" when it loads
// (or is not there: the defaults). No line is quoted: a PIN line left
// over from before the PIN file held a secret.
func controlConfigProblemsText(path string) string {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		return fmt.Sprintf("%s cannot be read: %v\n", path, err)
	}
	problems := ControlConfigProblems(data)
	if len(problems) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\033[0;31m%s does not load\033[0m - control stops before anything is asked or written:\n\n", path)
	for _, p := range problems {
		fmt.Fprintf(&b, "  - %s\n", strings.TrimPrefix(p.Error(), "control.conf "))
	}
	fmt.Fprintf(&b, "\nEdit the file: remove or correct the lines above; every other line stays as\n"+
		"it is. Then start 'tpm2-kira control' again.\n\n")
	return b.String()
}
