package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	In      io.Reader // the person's answers (tests); default stdin
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
	in    *bufio.Reader
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

	return []controlStep{keys, seal, attest, luksSalt, luksRemote}
}

// Control runs the guided workflow.
func Control(o ControlOptions) error {
	c := &controller{o: o, out: o.Out}
	if c.out == nil {
		c.out = os.Stdout
	}
	in := o.In
	if in == nil {
		in = os.Stdin
		c.tty = isTerminal(os.Stdin)
	}
	c.in = bufio.NewReader(in)
	if o.In != nil {
		c.tty = true
	}
	for {
		c.facts = collectFacts(o.TPMPath, o.Debug)
		steps := c.steps()
		c.show(steps)
		if !c.tty {
			return nil // the analysis and the recommendation, for a script
		}
		fmt.Fprint(c.out, "\nChoose a step by number, or q to leave: ")
		line, err := c.in.ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintln(c.out)
			return nil
		}
		line = strings.TrimSpace(line)
		if line == "" || line == "q" || line == "Q" {
			c.leave(steps)
			return nil
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 1 || n > len(steps) {
			continue
		}
		s := steps[n-1]
		if s.Blocked != "" {
			fmt.Fprintf(c.out, "\n%s: %s.\n", s.Title, s.Blocked)
			c.pause()
			continue
		}
		if s.Done != "" && !c.confirm(s.Title+" is done ("+s.Done+"). Run it again?") {
			continue
		}
		fmt.Fprintf(c.out, "\n\033[1m%s\033[0m\n%s\n\n", s.Title, s.Explain)
		if err := s.Run(c); err != nil {
			fmt.Fprintf(c.out, "\n\033[0;31mNot done:\033[0m %v\n", err)
		} else {
			c.ran = true
		}
		c.pause()
	}
}

// show draws the one screen: the facts, the steps, the recommendation.
func (c *controller) show(steps []controlStep) {
	f := &c.facts
	w := c.out
	if c.tty {
		fmt.Fprint(w, "\033[H\033[2J")
	}
	fmt.Fprintf(w, "%s control - the protections of this machine, step by step\n\n", kiraTag(tagYellow))

	fmt.Fprintln(w, "\033[1mWhat this machine has\033[0m")
	switch {
	case f.TPMErr != "":
		fmt.Fprintf(w, "  TPM         none usable (%s)\n", f.TPMErr)
	case f.UseSHA1:
		fmt.Fprintf(w, "  TPM         %s - no SHA-256 bank with a SHA-256 event log; the SHA-1 bank is used (--sha1), the weakness acknowledged\n", f.TPM)
	default:
		fmt.Fprintf(w, "  TPM         %s, SHA-256 bank and event log\n", f.TPM)
	}
	fmt.Fprintf(w, "  Boot        %s: PCRs %s\n", f.PCRsWhy, f.PCRs)
	if f.Initramfs != "" {
		fmt.Fprintf(w, "  Initramfs   %s\n", f.Initramfs)
	} else {
		fmt.Fprintln(w, "  Initramfs   neither mkinitcpio nor initramfs-tools found: no boot integration here")
	}
	if f.Adapter != "" {
		fmt.Fprintf(w, "  Bluetooth   %s (attestation by phone possible)\n", f.Adapter)
	} else {
		fmt.Fprintln(w, "  Bluetooth   no adapter: no attestation by phone")
	}
	switch {
	case f.Status.DevicesError != "":
		fmt.Fprintf(w, "  LUKS        %s\n", f.Status.DevicesError)
	case len(f.Status.Devices) == 0:
		fmt.Fprintln(w, "  LUKS        no encrypted device")
	default:
		for _, d := range f.Status.Devices {
			if d.Error != "" {
				fmt.Fprintf(w, "  LUKS        %s: %s\n", d.Device, d.Error)
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
			fmt.Fprintf(w, "  LUKS        %s: keyslots %s; %s\n", d.Device, strings.Join(parts, ", "), route)
		}
	}
	fmt.Fprintf(w, "  Unlock      mode %s\n", f.Status.UnlockMode)

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

func (c *controller) pause() {
	fmt.Fprint(c.out, "\nEnter to go on: ")
	c.in.ReadString('\n')
}

func (c *controller) confirm(q string) bool {
	fmt.Fprintf(c.out, "\n%s [y/N]: ", q)
	line, _ := c.in.ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}

// choose picks one of the items by number.
func (c *controller) choose(q string, items []string) (int, error) {
	fmt.Fprintln(c.out, q)
	for i, it := range items {
		fmt.Fprintf(c.out, "  %d  %s\n", i+1, it)
	}
	fmt.Fprint(c.out, "Number: ")
	line, _ := c.in.ReadString('\n')
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(items) {
		return 0, errors.New("no choice made")
	}
	return n - 1, nil
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
		if !c.confirm("The keyslot goes to " + dev + ". Go on?") {
			return errors.New("not confirmed")
		}
	} else {
		i, err := c.choose("Which device gets the keyslot?", devices)
		if err != nil {
			return err
		}
		dev = devices[i]
	}
	noConfig := false
	if mode == LuksModePasswordSalt && c.facts.Status.UnlockMode == UnlockPasswordRemoteSalt {
		// A typed-salt keyslot next to the phone's: the mode stays, the
		// typed salt is the fallback when the phone is not there.
		noConfig = true
	}
	return LuksEnrol(LuksEnrolOptions{
		Device: dev, Mode: mode, NoConfig: noConfig,
		Remote: FactorEnrolOptions{TPMPath: c.o.TPMPath, Timeout: 10 * time.Minute, AdapterWait: 30 * time.Second, Yes: true, Debug: c.o.Debug},
	})
}

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}
