package admin

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Step 1 of control, the boot chain: what tpm2-kira needs of the machine
// to be in its boot at all - the prerequisites, each judged on one line -
// and the two edits that put it there, each asked for: the sd-tpm2-kira
// hook in the HOOKS of mkinitcpio.conf, and the key's route on the kernel
// command line (crypttab on Debian). Step 2 opens when the chain is in
// place; the image is built once, when control is left.

// prereq is one line of the prerequisites: met, not met (red, with what
// to do or the risk), or plain information.
type prereq struct {
	state int // prereqMet, prereqNot, prereqInfo
	text  string
}

const (
	prereqMet = iota
	prereqNot
	prereqInfo
)

// prereqs are the boot chain's prerequisites as this machine meets them.
func (c *controller) prereqs() []prereq {
	f := &c.facts
	var out []prereq
	add := func(state int, format string, a ...any) {
		out = append(out, prereq{state, fmt.Sprintf(format, a...)})
	}
	switch {
	case f.TPMErr != "":
		add(prereqInfo, "TPM: none usable (%s) - the disk unlock works without one; the codes, the phone and the vault need it", f.TPMErr)
	case f.UseSHA1:
		add(prereqNot, "TPM: %s, %s - the SHA-1 bank is used (risk: SHA-1 collisions are practical)", f.TPM, f.SHA1Why)
	default:
		add(prereqMet, "TPM: %s, SHA-256 bank", f.TPM)
	}
	switch f.Initramfs {
	case "":
		add(prereqNot, "Initramfs: neither mkinitcpio nor initramfs-tools found - no boot integration here")
	default:
		add(prereqMet, "Initramfs: %s", f.Initramfs)
	}
	switch {
	case f.Initramfs == "":
	case !f.HookInstalled:
		add(prereqNot, "Boot integration: %s", f.HookState)
	default:
		add(prereqMet, "Boot integration: tpm2-kira's %s files are installed", map[string]string{"mkinitcpio": "hook", "initramfs-tools": "boot script"}[f.Initramfs])
	}
	if f.Initramfs == "mkinitcpio" {
		switch {
		case !slices.Contains(f.Hooks, "systemd"):
			add(prereqNot, "systemd in the initrd: HOOKS lack systemd - tpm2-kira runs in a systemd-based initramfs (systemd, sd-encrypt)")
		case !slices.Contains(f.Hooks, "sd-encrypt") && len(f.Status.Devices) > 0:
			add(prereqNot, "systemd in the initrd: HOOKS lack sd-encrypt - nothing opens the LUKS volumes at boot")
		default:
			add(prereqMet, "systemd in the initrd: systemd and sd-encrypt in HOOKS")
		}
	}
	switch {
	case f.Status.DevicesError != "":
		add(prereqNot, "LUKS: %s", f.Status.DevicesError)
	case len(f.Status.Devices) == 0:
		add(prereqInfo, "LUKS: no encrypted device - the TOTP codes at boot, but no disk key")
	default:
		var names []string
		for _, d := range f.Status.Devices {
			names = append(names, d.Device)
		}
		add(prereqMet, "LUKS: %s", strings.Join(names, ", "))
		if len(f.NoRecovery) > 0 {
			add(prereqNot, "Recovery passphrase: none on %s - every keyslot is tpm2-kira's, so the operating system's own prompt, the last way in when tpm2-kira itself fails, opens nothing (cryptsetup luksAddKey)", strings.Join(f.NoRecovery, ", "))
		} else {
			add(prereqMet, "Recovery passphrase: a keyslot that is not tpm2-kira's on every device")
		}
		switch {
		case len(f.EmptyPass) > 0:
			add(prereqNot, "Passphrase: %s opens with an empty passphrase (risk: anybody with the disk opens it - set one: cryptsetup luksChangeKey --key-slot N DEVICE, Enter at the old one)", strings.Join(f.EmptyPass, ", "))
		case f.EmptyPassErr != "":
			add(prereqInfo, "Passphrase: not tested for being empty (%s)", f.EmptyPassErr)
		default:
			add(prereqMet, "Passphrase: no keyslot opens with an empty one")
		}
	}
	switch {
	case !f.SecureBoot.Known:
		add(prereqInfo, "Secure Boot: state unknown, no efivars")
	case f.SecureBoot.SetupMode:
		add(prereqInfo, "Secure Boot: Setup Mode (risk on step 2's status)")
	case f.SecureBoot.Enabled:
		add(prereqMet, "Secure Boot: enabled")
	default:
		add(prereqInfo, "Secure Boot: disabled (risk on step 2's status)")
	}
	return out
}

// prereqText is the prerequisites, one line each, with a summary.
func (c *controller) prereqText() string {
	var b strings.Builder
	open := 0
	for _, p := range c.prereqs() {
		switch p.state {
		case prereqMet:
			fmt.Fprintf(&b, "  %s %s\n", good("✓"), p.text)
		case prereqNot:
			open++
			fmt.Fprintf(&b, "  %s %s\n", bad("✗"), bad(p.text))
		default:
			fmt.Fprintf(&b, "  %s %s\n", amber("•"), p.text)
		}
	}
	if open == 0 {
		fmt.Fprintf(&b, "  %s\n", good("All prerequisites are met."))
	} else {
		fmt.Fprintf(&b, "  %s\n", bad(fmt.Sprintf("%d not met: the steps that need them say so.", open)))
	}
	return b.String()
}

// bootStep is the hook in the image's HOOKS (mkinitcpio), or the check
// that the boot scripts are installed (initramfs-tools).
func (c *controller) bootStep() controlStep {
	f := &c.facts
	boot := controlStep{Key: "initramfs", Check: true, Run: (*controller).runInitramfs}
	switch f.Initramfs {
	case "mkinitcpio":
		boot.Title = "mkinitcpio adoption"
		switch {
		case !f.HookInstalled:
			boot.Blocked = f.HookState
		case !slices.Contains(f.Hooks, "systemd"):
			boot.Blocked = "the initramfs is not systemd-based (HOOKS lack systemd)"
		case f.HookState != "":
			boot.Explain = "The code screen, the gate and the key provider enter the boot image through the sd-tpm2-kira hook: " + mkinitcpioConf + " must carry it in HOOKS, next to sd-encrypt. The step shows the line as it should read and writes it when you say so - editing the file yourself works just as well."
		default:
			boot.Done = "sd-tpm2-kira in HOOKS of " + mkinitcpioConf
		}
	case "initramfs-tools":
		boot.Title = "initramfs-tools integration"
		if f.HookState == "" {
			boot.Done = "the boot scripts are in place"
		} else {
			boot.Blocked = f.HookState
		}
	default:
		boot.Title = "Initramfs integration"
		boot.Blocked = "neither mkinitcpio nor initramfs-tools found: no code screen at boot"
	}
	return boot
}

// routeStep is the key's route: systemd-cryptsetup takes a volume's key
// from tpm2-kira only where rd.luks.key= names the socket (keyscript= in
// crypttab on Debian). Blocked without a LUKS device: then the chain is
// the hook alone.
func (c *controller) routeStep() controlStep {
	f := &c.facts
	route := controlStep{Key: "route", Title: "Kernel command line adoption (the key's route)", Check: true,
		Explain: "systemd-cryptsetup takes a volume's key from tpm2-kira when its rd.luks.key= names the socket. The step shows each line as it should read and writes it when you say so - editing the file yourself works just as well. How the key is made, the boot reads from the volume's own LUKS header.",
		Run:     (*controller).runRoute}
	if f.Initramfs == "initramfs-tools" {
		route.Title = "crypttab adoption (the key's route)"
		route.Explain = "cryptsetup takes a volume's key from tpm2-kira when its crypttab line names tpm2-kira's keyscript. The step shows each line as it should read and writes it when you say so - editing the file yourself works just as well."
	}
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
	case len(f.Status.Devices) == 0 || f.Status.DevicesError != "":
		route.Blocked = "no LUKS device found: nothing to route"
	case len(unrouted) > 0:
		route.Explain += "\nOpen: " + strings.Join(unrouted, ", ") + " not routed through tpm2-kira."
	case routeResolved(f):
		var routed []string
		for _, d := range f.Status.Devices {
			if f.Routed[d.Device] {
				routed = append(routed, d.Device)
			}
		}
		route.Done = "the key routed for " + strings.Join(routed, ", ")
	}
	return route
}

// routeResolved says whether the key's route needs nothing: something is
// routed, and no device with a keyslot of ours is not.
func routeResolved(f *machineFacts) bool {
	if len(f.Status.Devices) == 0 || f.Status.DevicesError != "" {
		return false
	}
	any := false
	for _, routed := range f.Routed {
		any = any || routed
	}
	if !any {
		return false
	}
	for _, d := range f.Status.Devices {
		if d.Error != "" || f.Routed[d.Device] {
			continue
		}
		for _, ks := range d.Keyslots {
			if ks.Token != nil {
				return false
			}
		}
	}
	return true
}

// chainSteps are step 1: the hook, the route, and the way on to step 2
// once they are in place.
func (c *controller) chainSteps() []controlStep {
	boot := c.bootStep()
	route := c.routeStep()
	next := controlStep{Key: "continue", Title: "Continue to step 2", Menu: "hub",
		Explain: "The signing key and the TOTP codes, the phone, the ways the disk is unlocked, the network and SSH at boot - combined as this machine allows."}
	var open []string
	for _, s := range []controlStep{boot, route} {
		if s.Done == "" && !(s.Key == "route" && s.Blocked != "") {
			open = append(open, s.Title)
		}
	}
	if len(open) > 0 {
		next.Blocked = "first: " + strings.Join(open, ", ")
	}
	return []controlStep{boot, route, next}
}

// chainDone says whether step 1 is in place: the hook in the HOOKS the
// image is built with, and the key routed where there is a LUKS device to
// route.
func chainDone(f *machineFacts) bool {
	c := &controller{facts: *f}
	return c.chainSteps()[2].Blocked == ""
}

// runInitramfs wires the boot integration. On mkinitcpio it shows the
// HOOKS line as it is and as it should read, and writes it when asked -
// the standing rule that control edits no file of the system has this one
// exception, asked for every time; editing by hand works just as well,
// and the step says how. The build is a step of its own.
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
	case !mkinitcpioHookInstalled():
		return errors.New("the sd-tpm2-kira hook files are not installed: sudo make install-mkinitcpio, or the package; then run this step again")
	}
	file, oldLine, newLine, err := AdoptHookLine(mkinitcpioConf)
	if err != nil {
		return err
	}
	if oldLine == newLine {
		fmt.Fprintf(c.out, "sd-tpm2-kira is already in the HOOKS of %s.\n", file)
		return nil
	}
	fmt.Fprintf(c.out, "The boot image is built from the HOOKS of %s. The line reads\n\n    %s\n\nand must carry sd-tpm2-kira next to sd-encrypt, so the code screen runs before\nthe passphrase prompt:\n\n    %s\n\nPut that line into the file yourself - or let this step write it, which\nchanges nothing else of the file.\n\n", file, oldLine, newLine)
	ok, err := c.confirm("Write the line into "+file+"?", "Only the HOOKS assignment changes; 'No' leaves the editing to you.")
	if err != nil || !ok {
		fmt.Fprintf(c.out, "Nothing was written. Put the line above into %s.\n", file)
		return nil
	}
	file, line, err := AdoptHook(mkinitcpioConf)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "%s now reads: %s\nThe image is built when you quit control.\n", file, line)
	return nil
}

// runRoute shows, per unrouted device, the line as it should read and
// writes it when asked - the same ask-first editing as the mkinitcpio
// step; a volume named nowhere stays advice. A written command line is in
// the image on a UKI: the image is then rebuilt when control is left.
func (c *controller) runRoute() error {
	printed := false
	for _, fd := range c.facts.Route {
		if fd.Routed || fd.Problem == "" || c.facts.Routed[fd.Device] {
			continue
		}
		printed = true
		fmt.Fprintf(c.out, "%s (%s): %s: %s.\n", fd.Device, fd.UUID, fd.File, fd.Problem)
		if fd.Kind == "" {
			fmt.Fprintf(c.out, "The line to add, with your root= kept (this one is yours to write):\n\n    %s\n\n", fd.Should)
			continue
		}
		what := map[string]string{"cmdline": "the command line in", "entry": "the options line of", "crypttab": "the volume's line in"}[fd.Kind]
		fmt.Fprintf(c.out, "As it should read:\n\n    %s\n\nEdit %s %s yourself, or let this step write it.\n\n", fd.Should, what, fd.File)
		ok, err := c.confirmYes("Write it into "+fd.File+"?", "Only "+what+" "+fd.File+" changes; 'No' leaves the editing to you.")
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := WriteRouteFix(fd); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "%s written.\n\n", fd.File)
	}
	if !printed {
		fmt.Fprintln(c.out, "Nothing to route: no LUKS volume is known to the boot yet (rd.luks.name= on the kernel command line, or crypttab).")
	}
	return nil
}
