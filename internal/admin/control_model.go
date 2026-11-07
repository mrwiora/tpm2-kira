package admin

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/tpm2-trust/tpm2-kira/internal/measure"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"
)

// control's model: every line a screen shows is a controlStep - its state (done,
// open, blocked with the reason, dirty), what it does, the command it equals and how
// dangerous it is - and the steps are grouped in sections. Both the full screen
// (control_screen.go) and the line menus (control.go) draw the same model; what a
// line runs is the same either way.

// How much a step can break: it reads, it changes the machine, or it destroys what is
// there (a slot, a keyslot, a phone, the SSH CA). A destroying step says what goes,
// and asks for it to be typed.
const (
	dangerChange = iota
	dangerView
	dangerDestroy
)

// controlSection is one part of control: a section of the full screen, a submenu of the
// line menus' overview.
type controlSection struct {
	key, title, intro string
	required          bool // a protection: the recommendation while open
}

// controlSections are control's parts, in their order: the full screen's sidebar, and
// (but the overview and the boot chain) the line menus' overview.
var controlSections = []controlSection{
	{key: "overview", title: "Overview",
		intro: "What this machine has, judged line by line, and what it combines. Each section sets one part up; the recommended next step is named."},
	{key: "chain", title: "Boot chain",
		intro: "What tpm2-kira needs of the machine to be in its boot at all: the prerequisites, the hook in the boot image, the key's route. The other sections open when it is in place."},
	{key: "keys", title: "Keys & slots", required: true,
		intro: "The signing key approves boot states and authorises every write to the TPM; with it the TOTP codes at boot are sealed into slot 0 (the boot as it is) and slot 1 (the fallback for a boot whose kernel changed unpredicted). Everything else builds on them."},
	{key: "phone", title: "Phone",
		intro: "A phone (Marify, Bluetooth LE) checks the boot state against what it pinned and shows a code the machine shows too; it replaces Enter at the code screen, and it can hand back the salt of a disk key."},
	{key: "disk", title: "Disk unlock",
		intro: "How the disk's key is made at boot, beside the recovery passphrase: each way is a keyslot of its own, and they combine - at boot the one that answers first opens the disk, and cryptsetup's own prompt stays the fallback."},
	{key: "remote", title: "Network & SSH",
		intro: "The boot image's own network - for the vault, and for tpm2-kira's SSH server, where the codes are confirmed and passwords typed remotely. Set for the image alone; the running system's network stays as it is."},
	{key: "image", title: "Boot image",
		intro: "What the next boot image carries, and the switch that makes the boot log every step. The image is built when control is left, or here."},
	{key: "tools", title: "Tools",
		intro: "Views: the commands that read the machine, run as they are and shown here. Nothing in this section changes anything."},
	{key: "reference", title: "Reference",
		intro: "The help pages of every command, the expert ones included: what control does not do by itself (luks mark and derive, phone salt rotate, phone quote and verify, the boot's commands) is done there by hand."},
}

// sectionByKey is the section of a key.
func sectionByKey(key string) controlSection {
	for _, s := range controlSections {
		if s.key == key {
			return s
		}
	}
	return controlSection{key: key, title: key}
}

// sectionSteps are the lines of a section.
func (c *controller) sectionSteps(key string) []controlStep {
	switch key {
	case "overview":
		return c.hubSteps()
	case "chain":
		var out []controlStep
		for _, s := range c.chainSteps() {
			if s.Menu != "hub" {
				out = append(out, s)
			}
		}
		return out
	}
	return c.menuSteps(key)
}

// sectionOf is the section a hub line opens.
func sectionOf(menu string) string {
	if menu == "hub" {
		return "overview"
	}
	return menu
}

// annotate fills in what a step equals on the command line and how dangerous it is,
// by its key: one table for every screen.
func (c *controller) annotate(s controlStep) controlStep {
	f := &c.facts
	tpm := ""
	if c.o.TPMPath != "" && c.o.TPMPath != tpmdev.DefaultPath {
		tpm = " --tpm " + c.o.TPMPath
	}
	key, arg, _ := strings.Cut(s.Key, ":")
	cmd := ""
	switch key {
	case "setup":
		cmd = "tpm2-kira setup"
	case "seal":
		cmd = "tpm2-kira slot add" + tpm + " --nvram 0 --pcrs " + f.PCRs
	case "seal-more":
		cmd = "tpm2-kira slot add" + tpm + " --nvram N --pcrs LIST"
	case "approve":
		cmd = "tpm2-kira slot approve" + tpm
	case "slot":
		cmd, s.Danger = "tpm2-kira slot delete"+tpm+" --nvram "+arg, dangerDestroy
		if s.Destroys == "" {
			s.Destroys = "slot " + arg + " whole: its TOTP key (the authenticator's code stops matching), its phones, its phone salt, the vault's local part, the LUKS keyslots bound to it"
		}
	case "delete-all":
		cmd, s.Danger = "tpm2-kira luks remove DEVICE --keyslot N (each of tpm2-kira's); tpm2-kira slot delete"+tpm+" --yes --sweep; rm -r "+strings.Join(kiraDirs, " "), dangerDestroy
	case "channel":
		cmd = "tpm2-kira slot approve" + tpm + " --nvram " + arg + " --seal-channel"
	case "attest":
		cmd = "tpm2-kira phone enrol" + tpm
	case "phone-remove":
		cmd, s.Danger = "tpm2-kira phone unenrol"+tpm+" --nvram "+arg, dangerDestroy
	case "salt-remove":
		cmd, s.Danger = "tpm2-kira phone salt unenrol"+tpm+" --nvram "+arg, dangerDestroy
	case "bt-always":
		cmd = "TPM2_KIRA_ATTEST_BLUETOOTH in " + controlConfigPath()
	case "luks-salt", "luks-tpm", "luks-remote", "luks-remote-keyboard":
		cmd = "tpm2-kira luks enrol DEVICE " + map[string]string{
			"luks-salt": "--password typed --salt typed", "luks-tpm": "--password typed --salt tpm",
			"luks-remote": "--password typed --salt phone", "luks-remote-keyboard": "--password typed --salt phone --keyboard-pepper"}[key]
		if s.Done != "" {
			cmd, s.Danger = "tpm2-kira luks remove DEVICE --keyslot N", dangerDestroy
			s.Destroys = s.Done + ": the keyslot, so that this way opens the disk no more"
		}
	case "vault":
		cmd = "tpm2-kira luks enrol DEVICE --password tpm --salt vault --url URL --pin PIN --token TOKEN"
		if s.Done != "" {
			cmd = "tpm2-kira vault status" + tpm + "; tpm2-kira vault unenrol" + tpm
		}
	case "net":
		cmd = "TPM2_KIRA_NET* in " + controlConfigPath()
	case "ssh":
		cmd = "TPM2_KIRA_SSH* in " + controlConfigPath() + ", ASSH_* in " + sshConfPath(controlConfigPath())
	case "debug":
		cmd = "the boot settings in the TPM (NV index 0x01803000), signed"
	case "initramfs":
		cmd = "HOOKS in " + mkinitcpioConf
	case "route":
		cmd = "tpm2-kira luks route"
	case "pcrkey":
		cmd = ukiConfPath
	case "build":
		cmd = rebuildCommand(f.Initramfs)
	case "view", "help":
		s.Danger = dangerView
		cmd = "tpm2-kira " + strings.Join(viewArgs(s.Key), " ")
	}
	if s.Command == "" {
		s.Command = cmd
	}
	return s
}

// annotated is every step of a list annotated.
func (c *controller) annotated(steps []controlStep) []controlStep {
	out := make([]controlStep, len(steps))
	for i, s := range steps {
		out[i] = c.annotate(s)
	}
	return out
}

// confirmDestroy asks a destroying step's question: what goes, and the word to type
// for it. Anything else - Enter alone, n, a typo - keeps what is there.
func (c *controller) confirmDestroy(title, destroys, word string) (bool, error) {
	ans, err := c.ask().Input(title+" Type "+word+" to destroy it:",
		"\033[0;31mDestroys:\033[0m "+destroys+"\nAnything else than "+word+" keeps it.", "", nil)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(ans) == word, nil
}

// errKept is a destroying step answered with anything but its word.
var errKept = errors.New("not destroyed: kept as it is")

// sealMoreStep seals a slot beyond the standard pair, to PCRs of the person's choice.
func (c *controller) sealMoreStep() controlStep {
	f := &c.facts
	s := controlStep{Key: "seal-more", Title: "Seal another slot (2-15) to PCRs you choose", Optional: true,
		Explain: "A TOTP code sealed to a selection of your own, in a slot of its own - beside slot 0 and its fallback, for a boot state you want told apart. Asked: the slot, the PCRs (0e,2e,4u,7e,11u and the like), whether a TOTP code is shown.",
		Run:     (*controller).runSealMore}
	slot0, _, _ := c.slots()
	switch {
	case f.TPMErr != "":
		s.Blocked = "no TPM: " + f.TPMErr
	case f.Keys == "":
		s.Blocked = "needs the signing key"
	case slot0 == nil:
		s.Blocked = "needs slot 0 first (The boot state)"
	case len(c.freeSlots()) == 0:
		s.Blocked = "every slot is in use"
	}
	return s
}

// freeSlots are the slots 2-15 nothing is sealed in.
func (c *controller) freeSlots() []int {
	used := map[int]bool{}
	for _, s := range c.facts.Status.Slots {
		used[s.Slot] = true
	}
	for _, d := range c.facts.Dirt {
		used[d.Slot] = true
	}
	var out []int
	for n := 2; n <= 15; n++ {
		if !used[n] {
			out = append(out, n)
		}
	}
	return out
}

func (c *controller) runSealMore() error {
	free := c.freeSlots()
	var labels []string
	for _, n := range free {
		labels = append(labels, fmt.Sprintf("Slot %d", n))
	}
	i, err := c.choose("Which slot?", labels)
	if err != nil {
		return err
	}
	pcrs, err := c.ask().Input("PCRs for slot "+fmt.Sprint(free[i]),
		"Indices with a source each: none or r the register, e the event log, u the unified kernel image - such as 0e,2e,4u,7e,11u (tpm2-kira help slot).",
		c.facts.PCRs, func(s string) error {
			_, err := measure.ParsePCRSpecs(s)
			return err
		})
	if err != nil {
		return err
	}
	withTOTP, err := c.confirmYes("A TOTP code at boot?", "The code screen shows this slot's code beside the others.")
	if err != nil {
		return err
	}
	algo := measure.PCRHashAlgoSHA256
	if c.facts.UseSHA1 {
		algo = measure.PCRHashAlgoSHA1
	}
	fmt.Fprint(c.out, clearScreen)
	return Seal(c.o.TPMPath, pcrs, nvslot.ResolveNVRAMIndex(uint32(free[i])), "", "", c.o.Debug, algo, true, withTOTP)
}

// approveStep approves every slot (and the SSH CA) for the boot state as it is now.
func (c *controller) approveStep() controlStep {
	f := &c.facts
	s := controlStep{Key: "approve", Title: "Approve the slots for the next boot now", Optional: true,
		Explain: "What the hooks do after a kernel or image update, by hand: every slot and the SSH CA approved for the next boot's PCRs, with the signing key. A moved phone channel is shown and asked about.",
		Run: func(c *controller) error {
			return ResealCommand(c.o.TPMPath, 0, "", "", "", ChannelAsk, c.o.Debug)
		}}
	switch {
	case f.TPMErr != "":
		s.Blocked = "no TPM: " + f.TPMErr
	case f.Keys == "":
		s.Blocked = "needs the signing key"
	case len(f.Status.Slots) == 0 && f.SSHCA.CA == nil:
		s.Blocked = "nothing is sealed yet"
	}
	return s
}

// kiraDirs are the directories of tpm2-kira's own files: the keys and the
// configuration, and the state (recovery blobs, the adapters' firmware names). Vars:
// the tests' own.
var kiraDirs = []string{"/etc/tpm2-kira", "/var/lib/tpm2-kira"}

// kiraKeyslot is a LUKS keyslot with a tpm2-kira token.
type kiraKeyslot struct {
	device  string
	keyslot int
}

// kiraKeyslots are every keyslot of tpm2-kira's, on every device.
func (c *controller) kiraKeyslots() []kiraKeyslot {
	var out []kiraKeyslot
	for _, d := range c.facts.Status.Devices {
		for _, ks := range d.Keyslots {
			if ks.Token != nil {
				out = append(out, kiraKeyslot{d.Device, ks.Keyslot})
			}
		}
	}
	return out
}

// deleteAllStep removes everything of tpm2-kira's from the machine, in three parts,
// each shown and asked for its word: the LUKS keyslots of tpm2-kira's, the TPM and the
// EFI variables (slot delete --yes --sweep), and the files.
func (c *controller) deleteAllStep() controlStep {
	f := &c.facts
	s := controlStep{Key: "delete-all", Title: "Delete everything of tpm2-kira's on this machine", Optional: true, SelfConfirm: true,
		Explain: "In three parts, each shown and asked for on its own: tpm2-kira's LUKS keyslots; the TPM and the EFI variables - every slot, " +
			"the boot settings, the sealed machine-id, the SSH CA, and whatever this or an earlier version left at tpm2-kira's places; " +
			"the files in /etc/tpm2-kira and /var/lib/tpm2-kira. The recovery passphrase's keyslot stays. The package stays installed: " +
			"its hook is still in the boot image until it is taken out of HOOKS or the package is removed.",
		Destroys: "tpm2-kira's LUKS keyslots; every slot (all TOTP keys, phones, phone salts, the vault's local parts), the boot settings, the sealed machine-id, the SSH CA and everything else at tpm2-kira's places in the TPM and the EFI variables; the signing key's files, the configuration, the PIN, the PCR key and the state",
		Run:      (*controller).runDeleteAll}
	_, dirsErr := os.Stat(kiraDirs[0])
	switch {
	case f.TPMErr != "" && len(c.kiraKeyslots()) == 0 && dirsErr != nil:
		s.Blocked = "no TPM, no keyslot and no file of tpm2-kira's"
	}
	return s
}

// runDeleteAll is the three parts, each on its own word: a No to one goes on with the
// next.
func (c *controller) runDeleteAll() error {
	var done []string
	if ks := c.kiraKeyslots(); len(ks) > 0 {
		var names []string
		for _, k := range ks {
			names = append(names, fmt.Sprintf("keyslot %d of %s", k.keyslot, k.device))
		}
		fmt.Fprintf(c.out, "1. tpm2-kira's LUKS keyslots: %s. Removing each asks for a remaining passphrase (the recovery one).\n\n", strings.Join(names, ", "))
		ok, err := c.confirmDestroy("Remove tpm2-kira's LUKS keyslots?", strings.Join(names, ", ")+": the ways tpm2-kira opens the disk", "delete")
		if err != nil {
			return err
		}
		if ok {
			for _, k := range ks {
				if err := LuksRemove(LuksRemoveOptions{Device: k.device, Keyslot: k.keyslot, TPMPath: c.o.TPMPath}); err != nil {
					return fmt.Errorf("keyslot %d of %s: %w", k.keyslot, k.device, err)
				}
			}
			done = append(done, "the keyslots")
		}
	}
	if c.facts.TPMErr == "" {
		fmt.Fprintln(c.out, "\n2. The TPM and the EFI variables: every slot, the boot settings, the sealed machine-id, the SSH CA, and what this or an earlier version left at tpm2-kira's places, whatever its shape.")
		fmt.Fprintln(c.out)
		ok, err := c.confirmDestroy("Delete everything of tpm2-kira's in the TPM and the EFI variables?", "all of the above in the TPM and the EFI variables", "delete")
		if err != nil {
			return err
		}
		if ok {
			if err := NVRAMDeleteCommand(c.o.TPMPath, 0, true, false, true, c.o.Debug); err != nil && !strings.Contains(err.Error(), "nothing of tpm2-kira") {
				return err
			}
			done = append(done, "the TPM and the EFI variables")
		}
	}
	var dirs []string
	for _, d := range kiraDirs {
		if _, err := os.Stat(d); err == nil {
			dirs = append(dirs, d)
		}
	}
	if len(dirs) > 0 {
		fmt.Fprintf(c.out, "\n3. The files: %s - the signing key's files (a YubiKey's key itself stays on the token), control.conf and assh.conf, the PIN, the PCR key, the keys that may log in at boot, the recovery blobs. A slot sealed afterwards needs a new signing key (setup).\n\n", strings.Join(dirs, " and "))
		ok, err := c.confirmDestroy("Remove "+strings.Join(dirs, " and ")+"?", strings.Join(dirs, " and ")+", whole", "delete")
		if err != nil {
			return err
		}
		if ok {
			for _, d := range dirs {
				if err := os.RemoveAll(d); err != nil {
					return err
				}
				fmt.Fprintf(c.out, "Removed %s\n", d)
			}
			done = append(done, "the files")
		}
	}
	if len(done) == 0 {
		return errKept
	}
	fmt.Fprintf(c.out, "\nRemoved: %s. The boot image still carries tpm2-kira's hook: take sd-tpm2-kira out of HOOKS (or remove the package) and rebuild it.\n", strings.Join(done, ", "))
	return nil
}

// phoneRemoveSteps are a line per slot with phones: removing them.
func (c *controller) phoneRemoveSteps() []controlStep {
	var out []controlStep
	for _, sl := range c.facts.Status.Slots {
		if sl.Phones == 0 {
			continue
		}
		n := sl.Slot
		out = append(out, controlStep{Key: fmt.Sprintf("phone-remove:%d", n), Title: fmt.Sprintf("Remove the phones of slot %d", n), Optional: true, SelfConfirm: true,
			Explain:  "The phones enrolled in the slot go: they find this machine no more. Removing the last phone gives slot " + fmt.Sprint(n) + " a TOTP code again, at its next approval. A keyslot whose salt comes from the phone (0x1300, 0x1302) opens nothing afterwards: remove it too (Disk unlock).",
			Destroys: phonesText(sl.Phones) + " of slot " + fmt.Sprint(n),
			Run: func(c *controller) error {
				ok, err := c.confirmDestroy(fmt.Sprintf("Remove the phones of slot %d?", n), phonesText(sl.Phones)+" of slot "+fmt.Sprint(n)+"; a keyslot with the phone's salt opens nothing afterwards", fmt.Sprint(n))
				if err != nil {
					return err
				}
				if !ok {
					return errKept
				}
				return AttestUnenrol(c.o.TPMPath, uint32(n), "", c.o.Debug)
			}})
	}
	return out
}

// saltRemoveSteps are a line per slot holding a phone salt: removing it.
func (c *controller) saltRemoveSteps() []controlStep {
	var out []controlStep
	for _, sl := range c.facts.Status.Slots {
		if !sl.PhoneSalt {
			continue
		}
		n := sl.Slot
		out = append(out, controlStep{Key: fmt.Sprintf("salt-remove:%d", n), Title: fmt.Sprintf("Remove the phone salt of slot %d", n), Optional: true, SelfConfirm: true,
			Explain:  "The release key of the phone's salt goes from the slot: the phone hands back no salt afterwards, and a keyslot of 0x1300 or 0x1302 opens nothing. Remove that keyslot first (its line above), then this.",
			Destroys: "the phone salt's release key in slot " + fmt.Sprint(n),
			Run: func(c *controller) error {
				ok, err := c.confirmDestroy(fmt.Sprintf("Remove the phone salt of slot %d?", n), "the phone salt's release key; the keyslots with the phone's salt open nothing afterwards", fmt.Sprint(n))
				if err != nil {
					return err
				}
				if !ok {
					return errKept
				}
				return FactorUnenrol(c.o.TPMPath, nvslot.ResolveNVRAMIndex(uint32(n)), "", c.o.Debug)
			}})
	}
	return out
}

// buildStep builds the boot image now, instead of on leaving.
func (c *controller) buildStep() controlStep {
	f := &c.facts
	s := controlStep{Key: "build", Title: "Build the boot image now", Optional: true, SelfConfirm: true,
		Explain: "What control does when it is left, now: the image built with what is set up, its hook approving what it built.",
		Run:     (*controller).offerRebuild}
	switch {
	case f.Initramfs == "":
		s.Blocked = "neither mkinitcpio nor initramfs-tools found"
	case len(f.Pending) == 0:
		s.Done = "up to date"
	}
	return s
}

// viewArgs is a view's or a help page's command line, from its key.
func viewArgs(key string) []string {
	kind, rest, _ := strings.Cut(key, ":")
	if kind == "help" {
		return []string{"help", rest}
	}
	return strings.Fields(rest)
}

// toolSteps are the views: commands that read and change nothing.
func (c *controller) toolSteps() []controlStep {
	f := &c.facts
	noTPM := ""
	if f.TPMErr != "" {
		noTPM = "no TPM: " + f.TPMErr
	}
	view := func(title, args, blocked, explain string) controlStep {
		return controlStep{Key: "view:" + args, Title: title, Optional: true, SelfConfirm: true, Danger: dangerView,
			Blocked: blocked, Explain: explain, Run: func(c *controller) error { return c.runSelf(strings.Fields(args)) }}
	}
	out := []controlStep{
		view("Status", "status", "", "The machine's status as 'tpm2-kira status' says it: the slots, the phones, the keyslots, the image."),
		view("Slots in the TPM", "slot list", noTPM, "Every slot, its index and what it holds."),
	}
	for _, s := range f.Status.Slots {
		out = append(out, view(fmt.Sprintf("Slot %d in detail", s.Slot), fmt.Sprintf("slot info --nvram %d", s.Slot), noTPM,
			"The slot's blob: its PCRs as sealed against the live ones, its approvals, its methods."))
	}
	out = append(out, view("LUKS keyslots", "luks status", "", "Every LUKS device, its keyslots and which are tpm2-kira's, with their recipes."))
	for _, s := range f.Status.Slots {
		if s.Vault != "" {
			out = append(out, view(fmt.Sprintf("The vault of slot %d", s.Slot), fmt.Sprintf("vault status --nvram %d", s.Slot), noTPM, "Whether the vault answers, with its pinned key, and knows this device."))
		}
	}
	out = append(out,
		view("Phones", "phone status", noTPM, "The phones enrolled per slot."),
		view("Phone salts", "phone salt status", noTPM, "The phone salts per slot."),
		view("The TPM's EK certificate", "phone ekcert", noTPM, "The endorsement key's certificate and its vendor chain: what a phone and the vault check this TPM by."),
		view("YubiKeys", "yubikey list", "", "The YubiKeys attached, and their PIV slots."),
		view("The next boot image's plan", "initramfs plan", "", "What the next image carries, part by part, and why."),
		view("What each PCR measures", "pcrtips", "", "The PCRs, what moves them, and which to seal to."),
	)
	return out
}

// referenceSteps are the help pages.
func (c *controller) referenceSteps() []controlStep {
	var out []controlStep
	for _, topic := range c.o.HelpTopics {
		t := topic
		out = append(out, controlStep{Key: "help:" + t, Title: "tpm2-kira help " + t, Optional: true, SelfConfirm: true, Danger: dangerView,
			Explain: "The help page of '" + t + "'.", Run: func(c *controller) error { return c.runSelf([]string{"help", t}) }})
	}
	return out
}

// runSelf runs tpm2-kira itself with args, on this terminal: a view is the command as
// it is. A var: the tests see what runs.
var runSelf = func(tpmPath string, args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if tpmPath != "" && tpmPath != tpmdev.DefaultPath && !slices.Contains([]string{"help", "pcrtips", "yubikey"}, args[0]) && args[0] != "luks" {
		args = append([]string{"--tpm", tpmPath}, args...)
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func (c *controller) runSelf(args []string) error {
	fmt.Fprintf(c.out, "\033[2m$ tpm2-kira %s\033[0m\n\n", strings.Join(args, " "))
	return runSelf(c.o.TPMPath, args)
}
