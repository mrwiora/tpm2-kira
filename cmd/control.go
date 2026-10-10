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
	// BTFirmware is the adapter's firmware as the image build will find it
	// (attest_initramfs.go); empty when no log named it and none is
	// remembered, so the image may not start the adapter.
	BTFirmware []string
	// BTAuthorize is the adapter's USB device when its bus lets no new
	// device in by itself, so the image needs a rule for it; nil when not.
	BTAuthorize *USBDevice
	// ImageAuth says what the boot image lacks to let the adapter in; ""
	// when it carries the rule or needs none.
	ImageAuth string
	// BootDebug is the boot settings' debug switch (bootsettings.go).
	BootDebug bool
	// ImageBT says what the boot images lack of the adapter's part, when
	// it belongs in them (a phone, or Bluetooth packed always); "" when
	// they carry it or it does not belong there.
	ImageBT string
	// Pending are the reasons the boot image is out of date: a file it is
	// built from changed after it, or it lacks what belongs in it. Empty
	// when the image is as it should be.
	Pending  []string
	Guide    string // guided or manual (TPM2_KIRA_CONTROL); "" until chosen
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
	if stored, loose := pinStored(controlConfigPath()); stored {
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
		if deps := adapterDeps(f.Adapter); deps != nil {
			f.BTFirmware, f.BTAuthorize = deps.Firmware, deps.Authorize
		}
	}
	if cfg, err := LoadControlConfig(controlConfigPath()); err != nil {
		f.AttestConf = err.Error()
	} else {
		f.BTAlways = cfg.Attest.Bluetooth == "always"
		f.Guide = cfg.Control
		f.Remote = cfg.Remote
	}

	f.Status = collectStatus(StatusOptions{TPMPath: tpmPath, ConfigPath: controlConfigPath(), Debug: debug})
	if f.TPMErr == "" {
		f.BootDebug = BootDebug(tpmPath)
	}
	if f.TPMErr == "" {
		f.Dirt = collectDirt(tpmPath, f.Status.Devices)
	}
	for _, s := range f.Status.Slots {
		f.Phone = f.Phone || s.Phones > 0
		f.Salt = f.Salt || s.RemoteSalt
		f.Capped = f.Capped || strings.Contains(s.GenState, "read-locked until reboot")
	}
	if f.Initramfs == "mkinitcpio" {
		f.NewImage = imageNewerThanBoot()
	}
	if f.Adapter != "" && f.Initramfs != "" && f.HookState == "" && (f.Phone || f.BTAlways) {
		f.ImageBT = imageBluetoothProblem(f.BTFirmware)
		if f.BTAuthorize != nil {
			f.ImageAuth = imageAuthorizationProblem(f.BTAuthorize)
		}
	}
	f.Pending = pendingRebuild(f.Initramfs)
	if f.ImageBT != "" {
		f.Pending = append(f.Pending, f.ImageBT)
	}
	if f.ImageAuth != "" {
		f.Pending = append(f.Pending, f.ImageAuth)
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
	Check       bool   // a wiring check: pickable only while it is open
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
	// batch: the guided row runs; the stages skip their own rebuild
	// offers, the row ends with the one rebuild.
	batch bool
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
		keys.Explain = f.Keys + ". Its PIN, stored in " + controlConfigPath() + " (readable by root alone; nothing of the file goes into the boot image), lets the hooks reseal unattended after a kernel or initramfs update; without it that reseal is skipped and the next boot shows a PCR mismatch."
	default:
		keys.Done = f.Keys
	}
	// The boot integration is the second foundation: without the hook in
	// the image there is no code screen, no gate and no key at boot, so
	// everything else waits behind it.
	boot := controlStep{Key: "initramfs", Check: true, Run: (*controller).runInitramfs}
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

	// The key's route sits next to the boot integration: both are wiring,
	// checked rather than run once they are in place. systemd-cryptsetup
	// takes a volume's key from tpm2-kira only where rd.luks.key= names
	// the socket (keyscript= in crypttab on Debian); the disk-key steps
	// below wait for it.
	route := controlStep{Key: "route", Title: "Unlock at boot (the key's route)", Check: true,
		Explain: "systemd-cryptsetup takes a volume's key from tpm2-kira when its rd.luks.key= names the socket (keyscript= in crypttab on Debian). The step shows each line as it should read and writes it when you say so - editing the file yourself works just as well. How the key is made, the boot reads from the volume's own LUKS header.",
		Run:     (*controller).runRoute}
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
		route.Blocked = "no LUKS device found (root for the headers)"
	case len(unrouted) > 0:
		route.Explain += "\nOpen: " + strings.Join(unrouted, ", ") + " not routed through tpm2-kira."
	case routeResolved(f):
		route.Done = "the key routed"
	}

	steps := []controlStep{keys, boot}

	// Until the signing key exists and the boot integration is wired, the
	// overview is these two steps and Quit: everything else builds on
	// them. Only a dirty slot shows through, so a cleanup is never hidden.
	if keys.Done == "" || boot.Done == "" {
		for _, d := range f.Dirt {
			steps = append(steps, dirtyLine(d))
		}
		return c.finishSteps(steps)
	}
	steps = append(steps, route)

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
			if s.Phones > 0 {
				desc += ", " + phonesText(s.Phones)
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
			Explain: "The phone checks the boot state against what it pinned and shows a code the machine must show too; it replaces Enter at the code screen. It is enrolled in a boot whose slot 0 code you compared - the phone takes that boot as the good one - and it asks you so. While a phone is enrolled, slot 0 has no TOTP code (the screen says \"mobile attestation locked - please connect\" until the phone is in); slot 1, the fallback, keeps its code. Removing the last phone gives slot 0 a new TOTP code.",
			Run:     (*controller).runAttest}
		switch {
		case f.Adapter == "":
			attest.Blocked = "no Bluetooth adapter on this machine"
		case f.AttestConf != "":
			attest.Blocked = controlConfigPath() + ": " + f.AttestConf
		case strong.Phones > 0:
			attest.Done = phonesText(strong.Phones) + " (the slot has no TOTP code while a phone is enrolled)"
		case f.NewImage != "":
			// Enrolling pins this boot's values; a newer image on disk
			// makes the next boot differ, and a reboot cures both this
			// and the boot key's verdict below.
			attest.Blocked = f.NewImage
		case !f.Capped:
			attest.Blocked = "this boot did not pass tpm2-kira's code screen (the image at boot was not wired): reboot, then enrol - the phone would otherwise call the boot key refused instead of locked"
		}
		luksRemote := controlStep{Key: "luks-remote", Child: true, SelfConfirm: true, Title: "Disk key from password + remote salt (the phone)",
			Explain: "A LUKS keyslot whose key is derived from your password and the salt the phone hands back after it attested the boot: the disk needs the phone, this TPM in an approved boot, and your password. Enrolled, picking it offers the removal.",
			Run:     func(c *controller) error { return c.runLuks(LuksModePasswordRemoteSalt) }}
		switch {
		case !luksDevices:
			luksRemote.Blocked = "no LUKS device found (root for the headers)"
		case route.Done == "":
			luksRemote.Blocked = "needs the key's route (Unlock at boot above)"
		case attest.Done == "":
			luksRemote.Blocked = "needs the attestation by phone"
		case len(boundTo[strong.Slot]) > 0:
			luksRemote.Done = strings.Join(boundTo[strong.Slot], ", ")
		case f.NewImage != "":
			luksRemote.Blocked = f.NewImage
		case !f.Capped:
			luksRemote.Blocked = "this boot did not pass tpm2-kira's code screen: reboot, then enrol the salt - the phone would otherwise call the boot key refused instead of locked"
		}
		steps = append(steps, attest, luksRemote)
	}

	// The keyslot from a typed salt: independent of the slots - no TPM is
	// in its key, no slot binding in its token, and deleting a slot leaves
	// it untouched. It coexists with the remote-salt keyslot: at boot the
	// phone's salt is tried first, the typed salt is the fallback.
	luksSalt := controlStep{Key: "luks-salt", SelfConfirm: true, Title: "Disk key from password + salt (hashpwd2)",
		Explain: "A LUKS keyslot whose key is derived at boot from a password and a salt you type (Argon2id, 1 GiB); the recovery passphrase stays in its own keyslot. Bound to no slot - deleting a slot leaves it untouched - and it coexists with the remote-salt keyslot, as the typed fallback when the phone is not there. Enrolled, picking it offers the removal.",
		Run:     func(c *controller) error { return c.runLuks(LuksModePasswordSalt) }}
	switch {
	case !luksDevices:
		luksSalt.Blocked = "no LUKS device found (root for the headers)"
	case route.Done == "":
		luksSalt.Blocked = "needs the key's route (Unlock at boot above): the derived key must reach systemd-cryptsetup"
	case hasSalt:
		luksSalt.Done = "a keyslot is enrolled"
	}

	return c.finishSteps(append(steps, luksSalt))
}

// runRoute shows, per unrouted device, the line as it should read and
// writes it when asked - the same ask-first editing as the mkinitcpio
// step; a volume named nowhere stays advice. A written command line is in
// the image on a UKI, so the rebuild is offered after.
func (c *controller) runRoute() error {
	wrote, printed := false, false
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
		wrote = true
	}
	if !printed {
		fmt.Fprintln(c.out, "Nothing to route: no LUKS volume is known to the boot yet (rd.luks.name= on the kernel command line, or crypttab).")
	}
	if !wrote {
		return nil
	}
	if c.facts.Initramfs == "mkinitcpio" && !c.batch {
		// A unified kernel image carries the command line: rebuild.
		return c.offerRebuild()
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
	// The configuration file first: control writes it, and a step taken
	// on a file that does not load would be taken on defaults it never
	// chose (the guided/manual choice read as "not made", a PIN whose
	// file the settings reject). Everything wrong with it, then quit.
	if problems := controlConfigProblemsText(controlConfigPath()); problems != "" {
		fmt.Fprintf(c.out, "\n%s\n\n%s", c.header(), problems)
		return fmt.Errorf("%s does not load: fix it as shown, then start control again", controlConfigPath())
	}
	// The overview judges the risks itself, in red on the status, so the
	// steps run without the commands' advisory warnings: nothing is said
	// twice. Run by hand, seal and reseal keep them.
	defer func(old bool) { AdvisoryWarnings = old }(AdvisoryWarnings)
	AdvisoryWarnings = false
	if c.tty {
		if err := c.ensureGuide(); err != nil {
			return nil // Esc at the first question: leave, nothing stored
		}
	}
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
		fmt.Fprint(c.out, clearScreen+"\n"+c.header()+c.phase(steps)+"\n\n")
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
			if s.Check {
				blocked[s.Key] = "in place: " + s.Done
			}
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
	switch {
	case f.Adapter != "" && len(f.BTFirmware) == 0 && (f.Phone || f.BTAlways):
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
	switch {
	case f.ImageBT != "":
		fmt.Fprintf(&w, "  Boot image  %s\n", bad(f.ImageBT+" (risk: the phone is not asked at boot)"))
	case f.Adapter != "" && f.HookState == "" && (f.Phone || f.BTAlways):
		fmt.Fprintf(&w, "  Boot image  %s\n", good("carries "+f.Adapter+"'s driver and firmware for the phone's gate"))
	}
	if f.BootDebug {
		fmt.Fprintf(&w, "  Debug       %s\n", warn("on at boot: the code screen and the phone check log every step, on the console too"))
	}
	// The adapter's USB bus may let no new device in by itself
	// (usbcore.authorized_default=0, as USBGuard sets it): then the image
	// needs the rule that lets the adapter in, a check of its own.
	if f.Adapter != "" && f.HookState == "" && (f.Phone || f.BTAlways) {
		switch {
		case f.BTAuthorize == nil:
			fmt.Fprintf(&w, "  Adapter at boot  %s\n", good("its USB bus lets it in by itself"))
		case f.ImageAuth != "":
			fmt.Fprintf(&w, "  Adapter at boot  %s\n", bad(f.ImageAuth+" (risk: the driver never binds at boot and the phone is not asked)"))
		default:
			fmt.Fprintf(&w, "  Adapter at boot  %s\n", good(fmt.Sprintf("let in by tpm2-kira's rule in the image (USB %s, %s:%s); the bus blocks new devices", f.BTAuthorize.Port, f.BTAuthorize.Vendor, f.BTAuthorize.Product)))
		}
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
	// Said only when the image really is out of date: what changed since
	// it was built is looked at, not which steps ran.
	if pending := collectFacts(c.o.TPMPath, c.o.Debug).Pending; len(pending) > 0 {
		cmd := "mkinitcpio -P"
		if c.facts.Initramfs == "initramfs-tools" {
			cmd = "update-initramfs -u"
		}
		fmt.Fprintf(c.out, "Rebuild the initramfs for the next boot (%s): %s\n", cmd, strings.Join(pending, "; "))
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
	if err := AttestEnrol(EnrolOptions{
		TPMPath: c.o.TPMPath, Name: name, SHA1: c.facts.UseSHA1, Timeout: 10 * time.Minute, Debug: c.o.Debug,
		VerifyTPM: CheckOff, VerifyPhone: CheckWarn,
	}); err != nil {
		return err
	}
	// Without the prepacked Bluetooth the first phone brings the gate's
	// modules into the image: rebuild now, and the next boot shows
	// "changed" once on the phone. Prepacked, the image is already whole.
	if c.facts.Initramfs == "mkinitcpio" && !c.facts.BTAlways && !c.facts.Phone {
		fmt.Fprintln(c.out)
		fmt.Fprintln(c.out, "The first phone brings the Bluetooth gate into the image: rebuild, and the")
		fmt.Fprintln(c.out, "next boot shows \"changed\" once on the phone - check and approve it there.")
		return c.offerRebuild()
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

// ensureGuide asks, once, how control shall guide - the one guided row,
// or every step by hand - and keeps the answer in control.conf. The last
// entry of the overview switches it any time.
func (c *controller) ensureGuide() error {
	cfg, err := LoadControlConfig(controlConfigPath())
	if err != nil {
		return err // checked at the start; never asked over a file that does not load
	}
	if cfg.Control != "" {
		return nil
	}
	fmt.Fprint(c.out, clearScreen+"\n"+c.header()+"\n\n")
	choice := "guided"
	if err := c.form(huh.NewSelect[string]().Title("How shall control guide you?").
		Description("Kept in "+controlConfigPath()+"; the overview's last entry switches any time.").
		Options(
			huh.NewOption("Guided - one row until the reboot, then the phone and the disk (recommended)", "guided"),
			huh.NewOption("Manual - every step picked by hand; the overview says what is possible and why not", "manual"),
		).Value(&choice)).Run(); err != nil {
		return err
	}
	return setControlGuide(controlConfigPath(), choice)
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

// finishSteps closes every steps() return: in the guided mode the one row
// leads while part 1 is open, and both modes end with the switch to the
// other and keep every explanation of what is possible and why not.
func (c *controller) finishSteps(steps []controlStep) []controlStep {
	f := &c.facts
	guided := f.Guide == "guided"
	if guided {
		open := false
		for _, s := range steps {
			switch s.Key {
			case "setup", "initramfs", "route", "seal":
				open = open || (s.Done == "" && s.Blocked == "")
			}
		}
		if open {
			journey := controlStep{Key: "journey", Title: "Set up this machine (part 1 of 2)", SelfConfirm: true,
				Explain: "One row: the signing key, the mkinitcpio configuration, the key's route, the slots - one rebuild at the end, then the reboot. Part 2 (the phone, and the disk's key) continues after it; a stage already green is skipped, so the row resumes where it stopped.",
				Run:     (*controller).runJourney}
			steps = append([]controlStep{journey}, steps...)
		}
	}
	steps = append(c.imageHints(steps), steps...)
	debugStep := controlStep{Key: "debug", Title: "Debug at boot", Optional: true, SelfConfirm: true,
		Explain: "Makes the code screen and the phone check log every step they take at the next boots, on the console too - for finding out why a phone was not asked. A switch in the TPM (NV index 0x01803000), written with the signing key: no rebuild, the boot image and PCR 11 stay as they are. Picking it again switches it off.",
		Run:     (*controller).runBootDebug}
	switch {
	case f.TPMErr != "":
		debugStep.Blocked = "no TPM: " + f.TPMErr
	case f.Keys == "":
		debugStep.Blocked = "needs the signing key"
	case f.BootDebug:
		debugStep.Done = "on: every boot logs every step until it is switched off"
	}
	// Only where something runs at boot: a slot, or the switch still on.
	if len(f.Status.Slots) > 0 || f.BootDebug {
		steps = append(steps, debugStep)
	}
	// Like the switch: once a code screen exists to hold, or while set.
	if len(f.Status.Slots) > 0 || f.Remote.Net.NetworkdFile() != "" {
		steps = append(steps, c.remoteStep())
	}
	label, target := "Switch to the manual set-up", "manual"
	if !guided {
		label, target = "Switch to the guided set-up", "guided"
	}
	steps = append(steps, controlStep{Key: "guide", Title: label, Optional: true, SelfConfirm: true,
		Explain: "The choice lives in " + controlConfigPath() + " and switches here any time.",
		Run: func(c *controller) error {
			if err := setControlGuide(controlConfigPath(), target); err != nil {
				return err
			}
			c.facts.Guide = target
			fmt.Fprintf(c.out, "%s: TPM2_KIRA_CONTROL=%s\n", controlConfigPath(), target)
			return nil
		}})
	return steps
}

// phase names where the guided set-up stands, under the header.
func (c *controller) phase(steps []controlStep) string {
	if c.facts.Guide != "guided" {
		return ""
	}
	for _, s := range steps {
		if s.Key == "journey" {
			return "\n  Part 1 of 2: the machine, until the reboot"
		}
	}
	for _, s := range steps {
		switch s.Key {
		case "attest", "luks-remote", "luks-salt":
			if s.Done == "" {
				return "\n  Part 2 of 2: the phone, and the disk's key"
			}
		}
	}
	return ""
}

// runJourney is the guided row, part 1: the same functions the steps run,
// in order, each stage skipped when it is green already - the row resumes
// where it stopped - the rebuild once at the end, then the reboot screen.
func (c *controller) runJourney() error {
	type stage struct {
		title string
		open  func() bool
		run   func() error
	}
	stages := []stage{
		{"Signing key", func() bool {
			return c.facts.Keys == "" || (c.facts.YubiKey && !c.facts.PINStored)
		}, c.runSetup},
		{"mkinitcpio configuration", func() bool {
			return c.facts.Initramfs == "mkinitcpio" && c.facts.HookState != ""
		}, c.runInitramfs},
		{"Unlock at boot (the key's route)", func() bool {
			return len(c.facts.Status.Devices) > 0 && c.facts.Status.DevicesError == "" && !routeResolved(&c.facts)
		}, c.runRoute},
		{"TOTP codes at boot (slots 0 and 1)", func() bool {
			slot0, fallback := false, false
			for _, s := range c.facts.Status.Slots {
				slot0 = slot0 || s.Slot == 0
				fallback = fallback || s.Fallback
			}
			return c.facts.Keys != "" && c.facts.TPMErr == "" && (!slot0 || !fallback)
		}, c.runSeal},
	}
	c.batch = true
	defer func() { c.batch = false }()
	for _, st := range stages {
		if !st.open() {
			continue
		}
		fmt.Fprintf(c.out, "\n\033[1m%s\033[0m\n\n", st.title)
		if err := st.run(); err != nil {
			return err
		}
		c.facts = collectFacts(c.o.TPMPath, c.o.Debug)
	}
	c.batch = false
	if c.facts.Initramfs == "mkinitcpio" {
		fmt.Fprintf(c.out, "\n\033[1mThe one rebuild\033[0m\n\n")
		if err := c.offerRebuild(); err != nil {
			return err
		}
	}
	return c.rebootScreen()
}

// rebootScreen closes part 1: the reboot is what makes part 2 possible -
// the code screen runs, 'cap' locks the boot key's answer the designed
// way, and the phone can pin values the next boot matches.
func (c *controller) rebootScreen() error {
	fmt.Fprint(c.out, clearScreen+"\n"+c.header()+"\n\n")
	fmt.Fprintln(c.out, "Part 1 is done. The machine must boot through what was just built:")
	fmt.Fprintln(c.out, "at the boot, compare the code on the screen with your authenticator, press")
	fmt.Fprintln(c.out, "Enter and type your passphrase. Back in the system, run")
	fmt.Fprintln(c.out)
	fmt.Fprintln(c.out, "    sudo tpm2-kira control")
	fmt.Fprintln(c.out)
	fmt.Fprintln(c.out, "again: part 2 - the phone, and the disk's key - continues there.")
	fmt.Fprintln(c.out)
	yes := true
	if err := c.form(huh.NewConfirm().Title("Reboot now?").Description("'Later' leaves the reboot to you.").
		Affirmative("Reboot now").Negative("Later").Value(&yes)).Run(); err != nil || !yes {
		return nil
	}
	fmt.Fprintln(c.out, "Rebooting ...")
	reboot := exec.Command("systemctl", "reboot")
	reboot.Stdout, reboot.Stderr = c.out, c.out
	return reboot.Run()
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
		if c.batch {
			return nil
		}
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
	if c.batch {
		return nil // the guided row rebuilds once, at its end
	}
	return c.offerRebuild()
}

// offerRebuild proposes what belongs into the image before it is built -
// the Bluetooth modules, when an adapter is there, preselected and free to
// deselect - and runs mkinitcpio -P when asked.
func (c *controller) offerRebuild() error {
	if c.facts.Adapter != "" && (c.facts.BTAlways || c.facts.Phone) {
		fmt.Fprintln(c.out, btImagePlan(c.facts.Adapter))
	}
	if c.facts.Adapter != "" && !c.facts.BTAlways {
		ok, err := c.confirmYes("Pack Bluetooth into every boot image (~1.1 MB)?",
			btImagePlan(c.facts.Adapter)+"\n\nWith "+c.facts.Adapter+" in the image from the start, enrolling and removing phones never changes it, and the first enrolment causes no \"changed\" verdict at the next boot. Deselect to keep the image lean: the hook then adds Bluetooth once a phone is enrolled, and that first rebuild shows \"changed\" once. Yes writes TPM2_KIRA_ATTEST_BLUETOOTH=always into "+controlConfigPath()+"; nothing else is edited.")
		if err != nil {
			return err
		}
		if ok {
			if err := setAttestBluetooth(controlConfigPath(), "always"); err != nil {
				return err
			}
			fmt.Fprintf(c.out, "%s: TPM2_KIRA_ATTEST_BLUETOOTH=always\n", controlConfigPath())
			c.facts.BTAlways = true
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
	fmt.Fprintln(c.out)
	fmt.Fprintln(c.out, "Reboot before enrolling a phone or a remote salt: the phone pins what the")
	fmt.Fprintln(c.out, "next boot shows, and the boot key answers only in a boot through this image.")
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

// imageHints are the overview's two hints about the boot image, ahead of
// everything else: rebuild it when it is out of date, and - when it is
// current and this boot is not one through it - reboot. Each can be
// picked to do it; neither is a protection of its own.
func (c *controller) imageHints(steps []controlStep) []controlStep {
	f := &c.facts
	for _, s := range steps {
		// The row and an open wiring step rebuild by themselves.
		if s.Key == "journey" || ((s.Key == "initramfs" || s.Key == "route") && s.Done == "" && s.Blocked == "") {
			return nil
		}
	}
	if f.Initramfs == "" {
		return nil
	}
	if len(f.Pending) > 0 {
		return []controlStep{{Key: "rebuild", Title: "Rebuild the boot image", SelfConfirm: true,
			Explain: "The image the next boot starts is out of date: " + strings.Join(f.Pending, "; ") + ". Picking this rebuilds it.",
			Run: func(c *controller) error {
				if c.facts.Initramfs != "mkinitcpio" {
					return errors.New("run update-initramfs -u")
				}
				return c.offerRebuild()
			}}}
	}
	if len(f.Status.Slots) == 0 || (f.Capped && f.NewImage == "") {
		return nil
	}
	why := "the boot image is ready, and this boot did not go through it"
	if f.NewImage != "" {
		why = f.NewImage
	}
	explain := "The device is ready to be rebooted: " + why + ". At the boot, compare the code on the screen with your authenticator, press Enter and type your passphrase."
	if f.Guide == "guided" && !f.Phone {
		explain += " Part 2 - the phone, and the disk's key - continues afterwards in 'tpm2-kira control'."
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

// pendingRebuild lists the files a boot image is built from that changed
// after the image the next boot starts (mkinitcpioImages) was built.
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
// (or is not there: the defaults). The PIN line is never quoted.
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
	fmt.Fprintf(&b, "\nEdit the file: remove or correct the lines above; every other line, the PIN\n"+
		"included, stays as it is. Then start 'tpm2-kira control' again.\n\n")
	return b.String()
}
