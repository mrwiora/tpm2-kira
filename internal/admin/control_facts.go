package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/internal/diskkey"
	"github.com/tpm2-trust/tpm2-kira/internal/imageplan"
	"github.com/tpm2-trust/tpm2-kira/internal/measure"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/phonegate"
	"github.com/tpm2-trust/tpm2-kira/internal/sbstate"
	"github.com/tpm2-trust/tpm2-kira/internal/signing"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"
	"github.com/tpm2-trust/tpm2-kira/internal/vaultkey"
)

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
	EKUnknown  bool   // the EK root store has no root of the TPM's vendor yet: a risk, not untrusted
	SecureBoot sbstate.State
	Proof      *secureBootProof // what a phone and the vault will establish; nil when it cannot be read
	// MemoryMiB is the machine's RAM as its kernel counts it, 0 when it could
	// not be read; below diskkey.MinMemoryMiB the boot's derivation may not fit.
	MemoryMiB  uint64
	Initramfs  string // mkinitcpio, initramfs-tools, or ""
	HookState  string // why the boot integration would not run; "" when wired
	Rebuild    string // mkinitcpio: why the image still lacks the hook; "" when it carries it
	Adapter    string // hciN, or ""
	AttestConf string // "" when control.conf loads; else the reason

	Status   StatusReport   // the slots, the unlock mode, the LUKS devices, the notes
	Dirt     []SlotContents // slots whose blob is gone but of which parts remain
	Phone    bool           // a phone is enrolled for some slot
	Salt     bool           // a phone salt is enrolled for some slot
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
	// PCRKey: the PCR key exists; UKISigns: uki.conf has ukify sign with it;
	// UKISigErr: why the image built does not carry what the slots need.
	PCRKey    bool
	UKISigns  bool
	UKISigErr string
	// NoRecovery are the LUKS devices without a keyslot that is not
	// tpm2-kira's: nothing to authorise an enrolment, no way in by hand.
	NoRecovery []string
	// EmptyPass are the keyslots that open with an empty passphrase,
	// "keyslot N of /dev/x"; EmptyPassErr says why the test did not run.
	EmptyPass    []string
	EmptyPassErr string
	Wired        int // wired network interfaces: the image's network needs one
	// PlainSwap are the swaps a hibernation would write the memory to in
	// the clear (swap.go); empty when the kernel offers no hibernation.
	PlainSwap []string
	// SSHKeys is how many keys may log in at boot (-1: the file cannot be
	// read); SSHCA the SSH CA and its approval of the next boot. Both only
	// with SSH on.
	SSHKeys int
	SSHCA   sshCAState
	// SSHCAOtherKey: the SSH CA was made for another signing key than this
	// machine's, so reseal cannot approve it.
	SSHCAOtherKey bool
	// Vaults is each vault-enrolled slot's vault, asked now.
	Vaults   map[int]vaultkey.CheckResult
	Closed   bool   // PCR 15 is extended: this boot went through the code screen's close
	NewImage string // an image was rebuilt after this boot started; "" when not
	Routed   map[string]bool
	Route    []RouteFinding // the route's findings, for the step that writes the fixes
	Remote   RemoteConfig   // the boot image's network and SSH server (control.conf)
}

// collectFacts is the analysis.
func collectFacts(tpmPath string, debug bool) machineFacts {
	f := machineFacts{TPM: tpmPath, Routed: map[string]bool{}}

	if tpmDev, err := tpmdev.Open(tpmPath); err != nil {
		f.TPMErr = err.Error()
	} else {
		f.SHA256Bank = measure.TPMHasPCRBank(tpmDev, measure.PCRHashAlgoSHA256)
		f.SHA1Bank = measure.TPMHasPCRBank(tpmDev, measure.PCRHashAlgoSHA1)
		tpmDev.Close()
	}
	if _, err := measure.ReadRawEventLogFromPath(measure.DefaultEventlogPath); err == nil {
		f.LogRead = true
		if d, err := measure.EventDigestsForPCR(measure.DefaultEventlogPath, 0, measure.PCRHashAlgoSHA256); err == nil && len(d) > 0 {
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
	algo := measure.PCRHashAlgoSHA256
	if f.UseSHA1 {
		algo = measure.PCRHashAlgoSHA1
	}
	f.PCRs, f.PCRsWhy = DefaultPCRSelection("", algo)

	if _, err := os.Stat(signing.DefaultPrivateKeyPath); err == nil {
		f.Keys = "local key files in " + signing.DefaultKeysDir
		if k, err := signing.LoadCheckedSigningPrivateKey(signing.DefaultPrivateKeyPath); err == nil {
			if desc, ok := signing.YubiKeyDescription(k); ok {
				f.Keys = desc
				f.YubiKey = signing.YubiKeyWantsPIN(k)
			}
		}
	}
	if stored, loose := signing.PINStored(signing.PINPath()); stored {
		f.PINStored, f.PINLoose = !loose, loose
	}
	f.SecureBoot = sbstate.Read()
	if f.TPMErr == "" {
		bank := uint16(attest.AlgSHA256)
		if f.UseSHA1 {
			bank = attest.AlgSHA1
		}
		f.Proof = readSecureBootProof(tpmPath, bank)
	}
	f.MemoryMiB = diskkey.MemTotalMiB()
	if f.TPMErr == "" {
		f.EKBy, f.EKNote, f.EKUnknown = ekVerdict(tpmPath, debug)
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
		_, keyErr := os.Stat(pcrKeyPath)
		f.PCRKey, f.UKISigns = keyErr == nil, ukiConfSigns()
		if f.UKISigns {
			f.UKISigErr = "no unified kernel image found"
			if uki := findUKI(); uki != "" {
				f.UKISigErr = ukiSignedReason(uki)
			}
		}
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
		f.BootDebug = nvslot.BootDebug(tpmPath)
		if tpmDev, err := tpmdev.Open(tpmPath); err == nil {
			f.Closed = nvslot.Closed(tpmDev)
			tpmDev.Close()
		}
	}
	if f.TPMErr == "" {
		f.Dirt = collectDirt(tpmPath, f.Status.Devices)
	}
	f.NoRecovery, f.EmptyPass, f.EmptyPassErr = recoveryFacts(f.Status.Devices)
	f.PlainSwap = plainSwaps()
	for _, s := range f.Status.Slots {
		if s.Vault != "" {
			if f.Vaults == nil {
				f.Vaults = map[int]vaultkey.CheckResult{}
			}
			f.Vaults[s.Slot] = vaultkey.Check(s.Vault, s.VaultPin, s.VaultDevice, 5*time.Second)
		}
		f.Phone = f.Phone || s.Phones > 0
		f.Salt = f.Salt || s.PhoneSalt
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
		if pub, err := signing.LoadCheckedSigningPublicKey(signing.DefaultPublicKeyPath); err == nil {
			f.SSHCAOtherKey = !samePublicKey(f.SSHCA.CA.AuthorityKey(), pub)
		}
	}
	if f.HookState == "" {
		f.Pending, f.Unused, f.ImageErr = imageState(f.Initramfs, f.Plan)
		if f.Rebuild != "" {
			f.Pending = append([]string{f.Rebuild}, f.Pending...)
		}
		if f.UKISigns && f.UKISigErr != "" {
			f.Pending = append(f.Pending, "the image lacks the PCR key's signature of PCR 11")
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
		specs, err := measure.ParsePCRSpecs(s.PCRs)
		if err != nil {
			continue
		}
		if kernelInitrd, cmdline := measure.BootChainCoverage(measure.PCRSpecIndices(specs)); !kernelInitrd || !cmdline {
			weak = append(weak, s.Slot)
		}
	}
	return weak
}

// ekVerdict is what a phone concludes about this TPM's endorsement key:
// the vendor whose certificate chain vouches for it, or why none does.
func ekVerdict(tpmPath string, debug bool) (by, note string, unknown bool) {
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return "", err.Error(), false
	}
	defer tpmDev.Close()
	defer tpmdev.Cleanup(tpmDev, debug)
	alg, ek, pub, err := phonegate.PickCertifiedEK(tpmDev)
	if err != nil {
		return "", err.Error(), false
	}
	tpmdev.FlushHandle(tpmDev, ek.Handle)
	leaf := phonegate.ReadEKCert(tpmDev, alg)
	by, err = attest.VerifyEKCertificate(pub, leaf, phonegate.ReadEKCertChain(tpmDev, leaf), time.Now())
	if err != nil {
		return "", attest.EKCertNote(err), attest.IsVendorUnknown(err)
	}
	return by, "", false
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// factsText is "What this machine has", one line per fact, each marked
// green when it is as it should be and red with the risk in brackets
// when it is not.
// memoryNeed is the floor, as the memory lines say it.
func memoryNeed() string { return fmt.Sprintf("at least %d MiB", diskkey.MinMemoryMiB) }

func (c *controller) factsText() string {
	f := &c.facts
	var w strings.Builder
	switch {
	case f.TPMErr != "":
		fmt.Fprintf(&w, "  TPM         %s\n", bad(fmt.Sprintf("none usable (%s)", f.TPMErr)))
	case f.UseSHA1:
		fmt.Fprintf(&w, "  TPM         %s\n", warn(fmt.Sprintf("%s - %s; the SHA-1 bank is used (risk: SHA-1 collisions are practical, a measured boot can in principle be forged)", f.TPM, f.SHA1Why)))
	case f.LogSHA256:
		fmt.Fprintf(&w, "  TPM         %s\n", good(f.TPM+", SHA-256 bank and event log"))
	default:
		fmt.Fprintf(&w, "  TPM         %s, SHA-256 bank; no event log to read, the registers as they are\n", f.TPM)
	}
	if f.TPMErr == "" {
		switch {
		case f.EKBy != "":
			fmt.Fprintf(&w, "  Vendor      %s\n", good(f.EKBy+" vouches for the endorsement key"))
		case f.EKUnknown:
			fmt.Fprintf(&w, "  Vendor      %s\n", warn("not known yet: "+f.EKNote))
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
		fmt.Fprintf(&w, "  Secure Boot %s\n", bad("state unknown, "+f.SecureBoot.Why+" (risk: whether PCR 7 attests an enforced policy is unknown)"))
	case f.SecureBoot.SetupMode:
		fmt.Fprintf(&w, "  Secure Boot %s\n", bad("Setup Mode (risk: any root user can replace the keys, PCR 7 attests a policy that can be rewritten)"))
	case f.SecureBoot.Enabled:
		fmt.Fprintf(&w, "  Secure Boot %s\n", good("enabled"))
	default:
		fmt.Fprintf(&w, "  Secure Boot %s\n", bad("disabled (risk: the boot loader and the kernel run unsigned, and PCR 7 records only that)"))
	}
	if f.Proof != nil {
		if line, ok := f.Proof.text(); ok {
			fmt.Fprintf(&w, "  Proof       %s\n", good(line))
		} else {
			fmt.Fprintf(&w, "  Proof       %s\n", bad(line))
		}
	}
	switch {
	case f.MemoryMiB == 0:
		fmt.Fprintf(&w, "  Memory      %s\n", bad(fmt.Sprintf("not known (risk: the disk's key takes %s at boot, in an initrd without swap)", memoryNeed())))
	case f.MemoryMiB < diskkey.MinMemoryMiB:
		fmt.Fprintf(&w, "  Memory      %s\n", bad(fmt.Sprintf("%d MiB (risk: the disk's key takes %s at boot, in an initrd without swap: the kernel kills what does not fit, and only the passphrase by hand may still work)", f.MemoryMiB, memoryNeed())))
	default:
		fmt.Fprintf(&w, "  Memory      %s\n", good(fmt.Sprintf("%d MiB, the boot's Argon2id needs %d", f.MemoryMiB, diskkey.MinMemoryMiB)))
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
			fmt.Fprintf(&w, "  Slots       %s\n", bad(fmt.Sprintf("%s - slot %s leaves the kernel, the initrd or the command line unmeasured (risk: a replaced initrd or an edited command line still shows a valid code - approve with 11u, or 8e,9e)",
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
		fmt.Fprintf(&w, "  Key         %s\n", bad(fmt.Sprintf("%s (risk: %s holds the PIN, but other users can read it, or root does not own it - chown root:, chmod 600, consider a new PIN)", keyDesc, signing.PINPath())))
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
	if f.Status.CloseFinding != "" {
		fmt.Fprintf(&w, "  Close       %s\n", bad(f.Status.CloseFinding))
	}
	phone := f.planHas(imageplan.PartPhone)
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
	if len(f.PlainSwap) > 0 {
		fmt.Fprintf(&w, "  Hibernation %s\n", bad("to unencrypted swap: "+strings.Join(f.PlainSwap, ", ")+" (risk: the memory - the disk's key included - lands on the disk in the clear, and a resume from it runs past the boot image, the SSH CA open - encrypt the swap or disable hibernation)"))
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
