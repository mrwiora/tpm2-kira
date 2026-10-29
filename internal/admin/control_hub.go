package admin

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/imageplan"
	"github.com/mrwiora/tpm2-kira/internal/signing"
)

// Step 2 of control: what the machine combines, in submenus. Each option
// is open, done, or greyed with the reason this machine cannot have it
// (no TPM, no Bluetooth adapter, no wired interface, a missing option it
// builds on); the hub's line of a submenu sums its options up. Nothing of
// step 2 is open before the boot chain of step 1 is in place.

// controlMenu is a submenu of step 2.
type controlMenu struct {
	key, title, intro string
	required          bool // a protection: the recommendation while open
}

var controlMenus = []controlMenu{
	{key: "keys", title: "Signing key and TOTP codes", required: true,
		intro: "The signing key approves boot states and authorises every write to the TPM; with it the TOTP codes at boot are sealed into slot 0 (the boot as it is) and slot 1 (the fallback for a boot whose kernel changed unpredicted). Everything else of step 2 builds on them."},
	{key: "phone", title: "Attestation by phone",
		intro: "A phone (Marify, Bluetooth LE) checks the boot state against what it pinned and shows a code the machine shows too; it replaces Enter at the code screen, and it can hand back the salt of a disk key."},
	{key: "disk", title: "Disk unlock",
		intro: "How the disk's key is made at boot, beside the recovery passphrase: each way is a keyslot of its own, and they combine - at boot the one that answers first opens the disk, and cryptsetup's own prompt stays the fallback."},
	{key: "remote", title: "Network and SSH at boot",
		intro: "The boot image's own network - for the vault, and for tpm2-kira's SSH server, where the codes are confirmed and passwords typed remotely. Set for the image alone; the running system's network stays as it is."},
}

func menuByKey(key string) controlMenu {
	for _, m := range controlMenus {
		if m.key == key {
			return m
		}
	}
	return controlMenu{key: key, title: key}
}

// hubSteps are step 2: the image hints, step 1's line, a line per
// submenu, and the boot debug switch.
func (c *controller) hubSteps() []controlStep {
	f := &c.facts
	done := chainDone(f)
	steps := c.imageHints()
	chain := controlStep{Key: "chain", Title: "Step 1: the boot chain", Menu: "chain",
		Explain: "The prerequisites, the sd-tpm2-kira hook in the boot image and the key's route on the kernel command line."}
	if done {
		chain.Done, chain.Optional = "in place", true
	}
	steps = append(steps, chain)
	for _, m := range controlMenus {
		st := summarize(m, c.menuSteps(m.key))
		if !done && st.Dirty == "" {
			st.Done, st.Blocked = "", "needs step 1, the boot chain"
		}
		steps = append(steps, st)
	}
	return append(steps, c.debugStep())
}

// summarize is a submenu's line on step 2: red when an option is, open
// while a protection in it is, else what is done in it, else greyed with
// the reason when nothing in it is possible.
func summarize(m controlMenu, options []controlStep) controlStep {
	st := controlStep{Key: "menu:" + m.key, Title: m.title, Explain: m.intro, Menu: m.key, Optional: !m.required}
	var done, blocked []string
	open, possible := false, false
	for _, o := range options {
		switch {
		case o.Dirty != "":
			if st.Dirty == "" {
				st.Dirty = o.Title + ": " + o.Dirty
			}
		case o.Done != "":
			done = append(done, o.Title)
		case o.Blocked != "":
			blocked = append(blocked, o.Blocked)
		default:
			possible = true
			open = open || !o.Optional
		}
	}
	switch {
	case st.Dirty != "", open:
	case len(done) > 0:
		st.Done = strings.Join(done, ", ")
	case !possible && len(blocked) > 0:
		st.Blocked = blocked[0]
	}
	return st
}

// menuSteps are a submenu's options.
func (c *controller) menuSteps(key string) []controlStep {
	switch key {
	case "keys":
		return c.keysSteps()
	case "phone":
		return c.phoneSteps()
	case "disk":
		return c.diskSteps()
	case "remote":
		return []controlStep{c.netStep(), c.sshStep()}
	}
	return nil
}

// slots finds slot 0, the strong slot (the first that is not the
// fallback: it carries the phone, the phone salt and the vault) and
// whether the fallback is there.
func (c *controller) slots() (slot0, strong *StatusSlot, fallback bool) {
	for i := range c.facts.Status.Slots {
		s := &c.facts.Status.Slots[i]
		if s.Slot == 0 {
			slot0 = s
		}
		if !s.Fallback && strong == nil {
			strong = s
		}
		fallback = fallback || s.Fallback
	}
	return slot0, strong, fallback
}

// boundKeyslots are the keyslots of the recipes bound to a slot, from the
// LUKS headers: "keyslot N of /dev/x".
func (c *controller) boundKeyslots(slot int, recipes ...diskkey.Recipe) []string {
	var out []string
	for _, d := range c.facts.Status.Devices {
		for _, ks := range d.Keyslots {
			if ks.Token != nil && !ks.Token.Obsolete && slices.Contains(recipes, ks.Token.Recipe) && ks.Token.Slot != nil && *ks.Token.Slot == slot {
				out = append(out, fmt.Sprintf("keyslot %d of %s", ks.Keyslot, d.Device))
			}
		}
	}
	return out
}

// keysSteps: the signing key, the standard sealing while a slot of the
// pair is missing, and every populated (or dirty) slot as a line of its
// own that removes the slot whole when picked.
func (c *controller) keysSteps() []controlStep {
	f := &c.facts
	slot0, _, fallback := c.slots()

	keys := controlStep{Key: "setup", Title: "Signing key",
		Explain: "The key that approves boot states and authorises every write to the TPM: local files, or a key on a YubiKey.",
		Run:     (*controller).runSetup}
	switch {
	case f.Keys == "":
	case f.YubiKey && f.PINStored:
		keys.Done = f.Keys + "; its PIN in " + signing.PINPath()
	case f.YubiKey:
		// The key is there, the PIN not: the hooks' reseal after a kernel
		// update is skipped until it is. The step stores it.
		keys.Explain = f.Keys + ". Its PIN, stored in " + signing.PINPath() + " (readable by root alone; never in the boot image), lets the hooks approve unattended after a kernel or initramfs update; without it that approval is skipped and the next boot shows a PCR mismatch."
	default:
		keys.Done = f.Keys
	}
	steps := []controlStep{keys}

	// The standard sealing, slots 0 and 1: the step guides to it while one
	// of the two is missing and seals exactly what lacks; with both in
	// place the slot lines show them and the step disappears ('tpm2-kira
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

	lines := map[int]controlStep{}
	var order []int
	for i := range f.Status.Slots {
		s := f.Status.Slots[i]
		desc := "sealed to " + s.PCRs
		if s.Fallback {
			desc = "the fallback, " + desc
		}
		if s.Phones > 0 {
			desc += ", " + phonesText(s.Phones)
		}
		if s.Vault != "" {
			desc += ", the vault at " + s.Vault
		}
		for _, name := range c.boundKeyslots(s.Slot, diskkey.RecipePhoneSalt, diskkey.RecipeUnattendedVault, diskkey.RecipeUnattendedVaultPepper) {
			desc += ", " + name
		}
		n := s.Slot
		line := controlStep{Key: fmt.Sprintf("slot:%d", n), Title: fmt.Sprintf("Slot %d", n),
			Done: desc, Optional: true, SelfConfirm: true,
			Explain: "Picking a slot deletes it whole: the TOTP key (its codes in the authenticator), the phones, the phone salt, the vault's local part, the LUKS keyslots bound to it, the recovery blobs. Keyslots that are not tpm2-kira's - the recovery passphrase - stay.",
			Run:     func(c *controller) error { return c.runRemoveSlot(n) }}
		if !s.Signed && f.Keys != "" {
			// Sealed with another signing key (one setup made before):
			// reseal cannot approve it, so the next image change takes
			// its code away. It is not done, whatever it is sealed to.
			line.Done, line.Optional = "", false
			line.Dirty = desc + " - not signed by this machine's signing key (" + s.SignReason + "): slot approve cannot approve it; pick it to delete it, then seal again"
		}
		lines[n] = line
		order = append(order, n)
	}
	for _, d := range f.Dirt {
		lines[d.Slot] = dirtyLine(d)
		order = append(order, d.Slot)
	}
	sort.Ints(order)
	for _, n := range order {
		steps = append(steps, lines[n])
	}
	return steps
}

// phoneSteps: the enrolment of a phone, and whether Bluetooth is packed
// into every image.
func (c *controller) phoneSteps() []controlStep {
	f := &c.facts
	_, strong, _ := c.slots()
	attest := controlStep{Key: "attest", Title: "Enrol a phone", Optional: true,
		Explain: "The phone checks the boot state against what it pinned and shows a code the machine must show too; it replaces Enter at the code screen. It is enrolled in a boot whose slot 0 code you compared - the phone takes that boot as the good one - and it asks you so. While a phone is enrolled, slot 0 has no TOTP code (the screen says \"mobile attestation locked - please connect\" until the phone is in); slot 1, the fallback, keeps its code. Removing the last phone gives slot 0 a new TOTP code.",
		Run:     (*controller).runAttest}
	switch {
	case f.Adapter == "":
		attest.Blocked = "no Bluetooth adapter on this machine"
	case f.TPMErr != "":
		attest.Blocked = "no TPM: " + f.TPMErr
	case strong == nil:
		attest.Blocked = "needs slot 0 (Signing key and TOTP codes)"
	case f.AttestConf != "":
		attest.Blocked = controlConfigPath() + ": " + f.AttestConf
	case strong.Phones > 0:
		attest.Done = phonesText(strong.Phones) + " (slot " + fmt.Sprint(strong.Slot) + " has no TOTP code while a phone is enrolled)"
	case f.NewImage != "":
		// Enrolling pins this boot's values; a newer image on disk makes
		// the next boot differ, and a reboot cures both this and the boot
		// key's verdict below.
		attest.Blocked = f.NewImage
	case !f.Capped:
		attest.Blocked = "this boot did not pass tpm2-kira's code screen: reboot, then enrol - the phone would otherwise call the boot key refused instead of locked"
	}
	bt := controlStep{Key: "bt-always", Title: "Bluetooth in every boot image", Optional: true, SelfConfirm: true,
		Explain: "With the adapter in the image from the start (~1.1 MB), enrolling and removing phones never changes it, and the first enrolment causes no \"changed\" verdict at the next boot. Off, the image stays lean and the hook adds Bluetooth once a phone is enrolled. Picking it switches.",
		Run:     (*controller).runBTAlways}
	// What the gate needs at boot: a TPM to quote, and the signing key's
	// public half to check the enrolment with. Without them the plan
	// leaves Bluetooth out, packed always or not.
	switch {
	case f.BTAlways:
		bt.Done = "packed for " + f.Adapter
		if !f.planHas(imageplan.PartPhone) {
			bt.Done = "set, but the image leaves it out: " + f.Plan.Part(imageplan.PartPhone).Why
		}
	case f.Adapter == "":
		bt.Blocked = "no Bluetooth adapter on this machine"
	case f.TPMErr != "":
		bt.Blocked = "no TPM: a phone cannot attest this machine"
	case f.Keys == "":
		bt.Blocked = "needs the signing key (Signing key and TOTP codes)"
	case f.AttestConf != "":
		bt.Blocked = controlConfigPath() + ": " + f.AttestConf
	}
	return []controlStep{attest, bt}
}

// diskGate is what every disk key needs: a LUKS device, a recovery
// passphrase to authorise the keyslot, and the key's route.
func (c *controller) diskGate() string {
	f := &c.facts
	devices := 0
	for _, d := range f.Status.Devices {
		if d.Error == "" {
			devices++
		}
	}
	switch {
	case devices == 0 || f.Status.DevicesError != "":
		return "no LUKS device found"
	case len(f.NoRecovery) >= devices:
		return "needs a recovery passphrase, a keyslot besides tpm2-kira's, to authorise it (cryptsetup luksAddKey)"
	case c.routeStep().Done == "":
		return "needs the key's route (step 1)"
	}
	return ""
}

// diskSteps: the keyslot from a typed salt, the one from the phone's
// salt, the one from this TPM and a vault.
func (c *controller) diskSteps() []controlStep {
	f := &c.facts
	_, strong, _ := c.slots()
	gate := c.diskGate()
	typed := ""
	if f.Remote.SSH.On {
		typed = " With SSH at boot, it is typed in the SSH session as well as at the console."
	}

	// The keyslot from a typed salt: independent of the slots - no TPM is
	// in its key, no slot binding in its token, and deleting a slot leaves
	// it untouched. It coexists with the others: at boot the phone's salt
	// and the vault are tried first, the typed salt is the fallback.
	salt := controlStep{Key: "luks-salt", Optional: true, SelfConfirm: true, Title: "Password + salt (Argon2id)",
		Explain: "A LUKS keyslot whose key is derived at boot from a password and a salt you type (Argon2id, 1 GiB). Bound to no slot - deleting a slot leaves it untouched. Enrolled, picking it offers the removal." + typed,
		Run:     func(c *controller) error { return c.runLuks(diskkey.RecipeRecovery) }}
	switch {
	case gate != "":
		salt.Blocked = gate
	default:
		for _, d := range f.Status.Devices {
			for _, ks := range d.Keyslots {
				if ks.Token != nil && !ks.Token.Obsolete && ks.Token.Recipe == diskkey.RecipeRecovery {
					salt.Done = fmt.Sprintf("keyslot %d of %s", ks.Keyslot, d.Device)
				}
			}
		}
	}

	remote := controlStep{Key: "luks-remote", Optional: true, SelfConfirm: true, Title: "Password + phone salt (the phone)",
		Explain: "A LUKS keyslot whose key is derived from your password and the salt the phone hands back after it attested the boot: the disk needs the phone, this TPM in an approved boot, and your password. Enrolled, picking it offers the removal." + typed,
		Run:     func(c *controller) error { return c.runLuks(diskkey.RecipePhoneSalt) }}
	switch {
	case gate != "":
		remote.Blocked = gate
	case strong == nil:
		remote.Blocked = "needs slot 0 (Signing key and TOTP codes)"
	case len(c.boundKeyslots(strong.Slot, diskkey.RecipePhoneSalt)) > 0:
		remote.Done = strings.Join(c.boundKeyslots(strong.Slot, diskkey.RecipePhoneSalt), ", ")
	case f.Adapter == "":
		remote.Blocked = "needs a phone, and there is no Bluetooth adapter on this machine"
	case strong.Phones == 0:
		remote.Blocked = "needs an enrolled phone (Attestation by phone)"
	case f.NewImage != "":
		remote.Blocked = f.NewImage
	case !f.Capped:
		remote.Blocked = "this boot did not pass tpm2-kira's code screen: reboot, then enrol the salt - the phone would otherwise call the boot key refused instead of locked"
	}
	return []controlStep{salt, remote, c.vaultStep(gate, strong)}
}

// debugStep is the boot settings' debug switch, on step 2 itself.
func (c *controller) debugStep() controlStep {
	f := &c.facts
	st := controlStep{Key: "debug", Title: "Debug at boot", Optional: true, SelfConfirm: true,
		Explain: "Makes the code screen and the phone check log every step they take at the next boots, on the console too - for finding out why a phone was not asked. A switch in the TPM (NV index 0x01803000), written with the signing key: no rebuild, the boot image and PCR 11 stay as they are. Picking it again switches it off.",
		Run:     (*controller).runBootDebug}
	switch {
	case f.TPMErr != "":
		st.Blocked = "no TPM: " + f.TPMErr
	case f.Keys == "":
		st.Blocked = "needs the signing key"
	case f.BootDebug:
		st.Done = "on: every boot logs every step until it is switched off"
	}
	return st
}

// runBTAlways switches TPM2_KIRA_ATTEST_BLUETOOTH between always and auto,
// showing first what goes into the image for the adapter.
func (c *controller) runBTAlways() error {
	value, title := "always", "Pack Bluetooth into every boot image?"
	if c.facts.BTAlways {
		value, title = "auto", "Keep Bluetooth out of the image while no phone is enrolled?"
	}
	ok, err := c.confirmYes(title, btImagePlan(c.facts.Adapter)+"\n\nWritten into "+controlConfigPath()+" as TPM2_KIRA_ATTEST_BLUETOOTH="+value+"; the image is rebuilt when you quit control.")
	if err != nil || !ok {
		return err
	}
	if err := setAttestBluetooth(controlConfigPath(), value); err != nil {
		return err
	}
	c.facts.BTAlways = value == "always"
	fmt.Fprintf(c.out, "%s: TPM2_KIRA_ATTEST_BLUETOOTH=%s\n", controlConfigPath(), value)
	return nil
}
