package admin

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/vaultkey"

	"charm.land/huh/v2"
)

// control's option for the disk key from this TPM and a vault (tpm+vault,
// docs/VAULT.md): the vault's address, key pin and one-time token
// as 'tpm2-kira-vault token create' prints them, asked here; the vault is
// asked before anything is enrolled - does it answer, with the pinned key -
// and on every look at the machine afterwards, whether it still knows this
// device. The image needs its own network to reach the vault at boot: the
// option sets it up on the way when there is none.

var vaultPinRe = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)

// vaultStep is the option's line under Disk unlock.
func (c *controller) vaultStep(gate string, strong *StatusSlot) controlStep {
	f := &c.facts
	st := controlStep{Key: "luks-vault", Optional: true, SelfConfirm: true, Title: "This TPM + a vault (tpm+vault)",
		Explain: "A LUKS keyslot that opens unattended: its key is made from a part in this TPM and a part the vault (tpm2-kira-vault) releases to a fresh quote of an approved boot - or once an operator approves the boot. Nothing is typed; the recovery passphrase stays the way in when the vault refuses. The boot image reaches the vault over its own network. Enrolled, picking it checks the vault again or removes the keyslot.",
		Run:     (*controller).runVault}
	if f.Remote.SSH.On {
		st.Explain += " SSH at boot stays for the recovery passphrase when the vault does not answer."
	}
	var enrolled *StatusSlot
	for i := range f.Status.Slots {
		if f.Status.Slots[i].Vault != "" {
			enrolled = &f.Status.Slots[i]
		}
	}
	switch {
	case enrolled != nil:
		keyslots := c.boundKeyslots(diskkey.LuksModeTPMVault, enrolled.Slot)
		v := f.Vaults[enrolled.Slot]
		desc := fmt.Sprintf("slot %d with %s", enrolled.Slot, enrolled.Vault)
		if len(keyslots) > 0 {
			desc += ", " + strings.Join(keyslots, ", ")
		}
		switch {
		case len(keyslots) == 0:
			st.Dirty = desc + ", but no keyslot uses it: picking it offers to take the vault out of the slot"
		case f.Remote.Net.Mode == "off":
			st.Dirty = desc + ", but the boot image has no network to reach the vault (Network and SSH at boot)"
		case !v.Answers:
			st.Dirty = desc + ": the vault " + v.Problem
		case !v.Knows:
			st.Dirty = desc + ": the vault answers, but refuses this device (" + v.Problem + ") - revoked?"
		default:
			st.Done = desc + "; the vault answers and knows this device"
		}
	case gate != "":
		st.Blocked = gate
	case f.TPMErr != "":
		st.Blocked = "no TPM: " + f.TPMErr
	case f.Keys == "":
		st.Blocked = "needs the signing key"
	case strong == nil:
		st.Blocked = "needs slot 0 (Signing key and TOTP codes)"
	case f.Initramfs != "mkinitcpio" && f.Initramfs != "initramfs-tools":
		st.Blocked = "the boot image's network is built with mkinitcpio or initramfs-tools only"
	case f.Wired == 0 && f.Remote.Net.Mode == "off":
		st.Blocked = "needs a network in the boot image, and this machine has no wired interface (wireless is not supported there)"
	}
	return st
}

// runVault enrols - the network first when the image has none, then the
// vault's settings, asked until the vault answers with the pinned key, the
// keyslot - or, enrolled, checks again or removes.
func (c *controller) runVault() error {
	f := &c.facts
	for _, s := range f.Status.Slots {
		if s.Vault != "" {
			return c.vaultEnrolled(s)
		}
	}
	_, strong, _ := c.slots()
	if strong == nil {
		return errors.New("needs slot 0")
	}
	if f.Remote.Net.Mode == "off" {
		ok, err := c.confirmYes("The boot image needs a network to reach the vault. Set it up now?",
			"The image's own network (DHCP or a static address), written into "+controlConfigPath()+" - the same as Network and SSH at boot.")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("no network in the boot image: the vault could not be asked at boot")
		}
		if err := c.runNetwork(); err != nil {
			return err
		}
		if c.facts.Remote.Net.Mode == "off" {
			return errors.New("no network in the boot image: the vault could not be asked at boot")
		}
	}

	var url, pin, token string
	pepper := false
	for edit := true; ; {
		if edit {
			if err := c.form(
				huh.NewInput().Title("The vault's address").Description("https://host[:port], as 'tpm2-kira-vault token create' prints it.").
					Value(&url).Validate(func(s string) error {
					_, err := vaultkey.NewClient(strings.TrimSpace(s), "sha256:"+strings.Repeat("0", 64))
					return err
				}),
				huh.NewInput().Title("The vault's key pin").Description("sha256: and 64 hexadecimal characters: the vault is taken for real only with this key.").
					Value(&pin).Validate(func(s string) error {
					if !vaultPinRe.MatchString(strings.TrimSpace(s)) {
						return errors.New("sha256: and 64 hexadecimal characters")
					}
					return nil
				}),
				huh.NewInput().Title("The one-time token").EchoMode(huh.EchoModePassword).
					Value(&token).Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return errors.New("the token 'tpm2-kira-vault token create' printed")
					}
					return nil
				}),
			).Run(); err != nil {
				return err
			}
			url, pin, token = strings.TrimSpace(url), strings.ToLower(strings.TrimSpace(pin)), strings.TrimSpace(token)
		}
		fmt.Fprintf(c.out, "Asking the vault at %s ...\n", url)
		v := vaultkey.Check(url, pin, nil, 10*time.Second)
		if v.Answers {
			fmt.Fprintln(c.out, good("The vault answers, with the pinned key."))
			break
		}
		fmt.Fprintln(c.out, bad("The vault "+v.Problem+"."))
		fmt.Fprintln(c.out, "Asked from the running system: a vault that does not answer here cannot take the enrolment.")
		choice := "again"
		if err := c.form(huh.NewSelect[string]().Title("The vault did not answer").
			Options(huh.NewOption("Ask again", "again"), huh.NewOption("Change the settings", "edit"), huh.NewOption("Cancel", "cancel")).
			Value(&choice)).Run(); err != nil || choice == "cancel" {
			return errors.New("not enrolled: the vault did not answer")
		}
		edit = choice == "edit"
	}
	if err := c.form(huh.NewConfirm().Title("With an operator's pepper?").
		Description("The key then needs a secret an operator gives with each approval on the vault: every boot waits for that approval. Typed here once, never sent at enrolment, never stored by the vault.").
		Affirmative("Yes, with a pepper").Negative("No").Value(&pepper)).Run(); err != nil {
		return err
	}

	dev, err := c.pickDevice()
	if err != nil {
		return err
	}
	name, _ := os.Hostname()
	if err := LuksEnrol(LuksEnrolOptions{Device: dev, Mode: diskkey.LuksModeTPMVault,
		Vault: VaultEnrolOptions{TPMPath: c.o.TPMPath, SealIndex: uint32(strong.Slot), URL: url, Pin: pin, Token: token,
			Name: name, Pepper: pepper, Yes: true, Debug: c.o.Debug}}); err != nil {
		return err
	}
	fmt.Fprintln(c.out, "The vault's line on step 2 says, at every look, whether it still answers and knows this device.")
	return nil
}

// vaultEnrolled is the option picked with a vault in a slot: ask it again,
// or remove the keyslots and the vault's part of the slot.
func (c *controller) vaultEnrolled(s StatusSlot) error {
	v := c.facts.Vaults[s.Slot]
	switch {
	case v.Knows:
		fmt.Fprintf(c.out, "%s: %s\n", s.Vault, good("answers, the pinned key, and it knows this device"))
	default:
		fmt.Fprintf(c.out, "%s: %s\n", s.Vault, bad(v.Problem))
	}
	choice := "check"
	if err := c.form(huh.NewSelect[string]().Title("The vault of slot "+fmt.Sprint(s.Slot)).
		Options(huh.NewOption("Ask the vault again", "check"),
			huh.NewOption("Remove: the tpm+vault keyslots, and the vault's part of the slot", "remove")).
		Value(&choice)).Run(); err != nil {
		return err
	}
	if choice == "check" {
		return nil // the overview asks it again
	}
	ok, err := c.confirm("Remove the vault from slot "+fmt.Sprint(s.Slot)+"?",
		"The tpm+vault keyslots go - removing a keyslot asks for a remaining passphrase (the recovery one) - and the slot's local part with them. The vault keeps its record until its operator revokes the device.")
	if err != nil || !ok {
		return errors.New("not confirmed")
	}
	for _, d := range c.facts.Status.Devices {
		for _, ks := range d.Keyslots {
			if ks.Token != nil && ks.Token.Mode == diskkey.LuksModeTPMVault && ks.Token.Slot != nil && *ks.Token.Slot == s.Slot {
				if err := LuksRemove(LuksRemoveOptions{Device: d.Device, Keyslot: ks.Keyslot}); err != nil {
					return err
				}
			}
		}
	}
	return VaultUnenrol(c.o.TPMPath, uint32(s.Slot), "", c.o.Debug)
}

// pickDevice is the LUKS device a keyslot goes to: the one there is,
// confirmed, or one of several, chosen.
func (c *controller) pickDevice() (string, error) {
	var devices []string
	for _, d := range c.facts.Status.Devices {
		if d.Error == "" {
			devices = append(devices, d.Device)
		}
	}
	if len(devices) == 1 {
		if ok, err := c.confirm("The keyslot goes to "+devices[0]+".", "Go on?"); err != nil || !ok {
			return "", errors.New("not confirmed")
		}
		return devices[0], nil
	}
	i, err := c.choose("Which device gets the keyslot?", devices)
	if err != nil {
		return "", err
	}
	return devices[i], nil
}
