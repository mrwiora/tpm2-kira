package admin

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tpm2-trust/tpm2-kira/internal/diskkey"
	"github.com/tpm2-trust/tpm2-kira/internal/measure"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/phonegate"
	"github.com/tpm2-trust/tpm2-kira/internal/prompt"
	"github.com/tpm2-trust/tpm2-kira/internal/signing"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"
	"github.com/tpm2-trust/tpm2-kira/internal/wipe"
)

func (c *controller) runSetup() error {
	if c.facts.Keys != "" {
		k, err := signing.LoadCheckedSigningPrivateKey(signing.DefaultPrivateKeyPath)
		if err != nil {
			return err
		}
		if _, ok := signing.YubiKeyDescription(k); !ok {
			// setup never replaces a signing key: a new one leaves every
			// slot and the SSH CA to another key's approvals.
			fmt.Fprintf(c.out, "The signing key is %s: nothing to set again. A new signing key: move %s away, then run this step - every slot is sealed again then, and the SSH CA made again.\n", c.facts.Keys, signing.DefaultKeysDir)
			return nil
		}
	}
	if c.facts.Keys == "" {
		if err := Setup(SetupOptions{Debug: c.o.Debug}); err != nil {
			return err
		}
		k, err := signing.LoadCheckedSigningPrivateKey(signing.DefaultPrivateKeyPath)
		if err != nil {
			return err
		}
		if _, ok := signing.YubiKeyDescription(k); !ok || !signing.YubiKeyWantsPIN(k) {
			return nil
		}
	}
	return c.storePIN()
}

// storePIN asks the YubiKey's PIN, checks it on the token and stores it
// in control.conf for the unattended reseal.
func (c *controller) storePIN() error {
	key, err := signing.LoadCheckedSigningPrivateKey(signing.DefaultPrivateKeyPath)
	if err != nil {
		return err
	}
	return c.storePINOf(key)
}

func (c *controller) storePINOf(key crypto.Signer) error {
	desc, _ := signing.YubiKeyDescription(key)
	pin, err := c.ask().Password("PIN of "+desc,
		"Checked on the token, then stored in "+signing.PINPath()+" for the approval the hooks run; readable by root alone, never in the initramfs.",
		func(b []byte) error {
			if len(b) == 0 {
				return errors.New("the PIN is empty")
			}
			return nil
		})
	if err != nil {
		return err
	}
	defer wipe.Bytes(pin)
	if err := signing.VerifyYubiKeyPIN(key, pin); err != nil {
		return err
	}
	if err := signing.StorePIN(signing.PINPath(), pin); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "%s: the PIN stored, readable by root alone\n", signing.PINPath())
	return nil
}

// runSeal seals what lacks: slot 0 when it is not there - with a TOTP code
// when the person chooses one, and then the fallback slot 1 - else only
// the fallback of slot 0's code, so slot 0's TOTP key (and so its
// authenticator entry) stays as it is. Slot 0's selection is the one the
// analysis evaluated, put up as a recommendation: the person acknowledges
// it, or gives custom PCRs instead (confirmPCRs).
func (c *controller) runSeal() error {
	algo := measure.PCRHashAlgoSHA256
	if c.facts.UseSHA1 {
		algo = measure.PCRHashAlgoSHA1
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
	withTOTP, err := c.confirm("A TOTP code at boot?",
		"The code screen shows a code to compare with your authenticator app before you type anything: it proves the boot is one your signing key approved. Without it the vault, the TPM salt or a phone check the boot, and nothing is shown.")
	if err != nil {
		return err
	}
	fmt.Fprint(c.out, clearScreen)
	if err := Seal(c.o.TPMPath, sel, nvslot.ResolveNVRAMIndex(0), "", "", c.o.Debug, algo, true, withTOTP); err != nil {
		return err
	}
	if fallback || !withTOTP {
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
	return c.ask().Wait(what+" is sealed", "Scan the QR code above with your authenticator now: it is shown this once.", "It is in my authenticator")
}

// confirmPCRs puts the evaluated selection up as the recommendation for
// slot 0: acknowledged, it is sealed as evaluated; else the person gives
// custom PCRs, checked for form (what a selection protects, the overview
// judges afterwards). The fallback slot's selection is fixed by design.
func (c *controller) confirmPCRs() (string, error) {
	f := &c.facts
	const custom = "custom"
	choice, err := prompt.Select(c.ask(), "Slot 0 is sealed to these PCRs", "Evaluated for this machine: "+f.PCRsWhy+".",
		[]prompt.Option[string]{
			{Label: "The recommended " + f.PCRs, Value: f.PCRs},
			{Label: "Custom PCRs", Value: custom},
		}, f.PCRs)
	if err != nil {
		return "", err
	}
	if choice != custom {
		return choice, nil
	}
	return c.ask().Input("PCRs for slot 0",
		"Indices with a source each: none or r the register, e the event log, u the unified kernel image - such as 0e,2e,4u,7e,11u (tpm2-kira help slot).",
		f.PCRs, func(s string) error {
			_, err := measure.ParsePCRSpecs(s)
			return err
		})
}

func (c *controller) runAttest() error {
	name, _ := os.Hostname()
	// The machine's own TPM was judged on the overview (the Vendor line),
	// and the phone checks it authoritatively at enrolment: no second
	// verdict and no ask here. The phone's key is still checked.
	if err := AttestEnrol(EnrolOptions{
		TPMPath: c.o.TPMPath, Name: name, SHA1: c.facts.UseSHA1, Timeout: 10 * time.Minute, Debug: c.o.Debug,
		VerifyTPM: phonegate.CheckOff, VerifyPhone: phonegate.CheckWarn,
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

// runLuks enrols a keyslot of the recipe - or, with one enrolled already,
// offers its removal: the step is a toggle, a second enrolment is not.
func (c *controller) runLuks(recipe diskkey.Recipe) error {
	type enrolled struct {
		device string
		ks     KeyslotStatus
	}
	var have []enrolled
	for _, d := range c.facts.Status.Devices {
		for _, ks := range d.Keyslots {
			if ks.Token != nil && !ks.Token.Obsolete && ks.Token.Recipe == recipe {
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
		fmt.Fprintf(c.out, "This keyslot is enrolled already (%s), so picking the step offers its removal; enrolling anew is this same step. A remaining passphrase (the recovery one) authorises it.\n\n", recipe.Describe())
		ok, err := c.confirmDestroy(fmt.Sprintf("Remove keyslot %d of %s?", e.ks.Keyslot, e.device),
			fmt.Sprintf("keyslot %d of %s (%s): this way opens the disk no more", e.ks.Keyslot, e.device, recipe.Describe()), fmt.Sprint(e.ks.Keyslot))
		if err != nil {
			return err
		}
		if !ok {
			return errKept
		}
		return LuksRemove(LuksRemoveOptions{Device: e.device, Keyslot: e.ks.Keyslot, TPMPath: c.o.TPMPath})
	}
	dev, err := c.pickDevice()
	if err != nil {
		return err
	}
	if err := LuksEnrol(LuksEnrolOptions{
		Device: dev, Recipe: recipe,
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
	removes := "Picking the slot removes what is left of it"
	if len(d.Foreign) > 0 {
		removes = "Picking the slot shows the index of another shape, asks, and removes what is left of it"
	}
	return controlStep{Key: fmt.Sprintf("slot:%d", n), Title: fmt.Sprintf("Slot %d", n),
		Dirty: "dirty: " + d.Remains() + " left", SelfConfirm: true,
		Explain: "Slot " + fmt.Sprint(n) + ": " + d.Cause() + ". " + removes + "; then seal it again (slot add) and enrol its methods.",
		Run:     func(c *controller) error { return c.runRemoveSlot(n) }}
}

// confirmYes is confirm with Yes what Enter alone gives: a proposal to turn down.
func (c *controller) confirmYes(title, description string) (bool, error) {
	return c.ask().Confirm(title, description, true)
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
		if s.PhoneSalt {
			label += ", phone salt"
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
	fmt.Fprintln(c.out, "The authenticator's code for it stops matching. Removing a LUKS keyslot asks for a remaining passphrase (the recovery one); keyslots that are not tpm2-kira's stay.")
	fmt.Fprintln(c.out)
	ok, err := c.confirmDestroy(fmt.Sprintf("Delete slot %d whole?", slot), "slot "+fmt.Sprint(slot)+", "+label, fmt.Sprint(slot))
	if err != nil {
		return err
	}
	if !ok {
		return errKept
	}
	return DeleteSlot(DeleteSlotOptions{TPMPath: c.o.TPMPath, Slot: slot, Debug: c.o.Debug, Out: c.out,
		Foreign: foreignAsk(c.out, c.confirm)})
}

// channelStep is the red line of a slot whose phone channel is sealed to another
// PCR 7 than the next boot's: picking it shows old, new and what moved it, and asks.
func channelStep(slot int) controlStep {
	return controlStep{Key: fmt.Sprintf("channel:%d", slot), Title: fmt.Sprintf("Slot %d's phone channel", slot), SelfConfirm: true,
		Dirty:   fmt.Sprintf("sealed to another PCR %s than the next boot's (risk: no gate, the phones find no machine at the next boot; no hook follows it): pick it to look at what moved it and seal it again", nvslot.ChannelPCRList()),
		Explain: "The phones find no machine until the channel is sealed to the next boot's PCR " + nvslot.ChannelPCRList() + ". Look at what moved it first: a db or dbx update is yours; anything you did not do means this boot is not yours, and sealing hands the channel over to it.",
		Run:     func(c *controller) error { return c.runSealChannel(slot) }}
}

// runSealChannel shows the move, asks, and approves the slot with its channel. The
// move is printed, not the question's description: every form of the question shows it.
func (c *controller) runSealChannel(slot int) error {
	idx := nvslot.ResolveNVRAMIndex(uint32(slot))
	if err := c.showChannelMove(idx); err != nil {
		return err
	}
	ok, err := c.confirm(fmt.Sprintf("Seal slot %d's phone channel to the next boot's PCR %s?", slot, nvslot.ChannelPCRList()),
		"The values above are the ones it follows. No leaves it: the phones find no machine.")
	if err != nil || !ok {
		return errors.New("not sealed: the phones find no machine at the next boot")
	}
	return Reseal(c.o.TPMPath, "", idx, "", "", ChannelSeal, c.o.Debug)
}

// showChannelMove prints old, new and what moved it.
func (c *controller) showChannelMove(idx uint32) error {
	tpmDev, err := tpmdev.Open(c.o.TPMPath)
	if err != nil {
		return err
	}
	defer tpmDev.Close()
	raw, err := nvslot.ReadRecord(idx)
	if err != nil {
		return err
	}
	sb, err := nvslot.UnmarshalSealedBlob(raw)
	if err != nil {
		return err
	}
	move, err := nvslot.ChannelMoves(tpmDev, sb)
	if err != nil {
		return err
	}
	if move == nil {
		return errors.New("the channel has not moved any more")
	}
	printChannelMoveTo(c.out, move)
	return nil
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
	signer, err := signing.LoadCheckedSigningPrivateKey(signing.DefaultPrivateKeyPath)
	if err != nil {
		return err
	}
	if err := signing.PrepareSigningKey(signer); err != nil {
		return err
	}
	tpmDev, err := tpmdev.Open(c.o.TPMPath)
	if err != nil {
		return err
	}
	defer tpmDev.Close()
	if err := nvslot.WriteBootSettings(tpmDev, nvslot.BootSettings{Debug: on}, signer); err != nil {
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
