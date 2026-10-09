package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"
)

// Deleting a slot is one act that removes everything the slot is made of:
// the blob in the TPM (the TOTP key, the phones, the remote salt's release
// key) with its generation index and record counter, the LUKS keyslots
// bound to the slot by their token, and the recovery blobs stashed for it.
// 'control' offers exactly this one way to delete a slot; the expert
// commands (nvram delete, luks remove, attest unenrol, remote-salt unenrol)
// stay for taking one piece by hand. A deletion that fails halfway, or a
// piece taken by hand while the rest stays, leaves the slot *dirty*: parts
// of it exist while its blob is gone. status and control say so until a
// deletion removes what is left.

// SlotKeyslot is one LUKS keyslot bound to a slot.
type SlotKeyslot struct {
	Device string
	KeyslotStatus
}

// SlotContents is everything of one slot that exists.
type SlotContents struct {
	Slot       int
	Index      uint32
	Blob       bool // the slot's blob: TOTP key, phones, release key
	Generation bool // its generation index
	Counter    bool // its record counter
	Keyslots   []SlotKeyslot
	Recovery   []string // stashed blobs of this slot under NVRAMRecoveryDir
}

// Any says whether anything of the slot exists.
func (c SlotContents) Any() bool {
	return c.Blob || c.Generation || c.Counter || len(c.Keyslots) > 0 || len(c.Recovery) > 0
}

// Dirty says whether parts of the slot exist while its blob is gone: a
// deletion stopped halfway, a rewrite failed, or one piece was taken by
// hand. When a recovery blob is among the parts, 'nvram restore' is the
// other way out, and dirtText says so.
func (c SlotContents) Dirty() bool {
	return !c.Blob && c.Any()
}

// Remains names what exists, for a screen or an error.
func (c SlotContents) Remains() string {
	var parts []string
	if c.Blob {
		parts = append(parts, "the blob (TOTP key and phones)")
	}
	if c.Generation {
		parts = append(parts, "the generation index")
	}
	if c.Counter {
		parts = append(parts, "the record counter")
	}
	for _, ks := range c.Keyslots {
		parts = append(parts, fmt.Sprintf("keyslot %d of %s", ks.Keyslot, ks.Device))
	}
	if n := len(c.Recovery); n == 1 {
		parts = append(parts, "a recovery blob")
	} else if n > 1 {
		parts = append(parts, fmt.Sprintf("%d recovery blobs", n))
	}
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, ", ")
}

// collectSlotContents looks at one slot. tpmDev may be nil: the TPM parts
// are then reported as absent, and the caller says why the TPM is not there.
func collectSlotContents(tpmDev transport.TPM, devices []LuksDeviceStatus, slot int) SlotContents {
	c := SlotContents{Slot: slot, Index: NVRAMSlotStart + uint32(slot)}
	if tpmDev != nil {
		c.Blob = NVRAMIndexExists(tpmDev, c.Index)
		c.Generation = NVRAMIndexExists(tpmDev, GenerationIndex(c.Index))
		c.Counter = NVRAMIndexExists(tpmDev, AttestCounterIndex(c.Index))
	}
	for _, d := range devices {
		for _, ks := range d.Keyslots {
			if ks.Token != nil && ks.Token.Slot == slot {
				c.Keyslots = append(c.Keyslots, SlotKeyslot{Device: d.Device, KeyslotStatus: ks})
			}
		}
	}
	c.Recovery, _ = filepath.Glob(fmt.Sprintf("%s/slot-0x%08X-*.blob", NVRAMRecoveryDir, c.Index))
	return c
}

// collectDirt is the dirty slots, for control's overview and the advice
// after a manual delete.
func collectDirt(tpmPath string, devices []LuksDeviceStatus) []SlotContents {
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return nil // without the TPM, "the blob is gone" cannot be told from "cannot look"
	}
	defer tpmDev.Close()
	var out []SlotContents
	for slot := 0; slot <= int(MaxSlotNumber); slot++ {
		if c := collectSlotContents(tpmDev, devices, slot); c.Dirty() {
			out = append(out, c)
		}
	}
	return out
}

// dirtText is the dirty slots in one line.
func dirtText(dirt []SlotContents) string {
	var parts []string
	for _, d := range dirt {
		line := fmt.Sprintf("slot %d is dirty: %s left", d.Slot, d.Remains())
		if len(d.Recovery) > 0 {
			line += " ('tpm2-kira nvram restore' puts a recovery blob back instead)"
		}
		parts = append(parts, line)
	}
	return strings.Join(parts, "; ")
}

// readAllLuksStatuses reads every LUKS device's header; a listing error is
// returned with what could still be read (nothing, then).
func readAllLuksStatuses() ([]LuksDeviceStatus, error) {
	devs, err := listLuksDevices()
	var statuses []LuksDeviceStatus
	for _, d := range devs {
		statuses = append(statuses, readLuksStatus(d))
	}
	return statuses, err
}

// DeleteSlotOptions is what DeleteSlot takes.
type DeleteSlotOptions struct {
	TPMPath string
	Slot    int
	// ExistingKeyFile authorises luksKillSlot instead of the prompt for a
	// remaining passphrase (scripts and tests).
	ExistingKeyFile string
	Debug           bool
	Out             io.Writer // default stdout
}

// DeleteSlot removes everything of one slot. Every part is tried even when
// another fails: what could be removed is gone, and the error lists what is
// left - the slot is then dirty, and a later deletion takes the rest.
func DeleteSlot(o DeleteSlotOptions) error {
	out := o.Out
	if out == nil {
		out = os.Stdout
	}
	var failures []string
	fail := func(format string, a ...any) { failures = append(failures, fmt.Sprintf(format, a...)) }

	devices, devErr := readAllLuksStatuses()
	if devErr != nil {
		fail("the LUKS devices cannot be listed: %v - a keyslot bound to the slot may remain", devErr)
	}
	tpmDev, tpmErr := OpenTPM(o.TPMPath)
	if tpmErr != nil {
		tpmDev = nil
		fail("the TPM at %s cannot be opened: %v - what the slot keeps there was not removed", o.TPMPath, tpmErr)
	} else {
		defer tpmDev.Close()
	}

	c := collectSlotContents(tpmDev, devices, o.Slot)
	if !c.Any() && tpmErr == nil && devErr == nil {
		return fmt.Errorf("slot %d: nothing to delete", o.Slot)
	}
	var phones []string
	if c.Blob {
		if att, err := loadAttestBlob(tpmDev, c.Index); err == nil {
			for _, v := range att.Phone.Verifiers {
				phones = append(phones, v.Name)
			}
		}
	}

	// The LUKS keyslots first: they need a remaining passphrase, so a
	// Ctrl-C at the prompt leaves everything in place.
	for _, d := range devices {
		var bound []SlotKeyslot
		for _, ks := range c.Keyslots {
			if ks.Device == d.Device {
				bound = append(bound, ks)
			}
		}
		if len(bound) == 0 {
			continue
		}
		if len(bound) == len(d.Keyslots) {
			fail("the keyslot(s) of %s bound to slot %d are its only keyslots; removing them would make the device unopenable - add a recovery passphrase first (cryptsetup luksAddKey %s)",
				d.Device, o.Slot, d.Device)
			continue
		}
		existing, err := existingPassphrase(d.Device, o.ExistingKeyFile)
		if err != nil {
			fail("keyslot(s) of %s: no remaining passphrase to authorise luksKillSlot: %v", d.Device, err)
			continue
		}
		for _, ks := range bound {
			if err := killKeyslot(d.Device, ks.KeyslotStatus, existing); err != nil {
				fail("keyslot %d of %s: %v", ks.Keyslot, d.Device, err)
				continue
			}
			fmt.Fprintf(out, "%s keyslot %d removed (was %s)\n", d.Device, ks.Keyslot, describeKeyslot(ks.KeyslotStatus))
		}
		wipe(existing)
	}

	// The slot in the TPM: the blob, then its companions.
	if tpmDev != nil {
		for _, part := range []struct {
			there bool
			index uint32
			what  string
		}{
			{c.Blob, c.Index, "blob (TOTP key and phones)"},
			{c.Generation, GenerationIndex(c.Index), "generation index"},
			{c.Counter, AttestCounterIndex(c.Index), "record counter"},
		} {
			if !part.there {
				continue
			}
			if err := undefineIndex(tpmDev, part.index); err != nil {
				fail("the %s (0x%08X): %v", part.what, part.index, err)
				continue
			}
			fmt.Fprintf(out, "0x%08X removed (the %s)\n", part.index, part.what)
		}
	}

	// The recovery blobs: each holds the slot's sealed secret.
	for _, f := range c.Recovery {
		if err := os.Remove(f); err != nil {
			fail("the recovery blob %s: %v", f, err)
			continue
		}
		fmt.Fprintf(out, "%s removed\n", f)
	}

	if len(failures) > 0 {
		return fmt.Errorf("slot %d is not gone whole:\n  %s\nThe slot is dirty until a deletion removes the rest: fix the cause and delete it again (tpm2-kira control)",
			o.Slot, strings.Join(failures, "\n  "))
	}
	fmt.Fprintf(out, "Slot %d deleted whole.\n", o.Slot)
	if c.Blob {
		fmt.Fprintln(out, "Its code in the authenticator matches nothing now; remove the entry there.")
	}
	if len(phones) > 0 {
		fmt.Fprintf(out, "The phone(s) %s still list this machine; remove it there too.\n", quoted(phones))
	}
	return nil
}

// slotKeyslotAdvice says, after a manual 'nvram delete', which slots are
// dirty now - a LUKS keyslot or a companion index outliving its blob - and
// where the cleanup is. Best effort: "" when nothing is or nothing can be
// read.
func slotKeyslotAdvice(tpmPath string) string {
	devices, _ := readAllLuksStatuses()
	dirt := collectDirt(tpmPath, devices)
	if len(dirt) == 0 {
		return ""
	}
	return dirtText(dirt) + "\n'tpm2-kira control' (Remove a slot) deletes what is left; 'luks remove' takes a keyslot by hand.\n"
}
