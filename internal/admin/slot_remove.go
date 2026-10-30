package admin

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
	"github.com/mrwiora/tpm2-kira/internal/wipe"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/mrwiora/tpm2-kira/internal/machineid"
)

// Deleting a slot is one act that removes everything the slot is made of:
// the blob in the TPM (the TOTP key, the phones, the phone salt's release
// key) with its generation index and record counter, the LUKS keyslots
// bound to the slot by their token, and the recovery blobs stashed for it.
// 'control' offers exactly this one way to delete a slot; the expert
// commands (slot delete, luks remove, phone unenrol, phone salt unenrol)
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
	Record     bool // the slot's record (KIRAslotN): TOTP key, phones, release key
	Generation bool // its generation index
	Counter    bool // its record counter
	Keyslots   []SlotKeyslot
}

// Any says whether anything of the slot exists.
func (c SlotContents) Any() bool {
	return c.Record || c.Generation || c.Counter || len(c.Keyslots) > 0
}

// Dirty says whether parts of the slot exist while it is not whole - its
// record and its generation index: a deletion stopped halfway, a record
// removed or a firmware reset, a TPM cleared under its record.
func (c SlotContents) Dirty() bool {
	return c.Any() && (!c.Record || !c.Generation)
}

// Cause says how the slot came to be incomplete, and what that means;
// "" for a whole slot.
func (c SlotContents) Cause() string {
	switch {
	case !c.Dirty():
		return ""
	case c.Record && !c.Generation:
		return "its record is left without its slot in the TPM: the TPM was cleared, or the slot removed without the record - the record's keys are the old TPM's and open nothing"
	case c.Generation && !c.Record:
		return fmt.Sprintf("its record (the EFI variable KIRAslot%d) is gone: removed, or the firmware's variables were reset - its methods fail at boot, the fallbacks unlock (the password and salt typed, the OS recovery passphrase)", c.Slot)
	}
	return "a deletion stopped halfway, or a piece was taken by hand"
}

// Remains names what exists, for a screen or an error.
func (c SlotContents) Remains() string {
	var parts []string
	if c.Record {
		parts = append(parts, fmt.Sprintf("the record (EFI variable KIRAslot%d)", c.Slot))
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
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, ", ")
}

// collectSlotContents looks at one slot. tpmDev may be nil: the TPM parts
// are then reported as absent, and the caller says why the TPM is not there.
func collectSlotContents(tpmDev transport.TPM, devices []LuksDeviceStatus, slot int) SlotContents {
	c := SlotContents{Slot: slot, Index: nvslot.NVRAMSlotStart + uint32(slot)}
	c.Record = nvslot.HasRecord(c.Index)
	if tpmDev != nil {
		c.Generation = tpmdev.NVRAMIndexExists(tpmDev, nvslot.GenerationIndex(c.Index))
		c.Counter = tpmdev.NVRAMIndexExists(tpmDev, nvslot.AttestCounterIndex(c.Index))
	}
	for _, d := range devices {
		for _, ks := range d.Keyslots {
			if ks.Token != nil && ks.Token.BoundTo(slot) {
				c.Keyslots = append(c.Keyslots, SlotKeyslot{Device: d.Device, KeyslotStatus: ks})
			}
		}
	}
	return c
}

// collectDirt is the dirty slots, for control's overview and the advice
// after a manual delete.
func collectDirt(tpmPath string, devices []LuksDeviceStatus) []SlotContents {
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return nil // without the TPM, "the blob is gone" cannot be told from "cannot look"
	}
	defer tpmDev.Close()
	var out []SlotContents
	for slot := 0; slot <= int(nvslot.MaxSlotNumber); slot++ {
		if c := collectSlotContents(tpmDev, devices, slot); c.Dirty() {
			out = append(out, c)
		}
	}
	return out
}

// DirtySlot is an incomplete slot in the status report.
type DirtySlot struct {
	Slot    int    `json:"slot_number"`
	Remains string `json:"remains"`
	Cause   string `json:"cause"`
}

// dirtyReport is the incomplete slots for the status report.
func dirtyReport(dirt []SlotContents) []DirtySlot {
	var out []DirtySlot
	for _, d := range dirt {
		out = append(out, DirtySlot{Slot: d.Slot, Remains: d.Remains(), Cause: d.Cause()})
	}
	return out
}

// dirtText is the dirty slots in one line.
func dirtText(dirt []SlotContents) string {
	var parts []string
	for _, d := range dirt {
		parts = append(parts, fmt.Sprintf("slot %d is dirty: %s left", d.Slot, d.Remains()))
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
	tpmDev, tpmErr := tpmdev.Open(o.TPMPath)
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
	phones := 0
	if c.Record && tpmDev != nil {
		if att, err := phonegate.LoadAttestBlob(tpmDev, c.Index); err == nil {
			phones = len(att.Phone.Verifiers)
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
		wipe.Bytes(existing)
	}

	// The slot, as 'slot delete' takes it: its record, then what it keeps
	// in the TPM. Without the TPM the record goes alone.
	if tpmDev == nil {
		if ok, err := nvslot.RemoveRecord(c.Index); err != nil {
			fail("the record (KIRAslot%d): %v", o.Slot, err)
		} else if ok {
			fmt.Fprintf(out, "the record (EFI variable KIRAslot%d) removed\n", o.Slot)
		}
	} else {
		removed, err := nvslot.RemoveSlot(tpmDev, c.Index)
		for _, r := range removed {
			fmt.Fprintf(out, "0x%08X removed: %s\n", r.Index, r.What)
		}
		if err != nil {
			fail("%v", err)
		} else if c.Index == machineid.Slot {
			if err := removeMachineID(out); err != nil {
				fail("the sealed machine-id: %v", err)
			}
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("slot %d is not gone whole:\n  %s\nThe slot is dirty until a deletion removes the rest: fix the cause and delete it again (tpm2-kira control)",
			o.Slot, strings.Join(failures, "\n  "))
	}
	fmt.Fprintf(out, "Slot %d deleted whole.\n", o.Slot)
	if c.Record {
		fmt.Fprintln(out, "Its code in the authenticator matches nothing now; remove the entry there.")
	}
	if phones > 0 {
		fmt.Fprintf(out, "Your phone(s) still list this machine (%d enrolled); remove it in Marify too.\n", phones)
	}
	return nil
}

// slotKeyslotAdvice says, after a manual 'slot delete', which slots are
// dirty now - a LUKS keyslot or a companion index outliving its blob - and
// where the cleanup is. Best effort: "" when nothing is or nothing can be
// read.
func slotKeyslotAdvice(tpmPath string) string {
	devices, _ := readAllLuksStatuses()
	dirt := collectDirt(tpmPath, devices)
	if len(dirt) == 0 {
		return ""
	}
	return dirtText(dirt) + "\n'tpm2-kira control' (the slot's line) deletes what is left; 'luks remove' takes a keyslot by hand.\n"
}
