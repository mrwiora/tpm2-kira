package admin

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tpm2-trust/assh/persist"

	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
)

// useTestVars points the EFI variables at a directory of the test's own,
// with a variable of the firmware's in it, as a mounted efivarfs has.
func useTestVars(t *testing.T) {
	t.Helper()
	old := persist.VarDir
	persist.VarDir = t.TempDir()
	t.Cleanup(func() { persist.VarDir = old })
	seedFirmwareVars(persist.VarDir)
}

// seedFirmwareVars puts a firmware's variable into dir: an empty
// directory reads as an efivarfs that is not mounted.
func seedFirmwareVars(dir string) {
	os.WriteFile(filepath.Join(dir, "BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"), []byte{7, 0, 0, 0, 1, 0}, 0o644)
}

// What a slot is made of, and when it is dirty: not whole - its record and
// its generation index - while anything of it is there.
func TestSlotContentsDirtyAndRemains(t *testing.T) {
	c := SlotContents{Slot: 2, Index: nvslot.NVRAMSlotStart + 2}
	if c.Any() || c.Dirty() || c.Remains() != "nothing" {
		t.Fatalf("an empty slot: %+v", c)
	}
	c.Record, c.Generation, c.Counter = true, true, true
	c.Keyslots = []SlotKeyslot{{Device: "/dev/x", KeyslotStatus: KeyslotStatus{Keyslot: 1}}}
	if c.Dirty() {
		t.Fatal("a whole slot is not dirty")
	}
	if r := c.Remains(); !strings.Contains(r, "the record (EFI variable KIRAslot2)") || !strings.Contains(r, "generation index") ||
		!strings.Contains(r, "record counter") || !strings.Contains(r, "keyslot 1 of /dev/x") {
		t.Fatalf("remains: %s", r)
	}
	for what, change := range map[string]func(c *SlotContents){
		"without its record":           func(c *SlotContents) { c.Record = false },
		"without its generation index": func(c *SlotContents) { c.Generation = false },
		"with an earlier version's NV": func(c *SlotContents) { c.OldBlob = true },
	} {
		d := c
		change(&d)
		if !d.Dirty() {
			t.Errorf("a slot %s is not dirty", what)
		}
	}
	old := SlotContents{Slot: 2, OldBlob: true}
	if !old.Dirty() || old.Remains() != "a blob of an earlier version in NV" {
		t.Fatalf("an earlier version's blob alone: %+v, %s", old, old.Remains())
	}
	c.Record = false
	d := dirtText([]SlotContents{c, {Slot: 5, Counter: true}})
	if !strings.Contains(d, "slot 2 is dirty:") || !strings.Contains(d, "; slot 5 is dirty: the record counter left") {
		t.Fatalf("dirtText: %s", d)
	}
}

// collectSlotContents without a TPM still sees the keyslots and the
// record; the TPM parts stay absent for the caller to explain.
func TestCollectSlotContentsWithoutTPM(t *testing.T) {
	useTestVars(t)
	if err := nvslot.WriteRecord(nvslot.NVRAMSlotStart+2, []byte("x")); err != nil {
		t.Fatal(err)
	}

	zero, two := 0, 2
	devices := []LuksDeviceStatus{{Device: "/dev/x", Keyslots: []KeyslotStatus{
		{Keyslot: 0},
		{Keyslot: 1, Token: &diskkey.LuksToken{Recipe: diskkey.RecipePhoneSalt, Slot: &two}},
		{Keyslot: 2, Token: &diskkey.LuksToken{Recipe: diskkey.RecipePhoneSalt, Slot: &zero}},
		{Keyslot: 3, Token: &diskkey.LuksToken{Recipe: diskkey.RecipeRecovery}}, // bound to nothing: no slot takes it
	}}}
	c := collectSlotContents(nil, devices, 2)
	if !c.Record || c.Generation || c.Counter || c.OldBlob || len(c.Keyslots) != 1 || c.Keyslots[0].Keyslot != 1 {
		t.Fatalf("%+v", c)
	}
}

// DeleteSlot takes what it can and reports the rest: the keyslot, its
// token and the record go although the TPM is not there, and the error
// says the slot stays dirty.
func TestDeleteSlotTakesWhatItCan(t *testing.T) {
	oldList, oldCS, oldAuth, oldAsk := listLuksDevices, cryptsetup, cryptsetupAuth, terminalAskExisting
	defer func() {
		listLuksDevices, cryptsetup, cryptsetupAuth, terminalAskExisting = oldList, oldCS, oldAuth, oldAsk
	}()
	useTestVars(t)
	if err := nvslot.WriteRecord(nvslot.NVRAMSlotStart, []byte("x")); err != nil {
		t.Fatal(err)
	}

	const meta = `{
	  "keyslots": {"0": {"type": "luks2"}, "1": {"type": "luks2"}},
	  "tokens": {"0": {"type": "tpm2-kira-1300", "keyslots": ["1"], "recipe": 4864, "slot": 0, "created": "2026-10-07T17:30:00Z"}}
	}`
	listLuksDevices = func() ([]string, error) { return []string{"/dev/fake"}, nil }
	var tokenRemoved, killed []string
	cryptsetup = func(stdin []byte, args ...string) ([]byte, error) {
		switch args[0] {
		case "luksDump":
			return []byte(meta), nil
		case "token":
			tokenRemoved = append(tokenRemoved, strings.Join(args, " "))
		}
		return nil, nil
	}
	cryptsetupAuth = func(key, existing []byte, args ...string) ([]byte, error) {
		if args[0] == "luksKillSlot" && string(existing) == "recovery" {
			killed = append(killed, strings.Join(args, " "))
		}
		return nil, nil
	}
	terminalAskExisting = func(prompt string) ([]byte, error) { return []byte("recovery"), nil }

	var out bytes.Buffer
	err := DeleteSlot(DeleteSlotOptions{TPMPath: filepath.Join(t.TempDir(), "no-tpm"), Slot: 0, Out: &out})
	if err == nil || !strings.Contains(err.Error(), "dirty") || !strings.Contains(err.Error(), "the TPM at") {
		t.Fatalf("the TPM part must be reported: %v", err)
	}
	if len(killed) != 1 || !strings.HasSuffix(killed[0], "/dev/fake 1") {
		t.Fatalf("luksKillSlot: %v", killed)
	}
	if len(tokenRemoved) != 1 || !strings.Contains(tokenRemoved[0], "--token-id 0") {
		t.Fatalf("token remove: %v", tokenRemoved)
	}
	if _, err := nvslot.ReadRecord(nvslot.NVRAMSlotStart); !errors.Is(err, nvslot.ErrNoRecord) {
		t.Fatalf("the record was not removed: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "keyslot 1 removed") || !strings.Contains(got, "KIRAslot0) removed") {
		t.Fatalf("output: %s", got)
	}

	// The only keyslots of a device are never removed: the device must
	// stay openable, and the failure says what to add first.
	const allOurs = `{
	  "keyslots": {"1": {"type": "luks2"}},
	  "tokens": {"0": {"type": "tpm2-kira-1300", "keyslots": ["1"], "recipe": 4864, "slot": 0, "created": "2026-10-07T17:30:00Z"}}
	}`
	cryptsetup = func(stdin []byte, args ...string) ([]byte, error) { return []byte(allOurs), nil }
	killed = nil
	err = DeleteSlot(DeleteSlotOptions{TPMPath: filepath.Join(t.TempDir(), "no-tpm"), Slot: 0, Out: &out})
	if err == nil || !strings.Contains(err.Error(), "unopenable") || !strings.Contains(err.Error(), "recovery passphrase") {
		t.Fatalf("the last keyslot: %v", err)
	}
	if len(killed) != 0 {
		t.Fatal("the last keyslot was killed")
	}
}

// An incomplete slot says how it came to be: a record left by a cleared
// TPM, a record gone, an earlier version's blob, a deletion stopped.
func TestSlotContentsCause(t *testing.T) {
	for _, c := range []struct {
		s    SlotContents
		want string
	}{
		{SlotContents{Slot: 3, Record: true, Generation: true}, ""},
		{SlotContents{Slot: 3, Record: true}, "the TPM was cleared"},
		{SlotContents{Slot: 3, Generation: true, Counter: true}, "KIRAslot3) is gone"},
		{SlotContents{Slot: 3, Record: true, Generation: true, OldBlob: true}, "earlier version"},
		{SlotContents{Slot: 3, Counter: true}, "stopped halfway"},
	} {
		if got := c.s.Cause(); (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%+v: %q, want %q", c.s, got, c.want)
		}
	}
	notes := strings.Join(statusNotes(StatusReport{Dirt: dirtyReport([]SlotContents{{Slot: 3, Generation: true}})}), "\n")
	if !strings.Contains(notes, "slot 3 is incomplete") || !strings.Contains(notes, "is gone") || !strings.Contains(notes, "slot delete --nvram 3") {
		t.Errorf("status notes: %s", notes)
	}
}
