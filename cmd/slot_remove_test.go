package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What a slot is made of, and when it is dirty: parts without the blob.
func TestSlotContentsDirtyAndRemains(t *testing.T) {
	c := SlotContents{Slot: 2, Index: NVRAMSlotStart + 2}
	if c.Any() || c.Dirty() || c.Remains() != "nothing" {
		t.Fatalf("an empty slot: %+v", c)
	}
	c.Blob, c.Generation, c.Counter = true, true, true
	c.Keyslots = []SlotKeyslot{{Device: "/dev/x", KeyslotStatus: KeyslotStatus{Keyslot: 1}}}
	c.Recovery = []string{"a"}
	if c.Dirty() {
		t.Fatal("a whole slot is not dirty")
	}
	if r := c.Remains(); !strings.Contains(r, "the blob") || !strings.Contains(r, "generation index") ||
		!strings.Contains(r, "record counter") || !strings.Contains(r, "keyslot 1 of /dev/x") || !strings.Contains(r, "a recovery blob") {
		t.Fatalf("remains: %s", r)
	}
	c.Blob = false
	if !c.Dirty() {
		t.Fatal("parts without the blob are dirty")
	}
	only := SlotContents{Slot: 2, Recovery: []string{"a", "b"}}
	if !only.Dirty() || !only.Any() || only.Remains() != "2 recovery blobs" {
		t.Fatalf("recovery blobs alone: %+v, %s", only, only.Remains())
	}
	d := dirtText([]SlotContents{c, {Slot: 5, Counter: true}})
	if !strings.Contains(d, "slot 2 is dirty:") || !strings.Contains(d, "; slot 5 is dirty: the record counter left") {
		t.Fatalf("dirtText: %s", d)
	}
	// A recovery blob among the dirt: the other way out is named.
	if !strings.Contains(d, "nvram restore") || strings.Contains(strings.Split(d, ";")[1], "restore") {
		t.Fatalf("the restore alternative: %s", d)
	}
}

// collectSlotContents without a TPM still sees the keyslots and the
// recovery blobs; the TPM parts stay absent for the caller to explain.
func TestCollectSlotContentsWithoutTPM(t *testing.T) {
	oldDir := NVRAMRecoveryDir
	NVRAMRecoveryDir = t.TempDir()
	defer func() { NVRAMRecoveryDir = oldDir }()
	stash := filepath.Join(NVRAMRecoveryDir, "slot-0x01803012-1759823456.blob")
	os.WriteFile(stash, []byte("x"), 0o600)

	devices := []LuksDeviceStatus{{Device: "/dev/x", Keyslots: []KeyslotStatus{
		{Keyslot: 0},
		{Keyslot: 1, Token: &LuksToken{Mode: LuksModePasswordSalt, Slot: 2}},
		{Keyslot: 2, Token: &LuksToken{Mode: LuksModePasswordRemoteSalt, Slot: 0}},
	}}}
	c := collectSlotContents(nil, devices, 2)
	if c.Blob || c.Generation || c.Counter || len(c.Keyslots) != 1 || c.Keyslots[0].Keyslot != 1 || len(c.Recovery) != 1 {
		t.Fatalf("%+v", c)
	}
}

// DeleteSlot takes what it can and reports the rest: the keyslot, its
// token and the recovery blob go although the TPM is not there, and the
// error says the slot stays dirty.
func TestDeleteSlotTakesWhatItCan(t *testing.T) {
	oldDir, oldList, oldCS, oldAuth, oldAsk := NVRAMRecoveryDir, listLuksDevices, cryptsetup, cryptsetupAuth, terminalAsk
	defer func() {
		NVRAMRecoveryDir, listLuksDevices, cryptsetup, cryptsetupAuth, terminalAsk = oldDir, oldList, oldCS, oldAuth, oldAsk
	}()
	NVRAMRecoveryDir = t.TempDir()
	stash := filepath.Join(NVRAMRecoveryDir, "slot-0x01803010-1759823456.blob")
	os.WriteFile(stash, []byte("x"), 0o600)

	const meta = `{
	  "keyslots": {"0": {"type": "luks2"}, "1": {"type": "luks2"}},
	  "tokens": {"0": {"type": "tpm2-kira", "keyslots": ["1"], "mode": "password+salt", "slot": 0, "created": "2026-10-07T17:30:00Z"}}
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
	terminalAsk = func(prompt string) ([]byte, error) { return []byte("recovery"), nil }

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
	if _, statErr := os.Stat(stash); !os.IsNotExist(statErr) {
		t.Fatalf("the recovery blob was not removed: %v", statErr)
	}
	if got := out.String(); !strings.Contains(got, "keyslot 1 removed") {
		t.Fatalf("output: %s", got)
	}

	// The only keyslots of a device are never removed: the device must
	// stay openable, and the failure says what to add first.
	const allOurs = `{
	  "keyslots": {"1": {"type": "luks2"}},
	  "tokens": {"0": {"type": "tpm2-kira", "keyslots": ["1"], "mode": "password+salt", "slot": 0, "created": "2026-10-07T17:30:00Z"}}
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
