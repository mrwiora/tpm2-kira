package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

// A header's metadata as cryptsetup dumps it: two keyslots, one of them
// ours, one token of another kind.
const luksMetadataSample = `{
  "keyslots": {"0": {"type": "luks2", "key_size": 64}, "1": {"type": "luks2", "key_size": 64}, "2": {"type": "luks2", "key_size": 64}},
  "tokens": {
    "0": {"type": "tpm2-kira", "keyslots": ["1"], "mode": "password+salt", "slot": 0, "created": "2026-10-07T17:30:00Z"},
    "1": {"type": "systemd-tpm2", "keyslots": ["2"], "tpm2-blob": "x"},
    "2": {"type": "tpm2-kira", "keyslots": ["0"], "mode": "password+remotesalt", "slot": 0, "label": "luks", "created": "2026-10-07T18:00:00Z"}
  },
  "segments": {}, "digests": {}, "config": {}
}`

func TestParseLuksMetadata(t *testing.T) {
	slots, err := parseLuksMetadata([]byte(luksMetadataSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 3 || slots[0].Keyslot != 0 || slots[1].Keyslot != 1 || slots[2].Keyslot != 2 {
		t.Fatalf("%+v", slots)
	}
	if slots[1].Token == nil || slots[1].Token.Mode != LuksModePasswordSalt || slots[1].TokenID != 0 {
		t.Fatalf("keyslot 1: %+v", slots[1])
	}
	if slots[0].Token == nil || slots[0].Token.Mode != LuksModePasswordRemoteSalt || slots[0].Token.Slot != 0 || slots[0].TokenID != 2 {
		t.Fatalf("keyslot 0: %+v", slots[0])
	}
	if slots[2].Token != nil {
		t.Fatal("another kind's token taken for ours")
	}
	if d := describeKeyslot(slots[2]); !strings.Contains(d, "not tpm2-kira's") {
		t.Error(d)
	}
	if d := describeKeyslot(slots[1]); !strings.Contains(d, "password+salt") || !strings.Contains(d, "bound to slot 0") || !strings.Contains(d, "token 0") {
		t.Error(d)
	}
	if d := describeKeyslot(slots[0]); !strings.Contains(d, "password+remotesalt") || !strings.Contains(d, "slot 0") || !strings.Contains(d, `"luks"`) {
		t.Error(d)
	}
	if _, err := parseLuksMetadata([]byte("not json")); err == nil {
		t.Fatal("garbage parsed")
	}
}

func TestParseLsblk(t *testing.T) {
	out := `{"blockdevices": [
	  {"path": "/dev/sr0", "fstype": null},
	  {"path": "/dev/vda", "fstype": null, "children": [
	    {"path": "/dev/vda1", "fstype": "vfat"},
	    {"path": "/dev/vda3", "fstype": "crypto_LUKS", "children": [{"path": "/dev/mapper/vda3_crypt", "fstype": "LVM2_member"}]}]},
	  {"path": "/dev/vdb", "fstype": "crypto_LUKS"}]}`
	devs, err := parseLsblk([]byte(out))
	if err != nil || strings.Join(devs, " ") != "/dev/vda3 /dev/vdb" {
		t.Fatalf("%v %v", devs, err)
	}
}

// The token as luks mark writes it round-trips through its JSON, and
// luks status reads the device through cryptsetup (faked here).
func TestLuksStatusReadsTokens(t *testing.T) {
	old := cryptsetup
	defer func() { cryptsetup = old }()
	var imported []byte
	cryptsetup = func(stdin []byte, args ...string) ([]byte, error) {
		switch args[0] {
		case "luksDump":
			return []byte(luksMetadataSample), nil
		case "token":
			imported = stdin
			return nil, nil
		}
		return nil, nil
	}
	st := readLuksStatus("/dev/fake")
	if st.Error != "" || len(st.Keyslots) != 3 {
		t.Fatalf("%+v", st)
	}
	// Marking keyslot 2 (another kind's token is not ours, so it is free).
	if err := LuksMark(LuksMarkOptions{Device: "/dev/fake", Keyslot: 2, Mode: LuksModePasswordSalt}); err != nil {
		t.Fatal(err)
	}
	var tok LuksToken
	if err := json.Unmarshal(imported, &tok); err != nil || tok.Type != LuksTokenType || tok.Keyslots[0] != "2" || tok.Mode != LuksModePasswordSalt || tok.Created == "" {
		t.Fatalf("imported %s: %v", imported, err)
	}
	// The binding is in the header for everyone to see: luksDump's JSON
	// carries "slot": 0, whatever the mode.
	if !strings.Contains(string(imported), `"slot":0`) {
		t.Fatalf("the token does not name its slot: %s", imported)
	}
	// A keyslot marked already is refused; a keyslot that is not there too.
	if err := LuksMark(LuksMarkOptions{Device: "/dev/fake", Keyslot: 1, Mode: LuksModePasswordSalt}); err == nil || !strings.Contains(err.Error(), "marked already") {
		t.Fatalf("marked twice: %v", err)
	}
	if err := LuksMark(LuksMarkOptions{Device: "/dev/fake", Keyslot: 7, Mode: LuksModePasswordSalt}); err == nil || !strings.Contains(err.Error(), "no keyslot 7") {
		t.Fatalf("missing keyslot: %v", err)
	}
	if err := LuksMark(LuksMarkOptions{Device: "/dev/fake", Keyslot: 2, Mode: "hashpwd2"}); err == nil {
		t.Fatal("an unknown mode was taken")
	}
}
