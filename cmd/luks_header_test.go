package cmd

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeLuks2Header writes a minimal LUKS2 primary header whose JSON area
// holds the given tokens object, as cryptsetup lays it out: the binary
// header's magic, version and hdr_size, the JSON NUL-padded behind it.
func writeLuks2Header(t *testing.T, tokensJSON string) string {
	t.Helper()
	const hdrSize = 16384
	buf := make([]byte, hdrSize)
	copy(buf, luks2Magic)
	binary.BigEndian.PutUint16(buf[6:8], 2)
	binary.BigEndian.PutUint64(buf[8:16], hdrSize)
	js := `{"keyslots":{},"tokens":` + tokensJSON + `,"segments":{},"digests":{},"config":{}}`
	copy(buf[4096:], js)
	path := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The recipe is read straight from the device's LUKS2 header: the
// tpm2-kira tokens, a foreign token ignored, the remote salt's recipe
// winning over the typed one.
func TestReadLuks2TokensAndRecipe(t *testing.T) {
	dev := writeLuks2Header(t, `{
	  "0": {"type": "tpm2-kira-salt", "keyslots": ["1"], "created": "2026-10-07T17:30:00Z"},
	  "1": {"type": "systemd-tpm2", "keyslots": ["2"], "tpm2-blob": "x"},
	  "2": {"type": "tpm2-kira-remotesalt", "keyslots": ["3"], "slot": 0, "label": "luks", "created": "2026-10-07T18:00:00Z"},
	  "3": {"type": "tpm2-kira", "keyslots": ["4"], "mode": "password+remotesalt", "slot": 0, "created": "x"}
	}`)
	toks, err := ReadLuks2Tokens(dev)
	if err != nil || len(toks) != 3 {
		t.Fatalf("%v %+v", err, toks)
	}
	// The old one-type token is recognised but never acted on: with only
	// it as the remote-salt mark, the typed salt's recipe wins.
	if recipeOfTokens(toks) != LuksModePasswordRemoteSalt {
		t.Fatalf("the remote salt does not win: %q", recipeOfTokens(toks))
	}
	var fresh []LuksToken
	for _, tk := range toks {
		if !tk.Obsolete && tk.Mode == LuksModePasswordSalt {
			fresh = append(fresh, tk)
		}
		if tk.Obsolete {
			fresh = append(fresh, tk)
		}
	}
	if recipeOfTokens(fresh) != LuksModePasswordSalt {
		t.Fatalf("an obsolete token was acted on: %q", recipeOfTokens(fresh))
	}
	if recipeOfTokens(toks[:1]) != LuksModePasswordSalt && recipeOfTokens(toks[1:]) != LuksModePasswordSalt {
		t.Fatal("the typed salt's token was not read")
	}

	plain := writeLuks2Header(t, `{}`)
	if toks, err := ReadLuks2Tokens(plain); err != nil || len(toks) != 0 {
		t.Fatalf("no tokens: %v %+v", err, toks)
	}
	notLuks := filepath.Join(t.TempDir(), "ext4")
	os.WriteFile(notLuks, make([]byte, 8192), 0o600)
	if _, err := ReadLuks2Tokens(notLuks); err == nil || !strings.Contains(err.Error(), "no LUKS2 header") {
		t.Fatalf("a foreign device parsed: %v", err)
	}
}

// A volume's device is found the way the initrd names it: the kernel
// command line first, then the crypttabs - systemd's form and
// cryptsetup-initramfs's target=/source= lines.
func TestVolumeDevice(t *testing.T) {
	dir := t.TempDir()
	defer func(c string, ct []string) { bootCmdlinePath, bootCrypttabPaths = c, ct }(bootCmdlinePath, bootCrypttabPaths)
	bootCmdlinePath = filepath.Join(dir, "cmdline")
	bootCrypttabPaths = []string{filepath.Join(dir, "crypttab"), filepath.Join(dir, "cryptroot")}

	os.WriteFile(bootCmdlinePath, []byte("quiet rd.luks.name=ABCD-1234=cryptroot rd.luks.key=ABCD-1234=/run/tpm2-kira/unlock.sock\n"), 0o644)
	if dev, err := volumeDevice("cryptroot"); err != nil || dev != bootByUUIDDir+"/abcd-1234" {
		t.Fatalf("cmdline: %q %v", dev, err)
	}
	os.WriteFile(bootCrypttabPaths[0], []byte("# c\nother UUID=EEFF-0011 none luks\n"), 0o644)
	if dev, err := volumeDevice("other"); err != nil || dev != bootByUUIDDir+"/eeff-0011" {
		t.Fatalf("crypttab: %q %v", dev, err)
	}
	os.WriteFile(bootCrypttabPaths[1], []byte("target=vda3_crypt,source=/dev/vda3,key=none,rootdev\n"), 0o644)
	if dev, err := volumeDevice("vda3_crypt"); err != nil || dev != "/dev/vda3" {
		t.Fatalf("cryptroot: %q %v", dev, err)
	}
	if _, err := volumeDevice("unknown"); err == nil {
		t.Fatal("an unknown volume resolved")
	}

	// The routed volumes, for the code screen's words.
	uuids := routedUUIDs("rd.luks.name=ABCD-1234=cryptroot rd.luks.key=ABCD-1234=/run/tpm2-kira/unlock.sock luks.key=FFFF-2222=/run/tpm2-kira/unlock.sock rd.luks.key=DDDD-3333=/other.sock", "/run/tpm2-kira/unlock.sock")
	if len(uuids) != 2 || uuids[0] != "abcd-1234" || uuids[1] != "ffff-2222" {
		t.Fatalf("routed: %v", uuids)
	}
}

// unlockRecipe ties the two: the volume's device from the command line,
// the recipe from its header, cached; a volume of nobody's answers "" and
// says why.
func TestUnlockRecipe(t *testing.T) {
	dir := t.TempDir()
	defer func(c string, ct []string) { bootCmdlinePath, bootCrypttabPaths = c, ct }(bootCmdlinePath, bootCrypttabPaths)
	bootCmdlinePath = filepath.Join(dir, "cmdline")
	bootCrypttabPaths = []string{filepath.Join(dir, "crypttab")}
	dev := writeLuks2Header(t, `{"0": {"type": "tpm2-kira-salt", "keyslots": ["1"], "created": "x"}}`)
	os.WriteFile(bootCrypttabPaths[0], []byte("cryptroot "+dev+" none luks\n"), 0o644)

	r := &unlockRecipe{}
	if mode, why := r.forVolume("cryptroot"); mode != LuksModePasswordSalt || why != "" {
		t.Fatalf("recipe: %q %q", mode, why)
	}
	if mode, _ := r.forVolume("cryptroot"); mode != LuksModePasswordSalt { // cached
		t.Fatalf("cached recipe: %q", mode)
	}
	if mode, why := r.forVolume("stranger"); mode != "" || why == "" {
		t.Fatalf("a stranger's volume: %q %q", mode, why)
	}
}
