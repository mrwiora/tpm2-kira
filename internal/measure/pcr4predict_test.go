package measure

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/google/go-attestation/attest"
	"github.com/tpm2-trust/go-uefi-slim/authenticode"
	"github.com/tpm2-trust/go-uefi-slim/uki"
)

// minimalEFI is a PE32+ of one section holding data.
func minimalEFI(data string) []byte {
	const peOff, opt = 0x80, 0x80 + 4 + 20
	img := make([]byte, 0x400)
	copy(img, "MZ")
	binary.LittleEndian.PutUint32(img[0x3c:], peOff)
	copy(img[peOff:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(img[peOff+4:], 0x8664)
	binary.LittleEndian.PutUint16(img[peOff+6:], 1)
	binary.LittleEndian.PutUint16(img[peOff+20:], 240)
	binary.LittleEndian.PutUint16(img[peOff+22:], 0x22)
	binary.LittleEndian.PutUint16(img[opt:], 0x20b)
	binary.LittleEndian.PutUint32(img[opt+32:], 0x1000)
	binary.LittleEndian.PutUint32(img[opt+36:], 0x200)
	binary.LittleEndian.PutUint32(img[opt+56:], 0x2000)
	binary.LittleEndian.PutUint32(img[opt+60:], 0x200)
	binary.LittleEndian.PutUint16(img[opt+68:], 10)
	binary.LittleEndian.PutUint32(img[opt+108:], 16)
	sec := opt + 240
	copy(img[sec:], ".text")
	binary.LittleEndian.PutUint32(img[sec+8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(img[sec+12:], 0x1000)
	binary.LittleEndian.PutUint32(img[sec+16:], 0x200)
	binary.LittleEndian.PutUint32(img[sec+20:], 0x200)
	binary.LittleEndian.PutUint32(img[sec+36:], 0x60000020)
	copy(img[0x200:], data)
	return img
}

// imageEvent is an application event for a file, as the firmware logs it.
func imageEvent(path string, digest []byte) attest.Event {
	units := utf16.Encode([]rune(path + "\x00"))
	node := make([]byte, 4, 4+2*len(units))
	node[0], node[1] = 4, 4
	binary.LittleEndian.PutUint16(node[2:], uint16(4+2*len(units)))
	for _, u := range units {
		node = binary.LittleEndian.AppendUint16(node, u)
	}
	// A hard-drive node before it, as in a real log, and the end node after.
	dp := append([]byte{4, 1, 8, 0, 0, 0, 0, 0}, node...)
	dp = append(dp, 0x7f, 0xff, 4, 0)
	data := make([]byte, 32)
	binary.LittleEndian.PutUint64(data[24:], uint64(len(dp)))
	return attest.Event{Index: TPM2PCRBootLoader, Type: attest.EventType(evBootServicesApplication), Data: append(data, dp...), Digest: digest}
}

func espFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	defer func(r []string) { t.Cleanup(func() { espRoots = r }) }(espRoots)
	espRoots = []string{filepath.Join(root, "none"), root}
	for path, data := range files {
		f := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, minimalEFI(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func authHash(t *testing.T, data string, h crypto.Hash) []byte {
	t.Helper()
	d, err := authenticode.HashWith(minimalEFI(data), h)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// The next boot's PCR 4: the images as they are on the ESP, the other events
// as this boot had them, in this boot's order.
func TestPredictPCR4(t *testing.T) {
	for _, tc := range []struct {
		algo PCRHashAlgo
		hash crypto.Hash
	}{{PCRHashAlgoSHA256, crypto.SHA256}, {PCRHashAlgoSHA1, crypto.SHA1}} {
		root := espFixture(t, map[string]string{"EFI/BOOT/BOOTX64.EFI": "new loader", "uki-elsewhere.efi": "new uki"})
		sum := func(s string) []byte { return DigestOf(tc.algo, []byte(s)) }
		events := []attest.Event{
			{Index: 0, Type: 1, Digest: sum("other PCR")},
			{Index: TPM2PCRBootLoader, Type: 0x80000007, Digest: sum("calling")},
			{Index: TPM2PCRBootLoader, Type: evNoAction, Digest: sum("extends nothing")},
			{Index: TPM2PCRBootLoader, Type: 4, Digest: sum("separator")},
			imageEvent(`\EFI\BOOT\BOOTX64.EFI`, authHash(t, "old loader", tc.hash)),
			imageEvent(`\EFI\Linux\arch-linux.efi`, authHash(t, "old uki", tc.hash)),
		}
		p, err := predictPCR4(events, filepath.Join(root, "uki-elsewhere.efi"), tc.algo)
		if err != nil {
			t.Fatal(err)
		}
		want := make([]byte, tc.algo.DigestSize())
		for _, d := range [][]byte{sum("calling"), sum("separator"), authHash(t, "new loader", tc.hash), authHash(t, "new uki", tc.hash)} {
			want = ExtendDigest(tc.algo, want, d)
		}
		if !bytes.Equal(p.Value, want) {
			t.Errorf("%s: %x, want %x", tc.algo, p.Value, want)
		}
		if len(p.Replaced) != 2 || len(p.Kept) != 0 {
			t.Errorf("%s: replaced %v, kept %v", tc.algo, p.Replaced, p.Kept)
		}
	}
}

// An image with no file to hash (not on the ESP, no file path) stays as this
// boot had it, and is named. Nothing changed on disk: the log's own replay.
func TestPredictPCR4Kept(t *testing.T) {
	algo := PCRHashAlgoSHA256
	espFixture(t, map[string]string{"EFI/debian/shimx64.efi": "shim"})
	shim := authHash(t, "shim", crypto.SHA256)
	gone := DigestOf(algo, []byte("gone"))
	mem := imageEvent("", DigestOf(algo, []byte("memory")))
	mem.Data = make([]byte, 32)
	p, err := predictPCR4([]attest.Event{imageEvent(`\EFI\debian\shimx64.efi`, shim), imageEvent(`\EFI\debian\grubx64.efi`, gone), mem}, "", algo)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 32)
	for _, d := range [][]byte{shim, gone, mem.Digest} {
		want = ExtendDigest(algo, want, d)
	}
	if !bytes.Equal(p.Value, want) || len(p.Replaced) != 0 || len(p.Kept) != 2 || !strings.Contains(p.Kept[0], "grubx64") {
		t.Fatalf("%x (want %x), replaced %v, kept %v", p.Value, want, p.Replaced, p.Kept)
	}
	if _, err := predictPCR4([]attest.Event{{Index: TPM2PCRBootLoader, Type: 4, Digest: gone}}, "", algo); err == nil {
		t.Fatal("no image in the log predicted")
	}
}

// The paths of the logs of the machines the tests know.
func TestImageLoadPathOfRealLogs(t *testing.T) {
	for file, want := range map[string][]string{
		"../admin/testdata/arch-uki-eventlog.bin":      {`\EFI\BOOT\BOOTX64.EFI`, `\EFI\Linux\arch-linux.efi`},
		"../admin/testdata/debian13-grub-eventlog.bin": {`\EFI\debian\shimx64.efi`, `\EFI\debian\grubx64.efi`},
	} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		log, err := attest.ParseEventLog(raw)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, e := range log.Events(attest.HashSHA256) {
			if e.Index == TPM2PCRBootLoader && uint32(e.Type) == evBootServicesApplication {
				got = append(got, uki.ImageLoadPath(e.Data))
			}
		}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: %q", file, got)
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), append(append(make([]byte, 24), 0xff, 0xff, 0, 0, 0, 0, 0, 0), 1, 2)} {
		if p := uki.ImageLoadPath(bad); p != "" {
			t.Errorf("%x: %q", bad, p)
		}
	}
}

// 4u is read as the source for PCR 4 alone besides 11, and 4e is refused.
func TestParsePCR4(t *testing.T) {
	specs, err := ParsePCRSpecs("0e,2e,4u,7e,11u")
	if err != nil || specs[2].Index != 4 || specs[2].Source != PCRSourceUKI {
		t.Fatalf("%v %v", specs, err)
	}
	if specs, err := ParsePCRSpecs("4u:/x.efi"); err != nil || specs[0].Command != "/x.efi" {
		t.Fatalf("%v %v", specs, err)
	}
	if _, err := ParsePCRSpecs("4e"); err == nil || !strings.Contains(err.Error(), "4u") {
		t.Fatalf("4e: %v", err)
	}
	if _, err := ParsePCRSpecs("7u"); err == nil {
		t.Fatal("7u")
	}
}

// The prediction from a log file: the real Debian log's images, on an ESP that
// holds none of them, stays the log's own replay of PCR 4.
func TestPredictPCR4FromLog(t *testing.T) {
	espFixture(t, nil)
	p, err := PredictPCR4("../admin/testdata/debian13-grub-eventlog.bin", "", PCRHashAlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Kept) != 2 || len(p.Replaced) != 0 || len(p.Value) != 32 {
		t.Fatalf("%+v", p)
	}
	if _, err := PredictPCR4("/nonexistent", "", PCRHashAlgoSHA256); err == nil {
		t.Fatal("no log")
	}
}
