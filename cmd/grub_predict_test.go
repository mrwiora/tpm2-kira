package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/google/go-attestation/attest"
)

// The log of a Debian 13 boot (GRUB 2.12, kernel 6.12 with the EFI stub),
// with the digests of the files GRUB read as they were on that machine.
var debianFiles = map[string]string{
	"/boot/efi/EFI/debian/grub.cfg":         "e3956d7a55b8dc725aa5e7cc06cfaf7c57ca836de511af326094a638e9c86f68",
	"/boot/grub/x86_64-efi/command.lst":     "aef695413d1a1b9eaff753a15512d0ba79e23e5524033eec20c7a1c7c20eb1c4",
	"/boot/grub/grub.cfg":                   "66f0909a813c245fc8d9fcc3686533af022600de76d884bc36ebe29585e3aa69",
	"/boot/grub/grubenv":                    "f64122858064885ef0733e42c6a3d2d3fd642671f714db0d974b880c0f087430",
	"/boot/grub/x86_64-efi/bli.mod":         "a93f6959d35677880315454fbc7f54941a691e22f7e90ec2bed7e149690a8dec",
	"/boot/vmlinuz-6.12.111+deb13-amd64":    "6d8a7f745280cc06a6d2877c932f4dfa9079b694eb4227b61b27232642340794",
	"/boot/initrd.img-6.12.111+deb13-amd64": "7cb37648496d7356612e3180642fefce7ae4b35c322b49e993cbfacc26e8c932",
}

const (
	debianPCR8 = "c0d3f16211f0129be0c12e208cad72bb752aa8c797123f3265870453f12bc3b2"
	debianPCR9 = "6414e9f13844beb3f1afd8db6eddac473caa7fd192d23ac6c335a740ec2adc99"
)

func debianEvents(t *testing.T) []attest.Event {
	t.Helper()
	raw, err := os.ReadFile("testdata/debian13-grub-eventlog.bin")
	if err != nil {
		t.Fatal(err)
	}
	log, err := attest.ParseEventLog(raw)
	if err != nil {
		t.Fatal(err)
	}
	return log.Events(attest.HashSHA256)
}

func replay89(events []attest.Event) (pcr8, pcr9 string) {
	calc := &EventlogPCRCalculator{PCRIndices: []int{8, 9}, HashAlgo: PCRHashAlgoSHA256}
	pcrs, _, _, _, _ := calc.replayEventLog(events)
	return hex.EncodeToString(pcrs[8]), hex.EncodeToString(pcrs[9])
}

// mapFiles is grubFiles over digests, with grub.cfg's contents from the
// machine's file (its digest is the file's).
type mapFiles struct {
	digests map[string]string
	grubCfg []byte
}

func (m mapFiles) Digest(path string) ([]byte, bool) {
	if path == "/boot/grub/grub.cfg" && m.grubCfg != nil {
		d := sha256.Sum256(m.grubCfg)
		return d[:], true
	}
	h, ok := m.digests[path]
	if !ok {
		return nil, false
	}
	b, _ := hex.DecodeString(h)
	return b, true
}

func (m mapFiles) Read(path string) ([]byte, bool) {
	if path == "/boot/grub/grub.cfg" {
		return m.grubCfg, m.grubCfg != nil
	}
	return nil, false
}

func digestsFrom(files map[string]string) mapFiles {
	cfg, _ := os.ReadFile("testdata/debian13-grub.cfg")
	return mapFiles{digests: files, grubCfg: cfg}
}

// The menu commands rebuilt from the machine's grub.cfg hash to what GRUB
// measured.
func TestGrubMenuCommandMatchesTheLog(t *testing.T) {
	cfg, err := os.ReadFile("testdata/debian13-grub.cfg")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range debianEvents(t) {
		_, cmd, _ := strings.Cut(eventText(e), ": ")
		if e.Index != 8 || !(strings.HasPrefix(cmd, "menuentry ") || strings.HasPrefix(cmd, "submenu ")) {
			continue
		}
		rebuilt, ok := grubMenuCommand(cfg, menuID(cmd))
		if !ok {
			t.Fatalf("not found in grub.cfg: %q", menuID(cmd))
		}
		if rebuilt != cmd {
			t.Fatalf("rebuilt:\n%q\nlogged:\n%q", rebuilt, cmd)
		}
		n++
	}
	if n != 3 { // the simple entry, the advanced submenu, UEFI firmware settings
		t.Fatalf("%d menu commands", n)
	}
}

// With nothing changed on disk the prediction is the log: the machine's
// PCR 8 and 9 come out, and the file events were not touched (the digest
// conventions hold for every grub_cmd, kernel_cmdline and tag event).
func TestPredictGRUBReproducesTheBoot(t *testing.T) {
	events := debianEvents(t)
	if p8, p9 := replay89(events); p8 != debianPCR8 || p9 != debianPCR9 {
		t.Fatalf("the log does not replay to the machine's PCRs: %s %s", p8, p9)
	}
	p := predictGRUB(events, digestsFrom(debianFiles), []string{"6.12.86+deb13-amd64", "6.12.111+deb13-amd64"})
	if len(p.Substituted) != 0 || p.NewKernel != "" {
		t.Fatalf("substituted without a change: %v %q", p.Substituted, p.NewKernel)
	}
	if p8, p9 := replay89(events); p8 != debianPCR8 || p9 != debianPCR9 {
		t.Fatal("an unchanged prediction changed the PCRs")
	}
	// Every PCR 8 event reproduces from its text: the convention is known.
	for _, e := range events {
		if e.Index != 8 {
			continue
		}
		_, cmd, _ := strings.Cut(eventText(e), ": ")
		if d := sha256.Sum256([]byte(cmd)); !bytes.Equal(d[:], e.Digest) {
			t.Errorf("PCR8 %q does not hash as its text", eventText(e))
		}
	}
}

// A rebuilt initrd: two PCR 9 events change (the file GRUB read and the
// stub's initrd tag), PCR 8 does not, and PCR 9 replays to the extend of
// the new digest at those two places.
func TestPredictGRUBAfterUpdateInitramfs(t *testing.T) {
	events := debianEvents(t)
	files := map[string]string{}
	for k, v := range debianFiles {
		files[k] = v
	}
	newInitrd := strings.Repeat("ab", 32)
	files["/boot/initrd.img-6.12.111+deb13-amd64"] = newInitrd
	p := predictGRUB(events, digestsFrom(files), []string{"6.12.111+deb13-amd64"})
	if len(p.Substituted) != 2 || !strings.Contains(p.Substituted[0], "initrd.img") || !strings.Contains(p.Substituted[1], "Linux initrd") {
		t.Fatalf("substituted: %v", p.Substituted)
	}
	p8, p9 := replay89(events)
	if p8 != debianPCR8 {
		t.Fatal("PCR 8 changed on an initrd rebuild")
	}
	// The expected PCR 9 by hand: the log with the two digests swapped.
	want := debianEvents(t)
	n := 0
	for i := range want {
		if want[i].Index == 9 && hex.EncodeToString(want[i].Digest) == debianFiles["/boot/initrd.img-6.12.111+deb13-amd64"] {
			want[i].Digest, _ = hex.DecodeString(newInitrd)
			n++
		}
	}
	_, want9 := replay89(want)
	if n != 2 || p9 != want9 || p9 == debianPCR9 {
		t.Fatalf("PCR 9 %s, want %s (%d swapped)", p9, want9, n)
	}
}

// A kernel update: the version string moves in the file names, the GRUB
// commands, the kernel command line and the load options; grub.cfg has
// changed too. Everything that names the version is substituted.
func TestPredictGRUBAfterKernelUpdate(t *testing.T) {
	events := debianEvents(t)
	files := map[string]string{}
	for k, v := range debianFiles {
		files[k] = v
	}
	files["/boot/vmlinuz-6.12.120+deb13-amd64"] = strings.Repeat("11", 32)
	files["/boot/initrd.img-6.12.120+deb13-amd64"] = strings.Repeat("22", 32)
	p := predictGRUB(events, digestsFrom(files), []string{"6.12.86+deb13-amd64", "6.12.111+deb13-amd64", "6.12.120+deb13-amd64"})
	if p.NewKernel != "6.12.120+deb13-amd64" {
		t.Fatalf("new kernel %q", p.NewKernel)
	}
	joined := strings.Join(p.Substituted, "\n")
	for _, want := range []string{
		"PCR8 grub_cmd: echo Loading Linux 6.12.120+deb13-amd64 ...",
		"PCR8 grub_cmd: linux /vmlinuz-6.12.120+deb13-amd64 root=/dev/mapper/debian--vg-root ro quiet",
		"PCR9 /vmlinuz-6.12.111+deb13-amd64: now /boot/vmlinuz-6.12.120+deb13-amd64",
		"PCR8 kernel_cmdline: /vmlinuz-6.12.120+deb13-amd64 root=/dev/mapper/debian--vg-root ro quiet",
		"PCR8 grub_cmd: initrd /initrd.img-6.12.120+deb13-amd64",
		"PCR9 /initrd.img-6.12.111+deb13-amd64: now /boot/initrd.img-6.12.120+deb13-amd64",
		"PCR9 LoadOptions: BOOT_IMAGE=/vmlinuz-6.12.120+deb13-amd64 root=/dev/mapper/debian--vg-root ro quiet",
		"PCR9 Linux initrd: the initrd on disk",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
	// The two menu commands come from grub.cfg, which the test keeps as
	// it was, so they are not among the substitutions; the digest of
	// grub.cfg itself is the file's, so it is not substituted either.
	if len(p.Substituted) != 8 {
		t.Errorf("%d substitutions:\n%s", len(p.Substituted), joined)
	}
	p8, p9 := replay89(events)
	if p8 == debianPCR8 || p9 == debianPCR9 {
		t.Fatal("a kernel update left a PCR as it was")
	}
}

func TestInstalledKernelsOrder(t *testing.T) {
	dir := t.TempDir()
	for _, v := range []string{"6.12.9+deb13-amd64", "6.12.111+deb13-amd64", "6.12.86+deb13-amd64", "6.13.1+deb13-amd64"} {
		os.WriteFile(dir+"/vmlinuz-"+v, []byte("k"), 0o644)
		os.WriteFile(dir+"/initrd.img-"+v, []byte("i"), 0o644)
	}
	os.WriteFile(dir+"/vmlinuz-7.0.0+deb14-amd64", []byte("k"), 0o644) // no initrd: not bootable yet
	got := strings.Join(installedKernels(dir), " ")
	if got != "6.12.9+deb13-amd64 6.12.86+deb13-amd64 6.12.111+deb13-amd64 6.13.1+deb13-amd64" {
		t.Fatalf("order: %s", got)
	}
}
