package cmd

import (
	"bufio"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	evlog "github.com/google/go-attestation/attest"

	"github.com/matthias/tpm2-kira/attest"
)

func utf16le(s string) []byte {
	var b []byte
	for _, r := range utf16.Encode([]rune(s)) {
		b = append(b, byte(r), byte(r>>8))
	}
	return append(b, 0, 0)
}

func ev(pcr int, typ uint32, data []byte) evlog.Event {
	return evlog.Event{Index: pcr, Type: evlog.EventType(typ), Data: data}
}

func TestInitrdCoverageByBootPath(t *testing.T) {
	efiApp := ev(4, evEFIBootServicesApplication, []byte{1, 2, 3})
	cases := []struct {
		name   string
		events []evlog.Event
		want   []int
	}{
		{"GRUB (Arch)", []evlog.Event{
			ev(8, evIPL, []byte("grub_cmd: initrd /initramfs-linux.img\x00")),
			ev(9, evIPL, []byte("/initramfs-linux.img\x00")),
		}, []int{9}},
		{"GRUB (Debian)", []evlog.Event{ev(9, evIPL, []byte("/boot/initrd.img-6.12.0-amd64\x00"))}, []int{9}},
		{"EFI stub LoadFile2", []evlog.Event{ev(9, evEventTag, append([]byte{0x86, 0x22, 0x80, 0x8e, 13, 0, 0, 0}, "Linux initrd\x00"...))}, []int{9}},
		{"UKI", []evlog.Event{efiApp, ev(11, evIPL, utf16le(".linux")), ev(11, evIPL, utf16le(".initrd"))}, []int{11, 4}},
		{"initrdless", []evlog.Event{
			efiApp,
			ev(8, evIPL, []byte("grub_cmd: initrdfail\x00")), // a command, not a measurement of an initrd
			ev(9, evIPL, []byte("/boot/vmlinuz-6.12\x00")),
		}, nil},
	}
	for _, c := range cases {
		got := initrdCoverageFromEvents(c.events)
		if !slices.Equal(got.PCRs, c.want) {
			t.Errorf("%s: PCRs %v, want %v (%v)", c.name, got.PCRs, c.want, got.How)
		}
	}
}

func TestInitrdCoveragePrompt(t *testing.T) {
	sel := func(i ...int) attest.PCRSelection {
		s, _ := attest.NewPCRSelection(attest.AlgSHA256, i)
		return s
	}
	grub := initrdCoverage{PCRs: []int{9}, How: []string{"PCR 9: the boot loader measured the initrd file"}}
	ask := func(s attest.PCRSelection, cov initrdCoverage, answer string) bool {
		ok, err := decideInitrdCoverage(bufio.NewReader(strings.NewReader(answer)), s, cov, nil)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !ask(sel(0, 4, 7, 9), grub, "") {
		t.Error("covered selection was questioned")
	}
	if ask(sel(0, 2, 4, 7), grub, "\n") {
		t.Error("uncovered selection enrolled on Enter (default must be no)")
	}
	if ask(sel(0, 2, 4, 7), grub, "n\n") {
		t.Error("uncovered selection enrolled on 'n'")
	}
	if !ask(sel(0, 2, 4, 7), grub, "y\n") {
		t.Error("explicit 'y' refused")
	}
	if !ask(sel(0, 2, 4, 7), initrdCoverage{}, "") {
		t.Error("unknown coverage should not block enrolment")
	}
}
