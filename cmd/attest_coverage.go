package cmd

// Does the PCR selection a phone will check cover the initrd? The initrd is
// where a passphrase logger
// would sit; if no quoted PCR measures it, a modified initrd attests as
// "match". Which PCRs measure it depends on the boot path, so it is read from
// this boot's event log rather than assumed.

import (
	"bufio"
	"bytes"
	"fmt"
	"slices"
	"strings"
	"unicode/utf16"

	evlog "github.com/google/go-attestation/attest"

	"github.com/mrwiora/tpm2-kira/attest"
)

// Event types used below (TCG PC Client Platform Firmware Profile).
const (
	evIPL                        = 0x0000000D
	evEventTag                   = 0x00000006
	evEFIBootServicesApplication = 0x80000003
)

// initrdCoverage lists the PCRs that measured the initrd on this boot.
type initrdCoverage struct {
	PCRs []int
	How  []string
}

func (c *initrdCoverage) add(pcr int, how string) {
	if !slices.Contains(c.PCRs, pcr) {
		c.PCRs = append(c.PCRs, pcr)
		c.How = append(c.How, fmt.Sprintf("PCR %d: %s", pcr, how))
	}
}

// mentions reports whether data names word, as ASCII or UTF-16LE (systemd
// records section names in UTF-16).
func mentions(data []byte, word string) bool {
	if bytes.Contains(bytes.ToLower(data), []byte(word)) {
		return true
	}
	var u []byte
	for _, r := range utf16.Encode([]rune(word)) {
		u = append(u, byte(r), byte(r>>8))
	}
	return bytes.Contains(bytes.ToLower(data), u)
}

// initrdCoverageFromEvents recognises the three common ways an initrd gets
// measured:
//
//   - Linux EFI stub, initrd loaded through LoadFile2 (kernel 5.17+, e.g.
//     systemd-boot type 1 entries): PCR 9, tagged event "Linux initrd";
//   - GRUB: PCR 9, the initrd file as an EV_IPL event naming its path;
//   - Unified kernel image: systemd-stub measures its .initrd section into
//     PCR 11, and PCR 4 holds the hash of the whole UKI, initrd included.
func initrdCoverageFromEvents(events []evlog.Event) initrdCoverage {
	var c initrdCoverage
	uki := false
	for _, e := range events {
		t := uint32(e.Type)
		switch {
		case e.Index == 9 && t == evEventTag && mentions(e.Data, "initrd"):
			c.add(9, "the kernel's EFI stub measured the initrd")
		case e.Index == 9 && t == evIPL && (mentions(e.Data, "initrd") || mentions(e.Data, "initramfs")):
			c.add(9, "the boot loader measured the initrd file")
		case e.Index == 11 && t == evIPL && mentions(e.Data, ".initrd"):
			c.add(11, "systemd-stub measured the unified kernel image's .initrd section")
			uki = true
		}
	}
	if uki {
		for _, e := range events {
			if e.Index == 4 && uint32(e.Type) == evEFIBootServicesApplication {
				c.add(4, "the firmware measured the unified kernel image, initrd included")
				break
			}
		}
	}
	return c
}

func readInitrdCoverage(path string) (initrdCoverage, error) {
	raw, err := readRawEventLogFromPath(path)
	if err != nil {
		return initrdCoverage{}, err
	}
	log, err := evlog.ParseEventLog(raw)
	if err != nil {
		return initrdCoverage{}, err
	}
	events := log.Events(evlog.HashSHA256)
	if len(events) == 0 {
		events = log.Events(evlog.HashSHA1)
	}
	return initrdCoverageFromEvents(events), nil
}

// coveredBy reports whether one of the PCRs that measured the initrd is in sel.
func (c initrdCoverage) coveredBy(sel []uint8) bool {
	for _, p := range c.PCRs {
		if slices.Contains(sel, uint8(p)) {
			return true
		}
	}
	return false
}

// confirmInitrdCoverage tells the person enrolling whether the selection
// covers the initrd, and asks before enrolling a selection that does not.
func confirmInitrdCoverage(console *bufio.Reader, sel attest.PCRSelection, eventlogPath string) (bool, error) {
	cov, err := readInitrdCoverage(eventlogPath)
	return decideInitrdCoverage(console, sel, cov, err)
}

func decideInitrdCoverage(console *bufio.Reader, sel attest.PCRSelection, cov initrdCoverage, err error) (bool, error) {
	if err != nil || len(cov.PCRs) == 0 {
		why := "no initrd measurement found"
		if err != nil {
			why = err.Error()
		}
		fmt.Printf("Initrd:        could not tell which PCRs measured it (%s).\n", why)
		fmt.Println("               Make sure the quoted PCRs cover the kernel and initrd of your boot path.")
		return true, nil
	}
	if cov.coveredBy(sel.Indices) {
		return true, nil // covered: nothing to say
	}
	fmt.Println()
	fmt.Println("WARNING: the PCRs the phone will check do not cover the initrd.")
	for _, h := range cov.How {
		fmt.Printf("         On this boot, %s.\n", h)
	}
	fmt.Println("         A modified initrd - for example one that records your passphrase - would")
	fmt.Println("         then attest as unchanged. Enrol with --pcrs including one of:", formatPCRList(cov.PCRs))
	fmt.Println()
	for {
		fmt.Print("    Enrol anyway? [y/N]: ")
		line, err := console.ReadString('\n')
		if err != nil && line == "" {
			return false, fmt.Errorf("no answer on the console: %w", err)
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true, nil
		case "", "n", "no":
			return false, nil
		}
	}
}
