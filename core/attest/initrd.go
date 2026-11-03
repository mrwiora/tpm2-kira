package attest

import (
	"bytes"
	"slices"
	"strings"
)

// Whether the quoted PCRs measure the initrd, as a verifier establishes it at
// enrolment: from events it can check itself, never from what the machine says.
//
// An event's digest is of what was measured, its description is covered by nothing. So
// an event counts only where the verifier can make the digest itself:
//
//   - A unified kernel image: systemd-stub measures each section into PCR 11, its name
//     with a NUL and then its contents. The hash of ".initrd\0", followed by another
//     digest, among digests that replay to the quoted PCR 11 (systemd's phase words may
//     follow in the register, as for SameBootState) is that section's measurement.
//   - GRUB: it measures every command into PCR 8, the hash of the command's text, and
//     the files a command reads into PCR 9. The machine says the initrd command; its
//     hash among digests that replay to the quoted PCR 8 is that command run, and so
//     its file in PCR 9, which the selection must hold too.
//
// What cannot be established this way is not established, and red: the Linux EFI stub's
// "Linux initrd" event (PCR 9, a boot without GRUB or a UKI), whose digest is the file's
// and whose name nothing covers; a selection without those registers; a machine that
// sends no log. Nothing here decides: the person enrolling reads it.
//
// What it rests on: firmware, the stub and GRUB measuring as they do, and, as all of
// enrolment does (§13.1 of SECURITY-BACKGROUND.md), that the machine is trusted when it
// is enrolled: root can extend such a digest into either register afterwards.

// InitrdEvents is what the machine sends for it: digests of its event log in the quote's
// bank, believed only as far as they replay to the quoted registers.
type InitrdEvents struct {
	PCR8Chain  []byte // the digests of PCR 8's events, GRUB's commands
	PCR11Chain []byte // the digests of PCR 11's events, systemd-stub's sections
	Command    string // GRUB's initrd command, as it measured it: "initrd /initrd.img-..."
}

// InitrdEventsProvider is an optional EnrolBackend extension: this boot's events, from
// its event log.
type InitrdEventsProvider interface {
	InitrdEvents(alg uint16) InitrdEvents
}

// MaxInitrdChain bounds one of those chains: a machine has about a hundred events there.
const MaxInitrdChain = 16 << 10

// InitrdFinding is what a verifier established: State is one of the states below, PCRs
// those of the selection that measure the initrd, Detail why it is not established.
type InitrdFinding struct {
	State  string
	PCRs   []int
	Detail string
}

// The states, in need_anchor_key's initrd_coverage. Every state but InitrdCovered is
// shown red.
const (
	InitrdCovered        = "covered"
	InitrdNotEstablished = "not_established"
)

// replays says whether chain, whole digests of the bank's size, replays to value.
func replays(alg uint16, chain, value []byte) ([]byte, bool) {
	newHash, err := bankHash(alg)
	if err != nil {
		return nil, false
	}
	size := newHash().Size()
	if len(chain) == 0 || len(chain) > MaxInitrdChain || len(chain)%size != 0 || len(value) != size {
		return nil, false
	}
	cur := make([]byte, size)
	for off := 0; off < len(chain); off += size {
		h := newHash()
		h.Write(cur)
		h.Write(chain[off : off+size])
		cur = h.Sum(nil)
	}
	return cur, true
}

func quotedValue(values []PCRValue, idx uint8) []byte {
	for _, v := range values {
		if v.Index == idx {
			return v.Digest
		}
	}
	return nil
}

// EstablishInitrd reads, from verified quoted values, whether the selection measures the
// initrd. The values must come from a quote that verified: nothing here checks one.
func EstablishInitrd(sel PCRSelection, values []PCRValue, ev InitrdEvents) InitrdFinding {
	newHash, err := bankHash(sel.Alg)
	if err != nil {
		return InitrdFinding{State: InitrdNotEstablished, Detail: "a PCR bank of no known hash"}
	}
	size := newHash().Size()
	sum := func(b []byte) []byte {
		h := newHash()
		h.Write(b)
		return h.Sum(nil)
	}
	holds := func(idx uint8) bool { return slices.Contains(sel.Indices, idx) }
	notEstablished := func(why string) InitrdFinding { return InitrdFinding{State: InitrdNotEstablished, Detail: why} }

	if len(ev.PCR11Chain) > 0 && holds(11) {
		cur, ok := replays(sel.Alg, ev.PCR11Chain, quotedValue(values, 11))
		quoted := quotedValue(values, 11)
		if ok && (bytes.Equal(cur, quoted) || reachableByPhases(sel.Alg, cur, quoted)) {
			section := sum([]byte(".initrd\x00"))
			for off := 0; off+2*size <= len(ev.PCR11Chain); off += size {
				if bytes.Equal(ev.PCR11Chain[off:off+size], section) {
					pcrs := []int{11}
					if holds(4) { // the firmware measured the whole image
						pcrs = append(pcrs, 4)
					}
					return InitrdFinding{State: InitrdCovered, PCRs: pcrs}
				}
			}
		}
	}
	if ev.Command != "" && holds(8) && holds(9) && strings.HasPrefix(ev.Command, "initrd ") {
		cur, ok := replays(sel.Alg, ev.PCR8Chain, quotedValue(values, 8))
		if ok && bytes.Equal(cur, quotedValue(values, 8)) {
			command := sum([]byte(ev.Command))
			for off := 0; off+size <= len(ev.PCR8Chain); off += size {
				if bytes.Equal(ev.PCR8Chain[off:off+size], command) {
					return InitrdFinding{State: InitrdCovered, PCRs: []int{9}}
				}
			}
		}
	}
	switch {
	case !holds(11) && !(holds(8) && holds(9)):
		return notEstablished("the quote covers neither PCR 11 nor PCR 8 and 9, where a measured initrd shows")
	case len(ev.PCR11Chain) == 0 && len(ev.PCR8Chain) == 0:
		return notEstablished("the machine gave no events of those registers: no event log")
	}
	return notEstablished("no event the phone can check itself shows the initrd measured")
}
