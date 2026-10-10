package attest

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"strings"
)

// PCR11Phases are the words systemd extends into PCR 11 after tpm2-kira's
// boot check, in boot order: systemd-pcrnvdone.service's nvpcr-separator
// (systemd 258+; tpm2-kira.service orders itself before it), then
// systemd-pcrphase's phases. The digest is the bank's hash of the literal
// word (no NUL, no salt), so they are universal constants. Enrolment runs
// in the booted system, where PCR 11 holds some ordered subset of these
// beyond the boot-check value - a subset, because older systemd has no
// nvpcr-separator.
var PCR11Phases = []string{"enter-initrd", "nvpcr-separator", "leave-initrd", "sysinit", "ready"}

// bankHash returns the hash of a PCR bank.
func bankHash(alg uint16) (func() hash.Hash, error) {
	switch alg {
	case AlgSHA1:
		return sha1.New, nil
	case AlgSHA256:
		return sha256.New, nil
	}
	return nil, fmt.Errorf("unsupported PCR bank 0x%04x", alg)
}

// ExtendWord returns value extended with the bank's digest of word, as
// systemd-pcrphase does: H(value ‖ H(word)).
func ExtendWord(alg uint16, value []byte, word string) ([]byte, error) {
	newHash, err := bankHash(alg)
	if err != nil {
		return nil, err
	}
	h := newHash()
	h.Write([]byte(word))
	d := h.Sum(nil)
	h = newHash()
	h.Write(value)
	h.Write(d)
	return h.Sum(nil), nil
}

// OSSeparatorWord is what systemd-pcrosseparator.service extends, in the
// initrd before the disk is unlocked, into OSSeparatorPCRs (its ExecStart;
// systemd 262). The machine's boot check happens before that, enrolment
// and a check by hand after it, so one and the same boot shows either state.
const OSSeparatorWord = "os-separator"

// OSSeparatorPCRs are the registers systemd-pcrosseparator.service extends.
var OSSeparatorPCRs = []uint8{0, 1, 2, 3, 4, 5, 6, 7, 9, 12, 13, 14}

// SameBootState reports whether two values of one PCR describe the same
// measured boot: equal, or, on a register the OS separator is extended into,
// one of them is the other plus exactly that separator.
//
// The separator is a constant that systemd adds to every boot, so it says
// nothing about what was booted: code that differs gives a register value
// that differs, and no number of separators leads from one to the other
// short of a hash collision. Both directions are accepted because a profile
// may have been recorded at either moment (at enrolment after the separator,
// by "approve and remember" at whichever moment the phone was asked).
func SameBootState(idx uint8, a, b []byte) bool {
	if bytes.Equal(a, b) {
		return len(a) > 0
	}
	if idx == 11 {
		return SamePCR11Boot(a, b)
	}
	if len(a) != len(b) || !isOSSeparatorPCR(idx) {
		return false
	}
	var alg uint16
	switch len(a) {
	case 20:
		alg = AlgSHA1
	case 32:
		alg = AlgSHA256
	default:
		return false
	}
	if ext, err := ExtendWord(alg, a, OSSeparatorWord); err == nil && bytes.Equal(ext, b) {
		return true
	}
	if ext, err := ExtendWord(alg, b, OSSeparatorWord); err == nil && bytes.Equal(ext, a) {
		return true
	}
	return false
}

// SamePCR11Boot is SameBootState for PCR 11, whose later phases systemd
// extends with words (PCR11Phases): a value reachable from the other by
// phase words is the same boot, seen later - the booted system of the
// boot the profile knows. Either direction, as for SameBootState.
func SamePCR11Boot(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return len(a) > 0
	}
	if len(a) != len(b) {
		return false
	}
	var alg uint16
	switch len(a) {
	case 20:
		alg = AlgSHA1
	case 32:
		alg = AlgSHA256
	default:
		return false
	}
	return reachableByPhases(alg, a, b) || reachableByPhases(alg, b, a)
}

func isOSSeparatorPCR(idx uint8) bool {
	for _, i := range OSSeparatorPCRs {
		if i == idx {
			return true
		}
	}
	return false
}

// CheckMeasurePointValues verifies a predicted boot-check baseline against
// the TPM-signed live values of the same selection. Every predicted value
// must equal the live one, except PCR 11: there the live value must be
// reachable from the prediction by extending an ordered subset of
// PCR11Phases. PCRs are one-way, so a prediction that passes is an earlier
// state of the real register and deserves the quote's trust; a machine
// cannot pin a baseline for a boot it has not done.
func CheckMeasurePointValues(alg uint16, live, predicted []PCRValue) error {
	if len(predicted) != len(live) {
		return fmt.Errorf("boot-check values cover %d PCRs, the quote %d", len(predicted), len(live))
	}
	for i, p := range predicted {
		l := live[i]
		if p.Index != l.Index || len(p.Digest) != len(l.Digest) {
			return fmt.Errorf("boot-check values do not cover the quoted PCRs")
		}
		if bytes.Equal(p.Digest, l.Digest) {
			continue
		}
		if p.Index != 11 {
			return fmt.Errorf("the predicted PCR %d is not the running system's value", p.Index)
		}
		if !reachableByPhases(alg, p.Digest, l.Digest) {
			return fmt.Errorf("the predicted PCR 11 does not lead to the running system's value by systemd's phases (%s)",
				strings.Join(PCR11Phases, ", "))
		}
	}
	return nil
}

// reachableByPhases reports whether some ordered subset of PCR11Phases
// extends from into to.
func reachableByPhases(alg uint16, from, to []byte) bool {
	var walk func(cur []byte, next int) bool
	walk = func(cur []byte, next int) bool {
		if bytes.Equal(cur, to) {
			return true
		}
		for i := next; i < len(PCR11Phases); i++ {
			ext, err := ExtendWord(alg, cur, PCR11Phases[i])
			if err != nil {
				return false
			}
			if walk(ext, i+1) {
				return true
			}
		}
		return false
	}
	return !bytes.Equal(from, to) && walk(from, 0)
}
