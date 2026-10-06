package attest

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"strings"
)

// PCR11Phases are the words systemd-pcrphase extends into PCR 11, in boot
// order. The digest is the bank's hash of the literal word (no NUL, no salt),
// so they are universal constants. Enrolment runs in the booted system, where
// PCR 11 holds some prefix of these beyond the boot-check value.
var PCR11Phases = []string{"enter-initrd", "leave-initrd", "sysinit", "ready"}

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
