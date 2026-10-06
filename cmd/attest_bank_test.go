package cmd

import (
	"testing"

	"github.com/matthias/tpm2-kira/attest"
)

// The bank of a new enrolment: SHA-256 wherever the TPM has it; SHA-1 only
// on a TPM that offers nothing else, or when the sealed slot uses it.
func TestChooseAttestBank(t *testing.T) {
	bank := func(sha1, sha256 bool) func(PCRHashAlgo) bool {
		return func(a PCRHashAlgo) bool {
			if a == PCRHashAlgoSHA1 {
				return sha1
			}
			return sha256
		}
	}
	for _, c := range []struct {
		name          string
		alg           uint16
		fromSeal      bool
		sha1, sha256  bool
		want          uint16
		note, refused bool
	}{
		{"both banks: SHA-256, unchanged", attest.AlgSHA256, false, true, true, attest.AlgSHA256, false, false},
		{"SHA-256 only", attest.AlgSHA256, false, false, true, attest.AlgSHA256, false, false},
		{"old TPM, nothing sealed: SHA-1 with a note", attest.AlgSHA256, false, true, false, attest.AlgSHA1, true, false},
		{"sealed with SHA-1", attest.AlgSHA1, true, true, false, attest.AlgSHA1, false, false},
		{"sealed with SHA-1 on a TPM with both", attest.AlgSHA1, true, true, true, attest.AlgSHA1, false, false},
		{"sealed with SHA-256, bank gone: not silently another", attest.AlgSHA256, true, true, false, 0, false, true},
		{"sealed with SHA-1, bank gone", attest.AlgSHA1, true, false, true, 0, false, true},
		{"no bank at all", attest.AlgSHA256, false, false, false, 0, false, true},
	} {
		got, note, err := chooseAttestBank(c.alg, c.fromSeal, bank(c.sha1, c.sha256))
		if (err != nil) != c.refused || got != c.want || (note != "") != c.note {
			t.Errorf("%s: bank %#x, note %q, err %v", c.name, got, note, err)
		}
	}
}
