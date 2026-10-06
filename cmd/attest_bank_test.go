package cmd

import (
	"strings"
	"testing"

	"github.com/matthias/tpm2-kira/attest"
)

// The bank of a new enrolment is SHA-256 unless --sha1 is given, as for
// 'seal': SHA-1 is never chosen for the user. Where SHA-256 cannot work,
// enrolment stops and names the command.
func TestChooseAttestBank(t *testing.T) {
	bank := func(sha1, sha256 bool) func(PCRHashAlgo) bool {
		return func(a PCRHashAlgo) bool {
			if a == PCRHashAlgoSHA1 {
				return sha1
			}
			return sha256
		}
	}
	const none, s1, s256 = uint16(0), uint16(attest.AlgSHA1), uint16(attest.AlgSHA256)
	for _, c := range []struct {
		name         string
		flag         bool
		sealed       uint16
		sha1, sha256 bool
		want         uint16
		hint         string // part of the refusal, "" when accepted
	}{
		{"both banks, nothing sealed", false, none, true, true, s256, ""},
		{"SHA-256 only", false, none, false, true, s256, ""},
		{"sealed with SHA-256", false, s256, true, true, s256, ""},
		{"--sha1 on a TPM with both, nothing sealed", true, none, true, true, s1, ""},
		{"old TPM with --sha1", true, none, true, false, s1, ""},
		{"sealed with SHA-1, --sha1 given", true, s1, true, false, s1, ""},

		{"old TPM without --sha1: not picked for the user", false, none, true, false, 0, "attest enrol --sha1"},
		{"sealed with SHA-1 without --sha1", false, s1, true, false, 0, "attest enrol --sha1"},
		{"sealed with SHA-1 without --sha1, TPM has both", false, s1, true, true, 0, "attest enrol --sha1"},
		{"--sha1 against a SHA-256 seal", true, s256, true, true, 0, "drop --sha1"},
		{"--sha1 on a TPM without SHA-1", true, none, false, true, 0, "no SHA-1 PCR bank"},
		{"no bank at all", false, none, false, false, 0, "no SHA-256 PCR bank"},
	} {
		got, err := chooseAttestBank(c.flag, c.sealed, bank(c.sha1, c.sha256))
		switch {
		case c.hint == "" && (err != nil || got != c.want):
			t.Errorf("%s: bank %#x, err %v", c.name, got, err)
		case c.hint != "" && (err == nil || !strings.Contains(err.Error(), c.hint)):
			t.Errorf("%s: bank %#x, err %v; want a refusal naming %q", c.name, got, err, c.hint)
		}
		if c.hint == "attest enrol --sha1" && err != nil && !strings.Contains(err.Error(), "WARNING: SHA-1 is broken") {
			t.Errorf("%s: the refusal does not carry the SHA-1 warning", c.name)
		}
	}
}
