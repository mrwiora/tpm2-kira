package admin

import (
	"crypto/sha1"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/core/attest/attesttest"
	"github.com/mrwiora/tpm2-kira/internal/measure"
)

func TestSecureBootProof(t *testing.T) {
	chain := attesttest.SecureBootChain(attest.AlgSHA1, attest.SecureBootOn)
	pcr := attesttest.ReplayChain(attest.AlgSHA1, chain)
	sep, err := attest.ExtendWord(attest.AlgSHA1, pcr, attest.OSSeparatorWord)
	if err != nil {
		t.Fatal(err)
	}
	past, err := attest.ExtendWord(attest.AlgSHA1, sep, "logged")
	if err != nil {
		t.Fatal(err)
	}
	digest := func(word string) []byte {
		d := sha1.Sum([]byte(word))
		return d[:]
	}
	for _, tc := range []struct {
		name    string
		pcr     []byte
		chain   []byte
		systemd []measure.SystemdEvent
		ok      bool
		says    []string
	}{
		{"the firmware's events make it", pcr, chain, nil, true, []string{"on: PCR 7"}},
		{"past the OS separator", sep, chain, []measure.SystemdEvent{{Digest: digest(attest.OSSeparatorWord), What: attest.OSSeparatorWord}}, true, []string{"on: PCR 7"}},
		{"systemd's log accounts for more", past, chain, []measure.SystemdEvent{{Digest: digest(attest.OSSeparatorWord), What: attest.OSSeparatorWord}, {Digest: digest("logged"), What: "logged"}},
			false, []string{"not established", "adds 2", "together they make the register", "(risk:"}},
		{"nothing accounts for it", past, chain, nil, false, []string{"not established", "with no log at all"}},
		{"systemd's log does not account for it", past, chain, []measure.SystemdEvent{{Digest: digest("other"), What: "other"}}, false, []string{"adds 1", "do not make the register"}},
		{"no events", pcr, nil, nil, false, []string{"not established", "SHA-1 bank"}},
		{"off", attesttest.ReplayChain(attest.AlgSHA1, attesttest.SecureBootChain(attest.AlgSHA1, attest.SecureBootOff)), attesttest.SecureBootChain(attest.AlgSHA1, attest.SecureBootOff), nil, false, []string{"off: PCR 7"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := secureBootProofOf(attest.AlgSHA1, tc.pcr, tc.chain, tc.systemd).text()
			if ok != tc.ok {
				t.Errorf("ok %v: %s", ok, got)
			}
			for _, want := range tc.says {
				if !strings.Contains(got, want) {
					t.Errorf("%q has no %q", got, want)
				}
			}
		})
	}
}

// The line sits beside the firmware's, green or red, and a machine that could not read it has none.
func TestSecureBootProofIsShown(t *testing.T) {
	c := &controller{}
	c.facts.Proof = &secureBootProof{Finding: attest.SecureBootFinding{State: attest.SecureBootOn}}
	if got := c.factsText(); !strings.Contains(got, "Proof       \033[0;32mon: PCR 7") {
		t.Errorf("%s", got)
	}
	c.facts.Proof = &secureBootProof{Finding: attest.SecureBootFinding{State: attest.SecureBootNotEstablished, Detail: "why"}}
	if got := c.factsText(); !strings.Contains(got, "Proof       \033[0;31mnot established: why") {
		t.Errorf("%s", got)
	}
	c.facts.Proof = nil
	if got := c.factsText(); strings.Contains(got, "Proof ") {
		t.Errorf("%s", got)
	}
}
