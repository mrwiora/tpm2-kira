package attest_test

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/core/attest/attesttest"
)

func extendChain(chain []byte, digest []byte) ([]byte, []byte) {
	chain = append(append([]byte(nil), chain...), digest...)
	return chain, attesttest.ReplayChain(attest.AlgSHA256, chain)
}

func TestEstablishSecureBootStates(t *testing.T) {
	for _, alg := range []uint16{attest.AlgSHA256, attest.AlgSHA1} {
		for _, state := range []string{attest.SecureBootOn, attest.SecureBootOff, attest.SecureBootSetupMode} {
			chain := attesttest.SecureBootChain(alg, state)
			got := attest.EstablishSecureBoot(alg, attesttest.ReplayChain(alg, chain), chain)
			if got.State != state {
				t.Errorf("bank %#x, %s: established %+v", alg, state, got)
			}
			if got.Red() != (state != attest.SecureBootOn) {
				t.Errorf("%s: red %v", state, got.Red())
			}
		}
	}
}

// A state the machine merely claims is worth nothing: whatever it does, it cannot
// show "on" for a PCR 7 that was not measured by firmware in that state.
func TestEstablishSecureBootTakesNoClaim(t *testing.T) {
	alg := attest.AlgSHA256
	off := attesttest.SecureBootChain(alg, attest.SecureBootOff)
	offPCR := attesttest.ReplayChain(alg, off)
	on := attesttest.SecureBootChain(alg, attest.SecureBootOn)
	onDigest := sha256.Sum256(attest.UEFIVariableData("SecureBoot", []byte{1}))

	// The events of a firmware with Secure Boot on, beside the register of one without.
	if got := attest.EstablishSecureBoot(alg, offPCR, on); got.State != attest.SecureBootNotEstablished {
		t.Errorf("another boot's events: %+v", got)
	}
	// On appended: extended into the real register, after the firmware's separator.
	chain, pcr := extendChain(off, onDigest[:])
	if got := attest.EstablishSecureBoot(alg, pcr, chain); got.State != attest.SecureBootOff {
		t.Errorf("an extend after the separator: %+v", got)
	}
	// The events of an empty PK or of on, after the separator, change nothing either.
	onChain, onPCR := extendChain(on, sha256.New().Sum(nil))
	if got := attest.EstablishSecureBoot(alg, onPCR, onChain); got.State != attest.SecureBootOn {
		t.Errorf("an extend after the separator of a good boot: %+v", got)
	}
	noPK := sha256.Sum256(attest.UEFIVariableData("PK", nil))
	onChain, onPCR = extendChain(on, noPK[:])
	if got := attest.EstablishSecureBoot(alg, onPCR, onChain); got.State != attest.SecureBootOn {
		t.Errorf("an empty PK after the separator: %+v", got)
	}
}

func TestEstablishSecureBootNotEstablished(t *testing.T) {
	alg := attest.AlgSHA256
	chain := attesttest.SecureBootChain(alg, attest.SecureBootOn)
	pcr := attesttest.ReplayChain(alg, chain)
	size := sha256.Size
	sep := chain[len(chain)-size:]
	offDigest := sha256.Sum256(attest.UEFIVariableData("SecureBoot", []byte{0}))
	noState := append([]byte(nil), chain[size:]...)
	both := append(append(append([]byte(nil), chain[:size]...), offDigest[:]...), sep...)
	noSep := chain[:len(chain)-size]
	bad := make([]byte, 2*size)
	for name, tc := range map[string]struct {
		alg        uint16
		pcr, chain []byte
	}{
		"no event log":             {alg, pcr, nil},
		"PCR 7 not quoted":         {alg, nil, chain},
		"a chain of half a digest": {alg, pcr, chain[:size/2]},
		"too long":                 {alg, pcr, make([]byte, attest.MaxPCR7Chain+size)},
		"another bank":             {attest.AlgSHA1, pcr, chain},
		"an unknown bank":          {0x0013, pcr, chain},
		"does not replay":          {alg, pcr, bad},
		"no separator":             {alg, attesttest.ReplayChain(alg, noSep), noSep},
		"no SecureBoot variable":   {alg, attesttest.ReplayChain(alg, noState), noState},
		"named twice":              {alg, attesttest.ReplayChain(alg, both), both},
	} {
		got := attest.EstablishSecureBoot(tc.alg, tc.pcr, tc.chain)
		if got.State != attest.SecureBootNotEstablished || got.Detail == "" || !got.Red() {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

// The firmware's own word takes on away, and only before its separator: what comes after
// it is anyone's. Off and Setup Mode stay what they are.
func TestEstablishSecureBootFirmwareTakesOnAway(t *testing.T) {
	alg := attest.AlgSHA256
	debug := sha256.Sum256([]byte("UEFI Debug Mode"))
	errSep := sha256.Sum256([]byte{0xff, 0xff, 0xff, 0xff})
	state := func(chain []byte) attest.SecureBootFinding {
		return attest.EstablishSecureBoot(alg, attesttest.ReplayChain(alg, chain), chain)
	}
	withDebug := func(s string) []byte {
		return append(append([]byte(nil), debug[:]...), attesttest.SecureBootChain(alg, s)...)
	}
	withErrSep := func(s string) []byte {
		c := attesttest.SecureBootChain(alg, s)
		return append(append([]byte(nil), c[:len(c)-sha256.Size]...), errSep[:]...)
	}
	for name, c := range map[string]struct {
		chain []byte
		want  string
	}{
		"debug mode, on":            {withDebug(attest.SecureBootOn), attest.SecureBootNotEstablished},
		"debug mode, off":           {withDebug(attest.SecureBootOff), attest.SecureBootOff},
		"debug mode, setup mode":    {withDebug(attest.SecureBootSetupMode), attest.SecureBootSetupMode},
		"error separator, on":       {withErrSep(attest.SecureBootOn), attest.SecureBootNotEstablished},
		"error separator, off":      {withErrSep(attest.SecureBootOff), attest.SecureBootOff},
		"error separator, setup":    {withErrSep(attest.SecureBootSetupMode), attest.SecureBootSetupMode},
		"debug mode after the part": {append(attesttest.SecureBootChain(alg, attest.SecureBootOn), debug[:]...), attest.SecureBootOn},
		"error value after the part": {append(attesttest.SecureBootChain(alg, attest.SecureBootOn), errSep[:]...),
			attest.SecureBootOn},
	} {
		if got := state(c.chain); got.State != c.want {
			t.Errorf("%s: %+v, want %s", name, got, c.want)
		}
	}
	if got := state(withDebug(attest.SecureBootOn)); !strings.Contains(got.Detail, "UEFI Debug Mode") {
		t.Errorf("not named: %+v", got)
	}
	if got := state(withErrSep(attest.SecureBootOn)); !strings.Contains(got.Detail, "error separator") {
		t.Errorf("not named: %+v", got)
	}
}

func FuzzEstablishSecureBoot(f *testing.F) {
	alg := attest.AlgSHA256
	for _, s := range []string{attest.SecureBootOn, attest.SecureBootOff, attest.SecureBootSetupMode} {
		c := attesttest.SecureBootChain(alg, s)
		f.Add(attesttest.ReplayChain(alg, c), c)
	}
	f.Fuzz(func(t *testing.T, pcr, chain []byte) {
		got := attest.EstablishSecureBoot(alg, pcr, chain)
		if got.State != attest.SecureBootNotEstablished && got.Detail != "" {
			t.Fatalf("%+v", got)
		}
	})
}
