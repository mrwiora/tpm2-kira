package admin

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"strings"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/internal/measure"
	"github.com/tpm2-trust/tpm2-kira/internal/phonegate"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"
	"github.com/tpm2-trust/tpm2-kira/internal/untrusted"
)

// secureBootProof is what a phone and the vault will establish of Secure Boot: their check, on
// this machine's register and log. The firmware's variable, which control shows beside it, proves
// nothing to them, and the two can differ.
type secureBootProof struct {
	Finding attest.SecureBootFinding
	Gap     string // what the logs say of a register they do not make; for a person, never proof
}

// readSecureBootProof reads the live PCR 7 in the bank alg. Nil when the register cannot be read.
func readSecureBootProof(tpmPath string, alg uint16) *secureBootProof {
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return nil
	}
	defer tpmDev.Close()
	vals, err := phonegate.ReadPCRBank(tpmDev, attest.PCRSelection{Alg: alg, Indices: []uint8{7}})
	if err != nil || len(vals) != 1 {
		return nil
	}
	algo := "sha256"
	if alg == attest.AlgSHA1 {
		algo = "sha1"
	}
	return secureBootProofOf(alg, vals[0].Digest, phonegate.PCR7Chain(measure.DefaultEventlogPath, alg),
		measure.SystemdLogEvents(measure.SystemdMeasureLog, 7, algo))
}

// secureBootProofOf is the check, and, when the firmware's events do not make the register,
// whether systemd's log accounts for the rest.
func secureBootProofOf(alg uint16, pcr7, chain []byte, systemd []measure.SystemdEvent) *secureBootProof {
	p := &secureBootProof{Finding: attest.EstablishSecureBoot(alg, pcr7, chain)}
	if p.Finding.State != attest.SecureBootNotEstablished || len(chain) == 0 {
		return p
	}
	newHash := func() hash.Hash { return sha256.New() }
	if alg == attest.AlgSHA1 {
		newHash = func() hash.Hash { return sha1.New() }
	}
	size := newHash().Size()
	if len(chain)%size != 0 {
		return p
	}
	cur := make([]byte, size)
	extend := func(d []byte) {
		h := newHash()
		h.Write(cur)
		h.Write(d)
		cur = h.Sum(nil)
	}
	for off := 0; off < len(chain); off += size {
		extend(chain[off : off+size])
	}
	var names []string
	for _, e := range systemd {
		extend(e.Digest)
		names = append(names, untrusted.Quote(e.What))
	}
	made := string(cur) == string(pcr7)
	switch {
	case len(systemd) == 0:
		p.Gap = fmt.Sprintf("the firmware's log has %d events of PCR 7 and systemd's log none: something extended it with no log at all", len(chain)/size)
	case made:
		p.Gap = fmt.Sprintf("the firmware's log has %d events of PCR 7; systemd's log adds %d (%s), and together they make the register", len(chain)/size, len(systemd), strings.Join(names, ", "))
	default:
		p.Gap = fmt.Sprintf("the firmware's log has %d events of PCR 7; systemd's log adds %d (%s), and together they do not make the register: something extended it with no log at all", len(chain)/size, len(systemd), strings.Join(names, ", "))
	}
	return p
}

// text is the proof in a line; ok when it is on.
func (p *secureBootProof) text() (string, bool) {
	const risk = " (risk: a phone shows it red and the vault releases nothing)"
	switch p.Finding.State {
	case attest.SecureBootOn:
		return "on: PCR 7 and the event log show it, as a phone and the vault will see it", true
	case attest.SecureBootOff:
		return "off: PCR 7 and the event log show it" + risk, false
	case attest.SecureBootSetupMode:
		return "Setup Mode: PCR 7 and the event log show it" + risk, false
	}
	line := "not established: " + p.Finding.Detail
	if p.Gap != "" {
		line += "; " + p.Gap
	}
	return line + risk, false
}
