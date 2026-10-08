package attest_test

import (
	"bytes"
	"testing"

	. "github.com/mrwiora/tpm2-kira/attest"
	"github.com/mrwiora/tpm2-kira/attest/attesttest"
)

// factorBackend wraps the soft TPM as a FactorBackend: it offers a factor
// to keep when one is set, and records what the phone released.
type factorBackend struct {
	*attesttest.SoftTPM
	keep     *FactorBlob
	released *Release
	status   uint8
}

func (b *factorBackend) FactorToKeep() *FactorBlob { return b.keep }
func (b *factorBackend) TakeRelease(r *Release) (uint8, string) {
	b.released = r
	return b.status, "kept for the disk"
}

func attestWithFactor(t *testing.T, m *attesttest.Machine, p *attesttest.Phone, rec *MachineRecord, be *factorBackend) (*AttestResult, []Event) {
	t.Helper()
	a, b := attesttest.NewPipe()
	type r struct {
		res *AttestResult
		err error
	}
	done := make(chan r, 1)
	go func() {
		res, err := ServeAttestation(a, m.AttestIdentity(), be, nil)
		a.Close()
		done <- r{res, err}
	}()
	v, err := NewAttestVerifier(p.Config(), rec)
	if err != nil {
		t.Fatal(err)
	}
	perr := p.Drive(v, b)
	b.Close()
	got := <-done
	if got.err != nil || perr != nil {
		t.Fatalf("machine %v phone %v", got.err, perr)
	}
	return got.res, p.Events
}

// The factor's way through the protocol: the machine asks the phone to
// keep it in the evidence; the phone keeps it once the verdict is
// accepted and returns it in a Release after the accepted receipt - in
// that session, and in every later one - and the machine's backend gets
// it. A phone without a kept factor releases nothing.
func TestFactorIsKeptAndReleased(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	rec := enrol(t, m, p)
	be := &factorBackend{SoftTPM: m.TPM, status: ReleaseOK}

	// Without a factor anywhere: no release.
	res, _ := attestWithFactor(t, m, p, rec, be)
	if res.Release != nil || be.released != nil || p.Record.HasFactor() {
		t.Fatal("a factor came from nowhere")
	}

	// 'factor enrol': the evidence carries the factor to keep.
	blob := &FactorBlob{CredentialBlob: bytes.Repeat([]byte{0xC1}, 80), EncryptedSecret: bytes.Repeat([]byte{0xE5}, 65), Label: "luks"}
	be.keep = blob
	res, events := attestWithFactor(t, m, p, p.Record, be)
	offered := false
	for _, e := range events {
		if e.Type == EvVerdict && e.FactorOffered {
			offered = true
		}
	}
	if !offered {
		t.Fatal("the verdict did not say a factor was offered")
	}
	if !p.Record.HasFactor() || !bytes.Equal(p.Record.Factor.CredentialBlob, blob.CredentialBlob) || p.Record.Factor.Label != "luks" {
		t.Fatalf("the phone did not keep the factor: %+v", p.Record.Factor)
	}
	if res.Release == nil || !bytes.Equal(res.Release.CredentialBlob, blob.CredentialBlob) || !bytes.Equal(res.Release.EncryptedSecret, blob.EncryptedSecret) || res.Release.Kind != ReleaseKindFactor {
		t.Fatalf("the round trip did not return the factor: %+v", res.Release)
	}
	if be.released == nil {
		t.Fatal("the backend did not get the release")
	}
	acked := false
	for _, e := range events {
		if e.Type == EvReleaseAck && e.Result == ReleaseOK && e.Message == "kept for the disk" {
			acked = true
		}
	}
	if !acked {
		t.Fatalf("no release ack event: %+v", events)
	}

	// At boot: nothing to keep, the kept factor is released.
	be.keep, be.released = nil, nil
	m.TPM.ResetCount++
	res, _ = attestWithFactor(t, m, p, p.Record, be)
	if res.Release == nil || be.released == nil || !bytes.Equal(be.released.CredentialBlob, blob.CredentialBlob) {
		t.Fatal("the kept factor was not released at the next attestation")
	}

	// A backend without the extension gets no factor, and the phone's
	// session still ends well.
	a, b := attesttest.NewPipe()
	go func() {
		ServeAttestation(a, m.AttestIdentity(), m.TPM, nil)
		a.Close()
	}()
	v, _ := NewAttestVerifier(p.Config(), p.Record)
	if err := p.Drive(v, b); err != nil {
		t.Fatalf("phone against a backend without factors: %v", err)
	}
	b.Close()
	unsupported := false
	for _, e := range p.Events {
		if e.Type == EvReleaseAck && e.Result == ReleaseUnsupported {
			unsupported = true
		}
	}
	if !unsupported {
		t.Fatal("the phone was not told the machine takes no factor")
	}
}

// A rejected verdict releases nothing, and keeps nothing.
func TestFactorIsNotReleasedOnReject(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	rec := enrol(t, m, p)
	be := &factorBackend{SoftTPM: m.TPM, status: ReleaseOK, keep: &FactorBlob{CredentialBlob: []byte{1, 2, 3}, EncryptedSecret: []byte{4}}}
	p.Decision = DecisionReject
	a, b := attesttest.NewPipe()
	go func() {
		ServeAttestation(a, m.AttestIdentity(), be, nil)
		a.Close()
	}()
	v, _ := NewAttestVerifier(p.Config(), rec)
	p.Drive(v, b)
	b.Close()
	if be.released != nil || p.Record.HasFactor() {
		t.Fatal("a rejected verdict released or kept a factor")
	}
}
