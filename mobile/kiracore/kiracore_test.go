package kiracore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/matthias/tpm2-kira/attest"
	"github.com/matthias/tpm2-kira/attest/attesttest"
	"github.com/matthias/tpm2-kira/transport/frame"
)

// memLink is the machine's side of a simulated BLE link: fragments it sends
// become "notifications" for the phone.
type memLink struct {
	max    int
	toApp  chan []byte
	closed chan struct{}
	once   sync.Once
}

func (l *memLink) SendFragment(f []byte) error {
	if len(f) > l.max {
		return errors.New("fragment exceeds MTU")
	}
	select {
	case l.toApp <- append([]byte(nil), f...):
		return nil
	case <-l.closed:
		return errors.New("closed")
	}
}
func (l *memLink) MaxFragment() int { return l.max }
func (l *memLink) Close() error     { l.once.Do(func() { close(l.closed) }); return nil }

type event struct {
	Type          string          `json:"type"`
	SAS           string          `json:"sas"`
	Purpose       string          `json:"purpose"`
	NeedsDecision bool            `json:"needs_decision"`
	Record        json.RawMessage `json:"record"`
	Verdict       *attest.Verdict `json:"verdict"`
	Result        int             `json:"result"`
}

// app plays the mobile application around a Session.
type app struct {
	t       *testing.T
	noise   []byte
	anchor  *ecdsa.PrivateKey
	record  string
	events  []event
	verdict *attest.Verdict
}

func (a *app) cfg() string { return `{"verifier_id":"pixel-1","verifier_name":"Pixel 9"}` }

// run drives s over the link until the session ends.
func (a *app) run(s *Session, link *memLink, conn *frame.Conn, mtu int) {
	a.t.Helper()
	if err := s.SetMaxFragment(mtu - 3); err != nil {
		a.t.Fatal(err)
	}
	pending := []*Step{s.Start()}
	for !s.Finished() || len(pending) > 0 {
		if len(pending) == 0 {
			select {
			case n := <-link.toApp:
				pending = append(pending, s.OnNotification(n))
			case <-time.After(5 * time.Second):
				a.t.Fatal("timed out waiting for the machine")
			}
			continue
		}
		st := pending[0]
		pending = pending[1:]
		for i := 0; i < st.FragmentCount(); i++ {
			if len(st.Fragment(i)) > mtu-3 {
				a.t.Fatalf("RX write of %d bytes exceeds MTU %d", len(st.Fragment(i)), mtu)
			}
			conn.Deliver(st.Fragment(i)) // the machine's RX characteristic
		}
		for i := 0; i < st.EventCount(); i++ {
			var e event
			if err := json.Unmarshal([]byte(st.Event(i)), &e); err != nil {
				a.t.Fatal(err)
			}
			a.events = append(a.events, e)
			switch e.Type {
			case "sas":
				pending = append(pending, s.ConfirmSAS(true))
			case "need_anchor_key":
				a.anchor, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				der, _ := x509.MarshalPKIXPublicKey(&a.anchor.PublicKey)
				pending = append(pending, s.ProvideAnchorKey(der))
			case "need_signature":
				d := sha256.Sum256(s.PendingTBS())
				sig, _ := ecdsa.SignASN1(rand.Reader, a.anchor, d[:])
				pending = append(pending, s.ProvideSignature(sig))
			case "verdict":
				a.verdict = e.Verdict
				if e.NeedsDecision {
					pending = append(pending, s.Decide(DecisionApproveRemember, ""))
				}
			case "enrolled", "record_updated":
				a.record = string(e.Record)
			case "error":
				a.t.Fatalf("session error event: %s", st.Event(i))
			}
		}
	}
	if !s.Succeeded() {
		a.t.Fatal("session did not succeed")
	}
}

func newLinkConn(t *testing.T, mtu int) (*memLink, *frame.Conn) {
	l := &memLink{max: mtu - 3, toApp: make(chan []byte, 4096), closed: make(chan struct{})}
	c, err := frame.NewConn(l, frame.DefaultBudget)
	if err != nil {
		t.Fatal(err)
	}
	return l, c
}

func TestBindingEnrolAndAttest(t *testing.T) {
	for _, mtu := range []int{23, 185} {
		m, err := attesttest.NewMachine()
		if err != nil {
			t.Fatal(err)
		}
		noise, _ := GenerateNoiseKey()
		a := &app{t: t, noise: noise}

		// Enrolment.
		link, conn := newLinkConn(t, mtu)
		done := make(chan error, 1)
		go func() { _, err := m.ServeEnrolment(conn, true); conn.Close(); done <- err }()
		s, err := NewEnrolSession(a.cfg(), noise)
		if err != nil {
			t.Fatal(err)
		}
		a.run(s, link, conn, mtu)
		if err := <-done; err != nil {
			t.Fatalf("mtu %d: machine enrolment: %v", mtu, err)
		}
		if a.record == "" || s.RecordJSON() == "" {
			t.Fatal("no record after enrolment")
		}
		if _, err := RecordSummary(a.record); err != nil {
			t.Fatal(err)
		}

		// The machine's advertisement is recognisable with the record.
		sd := attest.BuildServiceData(attest.AdvFlagAttest, []byte{1, 2, 3, 4}, m.AdvKey)
		if !MatchAdvertisement(sd, a.record) || AdvertisementFlags(sd) != AdvFlagAttest {
			t.Fatal("advertisement not matched")
		}
		other := attest.BuildServiceData(attest.AdvFlagAttest, []byte{1, 2, 3, 4}, make([]byte, 32))
		if MatchAdvertisement(other, a.record) {
			t.Fatal("foreign advertisement matched")
		}

		// Attestation of a changed boot, approved and remembered.
		m.TPM.Extend(4, "new bootloader")
		m.TPM.ResetCount++
		link, conn = newLinkConn(t, mtu)
		type res struct {
			r   *attest.AttestResult
			err error
		}
		rch := make(chan res, 1)
		go func() {
			r, err := attest.ServeAttestation(conn, m.AttestIdentity(), m.TPM, nil)
			conn.Close()
			rch <- res{r, err}
		}()
		s, err = NewAttestSession(a.cfg(), noise, a.record)
		if err != nil {
			t.Fatal(err)
		}
		a.run(s, link, conn, mtu)
		got := <-rch
		if got.err != nil {
			t.Fatalf("mtu %d: machine attestation: %v", mtu, got.err)
		}
		if got.r.Check.Verdict != attest.VerdictApproved || !got.r.Check.Authentic {
			t.Fatalf("mtu %d: unexpected receipt check %+v", mtu, got.r.Check)
		}
		if a.verdict == nil || a.verdict.State != attest.StateChanged {
			t.Fatalf("expected a changed verdict, got %+v", a.verdict)
		}
	}
}

func TestStepCarriesErrorRecordOnFailure(t *testing.T) {
	noise, _ := GenerateNoiseKey()
	s, err := NewEnrolSession(`{"verifier_id":"x"}`, noise)
	if err != nil {
		t.Fatal(err)
	}
	if st := s.ProvideSignature([]byte{1}); st.Err() == "" {
		t.Fatal("out-of-order call must report an error")
	}
	if s.Finished() {
		t.Fatal("a rejected out-of-order call must not end the session")
	}
	if st := s.Abort("user cancelled"); !s.Finished() || st.EventCount() == 0 {
		t.Fatal("abort must end the session with an error event")
	}
}
