// Package attesttest provides an in-memory transport and a simulated phone
// for driving real protocol sessions in tests outside package attest
// (swtpm integration tests, the mobile binding).
package attesttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/matthias/tpm2-kira/attest"
)

// Pipe is one end of an in-memory record pipe implementing attest.Conn.
type Pipe struct {
	in, out chan []byte
	closed  chan struct{}
	once    *sync.Once
}

// NewPipe returns two connected ends.
func NewPipe() (*Pipe, *Pipe) {
	a, b := make(chan []byte, 64), make(chan []byte, 64)
	closed := make(chan struct{})
	once := &sync.Once{}
	return &Pipe{in: a, out: b, closed: closed, once: once}, &Pipe{in: b, out: a, closed: closed, once: once}
}

// Send implements attest.Conn.
func (p *Pipe) Send(r []byte) error {
	select {
	case <-p.closed:
		return errors.New("pipe closed")
	case p.out <- append([]byte(nil), r...):
		return nil
	}
}

// Recv implements attest.Conn.
func (p *Pipe) Recv() ([]byte, error) {
	select {
	case r := <-p.in:
		return r, nil
	case <-p.closed:
		select {
		case r := <-p.in:
			return r, nil
		default:
			return nil, errors.New("pipe closed")
		}
	}
}

// Close implements attest.Conn.
func (p *Pipe) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

// Phone simulates the app around an attest.Verifier: a software anchor key
// standing in for the Secure Enclave / StrongBox key, and a user who
// confirms codes and makes decisions.
type Phone struct {
	Noise     *attest.NoiseKeypair
	Anchor    *ecdsa.PrivateKey
	SASAnswer bool
	Decision  attest.Decision
	Confirm   string
	WantLog   bool // fetch the event log before deciding on a changed state
	Events    []attest.Event
	Record    *attest.MachineRecord
	SAS       string
}

// NewPhone creates a phone with fresh keys that confirms every code and
// approves every changed state once.
func NewPhone() (*Phone, error) {
	kp, err := attest.GenerateNoiseKeypair(nil)
	if err != nil {
		return nil, err
	}
	return &Phone{Noise: kp, SASAnswer: true, Decision: attest.DecisionApproveOnce}, nil
}

// Config returns the verifier configuration for this phone.
func (p *Phone) Config() attest.VerifierConfig {
	return attest.VerifierConfig{NoiseStatic: p.Noise, VerifierID: "test-phone", VerifierName: "Test Phone"}
}

// Drive runs v against conn until the session finishes.
func (p *Phone) Drive(v *attest.Verifier, conn attest.Conn) error {
	out, err := v.Start()
	if err != nil {
		return err
	}
	var lastErr error
	for {
		for _, r := range out.Records {
			if err := conn.Send(r); err != nil {
				return err
			}
		}
		next, err := p.react(v, out.Events)
		if next != nil && err != nil {
			for _, r := range next.Records {
				_ = conn.Send(r)
			}
		}
		if err != nil {
			return err
		}
		if next != nil {
			out = next
			continue
		}
		if v.Finished() {
			if !v.Succeeded() {
				return fmt.Errorf("verifier failed: %v", lastErr)
			}
			return nil
		}
		rec, err := conn.Recv()
		if err != nil {
			return err
		}
		out, lastErr = v.HandleRecord(rec)
	}
}

func (p *Phone) react(v *attest.Verifier, evs []attest.Event) (*attest.Output, error) {
	merged := &attest.Output{}
	acted := false
	for _, e := range evs {
		p.Events = append(p.Events, e)
		var o *attest.Output
		var err error
		switch e.Type {
		case attest.EvSAS:
			p.SAS = e.SAS
			o, err = v.ConfirmSAS(p.SASAnswer)
		case attest.EvNeedAnchorKey:
			if p.Anchor == nil {
				if p.Anchor, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
					return nil, err
				}
			}
			der, _ := x509.MarshalPKIXPublicKey(&p.Anchor.PublicKey)
			o, err = v.ProvideAnchorKey(der)
		case attest.EvNeedSignature:
			d := sha256.Sum256(e.TBS)
			sig, serr := ecdsa.SignASN1(rand.Reader, p.Anchor, d[:])
			if serr != nil {
				return nil, serr
			}
			o, err = v.ProvideSignature(sig)
		case attest.EvVerdict:
			if e.NeedsDecision {
				if p.WantLog && e.EventlogAvail {
					o, err = v.RequestEventlog()
				} else {
					o, err = v.Decide(p.Decision, p.Confirm)
				}
			}
		case attest.EvEventlog:
			if e.Complete {
				o, err = v.Decide(p.Decision, p.Confirm)
			}
		case attest.EvEnrolled, attest.EvRecordUpdated:
			p.Record = e.Record
		}
		if o != nil {
			acted = true
			merged.Records = append(merged.Records, o.Records...)
			merged.Events = append(merged.Events, o.Events...)
		}
		if err != nil {
			return merged, err
		}
	}
	if !acted {
		return nil, nil
	}
	return merged, nil
}

// Has reports whether an event of a type was seen.
func (p *Phone) Has(typ string) bool { return p.Last(typ) != nil }

// Last returns the most recent event of a type, or nil.
func (p *Phone) Last(typ string) *attest.Event {
	for i := len(p.Events) - 1; i >= 0; i-- {
		if p.Events[i].Type == typ {
			return &p.Events[i]
		}
	}
	return nil
}
