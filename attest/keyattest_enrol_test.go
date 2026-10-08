package attest_test

import (
	"errors"
	"testing"

	. "github.com/mrwiora/tpm2-kira/attest"
	"github.com/mrwiora/tpm2-kira/attest/attesttest"
)

// refusingBackend is the software TPM with a machine operator who refuses the
// phone's key attestation.
type refusingBackend struct {
	*attesttest.SoftEnrol
	seen *PhoneAttestation
}

func (r refusingBackend) JudgePhone(a PhoneAttestation) (bool, error) {
	*r.seen = a
	return false, nil
}

func TestMachineRefusesUnattestedPhone(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	var seen PhoneAttestation
	be := refusingBackend{SoftEnrol: &attesttest.SoftEnrol{SoftTPM: m.TPM, SASAnswer: true}, seen: &seen}
	a, b := attesttest.NewPipe()
	done := make(chan error, 1)
	go func() {
		_, err := ServeEnrolment(a, m.EnrolIdentity(), be, nil)
		a.Close()
		done <- err
	}()
	v, err := NewEnrolVerifier(p.Config())
	if err != nil {
		t.Fatal(err)
	}
	perr := p.Drive(v, b)
	merr := <-done
	if merr == nil || perr == nil {
		t.Fatalf("enrolment went through: machine %v phone %v", merr, perr)
	}
	var em *ErrorMsg
	if !errors.As(perr, &em) && p.Last(EvError) == nil {
		t.Fatalf("phone not told: %v", perr)
	}
	if e := p.Last(EvError); e == nil || e.Code != ErrCodePolicy {
		t.Fatalf("phone error: %+v", e)
	}
	if seen.Verified || len(seen.Problems) == 0 || seen.Problems[0] != "the phone sent no key attestation (its Android version or ROM cannot attest keys)" {
		t.Fatalf("judge saw %+v", seen)
	}
	if p.Record != nil {
		t.Fatal("the phone stored a record")
	}
}
