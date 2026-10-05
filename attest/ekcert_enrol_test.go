package attest_test

import (
	"testing"

	. "github.com/matthias/tpm2-kira/attest"
)

// The software TPM double has no EK certificate: enrolment still succeeds,
// the phone is told the TPM is not verified, and the record says so.
func TestEnrolReportsUnverifiedEK(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	rec := enrol(t, m, p)
	e := p.Last(EvNeedAnchorKey)
	if e == nil || e.EKVerifiedBy != "" || e.EKNote != "the TPM has no vendor certificate for its endorsement key" {
		t.Fatalf("need_anchor_key: %+v", e)
	}
	if e.InitrdCoverage != InitrdUnknownMsg {
		t.Fatalf("initrd coverage: %q", e.InitrdCoverage)
	}
	if rec.EKVerifiedBy != "" {
		t.Fatalf("record claims verification by %q", rec.EKVerifiedBy)
	}
}
