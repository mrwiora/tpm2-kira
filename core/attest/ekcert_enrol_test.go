package attest_test

import (
	"testing"

	. "github.com/tpm2-trust/tpm2-kira/core/attest"
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
	// The demo machine's 0, 2, 4, 7 and no event log: not established, and it says why.
	if e.InitrdCoverage != InitrdNotEstablished || e.InitrdDetail == "" {
		t.Fatalf("initrd coverage: %q, %q", e.InitrdCoverage, e.InitrdDetail)
	}
	if rec.EKVerifiedBy != "" {
		t.Fatalf("record claims verification by %q", rec.EKVerifiedBy)
	}
}
