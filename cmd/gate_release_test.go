package cmd

import (
	"testing"
	"time"
)

// An attested boot with a remote salt expected waits for the Release:
// until it is taken, the session is over, or the bound has passed.
func TestGateWaitsForTheRelease(t *testing.T) {
	s := &gateService{expectRelease: true, blob: &Attestation{ReleaseKeyPublic: []byte{1}}}
	s.status = GateStatus{Slot: 0, State: GateAttested, Releasing: true}
	s.releaseSince = time.Now()
	if st, _ := s.Status(); st.Released() {
		t.Fatal("released before the salt arrived")
	}
	s.Report(GateWaiting) // ignored after a verdict
	if st, _ := s.Status(); !st.Releasing || st.State != GateAttested {
		t.Fatalf("a report changed the verdict: %+v", st)
	}
	s.Report(GateSessionOver)
	if st, _ := s.Status(); !st.Released() {
		t.Fatalf("the session is over, yet not released: %+v", st)
	}

	// The bound.
	s.status.Releasing = true
	s.releaseSince = time.Now().Add(-releaseWait - time.Second)
	if st, _ := s.Status(); !st.Released() {
		t.Fatalf("the bound did not release the boot: %+v", st)
	}

	// Without the expectation nothing waits; a verdict without a release
	// key either.
	if (GateStatus{State: GateAttested}).Released() != true || (GateStatus{State: GateSession}).Released() {
		t.Fatal("Released() is wrong without a pending release")
	}
}
