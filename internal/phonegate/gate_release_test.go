package phonegate

import (
	"testing"
	"time"

	"github.com/mrwiora/tpm2-kira/internal/nvslot"
)

// An attested boot with a phone salt expected waits for the Release:
// until it is taken, the session is over, or the bound has passed.
func TestGateWaitsForTheRelease(t *testing.T) {
	s := &GateService{ExpectingRelease: true, Blob: &nvslot.Attestation{ReleaseKeyPublic: []byte{1}}}
	s.Current = GateStatus{Slot: 0, State: GateAttested, Releasing: true}
	s.ReleaseSince = time.Now()
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
	s.Current.Releasing = true
	s.ReleaseSince = time.Now().Add(-releaseWait - time.Second)
	if st, _ := s.Status(); !st.Released() {
		t.Fatalf("the bound did not release the boot: %+v", st)
	}

	// Without the expectation nothing waits; a verdict without a release
	// key either.
	if (GateStatus{State: GateAttested}).Released() != true || (GateStatus{State: GateSession}).Released() {
		t.Fatal("Released() is wrong without a pending release")
	}
}
