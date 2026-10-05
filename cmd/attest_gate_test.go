package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/matthias/tpm2-kira/attest"
	"github.com/matthias/tpm2-kira/transport/ble"
	"github.com/matthias/tpm2-kira/transport/frame"
)

// fakeAcceptor plays the BLE peripheral: each Accept either times out after
// its full window (advancing the fake clock) or returns a connection.
type fakeAcceptor struct {
	clock   *time.Time
	windows []time.Duration
	connect map[int]bool // 1-based Accept calls on which a phone connects
	err     error
}

type nopLink struct{}

func (nopLink) SendFragment([]byte) error { return nil }
func (nopLink) MaxFragment() int          { return 182 }
func (nopLink) Close() error              { return nil }

func (f *fakeAcceptor) Accept(_ ble.Advertisement, _ frame.Budget, timeout time.Duration) (*frame.Conn, error) {
	f.windows = append(f.windows, timeout)
	if f.err != nil {
		return nil, f.err
	}
	if f.connect[len(f.windows)] {
		*f.clock = f.clock.Add(time.Second)
		return frame.NewConn(nopLink{}, frame.DefaultBudget)
	}
	*f.clock = f.clock.Add(timeout)
	return nil, ble.ErrAcceptTimeout
}

func gateHarness(timeout time.Duration, acc *fakeAcceptor, serve func(*frame.Conn) (*attest.AttestResult, error)) (*attest.AttestResult, error, string) {
	var out bytes.Buffer
	now := func() time.Time { return *acc.clock }
	res, err := waitForReceipt(acc, ble.Advertisement{}, timeout, serve, &out, now)
	return res, err, out.String()
}

func receiptServe(*frame.Conn) (*attest.AttestResult, error) {
	return &attest.AttestResult{Receipt: &attest.Receipt{}}, nil
}

func TestGateWaitsInRoundsUntilTimeout(t *testing.T) {
	clock := time.Unix(0, 0)
	acc := &fakeAcceptor{clock: &clock}
	res, err, out := gateHarness(70*time.Second, acc, receiptServe)
	if res != nil || !errors.Is(err, errNoPhoneReachable) {
		t.Fatalf("got %v, %v; want errNoPhoneReachable", res, err)
	}
	want := []time.Duration{30 * time.Second, 30 * time.Second, 10 * time.Second}
	if len(acc.windows) != len(want) {
		t.Fatalf("advertising rounds %v, want %v", acc.windows, want)
	}
	for i := range want {
		if acc.windows[i] != want[i] {
			t.Fatalf("advertising rounds %v, want %v", acc.windows, want)
		}
	}
	if strings.Count(out, "nothing has connected over Bluetooth") != 1 {
		t.Errorf("the explanation should appear once:\n%s", out)
	}
	for _, line := range []string{"phone not reachable yet (round 1)", "phone not reachable yet (round 2)"} {
		if !strings.Contains(out, line) {
			t.Errorf("missing %q in:\n%s", line, out)
		}
	}
	// No "trying again" once the time is up.
	if strings.Contains(out, "round 3") {
		t.Errorf("promised a retry after the timeout:\n%s", out)
	}
}

func TestGateWaitsForeverWithoutTimeout(t *testing.T) {
	clock := time.Unix(0, 0)
	acc := &fakeAcceptor{clock: &clock, connect: map[int]bool{25: true}}
	res, err, out := gateHarness(0, acc, receiptServe)
	if err != nil || res == nil {
		t.Fatalf("got %v, %v", res, err)
	}
	if len(acc.windows) != 25 || clock.Sub(time.Unix(0, 0)) != 721*time.Second {
		t.Fatalf("%d rounds, %s elapsed", len(acc.windows), clock.Sub(time.Unix(0, 0)))
	}
	if !strings.Contains(out, "phone not reachable yet (round 24), still waiting") {
		t.Errorf("missing retry line:\n%s", out)
	}
}

func TestGateTellsAFailedSessionApartFromNoPhone(t *testing.T) {
	clock := time.Unix(0, 0)
	acc := &fakeAcceptor{clock: &clock, connect: map[int]bool{2: true, 3: true}}
	calls := 0
	serve := func(c *frame.Conn) (*attest.AttestResult, error) {
		calls++
		if calls == 1 {
			return nil, attest.ErrUnknownVerifier // a stranger's phone
		}
		return receiptServe(c)
	}
	res, err, out := gateHarness(time.Minute, acc, serve)
	if err != nil || res == nil {
		t.Fatalf("got %v, %v", res, err)
	}
	if !strings.Contains(out, "a phone connected, but the session ended without a receipt (attest: initiator is not an enrolled verifier)") {
		t.Errorf("failed session not reported:\n%s", out)
	}
	if strings.Count(out, "phone not reachable yet (round") != 1 {
		t.Errorf("only the first round had no phone:\n%s", out)
	}
}

func TestGateAdapterFailureIsNotNoPhone(t *testing.T) {
	clock := time.Unix(0, 0)
	acc := &fakeAcceptor{clock: &clock, err: errors.New("hci0: adapter gone")}
	_, err, _ := gateHarness(time.Minute, acc, receiptServe)
	if err == nil || errors.Is(err, errNoPhoneReachable) {
		t.Fatalf("adapter failure reported as %v", err)
	}
}
