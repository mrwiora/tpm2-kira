package phonegate

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrwiora/tpm2-kira/internal/journal"
)

// TestMain is also the radio worker of TestRadioWorker: the test binary,
// started again as 'gate-child'.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "gate-child" {
		os.Exit(RadioWorkerMain(true))
	}
	os.Exit(m.Run())
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// The worker is a process of its own: it confines itself before it asks
// the coordinator anything, says so in the coordinator's narrative, and
// ends when the coordinator stops it - while it still waits for an
// adapter.
func TestRadioWorker(t *testing.T) {
	out := &lockedBuffer{}
	journal.NarrateOut = out
	t.Cleanup(func() { journal.NarrateOut = os.Stdout })
	workerCommand = func(bool) *exec.Cmd { return exec.Command(os.Args[0], "gate-child") }
	t.Cleanup(func() { workerStopWait = 3 * time.Second })
	workerStopWait = time.Hour // a worker that does not end by itself hangs the test

	host := &fakeHost{identity: &gateIdentity{Slot: 1, FriendlyName: "box", NoisePrivate: make([]byte, 32)}}
	stop, err := StartRadioWorker(host, true)
	if err != nil {
		t.Fatal(err)
	}
	for !strings.Contains(out.String(), "radio worker, uid") {
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	t.Logf("%s", out)
	line := out.String()
	if !strings.Contains(line, "no new privileges") {
		t.Fatalf("the worker did not confine itself: %s", line)
	}
	if strings.Contains(line, "Landlock ABI") && !strings.Contains(line, "reads /sys alone") {
		t.Fatalf("the worker reads more than /sys: %s", line)
	}
}
