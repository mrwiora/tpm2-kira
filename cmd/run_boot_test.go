package cmd

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// A boot display drives systemd's READY only after it has tried to unseal
// every slot, and a slot that unseals only afterwards is marked as such.
func TestBootDisplayNotifiesAfterUnsealAndRetriesAfterwards(t *testing.T) {
	var mu sync.Mutex
	var log []string
	clock := time.Date(2026, 10, 6, 0, 0, 5, 0, time.UTC)
	retries := 0
	done := make(chan struct{})
	var shown []NVRAMSlot

	b := &bootDisplay{
		scan: func() ([]NVRAMSlot, error) {
			mu.Lock()
			log = append(log, "scan")
			mu.Unlock()
			return []NVRAMSlot{
				{SlotNumber: 0, Index: NVRAMSlotStart, Secret: "JBSWY3DPEHPK3PXP", Available: true},
				{SlotNumber: 1, Index: NVRAMSlotStart + 1, Available: true, Error: errors.New("PCR mismatch")},
			}, nil
		},
		retry: func(s NVRAMSlot) NVRAMSlot {
			mu.Lock()
			log = append(log, "retry")
			retries++
			n := retries
			mu.Unlock()
			if n < 2 {
				return s
			}
			s.Error, s.Secret = nil, "JBSWY3DPEHPK3PXP"
			return s
		},
		notify: func() {
			mu.Lock()
			log = append(log, "notify")
			mu.Unlock()
		},
		show: func(slots []NVRAMSlot, codes map[int]string) {
			mu.Lock()
			log = append(log, "show")
			shown = append([]NVRAMSlot(nil), slots...)
			allUp := len(codes) == 2
			mu.Unlock()
			if allUp {
				close(done)
				runtime.Goexit()
			}
		},
		sleep: func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() },
		now:   func() time.Time { mu.Lock(); defer mu.Unlock(); return clock },

		scanRetry: 30 * time.Second, quickRetryFor: time.Minute, retryEvery: 2 * time.Second,
	}
	go b.run()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("display never showed both slots")
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"scan", "notify", "show", "retry", "retry", "show"}
	if len(log) < len(want) {
		t.Fatalf("log %v", log)
	}
	for i, w := range want {
		if log[i] != w {
			t.Fatalf("step %d: got %q, want %q (log %v)", i, log[i], w, log)
		}
	}
	if !shown[1].AfterSeparator || shown[0].AfterSeparator {
		t.Fatalf("only the retried slot is marked: %+v", shown)
	}
}

func TestNextTOTPBoundary(t *testing.T) {
	at := func(s int) time.Time { return time.Date(2026, 1, 1, 0, 0, s, 500, time.UTC) }
	if got := nextTOTPBoundary(at(5)); got.Second() != 30 {
		t.Fatalf("from :05 got %v", got)
	}
	if got := nextTOTPBoundary(at(31)); got.Second() != 0 || got.Minute() != 1 {
		t.Fatalf("from :31 got %v", got)
	}
}
