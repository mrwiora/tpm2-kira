package cmd

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// The boot display releases the boot (READY) only after it has asked the TPM
// for every slot's codes; a slot that yields a code only afterwards is served
// live and marked; a slot's precomputed codes run out at the horizon.
func TestBootDisplayComputesCodesBeforeReleasingTheBoot(t *testing.T) {
	var mu sync.Mutex
	var log []string
	clock := time.Date(2026, 10, 6, 0, 0, 5, 0, time.UTC)
	lives := 0
	done := make(chan struct{})
	var shown [][]NVRAMSlot

	b := &bootDisplay{
		scan: func(from time.Time) ([]NVRAMSlot, error) {
			mu.Lock()
			log = append(log, "scan")
			mu.Unlock()
			return []NVRAMSlot{
				{SlotNumber: 0, Index: NVRAMSlotStart, Available: true, Codes: []string{"111111", "222222"}, CodesFrom: from},
				{SlotNumber: 1, Index: NVRAMSlotStart + 1, Available: true, Error: errors.New("PCR mismatch")},
			}, nil
		},
		live: func(s NVRAMSlot, now time.Time) NVRAMSlot {
			mu.Lock()
			log = append(log, "live")
			lives++
			n := lives
			mu.Unlock()
			if n < 2 {
				return s
			}
			s.Error, s.Code = nil, "999999"
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
			shown = append(shown, append([]NVRAMSlot(nil), slots...))
			exhausted := errors.Is(slots[0].Error, ErrCodesExhausted)
			mu.Unlock()
			if exhausted {
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
		t.Fatal("the display never ran out of precomputed codes")
	}

	mu.Lock()
	defer mu.Unlock()
	// Two retries until the slot yields a code; it is then recomputed live
	// when shown, like every window from here on.
	for i, w := range []string{"scan", "notify", "show", "live", "live", "live", "show"} {
		if log[i] != w {
			t.Fatalf("step %d: got %q, want %q (log %v)", i, log[i], w, log)
		}
	}
	first := shown[0]
	if first[0].Code != "111111" || first[0].AfterSeparator {
		t.Fatalf("first window should show the first precomputed code: %+v", first[0])
	}
	second := shown[1]
	if second[1].Code != "999999" || !second[1].AfterSeparator {
		t.Fatalf("the retried slot is served live and marked: %+v", second[1])
	}
	last := shown[len(shown)-1]
	if !errors.Is(last[0].Error, ErrCodesExhausted) || last[1].Code != "999999" {
		t.Fatalf("after the horizon slot 0 is exhausted, the live slot continues: %+v", last)
	}
	// The second window still had a precomputed code.
	for _, s := range shown[1 : len(shown)-1] {
		if s[0].Code != "111111" && s[0].Code != "222222" {
			t.Fatalf("precomputed codes should be served in order: %+v", s[0])
		}
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
