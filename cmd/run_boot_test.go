package cmd

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// A fake environment for the boot display: a clock that advances on every
// wait and sleep, and a script of Enter presses.
type fakeBoot struct {
	mu      sync.Mutex
	clock   time.Time
	log     []string
	shown   [][]NVRAMSlot
	enters  []bool // answers for successive waits
	lives   int
	stopped chan struct{} // closed when stop() ends the display
}

func (f *fakeBoot) display(scan func(time.Time) []NVRAMSlot, live func(NVRAMSlot, time.Time) NVRAMSlot, stop func([]NVRAMSlot) bool) *bootDisplay {
	return &bootDisplay{
		scan: func(now time.Time) ([]NVRAMSlot, error) {
			f.mu.Lock()
			f.log = append(f.log, "scan")
			f.mu.Unlock()
			return scan(now), nil
		},
		live: func(s NVRAMSlot, now time.Time) NVRAMSlot {
			f.mu.Lock()
			f.log = append(f.log, "live")
			f.lives++
			f.mu.Unlock()
			return live(s, now)
		},
		notify: func() { f.mu.Lock(); f.log = append(f.log, "notify"); f.mu.Unlock() },
		show: func(slots []NVRAMSlot, codes map[int]string, remaining time.Duration) {
			f.mu.Lock()
			f.log = append(f.log, "show")
			f.shown = append(f.shown, append([]NVRAMSlot(nil), slots...))
			f.mu.Unlock()
			if stop != nil && stop(slots) {
				close(f.stopped)
				runtime.Goexit()
			}
		},
		wait: func(d time.Duration) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.log = append(f.log, "wait")
			if len(f.enters) > 0 {
				enter := f.enters[0]
				f.enters = f.enters[1:]
				if enter {
					f.clock = f.clock.Add(time.Second)
					return true
				}
			}
			f.clock = f.clock.Add(d)
			return false
		},
		sleep: func(d time.Duration) { f.mu.Lock(); f.clock = f.clock.Add(d); f.mu.Unlock() },
		now:   func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.clock },

		hold: 90 * time.Second, scanRetry: 30 * time.Second, quickRetryFor: time.Minute, retryEvery: 2 * time.Second,
	}
}

func okSlot(now time.Time) []NVRAMSlot {
	return []NVRAMSlot{{SlotNumber: 0, Index: NVRAMSlotStart, Available: true, Code: now.Format("150405")}}
}

// Enter releases the boot: READY after the code was shown, then the display
// is done.
func TestBootDisplayEnterReleasesTheBoot(t *testing.T) {
	f := &fakeBoot{clock: time.Date(2026, 10, 6, 0, 0, 5, 0, time.UTC), enters: []bool{false, true}}
	b := f.display(okSlot, nil, nil)
	done := make(chan struct{})
	go func() { b.run(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after Enter")
	}
	want := []string{"scan", "show", "wait", "scan", "show", "wait", "notify"}
	if len(f.log) != len(want) {
		t.Fatalf("log %v", f.log)
	}
	for i := range want {
		if f.log[i] != want[i] {
			t.Fatalf("step %d: got %q, want %q (log %v)", i, f.log[i], want[i], f.log)
		}
	}
	if f.shown[0][0].Code == f.shown[1][0].Code {
		t.Fatal("each window should show a fresh code")
	}
}

// Without Enter the hold runs out and the boot goes on by itself.
func TestBootDisplayReleasesAfterTheHold(t *testing.T) {
	f := &fakeBoot{clock: time.Date(2026, 10, 6, 0, 0, 5, 0, time.UTC)}
	b := f.display(okSlot, nil, nil)
	done := make(chan struct{})
	go func() { b.run(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after the hold")
	}
	if f.log[len(f.log)-1] != "notify" || len(f.shown) < 3 {
		t.Fatalf("expected several windows then READY: %v", f.log)
	}
	if got := f.clock.Sub(time.Date(2026, 10, 6, 0, 0, 5, 0, time.UTC)); got < 90*time.Second || got > 91*time.Second {
		t.Fatalf("held for %v, want 90 s", got)
	}
}

// A slot with no code during the hold is served live after the release and
// marked; a slot that was fine is then locked.
func TestBootDisplayServesLateSlotsAfterRelease(t *testing.T) {
	f := &fakeBoot{clock: time.Date(2026, 10, 6, 0, 0, 5, 0, time.UTC), enters: []bool{true}}
	scan := func(now time.Time) []NVRAMSlot {
		return []NVRAMSlot{
			{SlotNumber: 0, Index: NVRAMSlotStart, Available: true, Code: "111111"},
			{SlotNumber: 1, Index: NVRAMSlotStart + 1, Available: true, Error: errors.New("PCR mismatch")},
		}
	}
	live := func(s NVRAMSlot, now time.Time) NVRAMSlot {
		if s.SlotNumber == 0 {
			s.Code, s.Error = "", ErrSeparatorLocked
			return s
		}
		f.mu.Lock()
		n := f.lives
		f.mu.Unlock()
		if n < 3 {
			return s
		}
		s.Code, s.Error = "999999", nil
		return s
	}
	stop := func(slots []NVRAMSlot) bool { return slots[1].Error == nil }
	f.stopped = make(chan struct{})
	b := f.display(scan, live, stop)
	go b.run()
	select {
	case <-f.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the late slot never came up")
	}
	last := f.shown[len(f.shown)-1]
	if !last[1].AfterSeparator || last[1].Code != "999999" {
		t.Fatalf("the late slot should be served live and marked: %+v", last[1])
	}
	if !errors.Is(last[0].Error, ErrSeparatorLocked) {
		t.Fatalf("the confirmed slot is locked after the release: %+v", last[0])
	}
	seen := false
	for i, e := range f.log {
		if e == "notify" {
			seen = true
			for _, before := range f.log[:i] {
				if before == "live" {
					t.Fatal("nothing is served live before the release")
				}
			}
		}
	}
	if !seen {
		t.Fatal("READY was never sent")
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
