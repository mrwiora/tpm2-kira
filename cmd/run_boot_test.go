package cmd

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

// With nothing sealed the display says so once, releases the boot and is
// done: the unit is in every image, and must not loop there for nothing.
func TestBootDisplayExitsWhenNothingIsSealed(t *testing.T) {
	f := &fakeBoot{clock: time.Date(2026, 10, 6, 0, 0, 5, 0, time.UTC)}
	b := f.display(nil, nil, nil)
	b.scan = func(time.Time) ([]NVRAMSlot, error) {
		f.mu.Lock()
		f.log = append(f.log, "scan")
		f.mu.Unlock()
		return nil, ErrNoSlots
	}
	done := make(chan struct{})
	go func() { b.run(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the display keeps running with nothing sealed")
	}
	if len(f.log) != 2 || f.log[0] != "scan" || f.log[1] != "notify" {
		t.Fatalf("log %v", f.log)
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

// A gate next to the display: its state is scripted by the fake clock.
func (f *fakeBoot) withGate(b *bootDisplay, at func(elapsed time.Duration) (GateStatus, bool)) (*[]GateStatus, time.Time) {
	start := f.clock
	events := &[]GateStatus{}
	b.phone = func() (GateStatus, bool) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return at(f.clock.Sub(start))
	}
	b.phoneEvent = func(_, cur GateStatus) { *events = append(*events, cur) }
	b.phonePoll = time.Second
	b.phoneGrace = time.Minute
	return events, start
}

func runDisplay(t *testing.T, b *bootDisplay) {
	t.Helper()
	done := make(chan struct{})
	go func() { b.run(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the display did not release the boot")
	}
}

func notified(f *fakeBoot) bool {
	for _, l := range f.log {
		if l == "notify" {
			return true
		}
	}
	return false
}

// A slot enrolled with a phone is verified by the phone: its verdict
// releases the boot without Enter, and the code was on the screen meanwhile.
func TestPhoneVerdictReleasesTheBoot(t *testing.T) {
	f := &fakeBoot{clock: time.Date(2026, 10, 6, 0, 0, 5, 0, time.UTC)}
	b := f.display(okSlot, nil, nil)
	events, start := f.withGate(b, func(e time.Duration) (GateStatus, bool) {
		switch {
		case e < 3*time.Second:
			return GateStatus{}, false // the gate is still starting
		case e < 8*time.Second:
			return GateStatus{Slot: 0, State: GateWaiting}, true
		case e < 12*time.Second:
			return GateStatus{Slot: 0, State: GateSession}, true
		}
		return GateStatus{Slot: 0, State: GateAttested, Phone: "Pixel"}, true
	})
	runDisplay(t, b)
	if got := f.clock.Sub(start); got < 12*time.Second || got > 14*time.Second {
		t.Fatalf("released after %s, want at the phone's verdict (12 s)", got)
	}
	if len(f.shown) == 0 || f.shown[0][0].Code == "" {
		t.Fatal("the code was not shown while the phone was asked")
	}
	var states []GateState
	for _, e := range *events {
		states = append(states, e.State)
	}
	if len(states) != 3 || states[0] != GateWaiting || states[1] != GateSession || states[2] != GateAttested {
		t.Fatalf("announced %v", states)
	}
	if !notified(f) {
		t.Fatal("no READY")
	}
}

// A phone that rejects the boot does not release it early; the hold runs
// its course, as it does when nobody answers (lazy mode holds nothing back).
func TestPhoneRejectionDoesNotReleaseEarly(t *testing.T) {
	for _, state := range []GateState{GateRejected, GateRefused, GateUnavailable, GateWaiting} {
		f := &fakeBoot{clock: time.Date(2026, 10, 6, 0, 0, 5, 0, time.UTC)}
		b := f.display(okSlot, nil, nil)
		_, start := f.withGate(b, func(e time.Duration) (GateStatus, bool) {
			if e < 5*time.Second {
				return GateStatus{Slot: 0, State: GateWaiting}, true
			}
			return GateStatus{Slot: 0, State: state, Phone: "Pixel"}, true
		})
		runDisplay(t, b)
		if got := f.clock.Sub(start); got != 90*time.Second {
			t.Fatalf("%s: released after %s, want the full hold", state, got)
		}
	}
}

// A phone in the middle of its session when the hold ends may finish, for a
// bounded time.
func TestPhoneSessionExtendsTheHold(t *testing.T) {
	gate := func(verdictAt time.Duration) func(time.Duration) (GateStatus, bool) {
		return func(e time.Duration) (GateStatus, bool) {
			switch {
			case e < 85*time.Second:
				return GateStatus{Slot: 0, State: GateWaiting}, true
			case verdictAt > 0 && e >= verdictAt:
				return GateStatus{Slot: 0, State: GateAttested, Phone: "Pixel"}, true
			}
			return GateStatus{Slot: 0, State: GateSession}, true
		}
	}
	f := &fakeBoot{clock: time.Date(2026, 10, 6, 0, 0, 5, 0, time.UTC)}
	b := f.display(okSlot, nil, nil)
	_, start := f.withGate(b, gate(100*time.Second))
	runDisplay(t, b)
	if got := f.clock.Sub(start); got < 100*time.Second || got > 102*time.Second {
		t.Fatalf("released after %s, want at the verdict (100 s)", got)
	}

	// A session that never ends: released when the grace is over.
	f = &fakeBoot{clock: time.Date(2026, 10, 6, 0, 0, 5, 0, time.UTC)}
	b = f.display(okSlot, nil, nil)
	_, start = f.withGate(b, gate(0))
	runDisplay(t, b)
	if got := f.clock.Sub(start); got != 150*time.Second {
		t.Fatalf("released after %s, want hold + grace (150 s)", got)
	}

	// Enter still works while a phone is connected.
	f = &fakeBoot{clock: time.Date(2026, 10, 6, 0, 0, 5, 0, time.UTC), enters: []bool{false, false, true}}
	b = f.display(okSlot, nil, nil)
	_, start = f.withGate(b, func(time.Duration) (GateStatus, bool) { return GateStatus{Slot: 0, State: GateSession}, true })
	runDisplay(t, b)
	if got := f.clock.Sub(start); got > 5*time.Second {
		t.Fatalf("Enter released after %s", got)
	}
}

// The keyboard reader reports Enter, and once stopped leaves what is typed
// to whoever reads the terminal next: the passphrase prompt.
func TestEnterReaderLetsGoOfTheTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	e := startEnterReader(int(r.Fd()))

	w.Write([]byte("abc")) // typing without Enter is not a confirmation
	select {
	case <-e.presses:
		t.Fatal("reported Enter without one")
	case <-time.After(300 * time.Millisecond):
	}
	w.Write([]byte("\n"))
	select {
	case <-e.presses:
	case <-time.After(2 * time.Second):
		t.Fatal("Enter not reported")
	}

	stopped := make(chan struct{})
	go func() { e.stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("the reader did not stop")
	}
	e.stop() // twice is fine

	// What is typed now is still there for the next reader.
	w.Write([]byte("my passphrase\n"))
	time.Sleep(400 * time.Millisecond)
	buf := make([]byte, 64)
	r.SetReadDeadline(time.Now().Add(time.Second))
	n, err := r.Read(buf)
	if err != nil || string(buf[:n]) != "my passphrase\n" {
		t.Fatalf("the stopped reader took input: %q %v", buf[:n], err)
	}

	// A terminal that is not there (closed stdin) never reports anything
	// and stops at once.
	r2, w2, _ := os.Pipe()
	w2.Close()
	e2 := startEnterReader(int(r2.Fd()))
	select {
	case <-e2.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the reader kept polling a closed input")
	}
	e2.stop()
	r2.Close()
}

// openPTY returns a pseudo-terminal: the side a keyboard types into and the
// terminal side a program reads.
func openPTY(t *testing.T) (keyboard, terminal *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminals here: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Skipf("cannot unlock the pseudo-terminal: %v", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Skipf("no pseudo-terminal name: %v", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("cannot open the terminal side: %v", err)
	}
	t.Cleanup(func() { s.Close(); m.Close() })
	return m, s
}

// The same on a terminal device, where a line is only readable once Enter
// was pressed: Enter is reported, and after the reader stopped, a line typed
// at the passphrase prompt is still there for the prompt.
func TestEnterReaderOnATerminal(t *testing.T) {
	keyboard, terminal := openPTY(t)
	fd, err := unix.Dup(int(terminal.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	e := startEnterReader(fd)

	keyboard.Write([]byte("no"))
	select {
	case <-e.presses:
		t.Fatal("reported Enter without one")
	case <-time.After(400 * time.Millisecond):
	}
	keyboard.Write([]byte("\r")) // the Enter key
	select {
	case <-e.presses:
	case <-time.After(2 * time.Second):
		t.Fatal("Enter on a terminal not reported")
	}
	keyboard.Write([]byte("\r")) // and again, as an impatient user does
	select {
	case <-e.presses:
	case <-time.After(2 * time.Second):
		t.Fatal("second Enter not reported")
	}
	e.stop()

	keyboard.Write([]byte("correct horse\r"))
	time.Sleep(400 * time.Millisecond)
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := unix.Read(fd, buf)
		got <- string(buf[:n])
	}()
	select {
	case line := <-got:
		if line != "correct horse\n" {
			t.Fatalf("the prompt read %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the stopped reader took the passphrase line")
	}
}

// The phone's code goes into the slot's line the moment the phone is in,
// not at the next window: a redraw follows the session's start.
func TestPhoneCodeShownAtOnce(t *testing.T) {
	f := &fakeBoot{clock: time.Date(2026, 10, 6, 0, 0, 5, 0, time.UTC)}
	b := f.display(okSlot, nil, nil)
	f.withGate(b, func(e time.Duration) (GateStatus, bool) {
		switch {
		case e < 4*time.Second:
			return GateStatus{Slot: 0, State: GateWaiting}, true
		case e < 9*time.Second:
			return GateStatus{Slot: 0, State: GateSession, Code: "K7QM-2XHD"}, true
		}
		return GateStatus{Slot: 0, State: GateAttested, Phone: "Pixel"}, true
	})
	runDisplay(t, b)
	// The first frame is the TOTP alone; a frame drawn at the session's
	// start (within a second of :09, well before the :30 window) follows.
	if len(f.shown) < 2 {
		t.Fatalf("%d frames; the session's start did not redraw", len(f.shown))
	}
	codes := phoneCodes(map[int]string{0: "123456"}, GateStatus{Slot: 0, Code: "K7QM-2XHD"}, true)
	if !strings.Contains(codes[0], "K7QM-2XHD") || strings.Contains(codes[0], "123456") {
		t.Fatalf("slot line with a phone in: %q", codes[0])
	}
	if codes := phoneCodes(map[int]string{0: "123456"}, GateStatus{}, false); codes[0] != "123456" {
		t.Fatalf("slot line without a phone: %q", codes[0])
	}
}
