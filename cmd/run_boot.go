package cmd

// The TOTP display at the passphrase prompt (tpm2-kira run).
//
// tpm2-kira.service orders itself after systemd-pcrphase-initrd.service
// (enter-initrd on PCR 11) and before systemd-pcrosseparator.service, and is
// Type=notify. While it holds READY=1 back, the PCRs still hold the sealed
// values, so it asks the TPM for a fresh code every 30 seconds and shows it
// with a question: does it match the authenticator? Enter sends READY=1,
// and so does the end of the hold (90 seconds by default), so a boot nobody
// watches continues on its own. The separator then extends os-separator into
// PCRs 0-7, 9, 12-14, after which the key's policy cannot be satisfied again
// until the next boot; the key never left the TPM, and the display has
// nothing left to show, so it exits. 'tpm2-kira cap' at initrd-switch-root
// read-locks the generation index on top of that.
//
// A slot that is enrolled with a phone is verified by that phone instead: a
// verdict from the phone releases the boot the way Enter does. The code
// stays on the screen all the same, as the fallback when the phone is not at
// hand. For that this process is also the gate's coordinator
// (gate_service.go): it holds the TPM for the radio worker
// (tpm2-kira-attest.service), which has none, and reads the phone's receipt
// itself. Its service ends with the hold (lazy mode: the phone has as long
// as the code is asked about, plus the time to finish an answer it has
// begun), and the worker ends with it. The process must not outlive the
// hold on the console in any case: it owns the terminal, and systemd's
// passphrase prompt waits for the terminal to be free.
//
// A slot that yields no code during the hold is served after the boot is
// released: a blob whose policy holds only after the separator (sealed by an
// earlier version, or from registers because the event log cannot be
// replayed) then gets its codes live, window by window, and the display
// says so.

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/sys/unix"
)

// HoldDefault is how long the display waits for Enter before it releases
// the boot on its own.
const HoldDefault = 90 * time.Second

// bootDisplay is RunCommand with its environment pluggable for tests.
type bootDisplay struct {
	scan   func(now time.Time) ([]NVRAMSlot, error) // every slot, with its code for now
	live   func(NVRAMSlot, time.Time) NVRAMSlot     // one slot's code for now
	notify func()                                   // tells systemd the boot may go on
	show   func(slots []NVRAMSlot, codes map[int]string, remaining time.Duration)
	wait   func(d time.Duration) bool // true: Enter was pressed within d
	sleep  func(time.Duration)
	now    func() time.Time

	// The Bluetooth gate, when one runs next to the display; nil otherwise.
	phone      func() (GateStatus, bool)  // its state for the slot it serves
	phoneEvent func(prev, cur GateStatus) // tells the user about a change
	phonePoll  time.Duration              // how often the state is looked at
	phoneGrace time.Duration              // how far a session in progress may extend the hold

	hold          time.Duration // how long to wait for Enter
	scanRetry     time.Duration // between attempts while nothing can be shown
	quickRetryFor time.Duration // after the release, failed slots are retried every retryEvery this long,
	retryEvery    time.Duration // then once per TOTP window
}

func (b *bootDisplay) run() {
	slots, allUp, err := b.holdForConfirmation()
	b.notify()
	if allUp {
		return // every slot was confirmed or at least shown; nothing more can be computed
	}
	if errors.Is(err, ErrNoSlots) {
		// Nothing is sealed: the unit is in every image so that a later
		// 'seal' needs no rebuild, but until then it has nothing to do.
		return
	}
	b.serveAfterRelease(slots)
}

// ErrNoSlots: no NVRAM slot holds a TOTP key.
var ErrNoSlots = errors.New("no TOTP key is sealed")

// holdForConfirmation shows a fresh code per window until the boot is
// confirmed - Enter, or the enrolled phone accepting it - or the hold ends,
// and reports the last slots and whether all of them had a code. A scan
// that fails outright releases the boot at once, with its error.
func (b *bootDisplay) holdForConfirmation() ([]NVRAMSlot, bool, error) {
	deadline := b.now().Add(b.hold)
	var slots []NVRAMSlot
	var gate GateStatus
	allUp := false
	// A phone that is in the middle of its session when the hold ends gets
	// to finish: releasing the boot under it would change the registers
	// between its question and its answer.
	limit := func() time.Time {
		if gate.State == GateSession {
			return deadline.Add(b.phoneGrace)
		}
		return deadline
	}
	for {
		now := b.now()
		s, err := b.scan(now)
		if err != nil {
			PrintKIRAError(err)
			return slots, false, err
		}
		slots = s
		allUp = true
		for _, sl := range slots {
			if sl.Error != nil {
				allUp = false
			}
		}
		codes, _ := GenerateTOTPCodesForSlots(slots)
		// What the prompt is about to say needs no announcement of its own.
		if cur, ok := gateStatus(b.phone); ok && cur.Asking() {
			gate = cur
		}
		remaining := limit().Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		b.show(slots, codes, remaining)
		boundary := nextTOTPBoundary(now)
		for {
			until := boundary
			if l := limit(); l.Before(until) {
				until = l
			}
			enter := b.waitFor(until, &gate)
			if enter || gate.State == GateAttested {
				return slots, allUp, nil
			}
			now := b.now()
			if !now.Before(limit()) {
				return slots, allUp, nil
			}
			if !now.Before(boundary) {
				break // a new code
			}
		}
	}
}

// waitFor waits until the given time, and reports Enter. While it waits it
// follows the gate: a change of its state is announced and ends the wait.
func (b *bootDisplay) waitFor(until time.Time, gate *GateStatus) bool {
	for {
		if cur, ok := gateStatus(b.phone); ok && cur != *gate {
			prev := *gate
			*gate = cur
			if b.phoneEvent != nil {
				b.phoneEvent(prev, cur)
			}
			return false
		}
		left := until.Sub(b.now())
		if left <= 0 {
			return false
		}
		if b.phone != nil && b.phonePoll > 0 && left > b.phonePoll {
			left = b.phonePoll
		}
		if b.wait(left) {
			return true
		}
	}
}

// serveAfterRelease keeps the display up for slots that had no code during
// the hold: once the separator has run, a blob sealed against
// post-separator values yields its codes live. Slots that were fine during
// the hold are now locked and shown as such.
func (b *bootDisplay) serveAfterRelease(slots []NVRAMSlot) {
	for len(slots) == 0 {
		b.sleep(b.scanRetry)
		s, err := b.scan(b.now())
		if err != nil {
			PrintKIRAError(err)
			continue
		}
		slots = s
	}
	failed := map[int]bool{}
	for _, s := range slots {
		failed[s.SlotNumber] = s.Error != nil
	}
	quickUntil := b.now().Add(b.quickRetryFor)
	for {
		now := b.now()
		for i := range slots {
			slots[i] = b.live(slots[i], now)
			if slots[i].Error == nil && failed[slots[i].SlotNumber] {
				slots[i].AfterSeparator = true
			}
		}
		codes, _ := GenerateTOTPCodesForSlots(slots)
		b.show(slots, codes, -1)
		boundary := nextTOTPBoundary(now)
		for b.now().Before(boundary) {
			step := boundary.Sub(b.now())
			if b.now().Before(quickUntil) && step > b.retryEvery {
				step = b.retryEvery
			}
			b.sleep(step)
			if b.now().Before(quickUntil) && b.retryFailed(slots, failed) {
				break // a slot came up: show it now
			}
		}
	}
}

// retryFailed gives every slot that had no code during the hold another
// try and reports whether one came up.
func (b *bootDisplay) retryFailed(slots []NVRAMSlot, failed map[int]bool) bool {
	changed := false
	now := b.now()
	for i, s := range slots {
		if s.Error == nil || !failed[s.SlotNumber] {
			continue
		}
		if _, ok := IsBlobVersionError(s.Error); ok {
			continue
		}
		if again := b.live(s, now); again.Error == nil {
			again.AfterSeparator = true
			slots[i] = again
			changed = true
		}
	}
	return changed
}

// nextTOTPBoundary is the next :00 or :30.
func nextTOTPBoundary(now time.Time) time.Time {
	sec := now.Second()
	wait := 30 - sec
	if sec >= 30 {
		wait = 60 - sec
	}
	return now.Truncate(time.Second).Add(time.Duration(wait) * time.Second)
}

// sdNotifyReady sends READY=1 to systemd when run as a Type=notify service.
// Errors are ignored: outside systemd there is nobody to tell.
func sdNotifyReady() {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	if addr[0] == '@' {
		addr = "\x00" + addr[1:] // abstract socket
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("READY=1\n"))
}

// enterReader reports Enter typed on stdin, until it is stopped. It must be
// stopped when the boot is released: the passphrase prompt reads the same
// terminal next, and no key typed there may end up here. So it never sits
// in a read: it polls, and reads only what is already waiting.
type enterReader struct {
	presses chan struct{}
	quit    chan struct{}
	done    chan struct{}
	once    sync.Once
}

func startEnterReader(fd int) *enterReader {
	e := &enterReader{presses: make(chan struct{}), quit: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(e.done)
		buf := make([]byte, 256)
		for {
			select {
			case <-e.quit:
				return
			default:
			}
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			n, err := unix.Poll(fds, 200)
			if err == unix.EINTR || (err == nil && n == 0) {
				continue
			}
			if err != nil || fds[0].Revents&unix.POLLIN == 0 {
				return // closed, hung up, or not a terminal: the hold runs its course
			}
			select {
			case <-e.quit:
				return
			default:
			}
			m, err := unix.Read(fd, buf)
			if err != nil || m <= 0 {
				return
			}
			if bytes.IndexByte(buf[:m], '\n') < 0 && bytes.IndexByte(buf[:m], '\r') < 0 {
				continue
			}
			select {
			case e.presses <- struct{}{}:
			case <-e.quit:
				return
			}
		}
	}()
	return e
}

// stop ends the reader and returns once it can no longer touch the terminal.
func (e *enterReader) stop() {
	e.once.Do(func() { close(e.quit) })
	<-e.done
}

// releaseTerminal gives up the controlling terminal that StandardInput=tty
// made this process the owner of. systemd's passphrase prompt takes the
// console for itself and waits for as long as another session owns it, so
// a display that outlives its hold would otherwise keep the prompt from
// ever appearing. Writing to the terminal still works afterwards.
func releaseTerminal(fd int) {
	// Giving it up sends the owner a hangup; it is not one.
	signal.Ignore(syscall.SIGHUP, syscall.SIGCONT)
	_ = unix.IoctlSetInt(fd, unix.TIOCNOTTY, 0)
}

// startCoordinator makes this process the gate's coordinator when the image
// carries a gate for an enrolled phone: it opens the TPM for it and listens
// on socket. Nil when there is nothing to coordinate.
func startCoordinator(tpmPath, socket, configPath string, debug bool) (*gateService, func()) {
	svc, server := openCoordinator(tpmPath, socket, configPath, debug)
	if svc == nil {
		return nil, func() {}
	}
	var once sync.Once
	// The TPM handle is left to the end of the process: an operation for
	// the worker may still be running on it.
	return svc, func() {
		once.Do(func() {
			server.Close()
			os.Remove(socket)
		})
	}
}

func openCoordinator(tpmPath, socket, configPath string, debug bool) (*gateService, *gateServer) {
	if socket == "" {
		return nil, nil
	}
	cfg, err := LoadAttestConfig(configPath)
	if err != nil || cfg.Mode != "lazy" {
		return nil, nil // no gate in this image
	}
	path := preferResourceManager(tpmPath)
	tpmDev, err := transport.OpenTPM(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm2-kira: the phone check is unavailable: cannot open the TPM at %s: %v\n", path, err)
		return nil, nil
	}
	l, err := listenGate(socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm2-kira: the phone check is unavailable: %v\n", err)
		tpmDev.Close()
		return nil, nil
	}
	svc := newGateService(tpmDev, 0, "", debug)
	return svc, serveGate(l, svc)
}

// RunCommand implements the run command (the display at boot).
func RunCommand(tpmPath string, nvramIndex uint32, hold time.Duration, gateSocket string, debug bool) {
	svc, endCoordinator := startCoordinator(tpmPath, gateSocket, DefaultAttestConfigPath, debug)
	open := func() (transport.TPMCloser, error) {
		tpmDev, err := OpenTPM(tpmPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
		}
		CleanupTPM(tpmDev, debug)
		return tpmDev, nil
	}
	enter := startEnterReader(0)
	var phone func() (GateStatus, bool)
	if svc != nil {
		phone = svc.Status
	}
	b := &bootDisplay{
		phone:      phone,
		phoneEvent: printGateEvent,
		phonePoll:  500 * time.Millisecond,
		phoneGrace: time.Minute,
		scan: func(now time.Time) ([]NVRAMSlot, error) {
			tpmDev, err := open()
			if err != nil {
				return nil, err
			}
			defer tpmDev.Close()
			var slots []NVRAMSlot
			if nvramIndex == 0 {
				slots = ScanNVRAMSlots(tpmDev, debug)
			} else {
				slots = ScanNVRAMSlot(tpmDev, nvramIndex, debug)
			}
			if len(slots) == 0 {
				if nvramIndex == 0 {
					return nil, fmt.Errorf("%w in NVRAM slots 0x%08X - 0x%08X (run 'tpm2-kira seal')", ErrNoSlots, NVRAMSlotStart, NVRAMSlotEnd)
				}
				return nil, fmt.Errorf("%w at NVRAM index 0x%08X (run 'tpm2-kira seal')", ErrNoSlots, nvramIndex)
			}
			return slots, nil
		},
		live: func(s NVRAMSlot, now time.Time) NVRAMSlot {
			tpmDev, err := open()
			if err != nil {
				s.Code, s.Error = "", err
				return s
			}
			defer tpmDev.Close()
			s.Code, _, s.Error = SlotCode(tpmDev, s.Index, now, debug)
			return s
		},
		notify: func() {
			enter.stop() // the terminal is the passphrase prompt's from here on
			// Lazy mode: the phone check ends with the hold, and the
			// radio worker with it.
			endCoordinator()
			// A display that goes on (codes that only compute after the
			// separator) writes to the terminal but must not own it.
			releaseTerminal(0)
			sdNotifyReady()
		},
		show: func(slots []NVRAMSlot, codes map[int]string, remaining time.Duration) {
			if tpmDev, err := open(); err == nil {
				PrintKIRASlots(tpmDev, slots, codes) // with PCR details
				tpmDev.Close()
			} else {
				printSlotsWithoutTPM(slots, codes)
			}
			if remaining >= 0 {
				fmt.Println()
				if st, ok := gateStatus(phone); ok && st.Asking() {
					fmt.Printf("   Slot #%d is enrolled with a phone: open the Kira app to verify this boot.\n", st.Slot)
					fmt.Println("   Without the phone: compare the code with your authenticator and press Enter.")
				} else {
					fmt.Println("   Does the code match your authenticator? Press Enter to continue to the passphrase.")
				}
				fmt.Printf("   (continues on its own in %d s)\n", int(remaining.Round(time.Second)/time.Second))
			}
			fmt.Println()
		},
		wait: func(d time.Duration) bool {
			select {
			case <-enter.presses:
				return true
			case <-time.After(d):
				return false
			}
		},
		sleep:         time.Sleep,
		now:           time.Now,
		hold:          hold,
		scanRetry:     30 * time.Second,
		quickRetryFor: time.Minute,
		retryEvery:    2 * time.Second,
	}
	b.run()
}

func gateStatus(phone func() (GateStatus, bool)) (GateStatus, bool) {
	if phone == nil {
		return GateStatus{}, false
	}
	return phone()
}

// printGateEvent tells the person at the console what the gate's change of
// state means for them. The verdict itself is printed by the gate.
func printGateEvent(prev, cur GateStatus) {
	switch cur.State {
	case GateWaiting:
		if prev.State == "" {
			fmt.Printf("   Slot #%d can be verified with your phone now: open the Kira app.\n", cur.Slot)
		}
	case GateSession:
		fmt.Println("   A phone is connected: answer there. The boot waits for it.")
	case GateAttested:
		fmt.Printf("   \033[0;32mSlot #%d verified with %s.\033[0m Continuing to the passphrase.\n", cur.Slot, phoneLabel(cur.Phone))
	case GateRejected, GateRefused:
		fmt.Printf("   \033[0;31mSlot #%d was NOT verified by the phone (see above).\033[0m Do not type your passphrase unless you know why.\n", cur.Slot)
	}
}

func phoneLabel(name string) string {
	if name == "" {
		return "your phone"
	}
	return name
}

// printSlotsWithoutTPM is the display when the TPM cannot be opened for the
// PCR details.
func printSlotsWithoutTPM(slots []NVRAMSlot, codes map[int]string) {
	fmt.Printf("[ \033[1;33mKIRA\033[0m ] Time UTC %s\n", time.Now().UTC().Format("15:04:05"))
	for _, slot := range slots {
		if slot.Error != nil {
			if line := slotErrorLine(slot.Error); line != "" {
				fmt.Printf("\033[0;31m#%d\033[0m: %s\n", slot.SlotNumber, line)
			} else {
				fmt.Printf("\033[0;31m#%d\033[0m: PCR Mismatch\n", slot.SlotNumber)
			}
		} else if code, exists := codes[slot.SlotNumber]; exists {
			fmt.Printf("\033[0;32m#%d\033[0m: %s\n", slot.SlotNumber, code)
		}
	}
}
