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
// A slot that yields no code during the hold is served after the boot is
// released: a blob whose policy holds only after the separator (sealed by an
// earlier version, or from registers because the event log cannot be
// replayed) then gets its codes live, window by window, and the display
// says so.

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
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

	hold          time.Duration // how long to wait for Enter
	scanRetry     time.Duration // between attempts while nothing can be shown
	quickRetryFor time.Duration // after the release, failed slots are retried every retryEvery this long,
	retryEvery    time.Duration // then once per TOTP window
}

func (b *bootDisplay) run() {
	slots, allUp := b.holdForConfirmation()
	b.notify()
	if allUp {
		return // every slot was confirmed or at least shown; nothing more can be computed
	}
	b.serveAfterRelease(slots)
}

// holdForConfirmation shows a fresh code per window until Enter or the end
// of the hold, and reports the last slots and whether all of them had a
// code. A scan that fails outright releases the boot at once.
func (b *bootDisplay) holdForConfirmation() ([]NVRAMSlot, bool) {
	deadline := b.now().Add(b.hold)
	var slots []NVRAMSlot
	allUp := false
	for {
		now := b.now()
		s, err := b.scan(now)
		if err != nil {
			PrintKIRAError(err)
			return slots, false
		}
		slots = s
		allUp = true
		for _, sl := range slots {
			if sl.Error != nil {
				allUp = false
			}
		}
		codes, _ := GenerateTOTPCodesForSlots(slots)
		b.show(slots, codes, deadline.Sub(now))
		d := nextTOTPBoundary(now).Sub(now)
		if left := deadline.Sub(now); left < d {
			d = left
		}
		if d <= 0 || b.wait(d) {
			return slots, allUp
		}
		if !b.now().Before(deadline) {
			return slots, allUp
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

// enterPresses reports every line typed on stdin. Without a terminal
// (stdin closed or not a tty) nothing is ever reported, so the hold runs
// its course.
func enterPresses() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		r := bufio.NewReader(os.Stdin)
		for {
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
			ch <- struct{}{}
		}
	}()
	return ch
}

// RunCommand implements the run command (the display at boot).
func RunCommand(tpmPath string, nvramIndex uint32, hold time.Duration, debug bool) {
	open := func() (transport.TPMCloser, error) {
		tpmDev, err := OpenTPM(tpmPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
		}
		CleanupTPM(tpmDev, debug)
		return tpmDev, nil
	}
	enter := enterPresses()
	b := &bootDisplay{
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
					return nil, fmt.Errorf("no TOTP secrets found in NVRAM slots 0x%08X - 0x%08X", NVRAMSlotStart, NVRAMSlotEnd)
				}
				return nil, fmt.Errorf("no TOTP secret found at NVRAM index 0x%08X", nvramIndex)
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
		notify: sdNotifyReady,
		show: func(slots []NVRAMSlot, codes map[int]string, remaining time.Duration) {
			if tpmDev, err := open(); err == nil {
				PrintKIRASlots(tpmDev, slots, codes) // with PCR details
				tpmDev.Close()
			} else {
				printSlotsWithoutTPM(slots, codes)
			}
			if remaining >= 0 {
				fmt.Println()
				fmt.Println("   Does the code match your authenticator? Press Enter to continue to the passphrase.")
				fmt.Printf("   (continues on its own in %d s)\n", int(remaining.Round(time.Second)/time.Second))
			}
			fmt.Println()
		},
		wait: func(d time.Duration) bool {
			select {
			case <-enter:
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
