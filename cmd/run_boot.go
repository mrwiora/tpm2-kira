package cmd

// The TOTP display at the passphrase prompt (tpm2-kira run).
//
// tpm2-kira.service orders itself after systemd-pcrphase-initrd.service
// (enter-initrd on PCR 11) and before systemd-pcrosseparator.service, and is
// Type=notify. Before READY=1 it asks the TPM for the codes of the next
// codeHorizon (TOTPCodes); the separator then extends
// os-separator into PCRs 0-7, 9, 12-14, after which the key's policy cannot
// be satisfied again until the next boot. The key never leaves the TPM; only
// those codes are in memory, each good for 30 seconds, and the display shows
// them for as long as the prompt is up. 'tpm2-kira cap' at initrd-switch-root
// read-locks the generation index on top of that.
//
// A slot that yields no code before the boot is released is retried
// afterwards: a blob whose policy holds only after the separator (sealed by
// an earlier version, or from registers because the event log cannot be
// replayed) then gets its codes live, window by window, and the display
// says so.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
)

// codeHorizon is how far ahead the display computes codes before the OS
// separator: one window, the current one. A firmware TPM takes noticeably
// long per policy pass, so one code is computed and shown at once; it is
// good for the rest of its 30-second window, and nothing is left for
// anyone who gets hold of the display process later. Whoever needs a code
// after that needs the next boot.
const codeHorizon = 30 * time.Second

// ErrCodesExhausted: the codes computed before the separator ran out.
var ErrCodesExhausted = errors.New("no further codes before the next boot: the codes computed before the OS separator ran out")

// bootDisplay is RunCommand with its environment pluggable for tests.
type bootDisplay struct {
	scan   func(from time.Time) ([]NVRAMSlot, error) // every slot, with its codes from 'from' on
	live   func(NVRAMSlot, time.Time) NVRAMSlot      // one code for now, computed in the TPM
	notify func()                                    // tells systemd the policies have been checked
	show   func([]NVRAMSlot, map[int]string)
	sleep  func(time.Duration)
	now    func() time.Time

	scanRetry     time.Duration // between attempts while nothing can be shown
	quickRetryFor time.Duration // failed slots are retried every retryEvery this long,
	retryEvery    time.Duration // then once per TOTP window
}

func (b *bootDisplay) run() {
	slots, err := b.scan(b.now())
	notified := false
	for err != nil {
		PrintKIRAError(err)
		if !notified {
			// Never hold the boot for a missing TPM or an empty NVRAM.
			b.notify()
			notified = true
		}
		b.sleep(b.scanRetry)
		slots, err = b.scan(b.now())
	}
	if !notified {
		b.notify()
	}
	quickUntil := b.now().Add(b.quickRetryFor)
	for {
		now := b.now()
		for i := range slots {
			b.refresh(&slots[i], now)
		}
		codes, _ := GenerateTOTPCodesForSlots(slots)
		b.show(slots, codes)
		boundary := nextTOTPBoundary(now)
		for b.now().Before(boundary) {
			step := boundary.Sub(b.now())
			if b.now().Before(quickUntil) && step > b.retryEvery {
				step = b.retryEvery
			}
			b.sleep(step)
			if b.now().Before(quickUntil) && b.retryFailed(slots) {
				break // a slot came up: show it now
			}
		}
		if !b.now().Before(quickUntil) {
			b.retryFailed(slots)
		}
	}
}

// refresh sets the slot's code for the window containing now: from the
// codes computed before the separator, or live for a slot that only works
// after it.
func (b *bootDisplay) refresh(s *NVRAMSlot, now time.Time) {
	switch {
	case s.AfterSeparator:
		*s = b.live(*s, now)
	case len(s.Codes) > 0:
		i := now.Unix()/30 - s.CodesFrom.Unix()/30
		if i >= 0 && i < int64(len(s.Codes)) {
			s.Code, s.Error = s.Codes[i], nil
		} else {
			s.Code, s.Error = "", ErrCodesExhausted
		}
	}
}

// retryFailed gives every failed slot another try and reports whether one
// came up. A slot that only yields a code now was not locked by the
// separator, so it is served live from here on.
func (b *bootDisplay) retryFailed(slots []NVRAMSlot) bool {
	changed := false
	now := b.now()
	for i, s := range slots {
		if s.Error == nil || s.AfterSeparator || errors.Is(s.Error, ErrCodesExhausted) {
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

// RunCommand implements the run command (continuous display at boot).
func RunCommand(tpmPath string, nvramIndex uint32, debug bool) {
	open := func() (transport.TPMCloser, error) {
		tpmDev, err := OpenTPM(tpmPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
		}
		CleanupTPM(tpmDev, debug)
		return tpmDev, nil
	}
	windows := int(codeHorizon / (30 * time.Second))
	b := &bootDisplay{
		scan: func(from time.Time) ([]NVRAMSlot, error) {
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
			for i := range slots {
				if slots[i].Error != nil {
					continue
				}
				codes, _, err := SlotCodes(tpmDev, slots[i].Index, from, windows, debug)
				if err != nil {
					slots[i].Code, slots[i].Error = "", err
					continue
				}
				slots[i].Codes, slots[i].CodesFrom = codes, from
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
		show: func(slots []NVRAMSlot, codes map[int]string) {
			if tpmDev, err := open(); err == nil {
				PrintKIRASlots(tpmDev, slots, codes) // with PCR details
				tpmDev.Close()
			} else {
				printSlotsWithoutTPM(slots, codes)
			}
			fmt.Println()
		},
		sleep:         time.Sleep,
		now:           time.Now,
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
