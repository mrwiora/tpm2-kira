package cmd

// The TOTP display at the passphrase prompt (tpm2-kira run).
//
// tpm2-kira.service orders itself after systemd-pcrphase-initrd.service
// (enter-initrd on PCR 11) and before systemd-pcrosseparator.service, and is
// Type=notify: every slot is unsealed once, then READY=1 lets the boot go on.
// The separator then extends os-separator into PCRs 0-7, 9, 12-14, which locks
// the secrets until the next boot - PCR extends are one-way, so nothing in the
// running system can unseal them again - while the display keeps showing codes
// from memory for as long as the prompt is up.
//
// A slot that did not unseal before the boot was released is retried
// afterwards: a blob sealed against post-separator values (by an older
// version, or from registers because the event log cannot be replayed) still
// works, but without the lock, and the display says so.

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
)

// bootDisplay is RunCommand with its environment pluggable for tests.
type bootDisplay struct {
	scan   func() ([]NVRAMSlot, error) // unseal every slot once
	retry  func(NVRAMSlot) NVRAMSlot   // one more attempt for a failed slot
	notify func()                      // tells systemd the policy has been checked
	show   func([]NVRAMSlot, map[int]string)
	sleep  func(time.Duration)
	now    func() time.Time

	scanRetry     time.Duration // between attempts while nothing can be shown
	quickRetryFor time.Duration // failed slots are retried every retryEvery this long,
	retryEvery    time.Duration // then once per TOTP window
}

func (b *bootDisplay) run() {
	slots, err := b.scan()
	notified := false
	for err != nil {
		PrintKIRAError(err)
		if !notified {
			// Never hold the boot for a missing TPM or an empty NVRAM.
			b.notify()
			notified = true
		}
		b.sleep(b.scanRetry)
		slots, err = b.scan()
	}
	if !notified {
		b.notify()
	}
	quickUntil := b.now().Add(b.quickRetryFor)
	for {
		codes, _ := GenerateTOTPCodesForSlots(slots)
		b.show(slots, codes)
		boundary := nextTOTPBoundary(b.now())
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

// retryFailed gives every failed slot another try and reports whether one
// came up. A slot that only unseals now was not locked by the separator.
func (b *bootDisplay) retryFailed(slots []NVRAMSlot) bool {
	changed := false
	for i, s := range slots {
		if s.Error == nil {
			continue
		}
		if _, ok := IsBlobVersionError(s.Error); ok {
			continue
		}
		if again := b.retry(s); again.Error == nil {
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
		tpmDev, err := transport.OpenTPM(tpmPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
		}
		CleanupTPM(tpmDev, debug)
		return tpmDev, nil
	}
	b := &bootDisplay{
		scan: func() ([]NVRAMSlot, error) {
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
		retry: func(s NVRAMSlot) NVRAMSlot {
			tpmDev, err := open()
			if err != nil {
				return s
			}
			defer tpmDev.Close()
			if again := ScanNVRAMSlot(tpmDev, s.Index, debug); len(again) == 1 {
				return again[0]
			}
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
			if bve, ok := IsBlobVersionError(slot.Error); ok {
				fmt.Printf("\033[0;31m#%d\033[0m: Incompatible blob version (found v%d, requires v%d) - re-seal with: tpm2-kira seal\n", slot.SlotNumber, bve.FoundVersion, bve.RequiredVersion)
			} else {
				fmt.Printf("\033[0;31m#%d\033[0m: PCR Mismatch\n", slot.SlotNumber)
			}
		} else if code, exists := codes[slot.SlotNumber]; exists {
			fmt.Printf("\033[0;32m#%d\033[0m: %s\n", slot.SlotNumber, code)
		}
	}
}
