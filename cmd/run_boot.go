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
// itself. Its service ends with the hold (the phone has as long
// as the code is asked about, plus the time to finish an answer it has
// begun), and the worker ends with it. The process must not outlive the
// hold on the console in any case: it owns the terminal, and systemd's
// passphrase prompt waits for the terminal to be free.
//
// A slot that yields no code during the hold is served after the boot is
// released: a blob whose policy holds only after the separator (sealed from
// registers because the event log cannot be replayed) then gets its codes
// live, window by window, and the display says so.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
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

// holdUnlimited is a hold that ends only with a confirmation: the SSH
// server's TPM2_KIRA_SSH_HOLD=0.
const holdUnlimited = 100 * 365 * 24 * time.Hour

// hintPrinter puts consoleHint on the console while the SSH server holds
// the boot: at every new window, and as soon as an address comes up or a
// session comes or goes.
type hintPrinter struct {
	srv  *remoteServer
	mu   sync.Mutex
	last string // the addresses and sessions it last showed
	left time.Duration
	quit chan struct{}
	once sync.Once
}

func startHintPrinter(srv *remoteServer) *hintPrinter {
	h := &hintPrinter{srv: srv, left: -1, quit: make(chan struct{})}
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-h.quit:
				return
			case <-t.C:
			case <-srv.changed:
			}
			h.mu.Lock()
			addrs, n := addresses(), srv.count()
			if key := fmt.Sprint(addrs, n); key != h.last && h.last != "" {
				h.last = key
				fmt.Print("\n" + consoleHint(srv.opts.Port, addrs, n, h.left))
			}
			h.mu.Unlock()
		}
	}()
	return h
}

// print shows the hint now; remaining is the hold's time left.
func (h *hintPrinter) print(remaining time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if remaining >= holdUnlimited/2 {
		remaining = -1
	}
	h.left = remaining
	addrs, n := addresses(), h.srv.count()
	h.last = fmt.Sprint(addrs, n)
	fmt.Print("\n" + consoleHint(h.srv.opts.Port, addrs, n, remaining))
}

func (h *hintPrinter) stop() {
	h.once.Do(func() { close(h.quit) })
}

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
			before := gate.Code
			enter := b.waitFor(until, &gate)
			if enter || gate.Released() {
				return slots, allUp, nil
			}
			now := b.now()
			if !now.Before(limit()) {
				return slots, allUp, nil
			}
			if !now.Before(boundary) {
				break // a new code
			}
			if gate.Code != before && gate.Code != "" {
				// The phone is in: its code, at once, on its own line (the
				// slot's line carries it from the next window on).
				fmt.Printf("%s %s  (the phone must show the same)\n", kiraTag(tagPurple), gate.Code)
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
// carries a gate for an enrolled phone - the hook puts the signing public
// key at signerPath with the gate and not otherwise: it opens the TPM for
// it and listens on socket. Nil when there is nothing to coordinate.
func startCoordinator(tpmPath, socket, signerPath string, debug bool) (*gateService, func()) {
	svc, server := openCoordinator(tpmPath, socket, signerPath, debug)
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

func openCoordinator(tpmPath, socket, signerPath string, debug bool) (*gateService, *gateServer) {
	if socket == "" {
		return nil, nil
	}
	if _, err := os.Stat(signerPath); err != nil {
		return nil, nil // no gate in this image
	}
	path := preferResourceManager(tpmPath)
	tpmDev, err := OpenTPM(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm2-kira: the phone check is unavailable: cannot open the TPM at %s: %v\n", path, err)
		return nil, nil
	}
	if s, err := ReadBootSettings(tpmDev); err == nil && s.Debug {
		debug, narrateDebug = true, true // the boot settings' debug: the narrative on the console too
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

// RunCommand implements the run command (the display at boot). With
// unlockSocket (or a socket from systemd's socket unit) this process is
// also the key provider for systemd-cryptsetup: it answers the volumes'
// key requests once the hold has ended, and stays until it is stopped.
// With remote.Port it is also the SSH server (remote_ssh.go): the codes
// are shown and confirmed in an SSH session, and the console says where.
func RunCommand(tpmPath string, nvramIndex uint32, hold time.Duration, gateSocket, unlockSocket string, remote RemoteOptions, debug bool) {
	svc, endCoordinator := startCoordinator(tpmPath, gateSocket, DefaultAttestSignerPath, debug)
	var srv *remoteServer
	ask := prompter(consoleAsk)
	if remote.Port > 0 {
		var err error
		if srv, err = startRemote(remote, os.Stdout, unlockLogger(debug)); err != nil {
			fmt.Fprintf(os.Stderr, "tpm2-kira: the SSH server is not started: %v - the code screen is at the console\n", err)
		} else {
			ask = srv.ask
			hold = remote.Hold
			if hold == 0 {
				hold = holdUnlimited
			}
		}
	}
	var unlock *unlockServer
	// What the next prompt is, for the code screen's words: the recipe of
	// the first routed volume, read from its LUKS2 header once it is
	// readable. The key itself is made per volume (unlockRecipe): nothing
	// is configured, the header is the truth.
	promptMode := func() string { return "" }
	if l, err := listenUnlock(unlockSocket); err != nil {
		fmt.Fprintf(os.Stderr, "tpm2-kira: the disk unlock is not served: %v\n", err)
	} else if l != nil {
		promptMode = screenRecipe(DefaultUnlockSocket)
		if svc != nil {
			// A slot whose enrolment holds a release key waits for the
			// salt that follows the phone's receipt.
			svc.ExpectRelease(true)
		}
		recipes := &unlockRecipe{}
		unlock = serveUnlock(l, diskKey(func() []byte {
			if svc == nil {
				return nil
			}
			// The phone's salt follows its receipt by one message: give
			// it the time, bounded (gate_service.go releaseWait).
			for {
				st, _ := svc.Status()
				if !st.Releasing {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			return svc.Salt()
		}, recipes.forVolume, ask), unlockLogger(debug))
	}
	open := func() (transport.TPMCloser, error) {
		tpmDev, err := OpenTPM(tpmPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
		}
		CleanupTPM(tpmDev, debug)
		return tpmDev, nil
	}
	enter := startEnterReader(0)
	atConsole := false // the hold ended with Enter at the console
	var hint *hintPrinter
	if srv != nil {
		hint = startHintPrinter(srv)
	}
	var phone func() (GateStatus, bool)
	if svc != nil {
		phone = svc.Status
	}
	b := &bootDisplay{
		phone:      phone,
		phoneEvent: gateEventPrinter(promptMode),
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
			if srv != nil {
				hint.stop()
				// Enter at the console stops the SSH server; otherwise the
				// session that confirmed (or the newest one) has the prompt.
				if srv.release(atConsole) {
					fmt.Printf("%s Confirmed over SSH: the password is asked in the SSH session.\n", kiraTag(tagYellow))
				}
			}
			// Lazy mode: the phone check ends with the hold, and the
			// radio worker with it.
			endCoordinator()
			// A display that goes on (codes that only compute after the
			// separator) writes to the terminal but must not own it.
			releaseTerminal(0)
			sdNotifyReady()
			// From here on systemd-cryptsetup's key requests are answered -
			// once the units READY let loose have printed their lines,
			// which would otherwise land in the prompt (waitPromptTurn).
			if unlock != nil {
				go func() {
					waitPromptTurn()
					unlock.release()
				}()
			}
		},
		show: func(slots []NVRAMSlot, codes map[int]string, remaining time.Duration) {
			if unlock != nil && unlock.Prompting() {
				return // the prompt owns the console; nothing is drawn over it
			}
			st, ok := gateStatus(phone)
			codes = phoneCodes(codes, slots, st, ok)
			if srv != nil && remaining >= 0 {
				// The codes go to the SSH sessions; the console says where.
				var screen bytes.Buffer
				printSlots(&screen, open, slots, codes)
				left := ""
				if remaining < holdUnlimited/2 {
					left = fmt.Sprintf(" (on its own in %d s)", int(remaining.Round(time.Second)/time.Second))
				}
				if st, ok := gateStatus(phone); ok && st.Asking() {
					fmt.Fprintf(&screen, "\n   Enter: continue without the phone%s; q: leave.\n\n", left)
				} else {
					fmt.Fprintf(&screen, "\n   Does the code match your authenticator? Enter: continue to %s, asked here%s; q: leave.\n\n", nextPrompt(promptMode()), left)
				}
				srv.show(screen.Bytes())
				hint.print(remaining)
				return
			}
			printSlots(os.Stdout, open, slots, codes)
			if remaining >= 0 {
				fmt.Println()
				if st, ok := gateStatus(phone); ok && st.Asking() {
					fmt.Printf("   Enter: continue without the phone (on its own in %d s).\n", int(remaining.Round(time.Second)/time.Second))
				} else {
					fmt.Printf("   Does the code match your authenticator? Enter: continue to %s (on its own in %d s).\n", nextPrompt(promptMode()), int(remaining.Round(time.Second)/time.Second))
				}
			}
			fmt.Println()
		},
		wait: func(d time.Duration) bool {
			var confirmed chan struct{} // nil without SSH: never ready
			if srv != nil {
				confirmed = srv.releases
			}
			select {
			case <-enter.presses:
				atConsole = true
				return true
			case <-confirmed:
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
	if unlock != nil {
		// The display is done; the key provider stays until systemd stops
		// the service at switch-root.
		waitForStop()
		unlock.Close()
	}
	if svc != nil {
		svc.Forget()
	}
}

// waitForStop returns when systemd (or anyone) asks this process to end.
func waitForStop() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch
}

// phoneCodes puts each phone slot's line into codes: a slot with phones
// has no TOTP code, and its line says how far the phone's check has got.
// The slot the gate serves follows the gate; any other phone slot waits.
func phoneCodes(codes map[int]string, slots []NVRAMSlot, st GateStatus, ok bool) map[int]string {
	out := make(map[int]string, len(codes))
	for k, v := range codes {
		out[k] = v
	}
	for _, s := range slots {
		if !s.Phone {
			continue
		}
		if !ok || st.Slot != s.SlotNumber {
			out[s.SlotNumber] = phoneLineLocked
			continue
		}
		out[s.SlotNumber] = phoneLine(st)
	}
	return out
}

// phoneLineLocked is a phone slot's line until a phone has connected.
const phoneLineLocked = "mobile attestation locked - please connect"

// phoneLine is the line of the slot the gate serves, by the gate's state.
// Which phone answered is not said: the person knows their phone, and the
// screen is no place to tell anyone else (docs/SECURITY-BACKGROUND.md §3.1).
func phoneLine(st GateStatus) string {
	switch st.State {
	case GateSession:
		if st.Code != "" {
			return "mobile attestation - phone code " + st.Code + " (the phone must show the same)"
		}
		return "mobile attestation - phone connected, answer there"
	case GateAttested:
		return "\033[0;32mmobile attestation passed\033[0m"
	case GateRejected, GateRefused:
		return "\033[0;31mmobile attestation FAILED\033[0m"
	case GateUnavailable:
		return "mobile attestation unavailable (no Bluetooth adapter) - the passphrase by hand"
	}
	return phoneLineLocked
}

func gateStatus(phone func() (GateStatus, bool)) (GateStatus, bool) {
	if phone == nil {
		return GateStatus{}, false
	}
	return phone()
}

// The prompt's turn on the console: READY lets the units ordered behind
// the code screen run, and their lines would land in the prompt. The last
// of them to print is systemd-pcrnvdone.service, "TPM PCR NvPCR
// Initialization Separator" - a oneshot before cryptsetup-pre.target, so
// it is done before any volume may ask for its key - and once it is
// active its line is on the console. waitPromptTurn watches for that
// instead of sitting out the whole pause; promptDelay caps the wait where
// the unit never runs (no measured OS, an older systemd). A pause only;
// nothing is trusted differently.

// promptGateUnit is the unit whose finish says the console is quiet.
const promptGateUnit = "systemd-pcrnvdone.service"

// promptDelay is the longest pause between the end of the code screen and
// the first key request answered.
var promptDelay = 3 * time.Second

// promptPoll is how often the unit is asked for.
var promptPoll = 100 * time.Millisecond

// unitActive asks systemd whether the unit is active - for a oneshot with
// RemainAfterExit: has finished, its console line printed. A var: tests
// replace it.
var unitActive = func(unit string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
}

// underSystemd says whether systemd is this boot's init; a Debian
// initramfs has none, and then nothing prints after READY. A var: tests
// replace it.
var underSystemd = func() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// waitPromptTurn returns when promptGateUnit has finished, at once without
// systemd, and after promptDelay at the latest.
func waitPromptTurn() {
	if !underSystemd() {
		return
	}
	for deadline := time.Now().Add(promptDelay); ; time.Sleep(promptPoll) {
		if unitActive(promptGateUnit) || !time.Now().Before(deadline) {
			return
		}
	}
}

// kiraTag is the "[ KIRA ]" tag in a colour: yellow for the screen and its
// lines, blue for the prompt, purple for the phone's code.
func kiraTag(colour string) string { return "[ \033[1;" + colour + "mKIRA\033[0m ]" }

const (
	tagYellow = "33"
	tagBlue   = "34"
	tagPurple = "35"
)

// nextPrompt names what follows the code screen, in the words of the
// routed volume's recipe: "the password prompt" when tpm2-kira asks (the
// password is what the person types; the salt is typed too, or comes from
// the phone), "cryptsetup's prompt" when nothing of tpm2-kira's answers.
func nextPrompt(mode string) string {
	switch mode {
	case LuksModePasswordSalt:
		return "the password and salt prompt"
	case LuksModePasswordRemoteSalt:
		return "the password prompt"
	}
	return "cryptsetup's prompt"
}

// gateEventPrinter tells the person at the console what the gate's change
// of state means for them, in the routed volume's words (resolved lazily:
// the header may not be readable when the screen starts). The verdict
// itself is the gate's to print.
func gateEventPrinter(modeOf func() string) func(prev, cur GateStatus) {
	return func(prev, cur GateStatus) {
		mode := modeOf()
		switch cur.State {
		case GateWaiting:
			if prev.State == "" {
				if mode == LuksModePasswordRemoteSalt {
					fmt.Printf("%s Slot #%d: open Marify on your phone to attest this boot and return the disk's salt.\n", kiraTag(tagYellow), cur.Slot)
				} else {
					fmt.Printf("%s Slot #%d: open Marify on your phone to attest this boot.\n", kiraTag(tagYellow), cur.Slot)
				}
			}
		case GateSession:
			// The phone code goes into the slot's own line (phoneCodes);
			// here only the fact that a phone is in.
			if prev.State != GateSession {
				fmt.Printf("%s A phone is connected: answer there. The boot waits for it.\n", kiraTag(tagYellow))
			}
		case GateAttested:
			switch {
			case cur.Releasing:
				fmt.Printf("%s \033[0;32mSlot #%d attested by your phone.\033[0m Waiting for the salt from the phone ...\n", kiraTag(tagYellow), cur.Slot)
			case prev.Releasing && cur.SaltTaken:
				fmt.Printf("%s \033[0;32mThe phone returned the salt.\033[0m Continuing to %s.\n", kiraTag(tagYellow), nextPrompt(mode))
			case prev.Releasing:
				fmt.Printf("%s \033[0;33mNo salt came from the phone.\033[0m Continuing to the password and salt prompt (a typed salt; Ctrl-C there: cryptsetup's own prompt).\n", kiraTag(tagYellow))
			case prev.State != GateAttested:
				fmt.Printf("%s \033[0;32mSlot #%d attested by your phone.\033[0m Continuing to %s.\n", kiraTag(tagYellow), cur.Slot, nextPrompt(mode))
			}
		case GateRejected, GateRefused:
			fmt.Printf("%s \033[0;31mSlot #%d was NOT attested by the phone (see above).\033[0m Do not type your password unless you know why.\n", kiraTag(tagYellow), cur.Slot)
		}
	}
}

// printSlots is the code screen onto w, with the PCR details of a slot
// that has no code when the TPM can be opened for them.
func printSlots(w io.Writer, open func() (transport.TPMCloser, error), slots []NVRAMSlot, codes map[int]string) {
	if tpmDev, err := open(); err == nil {
		FprintKIRASlots(w, tpmDev, slots, codes)
		tpmDev.Close()
		return
	}
	printSlotsWithoutTPM(w, slots, codes)
}

// printSlotsWithoutTPM is the display when the TPM cannot be opened for the
// PCR details.
func printSlotsWithoutTPM(w io.Writer, slots []NVRAMSlot, codes map[int]string) {
	fmt.Fprintf(w, "[ \033[1;33mKIRA\033[0m ] Time UTC %s\n", time.Now().UTC().Format("15:04:05"))
	for _, slot := range slots {
		if slot.Error != nil {
			if line := slotErrorLine(slot.Error); line != "" {
				fmt.Fprintf(w, "\033[0;31m#%d\033[0m: %s\n", slot.SlotNumber, line)
			} else {
				fmt.Fprintf(w, "\033[0;31m#%d\033[0m: PCR Mismatch\n", slot.SlotNumber)
			}
		} else if slot.Phone {
			fmt.Fprintf(w, "\033[0;33m#%d\033[0m: %s\n", slot.SlotNumber, phoneSlotText(codes, slot))
		} else if code, exists := codes[slot.SlotNumber]; exists {
			fmt.Fprintf(w, "\033[0;32m#%d\033[0m: %s\n", slot.SlotNumber, code)
		}
	}
}
