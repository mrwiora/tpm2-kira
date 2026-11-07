package admin

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tpm2-trust/tpm2-kira/internal/prompt"
	"github.com/tpm2-trust/tpm2-kira/internal/tui"
	"golang.org/x/sys/unix"
)

// sealedMachine is wired() with the key and the standard pair of slots.
func sealedMachine() *controller {
	c := wired()
	c.facts.Keys = "local key files"
	c.facts.Status.Slots = []StatusSlot{{Slot: 0, PCRs: "0e,2e,7e,11u", Signed: true, TOTP: true}, {Slot: 1, PCRs: "0e,7e", Fallback: true, Signed: true, TOTP: true}}
	c.o.HelpTopics = []string{"control", "luks"}
	return c
}

func frameText(rows []string) string { return tui.StripSGR(strings.Join(rows, "\n")) }

// The frame at the sizes a person meets: every row exactly as wide as the terminal,
// as many rows as it has; the sidebar and the detail side by side when there is room,
// one at a time when not.
func TestControlFrame(t *testing.T) {
	c := sealedMachine()
	m := c.model()
	g := tui.GlyphsFor(true)
	v := frameView{header: "[ KIRA ] control test · host", status: "  TPM  /dev/tpmrm0", prereqs: "  ✓ TPM"}
	for _, size := range [][2]int{{80, 25}, {132, 43}, {40, 24}, {30, 12}} {
		st := &screenState{}
		rows := st.frame(m, v, size[0], size[1], g)
		if len(rows) != size[1] {
			t.Errorf("%dx%d: %d rows", size[0], size[1], len(rows))
		}
		text := frameText(rows)
		if !strings.Contains(text, "Overview") || !strings.Contains(text, "[ KIRA ] control") {
			t.Errorf("%dx%d:\n%s", size[0], size[1], text)
		}
		wide := size[0] >= 72
		if wide != strings.Contains(text, "What this machine has") {
			t.Errorf("%dx%d: the overview's facts beside the sections: %v\n%s", size[0], size[1], wide, text)
		}
	}
	// A step's detail: what it does, its state, the command, what a destroy removes.
	st := &screenState{section: sectionIndex("keys"), focus: focusSteps, step: 1}
	text := frameText(st.frame(m, frameView{header: "h"}, 100, 40, g))
	for _, want := range []string{"Slot 0", "Done: sealed to 0e,2e,7e,11u", "Destroys: slot 0 whole", "The command: tpm2-kira slot delete --nvram 0", "⚠"} {
		if !strings.Contains(text, want) {
			t.Errorf("the slot's detail lacks %q:\n%s", want, text)
		}
	}
	// ASCII where the locale is not UTF-8.
	text = frameText(st.frame(m, frameView{header: "h"}, 100, 40, tui.GlyphsFor(false)))
	if strings.ContainsAny(text, "✓⚠│─") {
		t.Errorf("Unicode in an ASCII frame:\n%s", text)
	}
	// While the facts come: the frame is up, and says so.
	text = frameText((&screenState{}).frame(make(controlModel, len(controlSections)), frameView{header: "h", loading: true}, 80, 25, g))
	if !strings.Contains(text, "Looking at this machine") {
		t.Errorf("loading:\n%s", text)
	}
}

func sectionIndex(key string) int {
	for i, s := range controlSections {
		if s.key == key {
			return i
		}
	}
	return -1
}

// The keys: moving, into and out of a section, a blocked step says why instead of
// running, a destroying one runs (its question asks for the word), a line that opens a
// section goes there, search finds a step anywhere, Esc goes back and then leaves.
func TestControlScreenKeys(t *testing.T) {
	c := sealedMachine()
	m := c.model()
	st := &screenState{}
	key := func(names ...string) screenCmd {
		var cmd screenCmd
		for _, n := range names {
			k := tui.Key{Name: n}
			if len(n) == 1 {
				k = tui.Key{Name: tui.KeyRune, Rune: rune(n[0])}
			}
			cmd = st.key(k, m, 10)
		}
		return cmd
	}
	key(tui.KeyDown, tui.KeyDown)
	if st.section != 2 || st.focus != focusSections {
		t.Fatalf("down twice: %+v", st)
	}
	if key(tui.KeyEnter); st.focus != focusSteps || st.step != 0 {
		t.Fatalf("Enter on a section: %+v", st)
	}
	// keys: setup, slot 0, slot 1, seal-more, approve, delete-all; phone attest blocked
	if cmd := key(tui.KeyDown, tui.KeyEnter); cmd != cmdRun || st.selected(m).Key != "slot:0" {
		t.Fatalf("Enter on slot 0: %v %+v", cmd, st.selected(m))
	}
	st = &screenState{section: sectionIndex("phone"), focus: focusSteps}
	if cmd := key(tui.KeyEnter); cmd != cmdNone || !strings.Contains(st.message, "no Bluetooth adapter") {
		t.Fatalf("a blocked step ran: %v %q", cmd, st.message)
	}
	st = &screenState{section: sectionIndex("overview"), focus: focusSteps}
	for i, s := range m[st.section] {
		if s.Key == "menu:keys" {
			st.step = i
		}
	}
	if key(tui.KeyEnter); st.section != sectionIndex("keys") {
		t.Fatalf("a hub line opens its section: %+v", st)
	}
	st = &screenState{}
	key("/", "a", "p", "p", "r", "o", "v", "e", tui.KeyEnter)
	if st.searching || st.selected(m) == nil || st.selected(m).Key != "approve" || st.focus != focusSteps {
		t.Fatalf("search: %+v", st)
	}
	if key(tui.KeyEsc); st.focus != focusSections {
		t.Fatalf("Esc goes back first: %+v", st)
	}
	if key(tui.KeyEsc) != cmdQuit {
		t.Fatal("then Esc leaves")
	}
	if key("?"); !st.help || !strings.Contains(frameText(st.frame(m, frameView{header: "h"}, 100, 40, tui.GlyphsFor(true))), "Ctrl-L") {
		t.Fatal("? shows the keys")
	}
	st = &screenState{section: 99, step: 99, focus: focusSteps}
	st.clamp(m)
	if st.section != len(m)-1 {
		t.Fatalf("clamp: %+v", st)
	}
}

// openTestPty is a pseudo-terminal of the size given: its master and its slave.
func openTestPty(t *testing.T, cols, rows int) (ptm, pts *os.File) {
	t.Helper()
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	n, err := unix.IoctlGetInt(int(ptm.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetPointerInt(int(ptm.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	pts, err = os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.IoctlSetWinsize(int(ptm.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(cols), Row: uint16(rows)})
	t.Cleanup(func() { ptm.Close(); pts.Close() })
	return ptm, pts
}

// The full screen on a pseudo-terminal: up at once while the facts come, the slow
// ones after; keys move it; a step runs below it and the screen comes back; q leaves
// and the terminal is as it was.
func TestControlScreenOnAPty(t *testing.T) {
	ptm, pts := openTestPty(t, 100, 30)
	before, _ := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	var mu sync.Mutex
	var seen bytes.Buffer
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := ptm.Read(b)
			if err != nil {
				return
			}
			mu.Lock()
			seen.Write(b[:n])
			mu.Unlock()
		}
	}()
	text := func() string {
		mu.Lock()
		defer mu.Unlock()
		return tui.StripSGR(seen.String())
	}
	waitFor := func(want string) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); !strings.Contains(text(), want); time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("the screen never showed %q:\n%q", want, text())
			}
		}
	}
	slowDone := make(chan struct{})
	c := sealedMachine()
	facts := c.facts
	c.in, c.out = pts, pts
	c.p = prompt.New(pts, pts)
	c.fast = func(string, bool) machineFacts { f := facts; f.Checking = true; return f }
	c.slow = func(f *machineFacts) {
		<-slowDone
		f.Checking = false
	}
	ran := make(chan string, 1)
	defer func(old func(string, []string) error) { runSelf = old }(runSelf)
	runSelf = func(_ string, args []string) error { ran <- strings.Join(args, " "); return nil }

	done := make(chan error, 1)
	go func() { done <- c.screenLoop() }()
	waitFor("Overview")
	waitFor("checking ...")
	close(slowDone)
	// To Tools, into it, run the first view (status), back with Enter.
	ptm.Write([]byte("\033[B\033[B\033[B\033[B\033[B\033[B\033[B")) // the 8th section: Tools
	ptm.Write([]byte("\r"))
	waitFor("Status")
	ptm.Write([]byte("\r"))
	select {
	case got := <-ran:
		if got != "status" {
			t.Fatalf("ran %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the view did not run:\n%q", text())
	}
	waitFor("Back to control")
	ptm.Write([]byte("\r"))
	waitFor("1049h") // the screen is back
	ptm.Write([]byte("q"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("q did not leave:\n%q", text())
	}
	after, _ := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if after.Lflag != before.Lflag || !strings.Contains(seen.String(), "\033[?1049l") || !strings.Contains(seen.String(), "\033[?25h") {
		t.Fatalf("the terminal is not as it was: %x/%x", after.Lflag, before.Lflag)
	}
}
