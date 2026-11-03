package prompt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// vt is the part of a terminal these menus use, kept as a person would see it: rows,
// a scrollback above them, deferred autowrap at the last column, wide characters, and
// a resize that folds long rows as most terminals do. It counts the wraps, because a
// menu that lets the terminal wrap is one that may count its rows wrong.
type vt struct {
	mu            sync.Mutex
	width, height int
	lines         [][]vtCell // everything since the start
	top           int        // the index in lines of the screen's first row
	x, y          int        // y from top
	pendingWrap   bool
	reverse       bool
	wraps         int
	raw           bytes.Buffer
	unknown       []string
	esc           []byte
	rest          []byte
}

type vtCell struct {
	r       rune
	reverse bool
}

func newVT(width, height int) *vt {
	return &vt{width: width, height: height, lines: [][]vtCell{nil}}
}

func (v *vt) Write(b []byte) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.raw.Write(b)
	v.rest = append(v.rest, b...)
	for len(v.rest) > 0 {
		c := v.rest[0]
		switch {
		case len(v.esc) > 0:
			v.esc = append(v.esc, c)
			v.rest = v.rest[1:]
			if len(v.esc) >= 2 && c >= 0x40 && c <= 0x7e && (len(v.esc) > 2 || c != '[') {
				v.csi(string(v.esc))
				v.esc = nil
			}
		case c == 0x1b:
			v.esc = []byte{c}
			v.rest = v.rest[1:]
		case c == '\r':
			v.x, v.pendingWrap = 0, false
			v.rest = v.rest[1:]
		case c == '\n':
			v.lineFeed()
			v.rest = v.rest[1:]
		case c == '\a' || c == '\b':
			if c == '\b' && v.x > 0 {
				v.x--
			}
			v.rest = v.rest[1:]
		default:
			if c >= 0x80 && !fullRune(v.rest) {
				return len(b), nil // the rest of it comes with the next write
			}
			r, n := decodeRune(v.rest)
			v.put(r)
			v.rest = v.rest[n:]
		}
	}
	return len(b), nil
}

func (v *vt) csi(seq string) {
	if !strings.HasPrefix(seq, "\x1b[") {
		v.unknown = append(v.unknown, seq)
		return
	}
	final := seq[len(seq)-1]
	arg := seq[2 : len(seq)-1]
	n, _ := strconv.Atoi(arg)
	switch final {
	case 'A':
		v.y = max(0, v.y-max(n, 1))
		v.pendingWrap = false
	case 'J':
		if arg != "" && arg != "0" {
			v.unknown = append(v.unknown, seq)
			return
		}
		i := v.top + v.y
		if i < len(v.lines) {
			v.lines[i] = v.lines[i][:min(v.x, len(v.lines[i]))]
			v.lines = v.lines[:i+1]
		}
	case 'm':
		for _, p := range strings.Split(arg, ";") {
			switch p {
			case "", "0":
				v.reverse = false
			case "7":
				v.reverse = true
			}
		}
	default:
		v.unknown = append(v.unknown, seq)
	}
}

func (v *vt) lineFeed() {
	v.pendingWrap = false
	if v.y == v.height-1 {
		v.top++
	} else {
		v.y++
	}
	for v.top+v.y >= len(v.lines) {
		v.lines = append(v.lines, nil)
	}
}

func (v *vt) put(r rune) {
	w := 1
	if isWideForTest(r) {
		w = 2
	}
	if v.pendingWrap || v.x+w > v.width {
		v.wraps++
		v.x = 0
		v.lineFeed()
	}
	i := v.top + v.y
	for len(v.lines[i]) < v.x {
		v.lines[i] = append(v.lines[i], vtCell{r: ' '})
	}
	line := v.lines[i][:min(v.x, len(v.lines[i]))]
	line = append(line, vtCell{r, v.reverse})
	for j := 1; j < w; j++ {
		line = append(line, vtCell{0, v.reverse})
	}
	v.lines[i] = line
	v.x += w
	if v.x >= v.width {
		v.x, v.pendingWrap = v.width-1, true
	}
}

func isWideForTest(r rune) bool { return r >= 0x3000 && r <= 0xffef }

func decodeRune(b []byte) (rune, int) {
	s := string(b[:min(4, len(b))])
	for i, r := range s {
		if i == 0 {
			n := len(string(r))
			return r, n
		}
	}
	return 0xfffd, 1
}

func fullRune(b []byte) bool {
	c := b[0]
	need := 1
	switch {
	case c >= 0xf0:
		need = 4
	case c >= 0xe0:
		need = 3
	case c >= 0xc0:
		need = 2
	}
	return len(b) >= need
}

// resize folds the rows longer than the new width, the cursor at the end of the last.
func (v *vt) resize(width, height int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var folded [][]vtCell
	for _, l := range v.lines {
		if len(l) == 0 {
			folded = append(folded, nil)
		}
		for len(l) > 0 {
			n := min(width, len(l))
			folded = append(folded, l[:n])
			l = l[n:]
		}
	}
	v.lines, v.width, v.height = folded, width, height
	v.top = max(0, len(v.lines)-height)
	v.y = len(v.lines) - 1 - v.top
	v.x = len(v.lines[len(v.lines)-1])
	v.pendingWrap = false
}

// text is everything, scrollback and screen, each row without its right end's spaces.
func (v *vt) text() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	var rows []string
	for _, l := range v.lines {
		rows = append(rows, rowText(l))
	}
	return strings.TrimRight(strings.Join(rows, "\n"), "\n")
}

// highlighted is the rows in reverse video.
func (v *vt) highlighted() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	var rows []string
	for _, l := range v.lines {
		if len(l) > 0 && l[0].reverse {
			rows = append(rows, rowText(l))
		}
	}
	return strings.Join(rows, "\n")
}

func rowText(l []vtCell) string {
	var b strings.Builder
	for _, c := range l {
		if c.r != 0 {
			b.WriteRune(c.r)
		}
	}
	return strings.TrimRight(b.String(), " ")
}

// A terminal with a menu in it: the pty, the vt behind it, and what Select answered.
type menuTerm struct {
	t             *testing.T
	ptm, pts      *os.File
	v             *vt
	stop, stopped chan struct{}
	once          sync.Once
}

// pump is the terminal reading the pty, in a way that lets go of it: a read blocked on
// the master would keep the master open through its Close.
func (m *menuTerm) pump() {
	defer close(m.stopped)
	buf := make([]byte, 65536)
	fds := []unix.PollFd{{Fd: int32(m.ptm.Fd()), Events: unix.POLLIN}}
	for {
		select {
		case <-m.stop:
			return
		default:
		}
		if n, err := unix.Poll(fds, 20); err != nil || n == 0 {
			continue
		}
		n, err := m.ptm.Read(buf)
		if err != nil {
			return
		}
		m.v.Write(buf[:n])
	}
}

// hangUp is the terminal gone: the master closed.
func (m *menuTerm) hangUp() {
	m.once.Do(func() {
		close(m.stop)
		<-m.stopped
		m.ptm.Close()
	})
}

func newMenuTerm(t *testing.T, width, height int) *menuTerm {
	t.Helper()
	ptm, pts := openPty(t)
	t.Setenv("TERM", "xterm")
	t.Setenv("NO_COLOR", "")
	v := newVT(width, height)
	mt := &menuTerm{t: t, ptm: ptm, pts: pts, v: v, stop: make(chan struct{}), stopped: make(chan struct{})}
	go mt.pump()
	t.Cleanup(mt.hangUp)
	mt.size(width, height)
	return mt
}

func (m *menuTerm) size(width, height int) {
	m.t.Helper()
	ws := &unix.Winsize{Col: uint16(width), Row: uint16(height)}
	if err := unix.IoctlSetWinsize(int(m.pts.Fd()), unix.TIOCSWINSZ, ws); err != nil {
		m.t.Fatal(err)
	}
}

func (m *menuTerm) send(k string) { m.ptm.Write([]byte(k)) }

// until waits for the screen to say so; a timeout is the failure, with what it shows.
func (m *menuTerm) until(what string, ok func(screen string) bool) {
	m.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := m.v.text()
		if ok(s) {
			return
		}
		if time.Now().After(deadline) {
			m.t.Fatalf("%s: the screen shows:\n%s\nraw: %q", what, s, m.v.raw.String())
		}
		time.Sleep(time.Millisecond)
	}
}

// ask waits for the first draw: the menu ends with its prompt.
func (m *menuTerm) ask() {
	m.t.Helper()
	m.until("the menu is drawn", hasPrompt)
}

var promptRE = regexp.MustCompile(`(?s)Enter a\s+number\s+between\s+1\s+and\s+\d+:`)

func hasPrompt(s string) bool { return promptRE.MatchString(s) }

type result[T any] struct {
	v   T
	err error
}

func startSelect[T comparable](m *menuTerm, heading, question string, opts []Option[T], def T) <-chan result[T] {
	ch := make(chan result[T], 1)
	p := New(m.pts, m.pts)
	go func() {
		v, err := Select(p, heading, question, opts, def)
		ch <- result[T]{v, err}
	}()
	return ch
}

func wait[T any](t *testing.T, ch <-chan result[T]) result[T] {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("the menu did not end")
		panic("")
	}
}

var (
	basic = []Option[string]{
		{Label: "\033[0;32m✓\033[0m Open", Value: "open"},
		{Label: "- Greyed", Value: "greyed", Blocked: "no TPM here"},
		{Label: "  Quit", Value: "quit"},
	}
	helperEntries = []Option[string]{{Label: "first", Value: "a"}, {Label: "second", Value: "b"}}
)

func TestMenuArrows(t *testing.T) {
	m := newMenuTerm(t, 80, 24)
	before := lineDiscipline(t, m.pts)
	ch := startSelect(m, "Title", "The question", basic, "open")
	m.ask()
	if got := m.v.highlighted(); got != "1. ✓ Open" {
		t.Fatalf("the default is not under the cursor: %q", got)
	}
	want := "Title\nThe question\n" + menuHint + "\n1. ✓ Open\n2. - Greyed\n3.   Quit\nEnter a number between 1 and 3:"
	if got := m.v.text(); got != want {
		t.Fatalf("the menu:\n%s\nwant:\n%s", got, want)
	}
	// Down onto the greyed one: its reason shows, and Enter says it and stays.
	m.send("\x1b[B")
	m.until("the reason", func(s string) bool {
		return m.v.highlighted() == "2. - Greyed" && strings.Contains(s, "\nno TPM here\nEnter")
	})
	m.send("\r")
	m.until("the refusal", func(s string) bool { return strings.Contains(s, "no TPM here") && hasPrompt(s) })
	// Down again, the reason goes; SS3's form of the key; around the end.
	m.send("\x1b[B")
	m.until("past it", func(s string) bool { return m.v.highlighted() == "3.   Quit" && !strings.Contains(s, "no TPM here") })
	m.send("\x1bOB")
	m.until("around the end", func(s string) bool { return m.v.highlighted() == "1. ✓ Open" })
	m.send("\x1b[A")
	m.until("around the start", func(s string) bool { return m.v.highlighted() == "3.   Quit" })
	m.send("\n")
	r := wait(t, ch)
	if r.err != nil || r.v != "quit" {
		t.Fatalf("%+v", r)
	}
	if lineDiscipline(t, m.pts) != before {
		t.Fatal("the terminal is not given back")
	}
	m.until("question and answer", func(s string) bool { return s == "Title\nThe question\n> 3.   Quit" })
	if m.v.highlighted() != "" {
		t.Fatalf("reverse video stays: %q", m.v.highlighted())
	}
	if m.v.reverse {
		t.Fatal("reverse video is left on")
	}
	if len(m.v.unknown) > 0 {
		t.Fatalf("sequences the menu should not need: %q", m.v.unknown)
	}
}

func TestMenuNumbers(t *testing.T) {
	m := newMenuTerm(t, 80, 24)
	ch := startSelect(m, "", "Q", basic, "open")
	m.ask()
	// Not a number, out of range: asks again as the plain prompt does.
	m.send("x\r")
	m.until("not a number", func(s string) bool { return strings.Contains(s, "Invalid: must be a number between 1 and 3") })
	m.send("9\r")
	m.until("the prompt is empty again", func(s string) bool { return strings.Contains(s, "Invalid") && strings.HasSuffix(s, "and 3:") })
	// Typing clears the refusal; Backspace and Ctrl-U edit.
	m.send("7")
	m.until("typed", func(s string) bool { return !strings.Contains(s, "Invalid") && strings.HasSuffix(s, "and 3: 7") })
	m.send("\x7f")
	m.until("backspace", func(s string) bool { return strings.HasSuffix(s, "and 3:") })
	m.send("99\x15")
	m.until("Ctrl-U", func(s string) bool { return strings.HasSuffix(s, "and 3:") })
	// A greyed one by number: the reason, the cursor goes to it.
	m.send("2\r")
	m.until("greyed by number", func(s string) bool { return m.v.highlighted() == "2. - Greyed" && strings.Contains(s, "no TPM here") })
	// A number wins over the cursor, whichever came first.
	m.send("\x1b[B")
	m.until("the cursor", func(s string) bool { return m.v.highlighted() == "3.   Quit" })
	m.send("1\r")
	if r := wait(t, ch); r.err != nil || r.v != "open" {
		t.Fatalf("%+v", r)
	}
	m.until("the answer", func(s string) bool { return s == "Q\n> 1. ✓ Open" })
}

// A number and Enter in one write, as the VM test's session sends them.
func TestMenuNumberAndEnterAtOnce(t *testing.T) {
	m := newMenuTerm(t, 80, 24)
	ch := startSelect(m, "", "Q", basic, "open")
	m.ask()
	m.send("3\n")
	if r := wait(t, ch); r.err != nil || r.v != "quit" {
		t.Fatalf("%+v", r)
	}
}

// Enter alone takes the default and nothing else, as on the plain prompt: no default,
// no cursor, and the first key places it.
func TestMenuNoDefault(t *testing.T) {
	blocked := []Option[int]{{Label: "a", Value: 1}, {Label: "b", Value: 2, Blocked: "no"}}
	for _, def := range []int{0, 2} { // none holds it; a blocked one does
		m := newMenuTerm(t, 80, 24)
		ch := startSelect(m, "", "Q", blocked, def)
		m.ask()
		if got := m.v.highlighted(); got != "" {
			t.Fatalf("a cursor without a default: %q", got)
		}
		m.send("\r")
		m.until("asks again", func(s string) bool { return strings.Contains(s, "Invalid") })
		m.send("\x1b[A")
		m.until("up is the last", func(s string) bool { return m.v.highlighted() == "2. b" })
		m.send("\x1b[B")
		m.until("down, around, to the first", func(s string) bool { return m.v.highlighted() == "1. a" })
		m.send("\r")
		if r := wait(t, ch); r.err != nil || r.v != 1 {
			t.Fatalf("%+v", r)
		}
	}
}

func TestMenuCancel(t *testing.T) {
	for _, c := range []struct{ name, keys string }{
		{"Ctrl-C", "\x03"}, {"Ctrl-D", "\x04"}, {"Esc", "\x1b"}, {"Ctrl-C with a number typed", "12\x03"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := newMenuTerm(t, 80, 24)
			before := lineDiscipline(t, m.pts)
			ch := startSelect(m, "", "Q", basic, "open")
			m.ask()
			m.send(c.keys)
			if r := wait(t, ch); !errors.Is(r.err, ErrCancelled) {
				t.Fatalf("%+v", r)
			}
			if lineDiscipline(t, m.pts) != before {
				t.Fatal("the terminal is not given back")
			}
			m.until("the question and that it was cancelled", func(s string) bool { return s == "Q\n> cancelled" })
		})
	}
	// Ctrl-D with a number typed is nothing, as in a shell; another key's sequence too.
	m := newMenuTerm(t, 80, 24)
	ch := startSelect(m, "", "Q", basic, "open")
	m.ask()
	m.send("1\x04\x1b[5~\x1bx\r")
	if r := wait(t, ch); r.err != nil || r.v != "open" {
		t.Fatalf("%+v", r)
	}
}

// The terminal going away is a cancel.
func TestMenuHangup(t *testing.T) {
	m := newMenuTerm(t, 80, 24)
	ch := startSelect(m, "", "Q", basic, "open")
	m.ask()
	m.hangUp()
	if r := wait(t, ch); !errors.Is(r.err, ErrCancelled) {
		t.Fatalf("%+v", r)
	}
}

// Each signal that ends the process leaves the terminal as it was and the screen with
// the question alone.
func TestMenuSignals(t *testing.T) {
	for _, sig := range []unix.Signal{unix.SIGTERM, unix.SIGHUP, unix.SIGINT, unix.SIGQUIT, unix.SIGABRT} {
		t.Run(sig.String(), func(t *testing.T) {
			m := newMenuTerm(t, 30, 24)
			before := lineDiscipline(t, m.pts)
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(self)
			cmd.Env = append(os.Environ(), "PROMPT_TEST_HELPER=menu")
			cmd.Stdin, cmd.Stdout = m.pts, m.pts
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			m.ask()
			cmd.Process.Signal(sig)
			err = cmd.Wait()
			if lineDiscipline(t, m.pts) != before {
				t.Fatalf("%v left the terminal raw", sig)
			}
			m.until("the question alone", func(s string) bool { return s == "Title\nThe question" })
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("not ended by %v: %v", sig, err)
			}
		})
	}
}

// What usually breaks such a menu: entries longer than the row, words longer than the
// row, wide characters, a row that fits exactly. At every key the screen is the question
// and exactly the rows of one menu, and the terminal itself wrapped nothing.
func TestMenuWrapped(t *testing.T) {
	long := []Option[int]{
		{Label: "an entry with enough words to wrap over several rows on any narrow terminal at all", Value: 1},
		{Label: "\033[0;31m!\033[0m " + strings.Repeat("unbroken", 12), Value: 2},
		{Label: strings.Repeat("日本語", 15) + " and words", Value: 3, Blocked: "a reason that is long enough to wrap as well, over a row or two"},
		{Label: "\033[0;33m•\033[0m colours in a label that wraps \033[0;32m✓\033[0m and goes on past the end of it", Value: 4},
		{Label: "tab\there, and \x1b]0;a title\x07 a sequence that is not a colour", Value: 5},
		{Label: "x", Value: 6},
	}
	var entries []entry
	for _, o := range long {
		entries = append(entries, entry{o.Label, o.Blocked})
	}
	for _, width := range []int{8, 12, 20, 30, 41, 80, 200} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			const height = 200
			m := newMenuTerm(t, width, height)
			before := lineDiscipline(t, m.pts)
			ch := startSelect(m, "", "Q", long, 6)
			shadow := &menu{entries: entries, cursor: 5}
			expect := func(what string) {
				t.Helper()
				want := "Q\n" + stripped(shadow.rows(width, height))
				m.until(what, func(s string) bool { return s == want })
			}
			expect("the first draw")
			for i := range 2*len(long) + 1 {
				m.send("\x1b[B")
				shadow.move(+1)
				expect(fmt.Sprintf("down %d", i+1))
			}
			for i := range len(long) {
				m.send("\x1b[A")
				shadow.move(-1)
				expect(fmt.Sprintf("up %d", i+1))
			}
			m.send("\x1b[B\x1b[B\x1b[B") // the cursor on 1, from 6... whichever: to one not blocked
			shadow.move(+1)
			shadow.move(+1)
			shadow.move(+1)
			expect("on")
			for shadow.entries[shadow.cursor].blocked != "" {
				m.send("\x1b[B")
				shadow.move(+1)
				expect("past the greyed")
			}
			m.send("\r")
			r := wait(t, ch)
			if r.err != nil || r.v != long[shadow.cursor].Value {
				t.Fatalf("%+v, cursor %d", r, shadow.cursor)
			}
			if lineDiscipline(t, m.pts) != before {
				t.Fatal("the terminal is not given back")
			}
			m.until("the answer", func(s string) bool {
				return strings.HasPrefix(s, "Q\n> ") && !hasPrompt(s) && !strings.Contains(s, "Up, down")
			})
			if m.v.wraps != 0 {
				t.Fatalf("the terminal wrapped %d rows itself", m.v.wraps)
			}
		})
	}
}

// The prompt's own row: a long number typed on a narrow terminal stays counted.
func TestMenuLongTyping(t *testing.T) {
	m := newMenuTerm(t, 14, 40)
	ch := startSelect(m, "", "Q", basic, "open")
	m.ask()
	m.send(strings.Repeat("1", menuTyped+20))
	m.until("what fits is typed", func(s string) bool {
		return strings.Contains(strings.ReplaceAll(s, "\n", ""), strings.Repeat("1", menuTyped))
	})
	m.send("\x15")
	m.until("and it goes", func(s string) bool { return !strings.Contains(s, "1111") })
	m.send("\r")
	wait(t, ch)
	if m.v.wraps != 0 {
		t.Fatalf("the terminal wrapped %d rows itself", m.v.wraps)
	}
	if strings.Contains(m.v.text(), "and 3") {
		t.Fatalf("the prompt stays:\n%s", m.v.text())
	}
}

// Every width from none to wide, every cursor: no row reaches the last column.
func TestMenuRowsFit(t *testing.T) {
	m := &menu{entries: []entry{
		{"short", ""}, {strings.Repeat("word ", 40), "a reason, with words " + strings.Repeat("x", 90)},
		{strings.Repeat("語", 60), ""}, {strings.Repeat("y", 300), ""},
	}}
	for width := 3; width < 130; width++ {
		for c := -1; c < len(m.entries); c++ {
			m.cursor = c
			for _, r := range m.rows(width, 0) {
				if n := cells(r); n > width-1 && width > 3 {
					t.Fatalf("width %d, cursor %d: %d columns: %q", width, c, n, r)
				}
			}
		}
	}
}

// A menu taller than the terminal shows the part around the cursor; the question above
// goes into the scrollback, and nothing is left behind there.
func TestMenuTallerThanTheTerminal(t *testing.T) {
	var opts []Option[int]
	for i := range 30 {
		opts = append(opts, Option[int]{Label: fmt.Sprintf("entry number %02d", i+1), Value: i + 1})
	}
	for _, height := range []int{24, 8, 5, 3} {
		t.Run(fmt.Sprint(height), func(t *testing.T) {
			m := newMenuTerm(t, 40, height)
			ch := startSelect(m, "Title", "The question", opts, 1)
			m.until("drawn", hasPrompt)
			at := func(n int) string { return fmt.Sprintf("%2d. entry number %02d", n, n) }
			for n := 2; n <= 30; n++ {
				m.send("\x1b[B")
				m.until(fmt.Sprintf("the cursor on %d", n), func(s string) bool {
					return (height == 3 || m.v.highlighted() == at(n)) && strings.Count(s, "Enter a number") == 1 && strings.HasSuffix(s, "and 30:") && strings.Count(s, "Title") == 1
				})
				if rows := strings.Count(m.v.text(), "\n") + 1; rows > height+2 {
					t.Fatalf("at %d, %d rows, more than the screen and the question:\n%s", n, rows, m.v.text())
				}
			}
			m.send("\r")
			if r := wait(t, ch); r.err != nil || r.v != 30 {
				t.Fatalf("%+v", r)
			}
			m.until("question and answer", func(s string) bool { return s == "Title\nThe question\n> 30. entry number 30" })
			if m.v.wraps != 0 {
				t.Fatalf("the terminal wrapped %d rows itself", m.v.wraps)
			}
		})
	}
}

// At the bottom of the screen the rows scroll, and what is above stays, once.
func TestMenuAtTheBottom(t *testing.T) {
	m := newMenuTerm(t, 24, 12)
	var before strings.Builder
	for i := range 11 {
		fmt.Fprintf(&before, "printed by a step %d\n", i)
	}
	m.pts.WriteString(before.String())
	m.until("printed", func(s string) bool { return strings.Contains(s, "step 10") })
	ch := startSelect(m, "", "Q", basic, "quit")
	m.ask()
	for range 4 {
		m.send("\x1b[B")
		m.until("drawn", hasPrompt)
	}
	m.send("3\r")
	if r := wait(t, ch); r.err != nil || r.v != "quit" {
		t.Fatalf("%+v", r)
	}
	want := strings.TrimRight(before.String(), "\n") + "\nQ\n> 3.   Quit"
	m.until("what was printed, question and answer", func(s string) bool { return s == want })
}

// A window narrowed or widened under the menu: the next draw takes the new width, on
// its own, without a key.
func TestMenuResize(t *testing.T) {
	m := newMenuTerm(t, 80, 24)
	ch := startSelect(m, "", "Q", basic, "open")
	m.ask()
	shadow := &menu{entries: []entry{{basic[0].Label, ""}, {basic[1].Label, basic[1].Blocked}, {basic[2].Label, ""}}, cursor: 0}
	for _, w := range []int{20, 12, 50, 10, 80} {
		m.v.resize(w, 24)
		m.size(w, 24)
		want := "Q\n" + stripped(shadow.rows(w, 24))
		m.until(fmt.Sprintf("drawn again at %d", w), func(s string) bool { return s == want })
	}
	m.send("\r")
	if r := wait(t, ch); r.err != nil || r.v != "open" {
		t.Fatalf("%+v", r)
	}
}

func stripped(rows []string) string {
	var out []string
	for _, r := range rows {
		out = append(out, strings.TrimRight(sgr.ReplaceAllString(r, ""), " "))
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

// The plain prompt wherever rows cannot be counted or a cursor moved.
func TestMenuPlainWhereItCannot(t *testing.T) {
	check := func(t *testing.T, m *menuTerm, in *os.File, out *os.File) {
		t.Helper()
		ch := startSelectOn(in, out, basic, "open")
		m.until("the plain prompt", func(s string) bool { return strings.Contains(s, "Enter alone: ✓ Open") && hasPrompt(s) })
		m.send("3\r")
		if r := wait(t, ch); r.err != nil || r.v != "quit" {
			t.Fatalf("%+v", r)
		}
		if raw := m.v.raw.String(); strings.Contains(raw, "\033[J") || strings.Contains(raw, "\033[7m") {
			t.Fatalf("a cursor moved: %q", raw)
		}
	}
	t.Run("TERM=dumb", func(t *testing.T) {
		m := newMenuTerm(t, 80, 24)
		t.Setenv("TERM", "dumb")
		check(t, m, m.pts, m.pts)
	})
	t.Run("no TERM", func(t *testing.T) {
		m := newMenuTerm(t, 80, 24)
		t.Setenv("TERM", "")
		check(t, m, m.pts, m.pts)
	})
	t.Run("no width", func(t *testing.T) {
		m := newMenuTerm(t, 80, 24)
		m.size(0, 0)
		check(t, m, m.pts, m.pts)
	})
	t.Run("output not a terminal", func(t *testing.T) {
		m := newMenuTerm(t, 80, 24)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		defer w.Close()
		var out bytes.Buffer
		go io.Copy(&out, r)
		ch := startSelectOn(m.pts, w, basic, "open")
		time.Sleep(50 * time.Millisecond)
		m.send("3\r")
		if res := wait(t, ch); res.err != nil || res.v != "quit" {
			t.Fatalf("%+v", res)
		}
	})
}

func startSelectOn[T comparable](in, out *os.File, opts []Option[T], def T) <-chan result[T] {
	ch := make(chan result[T], 1)
	p := New(in, out)
	go func() {
		v, err := Select(p, "", "Q", opts, def)
		ch <- result[T]{v, err}
	}()
	return ch
}

// NO_COLOR takes the colours, not the cursor.
func TestMenuNoColor(t *testing.T) {
	m := newMenuTerm(t, 80, 24)
	t.Setenv("NO_COLOR", "1")
	ch := startSelect(m, "", "Q", basic, "open")
	m.ask()
	if got := m.v.highlighted(); got != "1. ✓ Open" {
		t.Fatalf("no cursor under NO_COLOR: %q", got)
	}
	m.send("\x1b[B")
	m.until("on the greyed one", func(string) bool { return m.v.highlighted() == "2. - Greyed" })
	m.send("\x1b[B\r")
	if r := wait(t, ch); r.err != nil {
		t.Fatalf("%+v", r)
	}
	m.until("the answer", func(s string) bool { return strings.HasSuffix(s, "> 3.   Quit") })
	for _, c := range sgrParams(m.v.raw.String()) {
		if c != "7" && c != "0" && c != "" {
			t.Fatalf("a colour under NO_COLOR: %q in %q", c, m.v.raw.String())
		}
	}
}

func sgrParams(s string) []string {
	var out []string
	for _, seq := range sgr.FindAllString(s, -1) {
		out = append(out, strings.Split(seq[2:len(seq)-1], ";")...)
	}
	return out
}
