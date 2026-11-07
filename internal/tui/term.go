package tui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/tpm2-trust/tpm2-kira/internal/termguard"
	"golang.org/x/sys/unix"
)

var errClosed = errors.New("the terminal is closed")

// Term is a terminal taken over for a full screen: raw input, the alternate screen,
// the cursor hidden. Leave gives it back as it was - also when a signal ends the
// process (termguard) - and so does a caller's deferred Leave after a panic.
type Term struct {
	in      int
	out     io.Writer
	restore func()
	mu      sync.Mutex
	winch   chan os.Signal
}

// Open is the terminal on in, drawn on out.
func Open(in *os.File, out io.Writer) *Term {
	return &Term{in: int(in.Fd()), out: out}
}

// IsTerminal says whether f is a terminal.
func IsTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// Size is the terminal's columns and rows; ok is false when it reports none (a pty
// nobody sized, a serial line).
func (t *Term) Size() (cols, rows int, ok bool) {
	ws, err := unix.IoctlGetWinsize(t.in, unix.TIOCGWINSZ)
	if err != nil || ws.Col == 0 || ws.Row == 0 {
		return 0, 0, false
	}
	return int(ws.Col), int(ws.Row), true
}

// FD is the terminal's input, for a Reader.
func (t *Term) FD() int { return t.in }

// linuxConsole: the Linux console keeps no alternate screen; what is drawn there is
// cleared on leaving instead.
func linuxConsole() bool { return strings.HasPrefix(os.Getenv("TERM"), "linux") }

const (
	enterSeq = "\033[?1049h\033[?25l\033[H\033[2J"
	leaveSeq = "\033[0m\033[?25h\033[?1049l"
)

// Enter takes the terminal: raw mode, the alternate screen, no cursor. Resizes come on
// Resized from here on.
func (t *Term) Enter() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.restore != nil {
		return nil
	}
	restore, err := termguard.Hold{
		Change: func(tm *unix.Termios) {
			tm.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
			tm.Iflag &^= unix.IXON | unix.ICRNL
			tm.Cc[unix.VMIN], tm.Cc[unix.VTIME] = 1, 0
		},
		OnSignal: func() { fmt.Fprint(t.out, t.leaveText()) },
		Flush:    true,
	}.Take(t.in)
	if err != nil {
		return err
	}
	t.restore = restore
	if t.winch == nil {
		t.winch = make(chan os.Signal, 1)
	}
	signal.Notify(t.winch, unix.SIGWINCH)
	fmt.Fprint(t.out, enterSeq)
	return nil
}

func (t *Term) leaveText() string {
	if linuxConsole() {
		return "\033[H\033[2J" + leaveSeq
	}
	return leaveSeq
}

// Leave gives the terminal back as Enter found it; a second Leave does nothing.
func (t *Term) Leave() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.restore == nil {
		return
	}
	if t.winch != nil {
		signal.Stop(t.winch)
	}
	fmt.Fprint(t.out, t.leaveText())
	t.restore()
	t.restore = nil
}

// Resized delivers a value when the terminal's size changed (nil before Enter).
func (t *Term) Resized() <-chan os.Signal { return t.winch }

// Glyphs are the characters a frame is drawn with: Unicode where the locale is UTF-8,
// ASCII elsewhere.
type Glyphs struct {
	Vert, Horiz, Cross, Good, Bad, Warn, Open, Blocked, More, Cursor, Ellipsis string
}

var (
	unicodeGlyphs = Glyphs{Vert: "│", Horiz: "─", Cross: "┼", Good: "✓", Bad: "✗", Warn: "⚠", Open: "•", Blocked: "-", More: "›", Cursor: "▶", Ellipsis: "…"}
	asciiGlyphs   = Glyphs{Vert: "|", Horiz: "-", Cross: "+", Good: "+", Bad: "x", Warn: "!", Open: "*", Blocked: "-", More: ">", Cursor: ">", Ellipsis: "~"}
)

// UTF8Locale says whether the locale's character set is UTF-8 (LC_ALL, LC_CTYPE, LANG,
// the first one set).
func UTF8Locale() bool {
	for _, v := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if s := os.Getenv(v); s != "" {
			s = strings.ToLower(s)
			return strings.Contains(s, "utf-8") || strings.Contains(s, "utf8")
		}
	}
	return false
}

// GlyphsFor is the set for a UTF-8 locale or not.
func GlyphsFor(utf8 bool) Glyphs {
	if utf8 {
		return unicodeGlyphs
	}
	return asciiGlyphs
}

// Colour says whether colours are wanted: not with NO_COLOR set (no-color.org).
func Colour() bool { return os.Getenv("NO_COLOR") == "" }
