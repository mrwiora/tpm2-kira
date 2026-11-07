package tui

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFit(t *testing.T) {
	for _, c := range []struct {
		in   string
		cols int
		want string
	}{
		{"abc", 5, "abc  "},
		{"abcdef", 4, "abc\033[0m~"},
		{"\033[0;32mok\033[0m", 4, "\033[0;32mok\033[0m\033[0m  "},
		{"a\tb", 3, "a b"},
		{"✓ x", 4, "✓ x"},
		{"abc", 0, ""},
	} {
		if got := Fit(c.in, c.cols, "~"); got != c.want {
			t.Errorf("Fit(%q, %d) = %q, want %q", c.in, c.cols, got, c.want)
		}
		if c.cols > 0 && Cells(Fit(c.in, c.cols, "~")) != c.cols {
			t.Errorf("Fit(%q, %d) is %d cells", c.in, c.cols, Cells(Fit(c.in, c.cols, "~")))
		}
	}
}

func TestLayout(t *testing.T) {
	rows := Layout("one two three four", 9, 2)
	if strings.Join(rows, "|") != "one two|  three|  four" {
		t.Fatalf("%q", rows)
	}
	if rows := Layout("\033[1mbold\033[0m word", 4, 0); len(rows) != 2 || StripSGR(rows[0]) != "bold" {
		t.Fatalf("%q", rows)
	}
}

func TestDecode(t *testing.T) {
	for in, want := range map[string]string{
		"\033[A": KeyUp, "\033[B": KeyDown, "\033[C": KeyRight, "\033[D": KeyLeft,
		"\033OA": KeyUp, "\033[5~": KeyPgUp, "\033[6~": KeyPgDn, "\033[1~": KeyHome, "\033[4~": KeyEnd,
		"\033[H": KeyHome, "\033[F": KeyEnd, "\033OH": KeyHome, "\033[Z": KeyBackTab, "\033[1;5A": KeyUp,
		"\r": KeyEnter, "\n": KeyEnter, "\t": KeyTab, "\x7f": KeyBackspace, "\x03": KeyCtrlC, "\x0c": KeyCtrlL,
		"\033[[A": KeyUnknown, "\033[3~": KeyUnknown, "\033\033": KeyEsc,
	} {
		k, n := Decode([]byte(in))
		if k.Name != want || (n != len(in) && in != "\033\033") {
			t.Errorf("Decode(%q) = %v, %d; want %s", in, k, n, want)
		}
	}
	if k, n := Decode([]byte("ä")); k.Name != KeyRune || k.Rune != 'ä' || n != 2 {
		t.Errorf("a character: %v %d", k, n)
	}
	for _, partial := range []string{"\033", "\033[", "\033[5", "\033O", "\xc3"} {
		if _, n := Decode([]byte(partial)); n != 0 {
			t.Errorf("Decode(%q) took %d bytes of a key not whole yet", partial, n)
		}
	}
	if k, n := Decode([]byte("\033q")); k.Name != KeyRune || k.Rune != 'q' || n != 2 {
		t.Errorf("Alt-q: %v %d", k, n)
	}
}

// A redraw writes the rows that changed and nothing else; a row the last frame had
// and this one not is erased.
func TestScreenDrawsWhatChanged(t *testing.T) {
	var out bytes.Buffer
	s := NewScreen(&out, true, GlyphsFor(false))
	if n := s.Draw([]string{"a", "b", "c"}, 10); n != 3 || !strings.HasPrefix(out.String(), "\033[H\033[2J") {
		t.Fatalf("first frame: %d rows, %q", n, out.String())
	}
	out.Reset()
	if n := s.Draw([]string{"a", "B"}, 10); n != 1 || !strings.Contains(out.String(), "\033[2;1HB") || !strings.Contains(out.String(), "\033[3;1H\033[K") || strings.Contains(out.String(), "\033[1;1H") {
		t.Fatalf("second frame: %d rows, %q", n, out.String())
	}
	out.Reset()
	if n := s.Draw([]string{"a", "B"}, 12); n != 2 {
		t.Fatalf("a new width redraws everything: %d", n)
	}
	out.Reset()
	plain := NewScreen(&out, false, GlyphsFor(false))
	plain.Draw([]string{"\033[31mred\033[0m"}, 5)
	if strings.Contains(out.String(), "31m") {
		t.Fatalf("NO_COLOR draws colours: %q", out.String())
	}
}

func TestColumns(t *testing.T) {
	rows := Columns("|", []int{3, 2}, []string{"abcd", "x"}, []string{"y"})
	if len(rows) != 2 || StripSGR(rows[0]) != "ab~|y " || StripSGR(rows[1]) != "x  |  " {
		t.Fatalf("%q", rows)
	}
}

func TestGlyphs(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("LANG", "de_DE.UTF-8")
	if !UTF8Locale() {
		t.Fatal("LANG UTF-8")
	}
	t.Setenv("LC_ALL", "C")
	if UTF8Locale() {
		t.Fatal("LC_ALL=C wins")
	}
	if GlyphsFor(false).Good != "+" || GlyphsFor(true).Good != "✓" {
		t.Fatal("glyph sets")
	}
}

// openPty is a pseudo-terminal: its master and its slave.
func openPty(t *testing.T) (ptm, pts *os.File) {
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
	pts, err = os.OpenFile("/dev/pts/"+itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ptm.Close(); pts.Close() })
	return ptm, pts
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Enter takes the terminal (raw, the alternate screen, no cursor), Leave gives it back
// as it was; the size is the terminal's, and keys come through the Reader.
func TestTermOnAPty(t *testing.T) {
	ptm, pts := openPty(t)
	before, _ := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	var out bytes.Buffer
	term := Open(pts, &out)
	if _, _, ok := term.Size(); ok {
		t.Fatal("a pty nobody sized has a size")
	}
	unix.IoctlSetWinsize(int(ptm.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: 80, Row: 24})
	if c, r, ok := term.Size(); !ok || c != 80 || r != 24 {
		t.Fatalf("size %d %d %v", c, r, ok)
	}
	if err := term.Enter(); err != nil {
		t.Fatal(err)
	}
	raw, _ := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if raw.Lflag&(unix.ICANON|unix.ECHO) != 0 || !strings.Contains(out.String(), "\033[?1049h") || !strings.Contains(out.String(), "\033[?25l") {
		t.Fatalf("not taken: lflag %x, %q", raw.Lflag, out.String())
	}
	ptm.Write([]byte("\033[Bq"))
	r := NewReader(term.FD())
	if k, ok, err := r.Read(time.Second); err != nil || !ok || k.Name != KeyDown {
		t.Fatalf("down: %v %v %v", k, ok, err)
	}
	if k, ok, _ := r.Read(time.Second); !ok || k.Rune != 'q' {
		t.Fatalf("q: %v", k)
	}
	ptm.Write([]byte("\033"))
	if k, ok, _ := r.Read(time.Second); !ok || k.Name != KeyEsc {
		t.Fatalf("Esc alone: %v %v", k, ok)
	}
	term.Leave()
	term.Leave()
	after, _ := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if after.Lflag != before.Lflag || after.Iflag != before.Iflag || !strings.HasSuffix(out.String(), leaveSeq) {
		t.Fatalf("not given back: %x/%x, %q", after.Lflag, before.Lflag, out.String())
	}
}
