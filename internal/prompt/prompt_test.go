package prompt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"golang.org/x/sys/unix"
)

func openPty(t *testing.T) (ptm, pts *os.File) {
	t.Helper()
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pty here: %v", err)
	}
	t.Cleanup(func() { ptm.Close() })
	if err := unix.IoctlSetPointerInt(int(ptm.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(ptm.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	pts, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pts.Close() })
	return ptm, pts
}

func lineDiscipline(t *testing.T, f *os.File) uint32 {
	t.Helper()
	tio, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	return tio.Lflag & (unix.ECHO | unix.ICANON | unix.ISIG)
}

// keys writes each part once the prompt has the terminal raw, or has it again.
func keys(t *testing.T, ptm, pts *os.File, parts ...string) {
	t.Helper()
	go func() {
		for _, k := range parts {
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if tio, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS); err == nil && tio.Lflag&unix.ICANON == 0 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			ptm.Write([]byte(k))
		}
	}()
}

// drain takes the terminal's output, which would fill up otherwise.
func drain(ptm *os.File) *bytes.Buffer {
	var b bytes.Buffer
	go io.Copy(&b, ptm)
	return &b
}

func pipe(s string) (*Prompter, *bytes.Buffer) {
	var out bytes.Buffer
	return New(strings.NewReader(s), &out), &out
}

func TestSelectFromAPipe(t *testing.T) {
	opts := []Option[string]{
		{Label: "\033[0;32m✓\033[0m Open", Value: "open"},
		{Label: "- Greyed  - no TPM", Value: "greyed", Blocked: "no TPM"},
		{Label: "  Quit", Value: ""},
	}
	p, out := pipe("x\n9\n2\n\n")
	got, err := Select(p, "Title", "Explained", opts, "")
	if err != nil || got != "" {
		t.Fatalf("got %q, %v", got, err)
	}
	text := out.String()
	for _, want := range []string{
		"Title\nExplained\nEnter alone: Quit\n1. ✓ Open\n2. - Greyed  - no TPM\n3.   Quit\nEnter a number between 1 and 3: ",
		"Invalid: must be a number between 1 and 3\n",
		"no TPM\nEnter a number between 1 and 3: ",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\033") {
		t.Errorf("colour on a pipe:\n%q", text)
	}
	if strings.Count(text, "Enter a number") != 4 {
		t.Errorf("not asked four times:\n%s", text)
	}
}

func TestSelectDefaults(t *testing.T) {
	opts := []Option[int]{{Label: "a", Value: 1}, {Label: "b", Value: 2, Blocked: "no"}}
	p, out := pipe("\n2\n1\n")
	if got, err := Select(p, "", "", opts, 2); err != nil || got != 1 {
		t.Fatalf("a blocked default: got %d, %v", got, err)
	}
	if strings.Contains(out.String(), "Enter alone") {
		t.Errorf("a blocked default is offered:\n%s", out)
	}
	if strings.Count(out.String(), "Invalid") != 1 {
		t.Errorf("Enter without a default asks again:\n%s", out)
	}
	p, _ = pipe("")
	if _, err := Select(p, "", "", opts, 1); !errors.Is(err, ErrCancelled) {
		t.Fatalf("EOF: %v", err)
	}
	if _, err := Select[int](p, "", "", nil, 0); err == nil {
		t.Fatal("no options, no error")
	}
}

func TestInputFromAPipe(t *testing.T) {
	number := func(s string) error {
		if s != "22" && s != "23" {
			return errors.New("a port number")
		}
		return nil
	}
	p, out := pipe("abc\n23\r\n\n")
	if got, err := p.Input("SSH port", "Why", "22", number); err != nil || got != "23" {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := p.Input("SSH port", "", "22", number); err != nil || got != "22" {
		t.Fatalf("the default: got %q, %v", got, err)
	}
	for _, want := range []string{"Why\nEnter alone keeps: 22\nSSH port ", "a port number\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out.String(), "empties") {
		t.Errorf("a line that cannot be empty is offered that:\n%s", out)
	}
	p, out = pipe("-\n")
	if got, err := p.Input("Gateway", "", "10.0.0.1", nil); err != nil || got != "" {
		t.Fatalf("- empties: got %q, %v", got, err)
	}
	if !strings.Contains(out.String(), "- empties it") {
		t.Errorf("not said:\n%s", out)
	}
	p, _ = pipe("one\ntwo")
	if got, _ := p.Input("A", "", "", nil); got != "one" {
		t.Fatalf("got %q", got)
	}
	if got, err := p.Input("B", "", "", nil); err != nil || got != "two" {
		t.Fatalf("the last line without its end: %q, %v", got, err)
	}
	if _, err := p.Input("C", "", "", nil); !errors.Is(err, ErrCancelled) {
		t.Fatalf("EOF: %v", err)
	}
	p, _ = pipe("a\x1bb\n")
	if _, err := p.Input("D", "", "", nil); err == nil {
		t.Fatal("a control character is taken")
	}
}

// A line too long is an error, and its rest does not answer the next prompt.
func TestTooLongFromAPipe(t *testing.T) {
	long := strings.Repeat("x", MaxLine+1)
	p, _ := pipe(long + "\nnext\n")
	if _, err := p.Input("A", "", "", nil); !errors.Is(err, ErrTooLong) {
		t.Fatalf("too long: %v", err)
	}
	if got, err := p.Input("B", "", "", nil); err != nil || got != "next" {
		t.Fatalf("what follows: %q, %v", got, err)
	}
	p, _ = pipe(strings.Repeat("x", MaxLine) + "\n")
	if got, err := p.Input("A", "", "", nil); err != nil || len(got) != MaxLine {
		t.Fatalf("at the limit: %d, %v", len(got), err)
	}
	p, _ = pipe(strings.Repeat("s", diskkey.MaxPassphrase+1) + "\nnext\n")
	if _, err := p.Password("PIN", "", nil); !errors.Is(err, ErrTooLong) {
		t.Fatalf("a secret too long: %v", err)
	}
	if got, err := p.Input("B", "", "", nil); err != nil || got != "next" {
		t.Fatalf("what follows a secret: %q, %v", got, err)
	}
	// A menu and a question ask again.
	p, _ = pipe(long + "\n1\n" + long + "\ny\n")
	if got, err := Select(p, "", "", []Option[int]{{Label: "a", Value: 7}}, 0); err != nil || got != 7 {
		t.Fatalf("menu: %d, %v", got, err)
	}
	if ok, err := p.Confirm("Sure?", "", false); err != nil || !ok {
		t.Fatalf("confirm: %v, %v", ok, err)
	}
}

func TestConfirmFromAPipe(t *testing.T) {
	for _, c := range []struct {
		in   string
		def  bool
		want bool
		says string
	}{
		{"\n", false, false, "Sure? [y/N] "},
		{"\n", true, true, "Sure? [Y/n] "},
		{"y\n", false, true, "[y/N]"},
		{"YES\n", false, true, "[y/N]"},
		{"n\n", true, false, "[Y/n]"},
		{"maybe\nno\n", true, false, "Invalid: y or n"},
	} {
		p, out := pipe(c.in)
		got, err := p.Confirm("Sure?", "", c.def)
		if err != nil || got != c.want || !strings.Contains(out.String(), c.says) {
			t.Errorf("%q, default %v: %v, %v; %q", c.in, c.def, got, err, out)
		}
	}
	p, _ := pipe("")
	if ok, err := p.Confirm("Sure?", "", true); ok || !errors.Is(err, ErrCancelled) {
		t.Fatalf("EOF is no yes, not even by default: %v, %v", ok, err)
	}
}

func TestWait(t *testing.T) {
	p, out := pipe("\n")
	if err := p.Wait("Back to step 2", "", "OK"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "Back to step 2 [Enter: OK] " {
		t.Fatalf("%q", out)
	}
	if err := p.Wait("Back", "", "OK"); !errors.Is(err, ErrCancelled) {
		t.Fatalf("EOF: %v", err)
	}
}

func TestPasswordFromAPipe(t *testing.T) {
	p, out := pipe("12345\n123456\nrest\n")
	got, err := p.Password("PIN", "Asked once", func(b []byte) error {
		if len(b) < 6 {
			return errors.New("too short")
		}
		return nil
	})
	if err != nil || string(got) != "123456" {
		t.Fatalf("%q, %v", got, err)
	}
	if strings.Contains(out.String(), "123456") {
		t.Fatalf("shown: %q", out)
	}
	if cap(got) != diskkey.MaxPassphrase {
		t.Fatalf("not the passphrase buffer: capacity %d", cap(got))
	}
	if rest, _ := p.Input("next", "", "", nil); rest != "rest" {
		t.Fatalf("what follows: %q", rest)
	}
}

func TestInputOnATerminal(t *testing.T) {
	ptm, pts := openPty(t)
	drain(ptm)
	var out bytes.Buffer
	p := New(pts, &out)
	before := lineDiscipline(t, pts)
	// Backspace over a rune of two bytes, Ctrl-U, an arrow's sequence (no effect).
	keys(t, ptm, pts, "wrong\x15abé\x7f\x1b[Ac\r")
	got, err := p.Input("Name", "", "", nil)
	if err != nil || got != "abc" {
		t.Fatalf("%q, %v", got, err)
	}
	if lineDiscipline(t, pts) != before {
		t.Fatal("the terminal is not given back")
	}
	for _, c := range []struct{ name, key string }{{"Ctrl-C", "ab\x03"}, {"Ctrl-D", "\x04"}, {"Esc", "\x1b"}} {
		keys(t, ptm, pts, c.key)
		if _, err := p.Input("Name", "", "", nil); !errors.Is(err, ErrCancelled) {
			t.Fatalf("%s: %v", c.name, err)
		}
		if lineDiscipline(t, pts) != before {
			t.Fatalf("%s: the terminal is not given back", c.name)
		}
	}
	// Ctrl-D with a line typed is nothing, as in a shell.
	keys(t, ptm, pts, "a\x04b\n")
	if got, err := p.Input("Name", "", "", nil); err != nil || got != "ab" {
		t.Fatalf("%q, %v", got, err)
	}
	// The tty's canonical mode would cut this at 4095 bytes without a word.
	keys(t, ptm, pts, strings.Repeat("x", MaxLine+1)+"\n")
	if _, err := p.Input("Name", "", "", nil); !errors.Is(err, ErrTooLong) {
		t.Fatalf("too long: %v", err)
	}
	keys(t, ptm, pts, strings.Repeat("x", MaxLine)+"\x7fy\n")
	if got, err := p.Input("Name", "", "", nil); err != nil || len(got) != MaxLine || got[MaxLine-1] != 'y' {
		t.Fatalf("at the limit: %d, %v", len(got), err)
	}
}

func TestSelectOnATerminal(t *testing.T) {
	ptm, pts := openPty(t)
	drain(ptm)
	var out bytes.Buffer
	p := New(pts, &out)
	keys(t, ptm, pts, "2\r")
	opts := []Option[string]{{Label: "a", Value: "a"}, {Label: "b", Value: "b"}}
	if got, err := Select(p, "", "", opts, "a"); err != nil || got != "b" {
		t.Fatalf("%q, %v", got, err)
	}
	keys(t, ptm, pts, "\x03")
	if _, err := Select(p, "", "", opts, "a"); !errors.Is(err, ErrCancelled) {
		t.Fatalf("Ctrl-C: %v", err)
	}
}

func TestPasswordOnATerminal(t *testing.T) {
	ptm, pts := openPty(t)
	echoed := make(chan string)
	go func() {
		var b bytes.Buffer
		io.Copy(&b, ptm)
		echoed <- b.String()
	}()
	var out bytes.Buffer
	p := New(pts, &out)
	before := lineDiscipline(t, pts)
	keys(t, ptm, pts, "seXcr\x7f\x7f\x7fcret\r")
	got, err := p.Password("PIN", "", nil)
	if err != nil || string(got) != "secret" {
		t.Fatalf("%q, %v", got, err)
	}
	if cap(got) != diskkey.MaxPassphrase {
		t.Fatalf("not the passphrase buffer: capacity %d", cap(got))
	}
	if lineDiscipline(t, pts) != before {
		t.Fatal("the terminal is not given back")
	}
	keys(t, ptm, pts, "pin\x03")
	if _, err := p.Password("PIN", "", nil); !errors.Is(err, ErrCancelled) {
		t.Fatalf("Ctrl-C: %v", err)
	}
	keys(t, ptm, pts, strings.Repeat("s", diskkey.MaxPassphrase+1)+"\r")
	if _, err := p.Password("PIN", "", nil); !errors.Is(err, ErrTooLong) {
		t.Fatalf("too long: %v", err)
	}
	pts.Close()
	select {
	case s := <-echoed:
		for _, leak := range []string{"secret", "pin", "s", "*"} {
			if strings.Contains(s, leak) {
				t.Fatalf("%q echoed: %q", leak, s[:min(len(s), 80)])
			}
		}
	case <-time.After(3 * time.Second):
		t.Log("the terminal's output did not end: nothing to look at")
	}
}

// The helper of TestSignalGivesTheTerminalBack: a prompt in a process that a signal ends.
func TestMain(m *testing.M) {
	if os.Getenv("PROMPT_TEST_HELPER") == "" {
		os.Exit(m.Run())
	}
	var out bytes.Buffer
	p := New(os.Stdin, &out)
	p.Password("PIN", "", nil)
	os.Exit(0)
}

func TestSignalGivesTheTerminalBack(t *testing.T) {
	for _, sig := range []unix.Signal{unix.SIGTERM, unix.SIGHUP, unix.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			ptm, pts := openPty(t)
			drain(ptm)
			before := lineDiscipline(t, pts)
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(self)
			cmd.Env = append(os.Environ(), "PROMPT_TEST_HELPER=1")
			cmd.Stdin = pts
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(10 * time.Second)
			for lineDiscipline(t, pts) == before {
				if time.Now().After(deadline) {
					cmd.Process.Kill()
					t.Fatal("the prompt never took the terminal")
				}
				time.Sleep(time.Millisecond)
			}
			cmd.Process.Signal(sig)
			err = cmd.Wait()
			if lineDiscipline(t, pts) != before {
				t.Fatalf("%v left the terminal raw", sig)
			}
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ProcessState.Sys().(interface{ Signal() unix.Signal }).Signal() != sig {
				t.Fatalf("not ended by %v: %v", sig, err)
			}
		})
	}
}

// Colours only on a terminal without NO_COLOR.
func TestColour(t *testing.T) {
	_, pts := openPty(t)
	var buf bytes.Buffer
	if New(strings.NewReader(""), &buf).Writer() == io.Writer(&buf) {
		t.Fatal("a buffer takes colours")
	}
	t.Setenv("NO_COLOR", "")
	if p := New(pts, pts); p.Writer() != io.Writer(pts) {
		t.Fatal("a terminal has its colours")
	}
	t.Setenv("NO_COLOR", "1")
	p := New(pts, pts)
	if p.Writer() == io.Writer(pts) {
		t.Fatal("NO_COLOR is not respected")
	}
	var plain bytes.Buffer
	(plainWriter{&plain}).Write([]byte("\033[H\033[2J\033[0;31mred\033[0m"))
	if plain.String() != "\033[H\033[2Jred" {
		t.Fatalf("%q", plain.String())
	}
}

func TestWrap(t *testing.T) {
	got := wrap("  aa \033[0;31mbb\033[0m cc dd\nshort", 8, 0)
	if got != "  aa bb\n  cc dd\nshort" && got != "  aa \033[0;31mbb\033[0m\n  cc dd\nshort" {
		t.Fatalf("%q", got)
	}
	if got := wrap("1. aaaa bbbb", 8, 3); got != "1. aaaa\n   bbbb" {
		t.Fatalf("%q", got)
	}
	if got := wrap("as it is, however long", 0, 0); got != "as it is, however long" {
		t.Fatalf("%q", got)
	}
}
