// Package prompt is what control asks a person with: numbered menus, lines,
// yes or no, and a secret line, as plain text, on a terminal or from a pipe. The
// standard library and x/sys alone: a tool that runs as root and takes PINs.
//
// A menu on a terminal that says its width takes the arrow keys too (menu.go): plain
// ANSI, inline, no alternate screen and no terminfo. Anywhere else, TERM=dumb and a
// terminal of no known width included, it is the numbered prompt.
//
// On a terminal a prompt reads key by key with the line discipline off, for one
// prompt at a time: Ctrl-C, Ctrl-D on an empty line and Esc cancel it (ErrCancelled),
// Backspace and Ctrl-U edit, and a line too long is refused instead of being cut
// by the tty. The terminal is given back on every way out, a signal included. From
// anything else a prompt reads one line, a byte at a time, so nothing past the line
// is taken from the input: the next prompt, or a command run after it, reads the
// same pipe. There, EOF cancels.
package prompt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/termguard"
	"github.com/mrwiora/tpm2-kira/internal/wipe"
	"golang.org/x/sys/unix"
)

// MaxLine is the longest line Input, Select, Confirm and Wait take; Password takes
// diskkey.MaxPassphrase.
const MaxLine = 4096

var (
	// ErrCancelled is Ctrl-C, Ctrl-D, Esc or the end of the input.
	ErrCancelled = errors.New("cancelled at the prompt")
	// ErrTooLong is a line longer than the prompt takes: refused whole, never cut.
	ErrTooLong = errors.New("the line is too long")
)

// escWait is how long the bytes of an escape sequence may lag behind its Esc: a key
// such as an arrow sends all of them at once, Esc alone sends one.
const escWait = 50 * time.Millisecond

// SGR sequences only: a colourless output still clears its screen.
var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")

// Prompter asks on one input and one output.
type Prompter struct {
	in      io.Reader
	tty     *os.File // the input, when it is a terminal
	out     io.Writer
	term    *os.File // the output, when it is a terminal and its TERM moves a cursor
	noColor bool
	width   func() int
}

// New is a Prompter reading in and writing out. Colour goes to out only when it is
// a terminal and NO_COLOR is not set; a line is edited only when in is a terminal.
func New(in io.Reader, out io.Writer) *Prompter {
	p := &Prompter{in: in, out: out, width: func() int { return 0 }}
	if f, ok := in.(*os.File); ok && isTerminal(f) {
		p.tty = f
	}
	f, ok := out.(*os.File)
	if !ok || !isTerminal(f) {
		p.out = plainWriter{out}
		return p
	}
	if os.Getenv("NO_COLOR") != "" {
		p.out = plainWriter{out}
		p.noColor = true
	}
	if t := os.Getenv("TERM"); t != "" && t != "dumb" {
		p.term = f
	}
	p.width = func() int {
		ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
		if err != nil {
			return 0
		}
		return int(ws.Col)
	}
	return p
}

// Writer is the output, colours taken out when it has none: what is printed between
// prompts goes through it too.
func (p *Prompter) Writer() io.Writer { return p.out }

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

type plainWriter struct{ w io.Writer }

func (w plainWriter) Write(b []byte) (int, error) {
	if _, err := w.w.Write(sgr.ReplaceAll(b, nil)); err != nil {
		return 0, err
	}
	return len(b), nil
}

func title(s string) string   { return "\033[1;33m" + s + "\033[0m" }
func refusal(s string) string { return "\033[0;31m" + s + "\033[0m" }
func grey(s string) string {
	return "\033[0;90m" + strings.ReplaceAll(s, "\033[0m", "\033[0;90m") + "\033[0m"
}

// Note prints a title and text, and asks nothing.
func (p *Prompter) Note(heading, text string) {
	if heading != "" {
		fmt.Fprintln(p.out, title(heading))
	}
	p.text(text)
}

// text prints a description, wrapped to the terminal's width.
func (p *Prompter) text(s string) {
	if s != "" {
		fmt.Fprintln(p.out, wrap(strings.TrimRight(s, "\n"), p.width(), 0))
	}
}

// Wait holds what is on the screen until Enter: "Title [Enter: label] ".
func (p *Prompter) Wait(heading, text, label string) error {
	p.text(text)
	for {
		fmt.Fprintf(p.out, "%s [Enter: %s] ", title(heading), label)
		_, err := p.line()
		if errors.Is(err, ErrTooLong) {
			continue
		}
		return err
	}
}

// Option is a line of a menu. One with a reason in Blocked is shown greyed, and
// picking it says the reason and asks again.
type Option[T comparable] struct {
	Label   string
	Value   T
	Blocked string
}

// Select asks for a number, and on a terminal that can take them for the arrow keys.
// Enter alone takes the option holding def, unless it is blocked or there is none: then
// it asks again.
func Select[T comparable](p *Prompter, heading, description string, opts []Option[T], def T) (T, error) {
	var zero T
	if len(opts) == 0 {
		return zero, errors.New("nothing to choose from")
	}
	if heading != "" {
		fmt.Fprintln(p.out, title(heading))
	}
	p.text(description)
	preset := -1
	for i, o := range opts {
		if o.Value == def && o.Blocked == "" {
			preset = i
			break
		}
	}
	if p.arrows() {
		entries := make([]entry, len(opts))
		for i, o := range opts {
			entries[i] = entry{label: o.Label, blocked: o.Blocked}
		}
		i, err := p.menu(entries, preset)
		if err != nil {
			return zero, err
		}
		return opts[i].Value, nil
	}
	if preset >= 0 {
		fmt.Fprintf(p.out, "\033[2mEnter alone: %s\033[0m\n", strings.TrimSpace(sgr.ReplaceAllString(opts[preset].Label, "")))
	}
	digits := len(strconv.Itoa(len(opts)))
	for i, o := range opts {
		label := o.Label
		if o.Blocked != "" {
			label = grey(label)
		}
		fmt.Fprintln(p.out, wrap(fmt.Sprintf("%*d. %s", digits, i+1, label), p.width(), digits+2))
	}
	for {
		fmt.Fprintf(p.out, "Enter a number between 1 and %d: ", len(opts))
		line, err := p.line()
		switch {
		case errors.Is(err, ErrTooLong):
			fmt.Fprintln(p.out, refusal(fmt.Sprintf("Invalid: must be a number between 1 and %d", len(opts))))
			continue
		case err != nil:
			return zero, err
		}
		n := preset + 1
		if s := strings.TrimSpace(string(line)); s != "" {
			if n, err = strconv.Atoi(s); err != nil {
				n = 0
			}
		}
		if n < 1 || n > len(opts) {
			fmt.Fprintln(p.out, refusal(fmt.Sprintf("Invalid: must be a number between 1 and %d", len(opts))))
			continue
		}
		if why := opts[n-1].Blocked; why != "" {
			fmt.Fprintln(p.out, wrap(refusal(why), p.width(), 0))
			continue
		}
		return opts[n-1].Value, nil
	}
}

// Input asks for a line, until validate takes it (nil: anything). Enter alone gives
// def, and when validate takes an empty line, "-" empties a def there is. The
// question comes last, beside the cursor; what explains it above it.
func (p *Prompter) Input(heading, description, def string, validate func(string) error) (string, error) {
	check := func(s string) error {
		if validate == nil {
			return nil
		}
		return validate(s)
	}
	p.text(description)
	clearable := def != "" && check("") == nil
	switch {
	case clearable:
		fmt.Fprintf(p.out, "\033[2mEnter alone keeps: %s; - empties it\033[0m\n", def)
	case def != "":
		fmt.Fprintf(p.out, "\033[2mEnter alone keeps: %s\033[0m\n", def)
	}
	for {
		fmt.Fprintf(p.out, "%s ", title(heading))
		b, err := p.line()
		if err != nil {
			return "", err
		}
		s := string(b)
		switch {
		case s == "":
			s = def
		case s == "-" && clearable:
			s = ""
		}
		if err := check(s); err != nil {
			fmt.Fprintln(p.out, wrap(refusal(err.Error()), p.width(), 0))
			continue
		}
		return s, nil
	}
}

// Confirm asks yes or no: "Title [y/N] ", the capital being what Enter alone gives.
func (p *Prompter) Confirm(heading, description string, def bool) (bool, error) {
	p.text(description)
	opts := "[y/N]"
	if def {
		opts = "[Y/n]"
	}
	for {
		fmt.Fprintf(p.out, "%s %s ", title(heading), opts)
		line, err := p.line()
		if errors.Is(err, ErrTooLong) {
			fmt.Fprintln(p.out, refusal("Invalid: y or n"))
			continue
		}
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(string(line))) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(p.out, refusal("Invalid: y or n"))
	}
}

// Password asks for a line that is not shown, until validate takes it (nil:
// anything; it gets the buffer itself, and must not keep or copy it). The answer is
// the locked buffer diskkey reads a passphrase into, and no copy of it was made: the
// caller wipes it. Everything else read is wiped on the way out.
func (p *Prompter) Password(heading, description string, validate func([]byte) error) ([]byte, error) {
	p.text(description)
	buf := diskkey.PassphraseBuffer()
	for {
		fmt.Fprintf(p.out, "%s ", title(heading))
		line, err := p.read(buf[:0], true)
		if p.tty != nil {
			fmt.Fprintln(p.out)
		}
		if err != nil {
			wipe.Bytes(buf[:cap(buf)])
			return nil, err
		}
		if validate != nil {
			if err := validate(line); err != nil {
				wipe.Bytes(buf[:cap(buf)])
				fmt.Fprintln(p.out, wrap(refusal(err.Error()), p.width(), 0))
				continue
			}
		}
		return line, nil
	}
}

// line reads a line that is shown.
func (p *Prompter) line() ([]byte, error) {
	line, err := p.read(make([]byte, 0, MaxLine), false)
	if p.tty != nil && err != nil {
		fmt.Fprintln(p.out)
	}
	return line, err
}

// read reads a line into buf, never past its capacity. A line longer than that is
// read to its end and refused whole, so that its rest does not answer the next prompt.
func (p *Prompter) read(buf []byte, secret bool) ([]byte, error) {
	if p.tty == nil {
		return p.readPlain(buf, secret)
	}
	restore, err := raw(int(p.tty.Fd()), nil)
	if err != nil {
		return nil, err
	}
	defer restore()
	return p.readKeys(buf, secret)
}

func (p *Prompter) readPlain(line []byte, secret bool) ([]byte, error) {
	one := make([]byte, 1)
	defer wipe.Bytes(one)
	over := false
	for {
		n, err := p.in.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				break
			}
			if len(line) == cap(line) {
				over = true
				continue
			}
			line = append(line, one[0])
			continue
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(line) > 0 || over {
				break
			}
			return nil, ErrCancelled
		}
		return nil, err
	}
	if over {
		return nil, tooLong(cap(line))
	}
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	if !secret {
		for _, c := range line {
			if c < 0x20 || c == 0x7f {
				return nil, errors.New("a control character in the line")
			}
		}
	}
	return line, nil
}

func tooLong(limit int) error { return fmt.Errorf("%w: more than %d bytes", ErrTooLong, limit) }

// readKeys is the line editor, with the terminal raw. A secret is not echoed.
func (p *Prompter) readKeys(line []byte, secret bool) ([]byte, error) {
	one := make([]byte, 1)
	defer wipe.Bytes(one)
	echo := func(s string) {
		if !secret {
			io.WriteString(p.tty, s)
		}
	}
	erase := func() {
		n := len(line) - 1
		for n > 0 && !secret && !utf8.RuneStart(line[n]) {
			n--
		}
		wipe.Bytes(line[n:])
		line = line[:n]
		echo("\b \b")
	}
	over := false
	for {
		n, err := p.tty.Read(one)
		if err != nil || n == 0 {
			if err == nil || errors.Is(err, io.EOF) || errors.Is(err, syscall.EIO) {
				return nil, ErrCancelled // the terminal is gone
			}
			return nil, err
		}
		switch c := one[0]; {
		case c == '\n' || c == '\r':
			echo("\r\n")
			if over {
				return nil, tooLong(cap(line))
			}
			return line, nil
		case c == 3:
			return nil, ErrCancelled
		case c == 4:
			if len(line) == 0 && !over {
				return nil, ErrCancelled
			}
		case c == 27:
			if _, alone := p.escape(); alone {
				return nil, ErrCancelled
			}
		case c == 127 || c == 8:
			if len(line) > 0 {
				erase()
			}
		case c == 21: // Ctrl-U
			for len(line) > 0 {
				erase()
			}
			over = false
		case c < 0x20:
		case len(line) == cap(line):
			if !over {
				over = true
				io.WriteString(p.tty, "\a")
			}
		default:
			line = append(line, c)
			if c < utf8.RuneSelf {
				echo(string(rune(c)))
			} else if !secret {
				p.tty.Write(one) // the bytes of a rune, as they come
			}
		}
	}
}

// escape reads the rest of a key's escape sequence and gives its last byte, the one
// that names the key (0: none does, Alt and a key). alone: no rest, Esc itself.
func (p *Prompter) escape() (final byte, alone bool) {
	fd := int(p.tty.Fd())
	more := func() bool {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, int(escWait/time.Millisecond))
		return err == nil && n > 0
	}
	if !more() {
		return 0, true
	}
	b := make([]byte, 1)
	if _, err := p.tty.Read(b); err != nil {
		return 0, false
	}
	if b[0] != '[' && b[0] != 'O' {
		return 0, false
	}
	for more() {
		if _, err := p.tty.Read(b); err != nil {
			return 0, false
		}
		if b[0] >= 0x40 && b[0] <= 0x7e {
			return b[0], false
		}
	}
	return 0, false
}

// raw takes the terminal's line discipline away and gives what gives it back, also when
// a signal ends the process (and runs onSignal then, when there is one, for what is on
// the screen).
func raw(fd int, onSignal func()) (func(), error) {
	return termguard.Hold{
		Change: func(t *unix.Termios) {
			t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
			t.Cc[unix.VMIN], t.Cc[unix.VTIME] = 1, 0
		},
		OnSignal: onSignal,
	}.Take(fd)
}

// sgrAt is an SGR sequence at the start of a string.
var sgrAt = regexp.MustCompile("^\x1b\\[[0-9;]*m")

// wrap breaks lines at spaces to width (0: as they are), the colours not counted. A
// broken line goes on at its own indentation, or at indent when that is more.
func wrap(s string, width, indent int) string {
	if width <= 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = wrapLine(l, width, indent)
	}
	return strings.Join(lines, "\n")
}

func wrapLine(l string, width, indent int) string {
	if visible(l) <= width {
		return l
	}
	lead := len(l) - len(strings.TrimLeft(l, " "))
	if lead > indent {
		indent = lead
	}
	if indent >= width/2 {
		return l
	}
	var b strings.Builder
	b.WriteString(l[:lead])
	used := lead
	for i, word := range strings.Split(l[lead:], " ") {
		w := visible(word)
		switch {
		case i == 0:
		case used+1+w > width:
			b.WriteString("\n" + strings.Repeat(" ", indent))
			used = indent
		default:
			b.WriteByte(' ')
			used++
		}
		b.WriteString(word)
		used += w
	}
	return b.String()
}

func visible(s string) int { return utf8.RuneCountInString(sgr.ReplaceAllString(s, "")) }
