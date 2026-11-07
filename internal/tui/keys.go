package tui

import (
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// Key is one key the terminal sent: a named one, or a character (Name "rune").
type Key struct {
	Name string
	Rune rune
}

// The named keys.
const (
	KeyUp        = "up"
	KeyDown      = "down"
	KeyLeft      = "left"
	KeyRight     = "right"
	KeyPgUp      = "pgup"
	KeyPgDn      = "pgdn"
	KeyHome      = "home"
	KeyEnd       = "end"
	KeyEnter     = "enter"
	KeyEsc       = "esc"
	KeyTab       = "tab"
	KeyBackTab   = "backtab"
	KeyBackspace = "backspace"
	KeyCtrlC     = "ctrl-c"
	KeyCtrlD     = "ctrl-d"
	KeyCtrlL     = "ctrl-l"
	KeyRune      = "rune"
	KeyUnknown   = "unknown"
)

// csiFinal names a CSI or SS3 sequence's final byte; csiTilde a "ESC [ n ~" one's n.
var (
	csiFinal = map[byte]string{'A': KeyUp, 'B': KeyDown, 'C': KeyRight, 'D': KeyLeft, 'H': KeyHome, 'F': KeyEnd, 'Z': KeyBackTab}
	csiTilde = map[string]string{"1": KeyHome, "7": KeyHome, "4": KeyEnd, "8": KeyEnd, "5": KeyPgUp, "6": KeyPgDn}
)

// Decode is the first key in b and how many bytes it took; 0 when b holds no whole key
// yet (an escape sequence cut short). A lone ESC is Esc only when nothing follows it:
// the caller decides that by the time (Reader).
func Decode(b []byte) (Key, int) {
	if len(b) == 0 {
		return Key{}, 0
	}
	switch c := b[0]; {
	case c == 0x1b:
		return decodeEscape(b)
	case c == '\r' || c == '\n':
		return Key{Name: KeyEnter}, 1
	case c == '\t':
		return Key{Name: KeyTab}, 1
	case c == 0x7f || c == 0x08:
		return Key{Name: KeyBackspace}, 1
	case c == 0x03:
		return Key{Name: KeyCtrlC}, 1
	case c == 0x04:
		return Key{Name: KeyCtrlD}, 1
	case c == 0x0c:
		return Key{Name: KeyCtrlL}, 1
	case c < 0x20:
		return Key{Name: KeyUnknown}, 1
	}
	if !utf8.FullRune(b) {
		return Key{}, 0
	}
	r, n := utf8.DecodeRune(b)
	if r == utf8.RuneError {
		return Key{Name: KeyUnknown}, n
	}
	return Key{Name: KeyRune, Rune: r}, n
}

// decodeEscape reads "ESC [ ... final", "ESC O x", and the Linux console's
// "ESC [ [ x" (its F keys); an Alt chord (ESC and a character) is the character.
func decodeEscape(b []byte) (Key, int) {
	if len(b) == 1 {
		return Key{}, 0
	}
	switch b[1] {
	case 'O':
		if len(b) < 3 {
			return Key{}, 0
		}
		if k, ok := csiFinal[b[2]]; ok {
			return Key{Name: k}, 3
		}
		return Key{Name: KeyUnknown}, 3
	case '[':
		if len(b) >= 3 && b[2] == '[' { // the Linux console: ESC [ [ A..E
			if len(b) < 4 {
				return Key{}, 0
			}
			return Key{Name: KeyUnknown}, 4
		}
		for i := 2; i < len(b); i++ {
			c := b[i]
			if c >= 0x40 && c <= 0x7e {
				params := string(b[2:i])
				if c == '~' {
					first := params
					for j, ch := range params {
						if ch == ';' {
							first = params[:j]
							break
						}
					}
					if k, ok := csiTilde[first]; ok {
						return Key{Name: k}, i + 1
					}
					return Key{Name: KeyUnknown}, i + 1
				}
				if k, ok := csiFinal[c]; ok {
					return Key{Name: k}, i + 1
				}
				return Key{Name: KeyUnknown}, i + 1
			}
		}
		return Key{}, 0
	case 0x1b:
		return Key{Name: KeyEsc}, 1
	}
	k, n := Decode(b[1:])
	if n == 0 {
		return Key{}, 0
	}
	return k, n + 1
}

// Reader reads keys from a terminal in raw mode.
type Reader struct {
	fd  int
	buf []byte
}

// NewReader reads from fd.
func NewReader(fd int) *Reader { return &Reader{fd: fd} }

// escWait is how long the rest of an escape sequence may take; a lone ESC after it is Esc.
const escWait = 50 * time.Millisecond

// Read waits up to timeout for a key (0: one poll, negative: no limit); ok is false
// when none came in time.
func (r *Reader) Read(timeout time.Duration) (Key, bool, error) {
	for {
		if k, n := Decode(r.buf); n > 0 {
			r.buf = r.buf[n:]
			return k, true, nil
		}
		wait := timeout
		if len(r.buf) > 0 {
			wait = escWait // the rest of a sequence, or Esc alone
		}
		got, err := r.fill(wait)
		if err != nil {
			return Key{}, false, err
		}
		if !got {
			if len(r.buf) > 0 && r.buf[0] == 0x1b {
				r.buf = r.buf[1:]
				return Key{Name: KeyEsc}, true, nil
			}
			if len(r.buf) > 0 { // a broken sequence: dropped
				r.buf = nil
			}
			return Key{}, false, nil
		}
	}
}

// fill reads what is waiting, after up to wait for it to come.
func (r *Reader) fill(wait time.Duration) (bool, error) {
	ms := -1
	if wait >= 0 {
		ms = int(wait / time.Millisecond)
	}
	fds := []unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, ms)
	if err == unix.EINTR {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if n == 0 || fds[0].Revents&unix.POLLIN == 0 {
		if n > 0 && fds[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0 {
			return false, errClosed
		}
		return false, nil
	}
	b := make([]byte, 256)
	m, err := unix.Read(r.fd, b)
	if err != nil {
		return false, err
	}
	if m == 0 {
		return false, errClosed
	}
	r.buf = append(r.buf, b[:m]...)
	return true, nil
}
