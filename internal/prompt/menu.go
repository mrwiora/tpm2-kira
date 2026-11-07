package prompt

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tpm2-trust/tpm2-kira/internal/tui"
	"golang.org/x/sys/unix"
)

// A menu on a terminal, drawn inline under its question:
//
//	Up, down and Enter, or a number and Enter; Esc cancels.
//	1. Open
//	2. Greyed - no TPM     (under the cursor: reverse video)
//	3. Quit
//	no TPM                 (the reason, while the cursor is on a greyed entry)
//	Enter a number between 1 and 3:
//
// What it draws goes again on every way out; the question stays above, and "> 2. Open"
// beneath it is the answer. No alternate screen and no terminfo: ANSI's cursor up, erase
// below and reverse video, on any TERM but dumb.
//
// Going back over what was drawn is what breaks such menus, when a row counted is not
// the row the terminal made. So the terminal never wraps here: every row is broken by
// this code, from the terminal's width asked anew for every draw, and stays out of the
// last column; a character of unknown width counts as two (too wide wraps early, which
// is harmless, too narrow would not be). A menu taller than the terminal shows the part
// around the cursor.

const (
	menuHint = "Up, down and Enter, or a number and Enter; Esc cancels."
	// menuTyped is the longest number taken at a menu's prompt.
	menuTyped = 32
	// menuPoll is how soon a changed window size is drawn.
	menuPoll = 200 * time.Millisecond
)

type entry struct{ label, blocked string }

type menu struct {
	entries []entry
	noColor bool
	cursor  int // -1: none yet, and Enter alone takes nothing
	typed   []byte
	note    string // a refusal, until the next key

	mu    sync.Mutex
	write func(string)
	drawn []string // the rows on the screen; the terminal's cursor ends the last
}

// arrows says whether a menu here can go by the keys: both ends terminals, with a TERM
// that moves a cursor and a width to count rows by.
func (p *Prompter) arrows() bool {
	if p.tty == nil || p.term == nil {
		return false
	}
	cols, _ := p.size()
	return cols > 0
}

// size is the terminal's columns and rows, 0 where it does not say.
func (p *Prompter) size() (cols, rows int) {
	ws, err := unix.IoctlGetWinsize(int(p.term.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0
	}
	return int(ws.Col), int(ws.Row)
}

// menu asks until an entry not blocked is taken, or it is cancelled.
func (p *Prompter) menu(entries []entry, preset int) (int, error) {
	m := &menu{entries: entries, noColor: p.noColor, cursor: preset,
		write: func(s string) { p.term.WriteString(s) }}
	// A signal's end: the menu goes from the screen, and the lock is never given up.
	restore, err := raw(int(p.tty.Fd()), func() {
		m.mu.Lock()
		m.write(m.erase(p.width()))
	})
	if err != nil {
		return 0, err
	}
	defer restore()
	done := false
	defer func() {
		if !done {
			m.leave(p.width(), "")
		}
	}()
	cols, rows := p.size()
	m.draw(cols, rows)
	for {
		c, err := p.nextByte(func() {
			if nc, nr := p.size(); nc > 0 && (nc != cols || nr != rows) {
				cols, rows = nc, nr
				m.draw(cols, rows)
			}
		})
		if err != nil {
			done = true
			m.leave(cols, "> cancelled")
			return 0, err
		}
		i, finished, err := m.key(c, p)
		if err != nil {
			done = true
			m.leave(cols, "> cancelled")
			return 0, err
		}
		if finished {
			done = true
			m.leave(cols, m.answer(i, cols))
			return i, nil
		}
		if nc, nr := p.size(); nc > 0 {
			cols, rows = nc, nr
		}
		m.draw(cols, rows)
	}
}

// nextByte waits for a byte of input and runs idle while there is none. The terminal
// gone is a cancel, as at a line.
func (p *Prompter) nextByte(idle func()) (byte, error) {
	fds := []unix.PollFd{{Fd: int32(p.tty.Fd()), Events: unix.POLLIN}}
	one := make([]byte, 1)
	for {
		n, err := unix.Poll(fds, int(menuPoll/time.Millisecond))
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			idle()
			continue
		}
		n, err = p.tty.Read(one)
		if errors.Is(err, syscall.EAGAIN) {
			continue
		}
		if err != nil || n == 0 {
			if err == nil || errors.Is(err, syscall.EIO) || errors.Is(err, io.EOF) {
				return 0, ErrCancelled
			}
			return 0, err
		}
		return one[0], nil
	}
}

// key takes a byte: finished with the entry taken, or an error that ends the menu.
func (m *menu) key(c byte, p *Prompter) (int, bool, error) {
	switch {
	case c == 3:
		return 0, false, ErrCancelled
	case c == 4:
		if len(m.typed) == 0 {
			return 0, false, ErrCancelled
		}
	case c == 27:
		final, alone := p.escape()
		switch {
		case alone:
			return 0, false, ErrCancelled
		case final == 'A':
			m.move(-1)
		case final == 'B':
			m.move(+1)
		}
	case c == '\n' || c == '\r':
		return m.enter()
	case c == 127 || c == 8:
		if n := len(m.typed); n > 0 {
			m.typed = m.typed[:n-1]
		}
		m.note = ""
	case c == 21: // Ctrl-U
		m.typed, m.note = nil, ""
	case c < 0x20 || c >= 0x7f:
	case len(m.typed) < menuTyped:
		m.typed = append(m.typed, c)
		m.note = ""
	}
	return 0, false, nil
}

// move goes up or down, around the ends. It goes over a greyed entry too, which is how
// its reason is read. With no cursor yet, down is the first entry and up the last.
func (m *menu) move(by int) {
	m.typed, m.note = nil, ""
	n := len(m.entries)
	switch {
	case m.cursor >= 0:
		m.cursor = (m.cursor + by + n) % n
	case by > 0:
		m.cursor = 0
	default:
		m.cursor = n - 1
	}
}

// enter is what the numbered prompt does with a line: a number typed goes first, else
// the entry under the cursor. Anything else asks again and says why.
func (m *menu) enter() (int, bool, error) {
	n := m.cursor + 1
	if s := strings.TrimSpace(string(m.typed)); s != "" {
		var err error
		if n, err = strconv.Atoi(s); err != nil {
			n = 0
		}
	}
	m.typed = nil
	if n < 1 || n > len(m.entries) {
		m.note = refusal(fmt.Sprintf("Invalid: must be a number between 1 and %d", len(m.entries)))
		return 0, false, nil
	}
	if why := m.entries[n-1].blocked; why != "" {
		m.cursor = n - 1
		m.note = refusal(why)
		return 0, false, nil
	}
	return n - 1, true, nil
}

// answer is the line that stays.
func (m *menu) answer(i, cols int) string {
	digits := len(strconv.Itoa(len(m.entries)))
	return strings.Join(m.layoutRows(fmt.Sprintf("> %d. %s", i+1, m.colored(m.entries[i].label)), cols, digits+4), "\r\n")
}

func (m *menu) colored(s string) string {
	s = sanitize(s)
	if m.noColor {
		return sgr.ReplaceAllString(s, "")
	}
	return s
}

func (m *menu) layoutRows(s string, width, indent int) []string {
	return layout(s, rowCells(width), indent)
}

// paint is a row in one style. Reverse video is no colour, and marks the cursor under
// NO_COLOR too: callers pass colour = true for what NO_COLOR takes away.
func (m *menu) paint(row, style string, colour bool) string {
	row = sgr.ReplaceAllString(row, "")
	if colour && m.noColor {
		return row
	}
	return style + row + "\033[0m"
}

// rows is what is drawn for a terminal of width and height (0: not said): each one a
// row of the terminal, none longer than rowCells(width).
func (m *menu) rows(width, height int) []string {
	cols := rowCells(width)
	digits := len(strconv.Itoa(len(m.entries)))
	var list []string
	first, last := 0, 0
	for i, e := range m.entries {
		rr := layout(fmt.Sprintf("%*d. %s", digits, i+1, m.colored(e.label)), cols, digits+2)
		for j := range rr {
			switch {
			case i == m.cursor && e.blocked != "":
				if m.noColor {
					rr[j] = m.paint(rr[j], "\033[7m", false)
				} else {
					rr[j] = m.paint(rr[j], "\033[0;90;7m", false)
				}
			case i == m.cursor:
				rr[j] = m.paint(rr[j], "\033[7m", false)
			case e.blocked != "":
				rr[j] = m.paint(rr[j], "\033[0;90m", true)
			}
		}
		if i == m.cursor {
			first, last = len(list), len(list)+len(rr)
		}
		list = append(list, rr...)
	}
	var status []string
	switch {
	case m.note != "":
		status = layout(m.colored(m.note), cols, 0)
	case m.cursor >= 0 && m.entries[m.cursor].blocked != "":
		status = layout(m.colored(m.entries[m.cursor].blocked), cols, 0)
		for j := range status {
			status[j] = m.paint(status[j], "\033[0;90m", true)
		}
	}
	ask := layout(fmt.Sprintf("Enter a number between 1 and %d: %s", len(m.entries), m.typed), cols, 0)
	hint := layout(menuHint, cols, 0)
	for j := range hint {
		hint[j] = m.paint(hint[j], "\033[2m", true)
	}
	fixed := len(status) + len(ask)
	if height > 0 && len(hint)+len(list)+fixed >= height {
		hint = nil
	}
	if height > 0 && len(list)+fixed >= height {
		list = window(list, first, last, height-1-fixed)
	}
	all := append(append(append(hint, list...), status...), ask...)
	if height > 0 && len(all) >= height {
		all = all[len(all)-max(height-1, 1):]
	}
	return all
}

// window is the part of list that fits in room rows, with the rows first to last in it;
// when there is room for them, a row above and below it says there is more.
func window(list []string, first, last, room int) []string {
	marks := room >= 3
	if marks {
		room -= 2
	}
	room = max(room, 1)
	top := max(0, min(first, last-room))
	end := min(len(list), top+room)
	if end-top < room {
		top = max(0, end-room)
	}
	if !marks {
		return list[top:end]
	}
	above, below := "", ""
	if top > 0 {
		above = "  ^ more"
	}
	if end < len(list) {
		below = "  v more"
	}
	return append(append([]string{above}, list[top:end]...), below)
}

// draw puts the menu where it was.
func (m *menu) draw(width, height int) {
	rows := m.rows(width, height)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.write(m.erase(width) + strings.Join(rows, "\r\n"))
	m.drawn = rows
}

// leave takes the menu off the screen and leaves line under the question.
func (m *menu) leave(width int, line string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.erase(width)
	if line != "" {
		s += line + "\r\n"
	}
	m.write(s)
	m.drawn = nil
}

// erase is what goes back to the first row drawn and clears from there down. Rows that
// a window narrowed since the draw are rows the terminal has folded: they are counted
// as such.
func (m *menu) erase(width int) string {
	if len(m.drawn) == 0 {
		return ""
	}
	up := -1
	for _, r := range m.drawn {
		up += max(1, (cells(r)+max(width, 1)-1)/max(width, 1))
	}
	if up == 0 {
		return "\r\033[J"
	}
	return fmt.Sprintf("\r\033[%dA\033[J", up)
}

// rowCells is how much of a row of a terminal this wide is drawn on.
func rowCells(width int) int { return max(width-1, 2) }

// The text measures are tui's, the full screen's too: one count of a row's cells.
func cells(s string) int                         { return tui.Cells(s) }
func runeCells(r rune) int                       { return tui.RuneCells(r) }
func sanitize(s string) string                   { return tui.Sanitize(s) }
func layout(s string, cols, indent int) []string { return tui.Layout(s, cols, indent) }
