package tui

import (
	"fmt"
	"io"
	"strings"
)

// Screen draws frames: a frame is one string per row, and what a row showed before is
// not written again, so a redraw over a slow line costs the rows that changed.
type Screen struct {
	out    io.Writer
	cols   int
	prev   []string
	colour bool
	glyphs Glyphs
}

// NewScreen draws on out; colour false draws every row without its colours.
func NewScreen(out io.Writer, colour bool, g Glyphs) *Screen {
	return &Screen{out: out, colour: colour, glyphs: g}
}

// Invalidate forgets what is on the terminal: the next Draw writes every row (after a
// resize, Ctrl-L, or when something else wrote on it).
func (s *Screen) Invalidate() { s.prev = nil }

// Draw shows rows on a terminal cols wide, each fitted to it; it returns how many rows
// it wrote.
func (s *Screen) Draw(rows []string, cols int) int {
	if cols != s.cols {
		s.prev, s.cols = nil, cols
	}
	var b strings.Builder
	if s.prev == nil {
		b.WriteString("\033[H\033[2J")
	}
	written := 0
	for i, r := range rows {
		if !s.colour {
			r = StripSGR(r)
		}
		r = Fit(r, cols, s.glyphs.Ellipsis)
		if i < len(s.prev) && s.prev[i] == r {
			continue
		}
		fmt.Fprintf(&b, "\033[%d;1H%s\033[0m", i+1, r)
		written++
	}
	for i := len(rows); i < len(s.prev); i++ { // rows the last frame had, this one not
		fmt.Fprintf(&b, "\033[%d;1H\033[K", i+1)
	}
	next := make([]string, len(rows))
	for i, r := range rows {
		if !s.colour {
			r = StripSGR(r)
		}
		next[i] = Fit(r, cols, s.glyphs.Ellipsis)
	}
	s.prev = next
	io.WriteString(s.out, b.String())
	return written
}

// Columns puts panes side by side: each pane's rows fitted to its width, joined by sep,
// as many rows as the tallest has.
func Columns(sep string, widths []int, panes ...[]string) []string {
	n := 0
	for _, p := range panes {
		n = max(n, len(p))
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		var b strings.Builder
		for j, p := range panes {
			if j > 0 {
				b.WriteString(sep)
			}
			row := ""
			if i < len(p) {
				row = p[i]
			}
			b.WriteString(Fit(row, widths[j], "~"))
		}
		out[i] = b.String()
	}
	return out
}
