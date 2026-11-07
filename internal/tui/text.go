// Package tui is a terminal's screen for a program that draws one: text measured in
// the cells it takes, the terminal's modes and size, its keys, and a frame that
// rewrites only the rows that changed. It knows nothing of what is drawn. The
// standard library and x/sys alone.
package tui

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// sgr is a Select Graphic Rendition sequence (a colour, bold), anywhere; sgrAt one
// at the start of a string.
var (
	sgr   = regexp.MustCompile("\x1b\\[[0-9;]*m")
	sgrAt = regexp.MustCompile("^\x1b\\[[0-9;]*m")
)

// StripSGR is s without its colours.
func StripSGR(s string) string { return sgr.ReplaceAllString(s, "") }

// Cells is the columns s can take at most: colours none, a character from the first
// that may be wide on two.
func Cells(s string) int {
	n := 0
	for _, r := range StripSGR(s) {
		n += RuneCells(r)
	}
	return n
}

// RuneCells is the columns a character can take at most.
func RuneCells(r rune) int {
	if r < 0x1100 {
		return 1
	}
	return 2
}

// Sanitize keeps a row's count true: a tab is a space, any other control character and
// what is no UTF-8 a question mark; SGR sequences and newlines stay.
func Sanitize(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		if loc := sgrAt.FindString(s); loc != "" {
			b.WriteString(loc)
			s = s[len(loc):]
			continue
		}
		r, n := utf8.DecodeRuneInString(s)
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r == '\n':
			b.WriteByte('\n')
		case r < 0x20, r >= 0x7f && r < 0xa0, r == utf8.RuneError:
			b.WriteByte('?')
		default:
			b.WriteString(s[:n])
		}
		s = s[n:]
	}
	return b.String()
}

// Layout is s broken into rows of at most cols columns: at spaces, and inside a word
// longer than a row. A broken line goes on at its own indentation, or at indent when
// that is more, unless that leaves too little of the row.
func Layout(s string, cols, indent int) []string {
	var rows []string
	for _, line := range strings.Split(Sanitize(s), "\n") {
		rows = append(rows, layoutLine(line, cols, indent)...)
	}
	return rows
}

func layoutLine(l string, cols, indent int) []string {
	lead := len(l) - len(strings.TrimLeft(l, " "))
	if lead > indent {
		indent = lead
	}
	if indent*2 >= cols {
		indent, lead = 0, 0
	}
	var rows []string
	var b strings.Builder
	used := lead
	b.WriteString(strings.Repeat(" ", lead))
	next := func() {
		rows = append(rows, b.String())
		b.Reset()
		b.WriteString(strings.Repeat(" ", indent))
		used = indent
	}
	for i, word := range strings.Split(strings.TrimLeft(l, " "), " ") {
		w := Cells(word)
		if i > 0 {
			if used+1+w > cols && used > indent || used >= cols {
				next()
			} else {
				b.WriteByte(' ')
				used++
			}
		}
		for len(word) > 0 {
			if loc := sgrAt.FindString(word); loc != "" {
				b.WriteString(loc)
				word = word[len(loc):]
				continue
			}
			r, n := utf8.DecodeRuneInString(word)
			if used+RuneCells(r) > cols && used > 0 {
				next()
				if used+RuneCells(r) > cols { // no room beside the indentation
					b.Reset()
					used = 0
				}
			}
			b.WriteString(word[:n])
			used += RuneCells(r)
			word = word[n:]
		}
	}
	return append(rows, b.String())
}

// Fit is s cut to cols columns and padded with spaces to exactly them: a cut row ends
// in an ellipsis, and its colours are reset at its end, so nothing runs into the next
// cell drawn.
func Fit(s string, cols int, ellipsis string) string {
	if cols <= 0 {
		return ""
	}
	s = strings.ReplaceAll(Sanitize(s), "\n", " ")
	if w := Cells(s); w <= cols {
		return s + reset(s) + strings.Repeat(" ", cols-w)
	}
	room := cols - Cells(ellipsis)
	if room < 0 {
		room, ellipsis = cols, ""
	}
	var b strings.Builder
	used := 0
	for len(s) > 0 {
		if loc := sgrAt.FindString(s); loc != "" {
			b.WriteString(loc)
			s = s[len(loc):]
			continue
		}
		r, n := utf8.DecodeRuneInString(s)
		if used+RuneCells(r) > room {
			break
		}
		b.WriteString(s[:n])
		used += RuneCells(r)
		s = s[n:]
	}
	out := b.String() + "\033[0m" + ellipsis
	return out + strings.Repeat(" ", cols-used-Cells(ellipsis))
}

// reset is the sequence that ends s's colours, "" when it has none.
func reset(s string) string {
	if sgr.MatchString(s) {
		return "\033[0m"
	}
	return ""
}
