package cmd

import (
	"strconv"
	"strings"
	"unicode"
)

// quoteUntrusted makes a string from an unverified source safe to print.
//
// Anyone with TPM access can replace the blob, so its strings may carry
// terminal escape sequences or control characters. A string made only of
// printable characters without spaces, quotes or backslashes is returned as
// is, which keeps ordinary paths and versions readable and copyable; anything
// else is Go-quoted, so control bytes show up as \x1b and never reach the
// terminal.
func quoteUntrusted(s string) string {
	if s != "" && strings.IndexFunc(s, needsQuoting) < 0 {
		return s
	}
	return strconv.Quote(s)
}

func needsQuoting(r rune) bool {
	return !unicode.IsPrint(r) || unicode.IsSpace(r) || r == '"' || r == '\'' || r == '\\' || r == unicode.ReplacementChar
}
