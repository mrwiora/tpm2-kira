package kira

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Terminal input shared by every prompt in the process.
//
// This is deliberately free of any notion of what is being asked for: the PIN
// resolver, the setup key-location menu and the seal PCR suggestion all read
// through it.

// stdinReader is shared by every prompt.
//
// A bufio.Reader may read ahead, so a second one wrapping os.Stdin would start
// after whatever the first had already buffered — losing input typed between two
// prompts. Setup asks a question and then the PIN prompt asks another, so they
// have to read through the same buffer.
var (
	stdinOnce   sync.Once
	stdinBuffer *bufio.Reader
)

// ReadLine reads one line from standard input, without the line ending.
func ReadLine() (string, error) {
	stdinOnce.Do(func() {
		stdinBuffer = bufio.NewReader(os.Stdin)
	})

	line, err := stdinBuffer.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// ReadSecret prompts on stderr and reads one line with terminal echo disabled.
func ReadSecret(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())

	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", fmt.Errorf("cannot read terminal settings to disable echo: %w", err)
	}

	noEcho := *termios
	noEcho.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &noEcho); err != nil {
		return "", fmt.Errorf("cannot disable terminal echo: %w", err)
	}
	defer func() {
		// Restoring matters more than the read succeeding: leaving the terminal
		// without echo makes the shell unusable afterwards.
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, termios)
		fmt.Fprintln(os.Stderr)
	}()

	fmt.Fprint(os.Stderr, prompt)

	return ReadLine()
}

// IsInteractive reports whether standard input is a terminal, so a prompt has
// somebody to answer it. A package hook has not.
func IsInteractive() bool { return isTerminal(int(os.Stdin.Fd())) }

func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}
