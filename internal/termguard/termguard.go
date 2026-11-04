// Package termguard changes a terminal for a while and gives it back on every way out
// the process has code for: the caller's own return, and a signal that would end it.
// What a process cannot catch, SIGKILL, leaves the terminal as it is.
package termguard

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Hold says how a terminal is changed. Change gets the terminal's settings and alters
// them. OnSignal, when there is one, runs when a signal is about to end the process,
// before the terminal is given back: for what is on the screen. Flush drops the input
// nobody read when the terminal is given back: what was typed for a secret must not
// answer whoever reads next, a shell.
type Hold struct {
	Change   func(*unix.Termios)
	OnSignal func()
	Flush    bool
}

// Take changes the terminal on fd and gives what gives it back, to be called once. A
// signal that would end the process gives it back first, and then ends it as it would
// have: the signals are taken before the terminal is, and the lock keeps a signal's end
// from running beside taking it.
func (h Hold) Take(fd int) (func(), error) {
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	t := *old
	h.Change(&t)
	back := uint(unix.TCSETS)
	if h.Flush {
		back = unix.TCSETSF
	}

	var mu sync.Mutex
	sigs := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sigs, unix.SIGTERM, unix.SIGHUP, unix.SIGINT, unix.SIGQUIT, unix.SIGABRT)
	go func() {
		select {
		case s := <-sigs:
			mu.Lock() // never given up: the process ends
			if h.OnSignal != nil {
				h.OnSignal()
			}
			unix.IoctlSetTermios(fd, back, old)
			signal.Reset(s)
			unix.Kill(unix.Getpid(), s.(syscall.Signal))
		case <-done:
		}
	}()
	restore := func() {
		signal.Stop(sigs)
		close(done)
		mu.Lock()
		defer mu.Unlock()
		unix.IoctlSetTermios(fd, back, old)
	}
	mu.Lock()
	err = unix.IoctlSetTermios(fd, unix.TCSETS, &t)
	mu.Unlock()
	if err != nil {
		restore()
		return nil, err
	}
	return restore, nil
}
