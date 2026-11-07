package tui

import (
	"bytes"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// Hush keeps the process's own output off a frame: while it holds, what anything
// writes to stdout or stderr (a warning deep in a package, a library's line) goes into
// a buffer, and the frame is drawn on Screen, the terminal stdout was. Stop gives
// stdout and stderr back and returns what came, to be shown below the frame.
type Hush struct {
	Screen   *os.File
	out, err int // the descriptors stdout and stderr were
	r        *os.File
	mu       sync.Mutex
	buf      bytes.Buffer
	done     chan struct{}
	stopOnce sync.Once
}

// StartHush takes stdout and stderr over.
func StartHush() (*Hush, error) {
	out, err := unix.Dup(1)
	if err != nil {
		return nil, err
	}
	errFD, err := unix.Dup(2)
	if err != nil {
		unix.Close(out)
		return nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		unix.Close(out)
		unix.Close(errFD)
		return nil, err
	}
	h := &Hush{Screen: os.NewFile(uintptr(out), "/dev/tty"), out: out, err: errFD, r: r, done: make(chan struct{})}
	unix.CloseOnExec(out)
	unix.CloseOnExec(errFD)
	if err := unix.Dup2(int(w.Fd()), 1); err != nil {
		w.Close()
		r.Close()
		unix.Close(out)
		unix.Close(errFD)
		return nil, err
	}
	unix.Dup2(int(w.Fd()), 2)
	w.Close() // fd 1 and 2 hold the pipe's writing end now
	go func() {
		defer close(h.done)
		b := make([]byte, 4096)
		for {
			n, err := r.Read(b)
			if n > 0 {
				h.mu.Lock()
				h.buf.Write(b[:n])
				h.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return h, nil
}

// Stop gives stdout and stderr back and returns what was written meanwhile. Screen
// stays open for what is still drawn on it; Close closes it.
func (h *Hush) Stop() []byte {
	h.stopOnce.Do(func() {
		unix.Dup2(h.out, 1)
		unix.Dup2(h.err, 2)
		unix.Close(h.err)
		<-h.done // the pipe's last writer is gone: the reader has everything
		h.r.Close()
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	return bytes.Clone(h.buf.Bytes())
}

// Close closes Screen, after Stop.
func (h *Hush) Close() { h.Screen.Close() }
