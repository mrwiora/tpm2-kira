package termguard

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The helper: holds the terminal on standard input, reads nothing, until a signal.
func TestMain(m *testing.M) {
	switch os.Getenv("TERMGUARD_TEST_HELPER") {
	case "":
		os.Exit(m.Run())
	case "flush":
		hold(true)
	case "keep":
		hold(false)
	}
}

func hold(flush bool) {
	_, err := Hold{Change: func(t *unix.Termios) { t.Lflag &^= unix.ECHO }, Flush: flush}.Take(0)
	if err != nil {
		os.Exit(3)
	}
	select {}
}

func openPty(t *testing.T) (ptm, pts *os.File) {
	t.Helper()
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skip("no pty: ", err)
	}
	t.Cleanup(func() { ptm.Close() })
	if err := unix.IoctlSetPointerInt(int(ptm.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Skip("no pty: ", err)
	}
	n, err := unix.IoctlGetInt(int(ptm.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Skip("no pty: ", err)
	}
	pts, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no pty: ", err)
	}
	t.Cleanup(func() { pts.Close() })
	go func() {
		b := make([]byte, 256)
		for {
			if _, err := ptm.Read(b); err != nil {
				return
			}
		}
	}()
	return ptm, pts
}

func until(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("never: ", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// A signal ends the process with the terminal given back, and its input as Flush says:
// a whole line waits, nobody has read it, and the signal comes.
func TestSignalGivesItBackAsAsked(t *testing.T) {
	for _, c := range []struct {
		mode string
		left int
	}{{"flush", 0}, {"keep", 7}} {
		t.Run(c.mode, func(t *testing.T) {
			ptm, pts := openPty(t)
			fd := int(pts.Fd())
			before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(self)
			cmd.Env = append(os.Environ(), "TERMGUARD_TEST_HELPER="+c.mode)
			cmd.Stdin = pts
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			until(t, "the echo off", func() bool {
				tio, err := unix.IoctlGetTermios(fd, unix.TCGETS)
				return err == nil && tio.Lflag&unix.ECHO == 0
			})
			ptm.WriteString("123456\n")
			until(t, "the line in the input", func() bool {
				n, err := unix.IoctlGetInt(fd, unix.TIOCINQ)
				return err == nil && n == 7
			})
			cmd.Process.Signal(unix.SIGTERM)
			cmd.Wait()
			after, err := unix.IoctlGetTermios(fd, unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			if after.Lflag != before.Lflag {
				t.Errorf("the terminal: %x, was %x", after.Lflag, before.Lflag)
			}
			if n, _ := unix.IoctlGetInt(fd, unix.TIOCINQ); n != c.left {
				t.Errorf("%d bytes of input left, want %d", n, c.left)
			}
		})
	}
}

// The caller's own return gives it back the same way.
func TestRestoreAsAsked(t *testing.T) {
	for _, c := range []struct {
		flush bool
		left  int
	}{{true, 0}, {false, 7}} {
		ptm, pts := openPty(t)
		fd := int(pts.Fd())
		before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		restore, err := Hold{Change: func(t *unix.Termios) { t.Lflag &^= unix.ECHO }, Flush: c.flush}.Take(fd)
		if err != nil {
			t.Fatal(err)
		}
		if held, _ := unix.IoctlGetTermios(fd, unix.TCGETS); held.Lflag&unix.ECHO != 0 {
			t.Error("the change did not happen")
		}
		ptm.WriteString("123456\n")
		until(t, "the line in the input", func() bool {
			n, err := unix.IoctlGetInt(fd, unix.TIOCINQ)
			return err == nil && n == 7
		})
		restore()
		if after, _ := unix.IoctlGetTermios(fd, unix.TCGETS); after.Lflag != before.Lflag {
			t.Errorf("the terminal: %x, was %x", after.Lflag, before.Lflag)
		}
		if n, _ := unix.IoctlGetInt(fd, unix.TIOCINQ); n != c.left {
			t.Errorf("flush %v: %d bytes left, want %d", c.flush, n, c.left)
		}
	}
}
