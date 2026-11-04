//go:build integration
// +build integration

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A stop of run has this long, whatever it was doing: systemd-shutdown waits
// for it, and a hard reboot with it.
const runStopBound = 2 * time.Second

// waitEnd is how long the process takes to end from now, failing past bound.
func waitEnd(t *testing.T, run *exec.Cmd, bound time.Duration, out fmt.Stringer) time.Duration {
	t.Helper()
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- run.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) {
			t.Errorf("waiting for run: %v", err)
		}
	case <-time.After(bound):
		// What it sits in: the Go runtime's dump goes to run's stderr.
		run.Process.Signal(syscall.SIGQUIT)
		<-done
		t.Fatalf("run did not end within %s of the signal. Its output:\n%s", bound, out)
	}
	took := time.Since(start)
	t.Logf("run ended %s after the signal", took)
	return took
}

// A prompt open on a real terminal, as at the console: the person may never
// type. SIGTERM ends run at once, and the terminal is left as it was.
func TestRunEndsAtSIGTERMWithThePromptOpen(t *testing.T) {
	dir := t.TempDir()
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	defer ptm.Close()
	if err := unix.IoctlSetPointerInt(int(ptm.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(ptm.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	console := fmt.Sprintf("/dev/pts/%d", n)
	pts, err := os.OpenFile(console, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pts.Close()
	before, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	var screen syncBuffer
	go io.Copy(&screen, ptm)

	// A volume of the recovery recipe, by its header alone: the prompt comes
	// before anything opens it.
	const hdrSize = 16384
	hdr := make([]byte, hdrSize)
	copy(hdr, "LUKS\xba\xbe")
	binary.BigEndian.PutUint16(hdr[6:8], 2)
	binary.BigEndian.PutUint64(hdr[8:16], hdrSize)
	copy(hdr[4096:], `{"keyslots":{},"tokens":{"0":{"type":"tpm2-kira-1100","keyslots":["0"],"recipe":4352,"created":"x"}},"segments":{},"digests":{},"config":{}}`)
	disk := filepath.Join(dir, "disk")
	if err := os.WriteFile(disk, hdr, 0o600); err != nil {
		t.Fatal(err)
	}
	crypttab := filepath.Join(dir, "crypttab")
	os.WriteFile(crypttab, []byte("cryptroot "+disk+" none luks\n"), 0o600)
	plan := filepath.Join(dir, "plan")
	os.MkdirAll(filepath.Join(plan, "unlock"), 0o755)
	sock := filepath.Join(dir, "unlock.sock")

	run := exec.Command("./tpm2-kira-boot", "run", "--plan", plan, "--tpm", filepath.Join(dir, "no-tpm"), "--hold", "0", "--unlock", sock)
	var out syncBuffer
	run.Stdout, run.Stderr = &out, &out
	run.Env = append(os.Environ(), "TPM2_KIRA_CONSOLE="+console, "TPM2_KIRA_CRYPTTAB="+crypttab)
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	defer run.Process.Kill()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no key socket:\n%s", out.String())
		}
	}
	c, err := net.DialUnix("unix", &net.UnixAddr{Name: "@" + strconv.Itoa(os.Getpid()) + "/cryptsetup/cryptroot", Net: "unix"}, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(screen.String(), "for disk cryptroot:"); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no prompt on the terminal: %q\n%s", screen.String(), out.String())
		}
	}
	during, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if during.Lflag&unix.ECHO != 0 {
		t.Fatalf("the prompt did not take the terminal raw")
	}

	run.Process.Signal(syscall.SIGTERM)
	waitEnd(t, run, runStopBound, &out)

	after, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if after.Lflag != before.Lflag {
		t.Errorf("the terminal is left with lflag %#x, it had %#x", after.Lflag, before.Lflag)
	}
	if _, err := os.Stat(sock); err == nil {
		t.Errorf("the key socket stayed")
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if b, err := io.ReadAll(c); err != nil || len(b) != 0 {
		t.Errorf("the request read %d bytes, %v: no key and no hang", len(b), err)
	}
}

// While run still waits for the TPM, before any part: the same.
func TestRunEndsAtSIGTERMWaitingForTheTPM(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan")
	os.MkdirAll(filepath.Join(plan, "tpm"), 0o755)
	run := exec.Command("./tpm2-kira-boot", "run", "--plan", plan, "--tpm", filepath.Join(dir, "no-tpm"), "--unlock", filepath.Join(dir, "unlock.sock"))
	var out syncBuffer
	run.Stdout, run.Stderr = &out, &out
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	defer run.Process.Kill()
	// Past the Go runtime's start, and no longer: the wait is 5 s.
	time.Sleep(200 * time.Millisecond)
	run.Process.Signal(syscall.SIGTERM)
	waitEnd(t, run, runStopBound, &out)
	if strings.Contains(out.String(), "did not appear") {
		t.Errorf("run sat out the TPM's wait:\n%s", out.String())
	}
}

// The prompt open in an SSH session: the session is told the machine boots,
// run ends, and the unprivileged half with it.
func TestRunEndsAtSIGTERMWithThePromptInASession(t *testing.T) {
	b := startRemoteBoot(t)
	c, r, _ := b.login(t)
	readUntil(t, r, "asked here")
	b.keyRequest(t)
	c.Write([]byte("\r"))
	readUntil(t, r, "Password for disk "+b.volume)

	b.run.Process.Signal(syscall.SIGTERM)
	waitEnd(t, b.run, runStopBound, b.out)
	readUntil(t, r, "The machine boots; the SSH server stops.")
	if d, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(b.port)); err == nil {
		d.Close()
		t.Error("the port still answers after run ended: ssh-child stayed")
	}
}

// During the hold, a session on the code screen: the same.
func TestRunEndsAtSIGTERMDuringTheHold(t *testing.T) {
	b := startRemoteBoot(t)
	_, r, _ := b.login(t)
	readUntil(t, r, "asked here")

	b.run.Process.Signal(syscall.SIGTERM)
	waitEnd(t, b.run, runStopBound, b.out)
	readUntil(t, r, "The machine boots; the SSH server stops.")
	if d, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(b.port)); err == nil {
		d.Close()
		t.Error("the port still answers after run ended: ssh-child stayed")
	}
}
