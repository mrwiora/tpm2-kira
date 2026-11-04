package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tpm2-trust/tpm2-kira/internal/piv"
	"github.com/tpm2-trust/tpm2-kira/internal/piv/pivtest"
	"golang.org/x/sys/unix"
)

// The helper of the signal tests: the PIN's prompt in a process that a signal ends.
func TestMain(m *testing.M) {
	if os.Getenv("PIN_TEST_HELPER") == "" {
		os.Exit(m.Run())
	}
	readNoEcho(os.Stdin)
	os.Exit(0)
}

// pipeWith is a pipe holding data, its writer closed; neither end close-on-exec, as a
// descriptor a script passes down is not.
func pipeWith(t *testing.T, data string) int {
	t.Helper()
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(p[1], []byte(data)); err != nil {
		t.Fatal(err)
	}
	unix.Close(p[1])
	return p[0]
}

// captureBuffers keeps every buffer a PIN is read into, to look at it afterwards.
func captureBuffers(t *testing.T) *[][]byte {
	t.Helper()
	var bufs [][]byte
	old := pinBuffer
	pinBuffer = func() []byte {
		b := make([]byte, 0, 512)
		bufs = append(bufs, b)
		return b
	}
	t.Cleanup(func() { pinBuffer = old })
	return &bufs
}

func wiped(b []byte) bool {
	for _, c := range b[:cap(b)] {
		if c != 0 {
			return false
		}
	}
	return true
}

func allWiped(bufs [][]byte) bool {
	for _, b := range bufs {
		if !wiped(b) {
			return false
		}
	}
	return true
}

// One line, into the buffer, and the descriptor gone: for this process, and for a child
// it starts, which would otherwise inherit it.
func TestDescriptorIsReadAndClosed(t *testing.T) {
	t.Cleanup(forgetDescriptorPIN)
	bufs := captureBuffers(t)
	fd := pipeWith(t, "123456\nrest of the pipe\n")
	if err := UsePINDescriptor(fd); err != nil {
		t.Fatal(err)
	}
	if string(descriptorPIN.pin) != "123456" || !descriptorPIN.given || descriptorPIN.source != fmt.Sprintf("descriptor %d", fd) {
		t.Errorf("read %q, %+v", descriptorPIN.pin, descriptorPIN.source)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); !errors.Is(err, unix.EBADF) {
		t.Errorf("the descriptor after the read: %v", err)
	}
	child := exec.Command("/bin/sh", "-c", fmt.Sprintf("test ! -e /proc/self/fd/%d", fd))
	if out, err := child.CombinedOutput(); err != nil {
		t.Errorf("a child has the descriptor: %v %s", err, out)
	}
	// In the buffer it was given, and that is what is wiped at the end.
	if len(*bufs) != 1 || &(*bufs)[0][:1][0] != &descriptorPIN.pin[0] {
		t.Errorf("the PIN is not in the locked buffer")
	}
	CloseTokenSessions()
	if !allWiped(*bufs) {
		t.Errorf("not wiped when the command ends: %q", (*bufs)[0][:8])
	}
	if descriptorPIN.given || descriptorPIN.pin != nil {
		t.Errorf("still held: %+v", descriptorPIN)
	}
}

// Every descriptor that gives no PIN is an error of its own, what was read wiped.
func TestBadDescriptors(t *testing.T) {
	t.Cleanup(forgetDescriptorPIN)
	// Closed: first, as the next descriptor opened takes its number.
	closed := pipeWith(t, "123456\n")
	unix.Close(closed)
	if err := UsePINDescriptor(closed); err == nil || !strings.Contains(err.Error(), "not open") || descriptorPIN.given {
		t.Errorf("a closed descriptor: %v", err)
	}
	var ends [2]int
	if err := unix.Pipe(ends[:]); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ends[0])
	dir, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	null, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(null)
	for _, c := range []struct {
		name, want string
		fd         int
	}{
		{"never opened", "not open", 987},
		{"negative", "3 or above", -1},
		{"stdin", "3 or above", 0},
		{"stdout", "3 or above", 1},
		{"stderr", "3 or above", 2},
		{"write end", "bad file descriptor", ends[1]},
		{"directory", "pipe, a socket or a file", dir},
		{"device", "pipe, a socket or a file", null},
		{"empty", "no PIN", pipeWith(t, "")},
		{"empty line", "no PIN", pipeWith(t, "\n123456\n")},
		{"too long", "more than 8 bytes", pipeWith(t, "123456789\n")},
		{"too long, no end", "more than 8 bytes", pipeWith(t, strings.Repeat("1", 5000))},
		{"too long by the \\r", "more than 8 bytes", pipeWith(t, "123456789\r\n")},
	} {
		bufs := captureBuffers(t)
		err := UsePINDescriptor(c.fd)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), fmt.Sprintf("--pin-fd %d", c.fd)) {
			t.Errorf("%s: %v", c.name, err)
		}
		if descriptorPIN.given {
			t.Errorf("%s: taken", c.name)
		}
		if !allWiped(*bufs) {
			t.Errorf("%s: left in the buffer: %q", c.name, (*bufs)[0][:9])
		}
	}
}

func TestLineEnds(t *testing.T) {
	t.Cleanup(forgetDescriptorPIN)
	for in, want := range map[string]string{"123456": "123456", "12345678\n": "12345678", "12345678\r\n": "12345678", "1234567\r": "1234567"} {
		if err := UsePINDescriptor(pipeWith(t, in)); err != nil || string(descriptorPIN.pin) != want {
			t.Errorf("%q: %q, %v", in, descriptorPIN.pin, err)
		}
	}
}

func TestDescriptorPINIsHandedOverOnce(t *testing.T) {
	t.Cleanup(forgetDescriptorPIN)
	if err := UsePINDescriptor(pipeWith(t, "123456\n")); err != nil {
		t.Fatal(err)
	}
	// The file and the terminal are not asked, the first time or the second.
	t.Setenv("TPM2_KIRA_CONTROL_CONF", filepath.Join(t.TempDir(), "control.conf"))
	os.WriteFile(PINPath(), []byte("999999\n"), 0o600)
	old := PromptPIN
	PromptPIN = func(*YubiKeySigner) ([]byte, error) { t.Error("asked"); return []byte("888888"), nil }
	defer func() { PromptPIN = old }()
	pin, source, err := readPIN(nil)
	if err != nil || string(pin) != "123456" || !strings.HasPrefix(source, "descriptor ") {
		t.Errorf("%q from %q: %v", pin, source, err)
	}
	if pin, _, err := readPIN(nil); err == nil || pin != nil {
		t.Errorf("a second time: %q %v", pin, err)
	}
}

func TestPINFileIsWipedAfterTheLook(t *testing.T) {
	t.Setenv("TPM2_KIRA_CONTROL_CONF", filepath.Join(t.TempDir(), "control.conf"))
	path := PINPath()
	os.WriteFile(path, []byte("123456\n"), 0o600)
	bufs := captureBuffers(t)
	if stored, loose := PINStored(path); !stored || loose {
		t.Errorf("stored %v, loose %v", stored, loose)
	}
	if len(*bufs) != 1 || !allWiped(*bufs) {
		t.Errorf("PINStored left the PIN: %q", (*bufs)[0][:6])
	}

	// Loose: refused, and what was read to find out is wiped.
	os.Chmod(path, 0o644)
	bufs = captureBuffers(t)
	if pin, ok, err := pinFromFile(); err == nil || ok || pin != nil {
		t.Errorf("loose: %q %v %v", pin, ok, err)
	}
	if !allWiped(*bufs) {
		t.Errorf("a loose file's PIN stays: %q", (*bufs)[0][:6])
	}
	os.Chmod(path, 0o600)

	// More than a PIN: an error, not the terminal, and it counts as stored.
	os.WriteFile(path, []byte("123456789\n"), 0o600)
	bufs = captureBuffers(t)
	if pin, ok, err := pinFromFile(); err == nil || !strings.Contains(err.Error(), "more than 8 bytes") || ok || pin != nil {
		t.Errorf("too long: %q %v %v", pin, ok, err)
	}
	if !allWiped(*bufs) {
		t.Errorf("too long: stays %q", (*bufs)[0][:9])
	}
	if stored, _ := PINStored(path); !stored {
		t.Error("a file that holds something reads as empty")
	}

	// Empty: there is none, and it asks on.
	os.WriteFile(path, []byte("\n"), 0o600)
	if pin, ok, err := pinFromFile(); err != nil || ok || pin != nil {
		t.Errorf("empty: %q %v %v", pin, ok, err)
	}
}

// The terminal's PIN: echo off, into the buffer, the terminal back, and a line too long
// leaves nothing for the next reader.
func TestPromptOnATerminal(t *testing.T) {
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skip("no pty: ", err)
	}
	defer ptm.Close()
	if err := unix.IoctlSetPointerInt(int(ptm.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Skip("no pty: ", err)
	}
	n, err := unix.IoctlGetInt(int(ptm.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Skip("no pty: ", err)
	}
	pts, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no pty: ", err)
	}
	defer pts.Close()
	go func() { // drains what the terminal writes, an echo included
		b := make([]byte, 256)
		for {
			if _, err := ptm.Read(b); err != nil {
				return
			}
		}
	}()
	before, _ := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	echoOff := func() {
		for i := 0; i < 500; i++ {
			if tio, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS); err == nil && tio.Lflag&unix.ECHO == 0 {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("the echo stayed on")
	}
	go func() { echoOff(); ptm.WriteString("123456\n") }()
	bufs := captureBuffers(t)
	pin, err := readNoEcho(pts)
	if err != nil || string(pin) != "123456" || &pin[0] != &(*bufs)[0][:1][0] {
		t.Fatalf("%q, %v", pin, err)
	}
	if after, _ := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS); after.Lflag != before.Lflag {
		t.Errorf("the terminal after the prompt: %x, was %x", after.Lflag, before.Lflag)
	}

	go func() { echoOff(); ptm.WriteString("123456789012\n") }()
	bufs = captureBuffers(t)
	if pin, err := readNoEcho(pts); err == nil || pin != nil {
		t.Fatalf("too long: %q, %v", pin, err)
	}
	if !allWiped(*bufs) {
		t.Errorf("too long: left %q", (*bufs)[0][:9])
	}
	if left, _ := unix.IoctlGetInt(int(pts.Fd()), unix.TIOCINQ); left != 0 {
		t.Errorf("%d bytes of a PIN wait for the next reader of the terminal", left)
	}
}

// openPINPty is a pty the test reads and types on.
func openPINPty(t *testing.T) (ptm, pts *os.File) {
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
	go func() { // drains what the terminal writes, an echo included
		b := make([]byte, 256)
		for {
			if _, err := ptm.Read(b); err != nil {
				return
			}
		}
	}()
	return ptm, pts
}

// startPINPrompt runs the helper on the terminal, its controlling terminal, and waits
// for it to take the echo away.
func startPINPrompt(t *testing.T, pts *os.File) *exec.Cmd {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), "PIN_TEST_HELPER=1", "GOTRACEBACK=none")
	cmd.Stdin = pts
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	deadline := time.Now().Add(10 * time.Second)
	for {
		tio, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if tio.Lflag&unix.ECHO == 0 {
			return cmd
		}
		if time.Now().After(deadline) {
			t.Fatal("the prompt never took the echo")
		}
		time.Sleep(time.Millisecond)
	}
}

// Every signal that ends the process, sent or typed, gives the terminal back as it was
// and ends the process. That the input goes too: internal/termguard's tests.
func TestSignalAtThePINPromptGivesTheTerminalBack(t *testing.T) {
	check := func(t *testing.T, sig unix.Signal, pts *os.File, before *unix.Termios, err error) {
		t.Helper()
		after, gerr := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
		if gerr != nil {
			t.Fatal(gerr)
		}
		if after.Lflag != before.Lflag || after.Cc != before.Cc {
			t.Errorf("%v left the terminal: lflag %x, was %x", sig, after.Lflag, before.Lflag)
		}
		if err == nil {
			t.Errorf("%v: the process went on to its end", sig)
		}
	}
	for _, sig := range []unix.Signal{unix.SIGTERM, unix.SIGHUP, unix.SIGINT, unix.SIGQUIT, unix.SIGABRT} {
		t.Run(sig.String(), func(t *testing.T) {
			ptm, pts := openPINPty(t)
			before, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			cmd := startPINPrompt(t, pts)
			ptm.WriteString("123")
			cmd.Process.Signal(sig)
			check(t, sig, pts, before, cmd.Wait())
		})
	}
	t.Run("Ctrl-C", func(t *testing.T) {
		ptm, pts := openPINPty(t)
		before, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		cmd := startPINPrompt(t, pts)
		ptm.WriteString("123\x03")
		check(t, unix.SIGINT, pts, before, cmd.Wait())
	})
}

// Ctrl-Z cannot stop the prompt, which a shell would take the terminal from and which
// would then go on with the echo on: the terminal has no suspend key during it, and has
// it back after.
func TestNoSuspendAtThePINPrompt(t *testing.T) {
	ptm, pts := openPINPty(t)
	before, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if before.Cc[unix.VSUSP] == 0 {
		t.Skip("this pty has no suspend key to begin with")
	}
	cmd := startPINPrompt(t, pts)
	held, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if held.Cc[unix.VSUSP] != 0 {
		t.Errorf("the suspend key at the prompt: %d", held.Cc[unix.VSUSP])
	}
	ptm.WriteString("\x1a123456\n")
	if err := cmd.Wait(); err != nil {
		t.Errorf("the prompt: %v", err)
	}
	after, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if after.Cc != before.Cc || after.Lflag != before.Lflag {
		t.Errorf("the terminal is not as it was: %x, %x", after.Lflag, before.Lflag)
	}
}

// A regular file on the descriptor is held to what the PIN file is, and is refused
// unread; a file of root's or this user's alone is fine.
func TestLooseFileOnTheDescriptor(t *testing.T) {
	t.Cleanup(forgetDescriptorPIN)
	open := func(mode os.FileMode) int {
		path := filepath.Join(t.TempDir(), "pin")
		if err := os.WriteFile(path, []byte("123456\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(path, unix.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		return fd
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if err := UsePINDescriptor(open(mode)); err != nil || string(descriptorPIN.pin) != "123456" {
			t.Errorf("mode %o: %v, %q", mode, err, descriptorPIN.pin)
		}
		forgetDescriptorPIN()
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o620, 0o602, 0o610, 0o601} {
		fd := open(mode)
		bufs := captureBuffers(t)
		err := UsePINDescriptor(fd)
		if err == nil || !strings.Contains(err.Error(), "can be read by other users") || descriptorPIN.given {
			t.Errorf("mode %o: %v", mode, err)
		}
		if len(*bufs) != 0 {
			t.Errorf("mode %o: read before it was refused", mode)
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); !errors.Is(err, unix.EBADF) {
			t.Errorf("mode %o: the descriptor stays: %v", mode, err)
		}
	}
	// Not this user's, not root's: the rule, as this test cannot make such a file.
	if !looseFile(0o600, uint32(os.Geteuid())+1) && os.Geteuid() != 0 {
		t.Error("a file of another user")
	}
	// Loose as a mode is, a pipe is nobody's to open.
	if err := UsePINDescriptor(pipeWith(t, "123456\n")); err != nil {
		t.Errorf("a pipe: %v", err)
	}
	forgetDescriptorPIN()
	socks, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(socks[1])
	unix.Write(socks[1], []byte("123456\n"))
	unix.Shutdown(socks[1], unix.SHUT_WR)
	if err := UsePINDescriptor(socks[0]); err != nil || string(descriptorPIN.pin) != "123456" {
		t.Errorf("a socket: %v", err)
	}
}

// The variable set: the reason there is no PIN says so, once it is what a hook shows;
// without it, nothing of it. The value is in neither.
func TestIgnoredVariableIsInTheReason(t *testing.T) {
	t.Cleanup(func() { pinEnvIgnored = false })
	pinEnvIgnored = false
	if strings.Contains(noTerminalPIN().Error(), ignoredPINEnv) {
		t.Errorf("not set, and said: %v", noTerminalPIN())
	}
	IgnorePINEnv(io.Discard)
	if pinEnvIgnored {
		t.Error("not set, and taken as set")
	}
	t.Setenv(ignoredPINEnv, "secret-1234")
	var said strings.Builder
	IgnorePINEnv(&said)
	IgnorePINEnv(&said)
	if strings.Count(said.String(), "WARNING") != 1 || strings.Contains(said.String(), "secret-1234") {
		t.Errorf("said: %s", said.String())
	}
	if _, set := os.LookupEnv(ignoredPINEnv); set {
		t.Error("it stays in the environment of what the command starts")
	}
	if got := noTerminalPIN().Error(); !strings.Contains(got, ignoredPINEnv+" is set and ignored") || strings.Contains(got, "secret-1234") {
		t.Errorf("the reason: %s", got)
	}
}

// A wrong PIN is wiped when the card refuses it, not when the command ends; a right one
// stays for a key that asks again, and goes with the session.
func TestSessionWipesThePIN(t *testing.T) {
	card := pivtest.New(1)
	key := card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	oldDial := DialTokens
	DialTokens = func(time.Duration) ([]*TokenConn, func(), error) {
		return []*TokenConn{{Reader: "emulated", Transport: card, Close: func(bool) error { return nil }}}, func() {}, nil
	}
	t.Cleanup(func() { CloseTokenSessions(); DialTokens = oldDial })
	t.Setenv("TPM2_KIRA_CONTROL_CONF", filepath.Join(t.TempDir(), "control.conf"))
	slot := TokenSlot{Slot: piv.SlotAuthentication, Algorithm: piv.AlgECCP256, PINPolicy: piv.PINPolicyOnce, TouchPolicy: piv.TouchPolicyNever, PoliciesKnown: true, PublicKey: key.Public()}
	stub, err := MarshalYubiKeyStub(1, slot)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "seal.key")
	if err := WriteSigningKeyFile(path, stub); err != nil {
		t.Fatal(err)
	}
	signer, err := LoadSigningPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(nil)

	bufs := captureBuffers(t)
	if err := UsePINDescriptor(pipeWith(t, "000000\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("a wrong PIN signed")
	}
	if !allWiped(*bufs) {
		t.Errorf("a refused PIN stays: %q", (*bufs)[0][:6])
	}
	CloseTokenSessions()

	bufs = captureBuffers(t)
	if err := UsePINDescriptor(pipeWith(t, "123456\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatal(err)
	}
	CloseTokenSessions()
	if !allWiped(*bufs) {
		t.Errorf("the session's PIN stays: %q", (*bufs)[0][:6])
	}
}
