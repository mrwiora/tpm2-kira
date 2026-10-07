package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestParseUnlockPeer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		want   unlockRequest
		errHas string
	}{
		{"@d7067f78d9827418/cryptsetup/cryptroot", unlockRequest{"cryptroot", "cryptsetup"}, ""},
		{"\x00abc/cryptsetup/home", unlockRequest{"home", "cryptsetup"}, ""},
		{"@abc/cryptsetup-tpm2/cryptroot", unlockRequest{"cryptroot", "cryptsetup-tpm2"}, ""},
		{"@abc/cryptsetup-fido2-salt/x", unlockRequest{"x", "cryptsetup-fido2-salt"}, ""},
		{"@abc/cryptsetup-pkcs11/x", unlockRequest{"x", "cryptsetup-pkcs11"}, ""},
		{"@abc/cryptsetup/", unlockRequest{}, "malformed"},
		{"@abc/cryptsetup/a/b", unlockRequest{}, "malformed"},
		{"@abc/cryptsetup-magic/x", unlockRequest{}, "unknown"},
		{"", unlockRequest{}, "not a systemd-cryptsetup"},
		{"/run/other.sock", unlockRequest{}, "not a systemd-cryptsetup"},
	} {
		got, err := parseUnlockPeer(tc.name)
		if tc.errHas != "" {
			if err == nil || !strings.Contains(err.Error(), tc.errHas) {
				t.Errorf("%q: error %v, want one containing %q", tc.name, err, tc.errHas)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q: %+v, %v; want %+v", tc.name, got, err, tc.want)
		}
	}
	if (unlockRequest{"v", "cryptsetup"}).Direct() == false || (unlockRequest{"v", "cryptsetup-tpm2"}).Direct() {
		t.Error("Direct is wrong")
	}
}

// askLike connects the way systemd-cryptsetup does: from an abstract socket
// named random/<kind>/<volume>.
func askLike(t *testing.T, path, kind, volume string) net.Conn {
	t.Helper()
	laddr := &net.UnixAddr{Name: "@" + strings.ReplaceAll(t.Name(), "/", "_") + "-" + volume + "/" + kind + "/" + volume, Net: "unix"}
	c, err := net.DialUnix("unix", laddr, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUnlockServerAnswersAfterRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unlock.sock")
	l, err := listenUnlock(path)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var asked []string
	var logs []string
	var sawPrompting atomic.Bool
	var s *unlockServer
	s = serveUnlock(l, func(v string) ([]byte, error) {
		sawPrompting.Store(s.Prompting())
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, v)
		if v == "nokey" {
			return nil, errors.New("nothing for it")
		}
		return []byte("secret-for-" + v), nil
	}, func(m string) { mu.Lock(); logs = append(logs, m); mu.Unlock() })
	defer s.Close()

	// Before the release the request waits, whatever it is.
	c := askLike(t, path, "cryptsetup", "cryptroot")
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("answered before the release: %v", err)
	}
	mu.Lock()
	if len(asked) != 0 {
		t.Fatalf("the key was asked for before the release: %v", asked)
	}
	mu.Unlock()

	if s.Prompting() {
		t.Fatal("prompting before any request was answered")
	}
	s.release()
	s.release() // twice is fine
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "secret-for-cryptroot" {
		t.Fatalf("key: %q, %v", got, err)
	}
	if s.Prompting() || !sawPrompting.Load() {
		t.Fatal("the display was not told that a prompt was open")
	}

	// A second volume, served after the first.
	c2 := askLike(t, path, "cryptsetup", "home")
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, _ := io.ReadAll(c2); string(got) != "secret-for-home" {
		t.Fatalf("second key: %q", got)
	}

	// No key: the connection is closed without data.
	c3 := askLike(t, path, "cryptsetup", "nokey")
	defer c3.Close()
	c3.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, err := io.ReadAll(c3); len(got) != 0 || err != nil {
		t.Fatalf("no key: %q, %v", got, err)
	}

	// A token's saved key is not this provider's: closed without data, and
	// the key function is not even asked.
	c4 := askLike(t, path, "cryptsetup-tpm2", "cryptroot")
	defer c4.Close()
	c4.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, _ := io.ReadAll(c4); len(got) != 0 {
		t.Fatalf("token request answered: %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(asked, ",") != "cryptroot,home,nokey" {
		t.Errorf("asked for %v", asked)
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "no key for nokey") || !strings.Contains(joined, "cryptsetup-tpm2 key") {
		t.Errorf("logs: %q", joined)
	}
}

func TestUnlockServerRefusesStrangers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unlock.sock")
	l, err := listenUnlock(path)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var logs []string
	s := serveUnlock(l, func(v string) ([]byte, error) { t.Error("asked"); return nil, nil },
		func(m string) { mu.Lock(); logs = append(logs, m); mu.Unlock() })
	defer s.Close()
	s.release()
	// A plain client without systemd-cryptsetup's abstract name.
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, _ := io.ReadAll(c); len(got) != 0 {
		t.Fatalf("answered a stranger: %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(logs) != 2 || !strings.Contains(logs[0], "hold has ended") || !strings.Contains(logs[1], "refusing") {
		t.Errorf("logs: %v", logs)
	}
}

// The peer check passes for our own connections (the tests above would not
// be answered otherwise) and names the uid when it refuses.
func TestPeerIsUs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := net.Dial("unix", path)
		if err == nil {
			time.Sleep(100 * time.Millisecond)
			c.Close()
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := peerIsUs(c); err != nil {
		t.Fatalf("our own connection refused: %v", err)
	}
	// Anything but a unix socket has no peer credentials.
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	go func() {
		c, err := net.Dial("tcp", tl.Addr().String())
		if err == nil {
			time.Sleep(100 * time.Millisecond)
			c.Close()
		}
	}()
	tc, err := tl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	if err := peerIsUs(tc); err == nil {
		t.Fatal("a tcp connection passed the peer check")
	}
}

func TestListenUnlockWithoutASocketIsNothing(t *testing.T) {
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	if l, err := listenUnlock(""); l != nil || err != nil {
		t.Fatalf("%v %v", l, err)
	}
	// LISTEN_FDS for another process is ignored.
	t.Setenv("LISTEN_PID", "1")
	t.Setenv("LISTEN_FDS", "1")
	if l, err := listenUnlock(""); l != nil || err != nil {
		t.Fatalf("%v %v", l, err)
	}
}

func TestListenerFromFD(t *testing.T) {
	// The socket unit passes a listening socket on fd 3; the same adoption,
	// on whatever fd the test's socket got (fd 3 belongs to the runtime here).
	path := filepath.Join(t.TempDir(), "s.sock")
	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	f, err := ul.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	l := listenerFromFD(int(f.Fd()))
	if l == nil {
		t.Fatal("not adopted")
	}
	defer l.Close()
	// It is the same socket: a connection to path is accepted here.
	go func() {
		c, err := net.Dial("unix", path)
		if err == nil {
			c.Write([]byte("x"))
			c.Close()
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b, _ := io.ReadAll(c)
	if string(b) != "x" {
		t.Fatalf("got %q", b)
	}
}

func TestReadPassphraseFromAPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	go func() {
		w.Write([]byte("hunter2\r\n"))
		w.Close()
	}()
	pw, err := readPassphrase(r, int(r.Fd()))
	if err != nil || string(pw) != "hunter2" {
		t.Fatalf("%q %v", pw, err)
	}
	// The last line without a newline counts too; nothing at all is an error.
	r2, w2, _ := os.Pipe()
	defer r2.Close()
	go func() { w2.Write([]byte("tail")); w2.Close() }()
	if pw, err := readPassphrase(r2, int(r2.Fd())); err != nil || string(pw) != "tail" {
		t.Fatalf("%q %v", pw, err)
	}
	r3, w3, _ := os.Pipe()
	defer r3.Close()
	w3.Close()
	if _, err := readPassphrase(r3, int(r3.Fd())); err == nil {
		t.Fatal("an empty pipe gave a passphrase")
	}
}

func TestWipe(t *testing.T) {
	b := []byte("secret")
	wipe(b)
	if !bytes.Equal(b, make([]byte, 6)) {
		t.Fatal("not wiped")
	}
	// The whole backing array, not only the part in view.
	full := []byte("secret-and-more")
	wipe(full[:3])
	if !bytes.Equal(full, make([]byte, len(full))) {
		t.Fatalf("only the view was wiped: %q", full)
	}
}

// The prompt on a terminal keeps the passphrase in one buffer: what is
// typed beyond cryptsetup's limit is refused with a bell, and Backspace
// zeroes the byte it takes away.
func TestReadPassphraseOnATerminal(t *testing.T) {
	ptm, pts, err := openPty()
	if err != nil {
		t.Skip("no pty: ", err)
	}
	defer ptm.Close()
	defer pts.Close()
	go func() {
		ptm.Write([]byte("abx\x7fc"))
		ptm.Write(bytes.Repeat([]byte("z"), maxPassphrase))
		ptm.Write([]byte("\n"))
	}()
	pw, err := readPassphrase(pts, int(pts.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	want := "abc" + strings.Repeat("z", maxPassphrase-3)
	if string(pw) != want {
		t.Fatalf("got %d bytes %q...", len(pw), pw[:8])
	}
	if cap(pw) != maxPassphrase {
		t.Fatalf("capacity %d: the buffer grew", cap(pw))
	}
	var echo []byte
	buf := make([]byte, 4096)
	ptm.SetReadDeadline(time.Now().Add(time.Second))
	for !bytes.Contains(echo, []byte("\a")) {
		n, err := ptm.Read(buf)
		echo = append(echo, buf[:n]...)
		if err != nil {
			t.Fatalf("no bell for the byte over the limit (%v): %q", err, echo)
		}
	}
}

func openPty() (ptm, pts *os.File, err error) {
	ptm, err = os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := unix.IoctlSetPointerInt(int(ptm.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		ptm.Close()
		return nil, nil, err
	}
	n, err := unix.IoctlGetInt(int(ptm.Fd()), unix.TIOCGPTN)
	if err != nil {
		ptm.Close()
		return nil, nil, err
	}
	pts, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		ptm.Close()
		return nil, nil, err
	}
	return ptm, pts, nil
}

// The prompt on a socket console (what the integration test with
// systemd-cryptsetup uses): the question goes out, the answer comes back.
func TestConsolePassphraseOnASocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "console.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	t.Setenv("TPM2_KIRA_CONSOLE", path)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 256)
		n, _ := c.Read(buf)
		if !strings.Contains(string(buf[:n]), "passphrase for disk vol") {
			t.Errorf("prompt: %q", buf[:n])
		}
		c.Write([]byte("\n")) // an empty line asks again
		c.Read(buf)           // the newline echo and the second prompt
		c.Write([]byte("open sesame\n"))
		io.Copy(io.Discard, c)
	}()
	pw, err := consolePassphrase("vol")
	if err != nil || string(pw) != "open sesame" {
		t.Fatalf("%q %v", pw, err)
	}
}

// With a salt from the coordinator the provider asks for the password and
// answers with the combined key; without one, with the passphrase as typed.
func TestDiskKeyCombinesWithTheFactor(t *testing.T) {
	if testing.Short() {
		t.Skip("1 GiB of Argon2id")
	}
	path := filepath.Join(t.TempDir(), "console.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	t.Setenv("TPM2_KIRA_CONSOLE", path)
	prompts := make(chan string, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				prompts <- string(buf[:n])
				c.Write([]byte("hunter2\n"))
				io.Copy(io.Discard, c)
			}()
		}
	}()
	salt := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	key, err := diskKey(func() []byte { return append([]byte(nil), salt...) }, UnlockPassphrase)("cryptroot")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := Combine([]byte("hunter2"), salt)
	if !bytes.Equal(key, want) {
		t.Fatal("the key is not the combination of password and salt")
	}
	if p := <-prompts; !strings.Contains(p, "released the disk factor") || !strings.Contains(p, "enter password for disk cryptroot") {
		t.Errorf("prompt: %q", p)
	}
	plain, err := diskKey(func() []byte { return nil }, UnlockPassphrase)("cryptroot")
	if err != nil || string(plain) != "hunter2" {
		t.Fatalf("without a factor: %q %v", plain, err)
	}
	if p := <-prompts; !strings.Contains(p, "enter passphrase for disk cryptroot") || strings.Contains(p, "factor") {
		t.Errorf("prompt without a factor: %q", p)
	}
}

// The Debian keyscript's half: unlock-key asks the socket the way
// systemd-cryptsetup does and gets the key; without a socket it gives up
// after the wait (and would become askpass).
func TestAskUnlockSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unlock.sock")
	l, err := listenUnlock(path)
	if err != nil {
		t.Fatal(err)
	}
	var asked string
	s := serveUnlock(l, func(v string) ([]byte, error) { asked = v; return []byte("key\n"), nil }, func(string) {})
	defer s.Close()
	s.release()
	key, err := askUnlockSocket(path, "vda3_crypt", time.Second)
	if err != nil || string(key) != "key\n" || asked != "vda3_crypt" {
		t.Fatalf("%q %v (asked %q)", key, err, asked)
	}
	start := time.Now()
	if _, err := askUnlockSocket(filepath.Join(t.TempDir(), "none.sock"), "v", 300*time.Millisecond); err == nil || time.Since(start) < 250*time.Millisecond {
		t.Fatalf("without a socket: %v after %v", err, time.Since(start))
	}
}

// In mode hashpwd2 the provider asks for the password and the salt and
// answers with their combination; a released factor takes the salt's
// place and only the password is asked for.
func TestDiskKeyHashpwd2Mode(t *testing.T) {
	if testing.Short() {
		t.Skip("1 GiB of Argon2id")
	}
	path := filepath.Join(t.TempDir(), "console.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	t.Setenv("TPM2_KIRA_CONSOLE", path)
	prompts := make(chan string, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					s := string(buf[:n])
					prompts <- s
					switch {
					case strings.Contains(s, "enter password"):
						c.Write([]byte("hunter2\n"))
					case strings.Contains(s, "enter salt"):
						c.Write([]byte("my-salt\n"))
					}
				}
			}()
		}
	}()
	key, err := diskKey(func() []byte { return nil }, UnlockHashpwd2)("cryptroot")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := Combine([]byte("hunter2"), []byte("my-salt"))
	if !bytes.Equal(key, want) {
		t.Fatal("the key is not hashpwd2's derivation of password and salt")
	}
	seen := ""
	for done := false; !done; {
		select {
		case p := <-prompts:
			seen += p
		default:
			done = true
		}
	}
	if !strings.Contains(seen, "hashpwd2: the key is derived") || !strings.Contains(seen, "enter password") || !strings.Contains(seen, "enter salt") {
		t.Errorf("prompts: %q", seen)
	}
}

func TestParseUnlockConfig(t *testing.T) {
	cfg, err := ParseUnlockConfig([]byte("# comment\nTPM2_KIRA_UNLOCK=hashpwd2\n"))
	if err != nil || cfg.Mode != UnlockHashpwd2 {
		t.Fatalf("%+v %v", cfg, err)
	}
	if cfg, err := ParseUnlockConfig(nil); err != nil || cfg.Mode != UnlockPassphrase {
		t.Fatalf("empty: %+v %v", cfg, err)
	}
	for _, bad := range []string{"TPM2_KIRA_UNLOCK=yes\n", "TPM2_KIRA_SALT=x\n", "nonsense\n"} {
		if _, err := ParseUnlockConfig([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if cfg, err := LoadUnlockConfig(filepath.Join(t.TempDir(), "none")); err != nil || cfg.Mode != UnlockPassphrase {
		t.Fatalf("missing file: %+v %v", cfg, err)
	}
}
