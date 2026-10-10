package cmd

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testLog collects run's journal lines.
type testLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *testLog) add(s string) { l.mu.Lock(); l.lines = append(l.lines, s); l.mu.Unlock() }

func (l *testLog) has(want string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

// waitLog waits until run has logged want.
func (l *testLog) wait(t *testing.T, want string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !l.has(want); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			l.mu.Lock()
			defer l.mu.Unlock()
			t.Fatalf("never logged %q:\n%s", want, strings.Join(l.lines, "\n"))
		}
	}
}

// testRemote starts the SSH server on a free port, its unprivileged half
// being this test binary (TestMain), with one key that may log in. There
// is no sealed key: a throwaway one is served.
func testRemote(t *testing.T) (*remoteServer, ssh.Signer, *testLog) {
	t.Helper()
	dir := t.TempDir()
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	client, _ := ssh.NewSignerFromKey(sk)
	auth := filepath.Join(dir, "authorized_keys")
	os.WriteFile(auth, ssh.MarshalAuthorizedKey(client.PublicKey()), 0o600)
	old := serveCommand
	serveCommand = func(string) *exec.Cmd {
		c := exec.Command(os.Args[0])
		c.Env = []string{"TPM2_KIRA_TEST_SERVE=1"}
		return c
	}
	t.Cleanup(func() { serveCommand = old })
	log := &testLog{}
	srv, err := startRemote(RemoteOptions{Port: 0, HostKey: filepath.Join(dir, "none.sealed"), AuthorizedKeys: auth}, io.Discard, log.add)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.stop("test over") })
	return srv, client, log
}

// login logs in with a terminal and the shell, as 'ssh root@host' does,
// trusting only run's host key - which run holds and the unprivileged
// half has never seen.
func login(t *testing.T, srv *remoteServer, key ssh.Signer) (io.Writer, *bufio.Reader, *ssh.Session) {
	t.Helper()
	c, err := ssh.Dial("tcp", "127.0.0.1:"+strconv.Itoa(srv.opts.Port), &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.FixedHostKey(mustPublicKey(t, srv.hostKey.key)),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	in, _ := sess.StdinPipe()
	out, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	return in, bufio.NewReader(out), sess
}

func mustPublicKey(t *testing.T, k ed25519.PrivateKey) ssh.PublicKey {
	p, err := ssh.NewPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// until reads the session's output up to and including want.
func until(t *testing.T, r *bufio.Reader, want string) string {
	t.Helper()
	got := make(chan string, 1)
	go func() {
		var b []byte
		for !bytes.Contains(b, []byte(want)) {
			c, err := r.ReadByte()
			if err != nil {
				got <- "EOF before it: " + string(b)
				return
			}
			b = append(b, c)
		}
		got <- string(b)
	}()
	select {
	case s := <-got:
		if strings.HasPrefix(s, "EOF before it: ") {
			t.Fatalf("waiting for %q: %s", want, s)
		}
		return s
	case <-time.After(10 * time.Second):
		t.Fatalf("waiting for %q: nothing", want)
		return ""
	}
}

// The unprivileged half runs without new privileges and (where the kernel
// has it) without file access; it logs in with run's host key; a login
// sees the code screen - also the one drawn before it came - and Enter in
// it confirms; the password is then asked in that session, with the echo
// there.
func TestRemoteSessionConfirmsAndAnswers(t *testing.T) {
	srv, key, log := testRemote(t)
	log.wait(t, "no new privileges")
	srv.show([]byte("#0: 123456\n"))
	in, r, _ := login(t, srv, key)
	until(t, r, "#0: 123456\r\n")
	log.wait(t, "a session is in: root from 127.0.0.1")
	srv.show([]byte("#0: 654321\n"))
	until(t, r, "#0: 654321\r\n")
	in.Write([]byte("\r"))
	select {
	case <-srv.releases:
	case <-time.After(10 * time.Second):
		t.Fatal("Enter in the session did not confirm")
	}
	if !srv.release(false) {
		t.Fatal("the confirming session has no prompt")
	}
	until(t, r, "Confirmed.")

	type answer struct {
		pw  []byte
		err error
	}
	got := make(chan answer, 1)
	go func() {
		pw, err := srv.ask("cryptroot", "Password", "the key is derived from your password.")
		got <- answer{pw, err}
	}()
	until(t, r, "Password for disk cryptroot:")
	in.Write([]byte("sex\x7fcret\r"))
	a := <-got
	if a.err != nil || string(a.pw) != "secret" {
		t.Fatalf("asked in the session: %q %v", a.pw, a.err)
	}
	if echo := until(t, r, "\r\n"); !strings.Contains(echo, "***\b \b****") {
		t.Fatalf("echo %q", echo)
	}
}

// The session leaves in the middle of a prompt: cancelled, so that
// cryptsetup's own prompt follows at the console.
func TestRemoteSessionLeavesPrompt(t *testing.T) {
	srv, key, _ := testRemote(t)
	in, r, sess := login(t, srv, key)
	for srv.count() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	in.Write([]byte("\r"))
	<-srv.releases
	srv.release(false)
	errc := make(chan error, 1)
	go func() {
		_, err := srv.ask("cryptroot", "Password", "")
		errc <- err
	}()
	until(t, r, "Password for disk cryptroot:")
	sess.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("a closed session answered")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the prompt of a closed session never ended")
	}
}

// Only the code screen is served: a key that is not authorized does not
// log in, a command or a forwarding is refused.
func TestRemoteRefuses(t *testing.T) {
	srv, key, log := testRemote(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	stranger, _ := ssh.NewSignerFromKey(other)
	addr := "127.0.0.1:" + strconv.Itoa(srv.opts.Port)
	cfg := func(k ssh.Signer) *ssh.ClientConfig {
		return &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.PublicKeys(k)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second}
	}
	if c, err := ssh.Dial("tcp", addr, cfg(stranger)); err == nil {
		c.Close()
		t.Fatal("a key that is not authorized logged in")
	}
	log.wait(t, "refused publickey login of root")

	c, err := ssh.Dial("tcp", addr, cfg(key))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, _ := c.NewSession()
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	if err := sess.Run("cat /etc/shadow"); err == nil {
		t.Fatal("a command ran")
	}
	if !strings.Contains(stderr.String(), "only the code screen is served") {
		t.Fatalf("stderr %q", stderr.String())
	}
	if _, err := c.Dial("tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("a forwarding was opened")
	}
	if srv.count() != 0 {
		t.Fatal("a refused request became a session")
	}
}

// Enter at the console stops the server: the sessions are told and
// closed, the port is closed with the unprivileged half, and the prompt
// is the console's.
func TestRemoteConsoleReleaseStops(t *testing.T) {
	srv, key, _ := testRemote(t)
	_, r, _ := login(t, srv, key)
	srv.show([]byte("#0: 123456\n"))
	until(t, r, "123456")
	if srv.release(true) {
		t.Fatal("a session kept the prompt after Enter at the console")
	}
	until(t, r, "the SSH server stops")
	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("the session was not closed: %v", err)
	}
	select {
	case <-srv.child.exited:
	default:
		t.Fatal("remote serve still runs")
	}
	if c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(srv.opts.Port)); err == nil {
		c.Close()
		t.Fatal("the port still answers")
	}
	if srv.promptTarget() != nil {
		t.Fatal("a prompt target after the stop")
	}
}

// Released by the phone (or the hold's end) with a session in: the newest
// session takes the prompt; with none in, the server stops.
func TestRemoteReleaseElsewhere(t *testing.T) {
	srv, key, _ := testRemote(t)
	login(t, srv, key)
	for srv.count() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	_, r2, _ := login(t, srv, key)
	for srv.count() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if !srv.release(false) {
		t.Fatal("no session took the prompt")
	}
	until(t, r2, "Confirmed.")

	srv2, _, _ := testRemote(t)
	if srv2.release(false) {
		t.Fatal("a prompt target without a session")
	}
	<-srv2.done
}

// A host key that does not unseal (here: none in the image) is replaced by
// a throwaway key, and the console says so with the fingerprint to compare.
func TestRemoteThrowawayHostKey(t *testing.T) {
	srv, _, _ := testRemote(t)
	hk := srv.hostKey
	if hk.Throwaway == "" || len(hk.key) != ed25519.PrivateKeySize || hk.Fingerprint != hostKeyFingerprint(hk.key.Public().(ed25519.PublicKey)) {
		t.Fatalf("%+v", hk)
	}
	h := consoleHint(22, []string{"192.0.2.10 (enp1s0)"}, hk, 0, -1)
	if !strings.Contains(h, hk.Fingerprint+": a throwaway key") || !strings.Contains(h, "the image holds no sealed host key") {
		t.Fatalf("hint:\n%s", h)
	}
	if h := consoleHint(22, nil, hostKeyAtBoot{Fingerprint: "SHA256:abc"}, 0, -1); !strings.Contains(h, "Host key SHA256:abc (unsealed from the TPM)") {
		t.Fatalf("hint:\n%s", h)
	}
}

// The console names every address to log in at, the port when it is not
// 22, and that Enter continues there.
func TestConsoleHint(t *testing.T) {
	h := consoleHint(2222, []string{"192.0.2.10 (enp1s0)", "2001:db8::10 (enp1s0)"}, hostKeyAtBoot{}, 1, 30*time.Second)
	for _, want := range []string{"ssh root@192.0.2.10 -p 2222   (enp1s0)", "ssh root@2001:db8::10 -p 2222", "(30 s)", "An SSH session is connected", "Enter here: continue at this console"} {
		if !strings.Contains(h, want) {
			t.Errorf("hint lacks %q:\n%s", want, h)
		}
	}
	if h := consoleHint(22, nil, hostKeyAtBoot{}, 0, -1); !strings.Contains(h, "waiting for a network address (port 22)") || strings.Contains(h, "-p 22") || strings.Contains(h, " s)") {
		t.Errorf("no address, no limit:\n%s", h)
	}
}

// remote serve refuses to run as root, and without run's descriptors.
func TestRemoteServeAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		if err := RemoteServeCommand(); err == nil || !strings.Contains(err.Error(), "refuses to run as root") {
			t.Fatalf("as root: %v", err)
		}
		return
	}
	c := exec.Command(os.Args[0])
	c.Env = []string{"TPM2_KIRA_TEST_SERVE=1"}
	if out, err := c.CombinedOutput(); err == nil || !strings.Contains(string(out), "no control socket") {
		t.Fatalf("without run: %v %s", err, out)
	}
}
