package cmd

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testRemote starts the SSH server on a free port with a fake tinysshd
// that writes its arguments to a file.
func testRemote(t *testing.T) (*remoteServer, string, string) {
	t.Helper()
	dir := t.TempDir()
	args := filepath.Join(dir, "args")
	fake := filepath.Join(dir, "tinysshd")
	os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" > "+args+".tmp && mv "+args+".tmp "+args+"\n"), 0o755)
	old := tinysshdPath
	tinysshdPath = fake
	t.Cleanup(func() { tinysshdPath = old })
	socket := filepath.Join(dir, "remote.sock")
	// No sealed key: the server comes up with a throwaway one.
	srv, err := startRemote(RemoteOptions{Port: 0, HostKey: filepath.Join(dir, "none.sealed"), KeyDir: filepath.Join(dir, "keydir"), Socket: socket}, io.Discard, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.stop("test over") })
	return srv, socket, args
}

// session dials the code screen as 'remote session' does.
func session(t *testing.T, socket string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	return c, bufio.NewReader(c)
}

// until reads the session's output up to and including want.
func until(t *testing.T, r *bufio.Reader, want string) string {
	t.Helper()
	var got []byte
	for !bytes.Contains(got, []byte(want)) {
		b, err := r.ReadByte()
		if err != nil {
			t.Fatalf("waiting for %q: %v; got %q", want, err, got)
		}
		got = append(got, b)
	}
	return string(got)
}

// A connection to the port starts tinysshd with the session command and
// the unsealed host key's directory.
func TestRemoteStartsTinysshd(t *testing.T) {
	srv, _, args := testRemote(t)
	c, err := net.Dial("tcp", srv.tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if b, err := os.ReadFile(args); err == nil {
			if got := strings.TrimSpace(string(b)); !strings.HasPrefix(got, "-e exec ") || !strings.HasSuffix(got, " remote session --socket "+srv.opts.Socket+" "+srv.hostKey.Dir) {
				t.Fatalf("tinysshd %s", got)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("tinysshd was not started")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A session sees the code screen - also the one drawn before it came -
// and Enter in it confirms; the password is then asked in that session,
// with the echo there.
func TestRemoteSessionConfirmsAndAnswers(t *testing.T) {
	srv, socket, _ := testRemote(t)
	srv.show([]byte("#0: 123456\n"))
	c, r := session(t, socket)
	until(t, r, "#0: 123456\r\n")
	srv.show([]byte("#0: 654321\n"))
	until(t, r, "#0: 654321\r\n")
	c.Write([]byte("\r"))
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
	c.Write([]byte("sex\x7fcret\r"))
	a := <-got
	if a.err != nil || string(a.pw) != "secret" {
		t.Fatalf("asked in the session: %q %v", a.pw, a.err)
	}
	if echo := until(t, r, "\r\n"); !strings.Contains(echo, "***\b \b****") {
		t.Fatalf("echo %q", echo)
	}

	// The session leaves in the middle of a prompt: cancelled, so that
	// cryptsetup's own prompt follows.
	go func() {
		pw, err := srv.ask("cryptroot", "Password", "")
		got <- answer{pw, err}
	}()
	until(t, r, "Password for disk cryptroot:")
	c.Close()
	if a := <-got; a.err == nil {
		t.Fatalf("a closed session answered %q", a.pw)
	}
}

// Enter at the console stops the server: the sessions are told and
// closed, the port and the socket are gone, and the prompt is the
// console's.
func TestRemoteConsoleReleaseStops(t *testing.T) {
	srv, socket, _ := testRemote(t)
	_, r := session(t, socket)
	srv.show([]byte("#0: 123456\n"))
	until(t, r, "123456")
	if srv.release(true) {
		t.Fatal("a session kept the prompt after Enter at the console")
	}
	until(t, r, "the SSH server stops")
	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("the session was not closed: %v", err)
	}
	if _, err := net.Dial("tcp", srv.tcp.Addr().String()); err == nil {
		t.Fatal("the port still answers")
	}
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatalf("the socket is still there: %v", err)
	}
	if srv.promptTarget() != nil {
		t.Fatal("a prompt target after the stop")
	}
	if _, err := os.Stat(srv.hostKey.Dir); !os.IsNotExist(err) {
		t.Fatalf("the host key is still there: %v", err)
	}
}

// A host key that does not unseal (here: none in the image) is replaced by
// a throwaway key in tinysshd's format, and the console says so with the
// fingerprint to compare.
func TestRemoteThrowawayHostKey(t *testing.T) {
	srv, _, _ := testRemote(t)
	hk := srv.hostKey
	pk, err1 := os.ReadFile(filepath.Join(hk.Dir, "ed25519.pk"))
	sk, err2 := os.ReadFile(filepath.Join(hk.Dir, ".ed25519.sk"))
	if err1 != nil || err2 != nil || len(pk) != 32 || len(sk) != 64 || !bytes.Equal(sk[32:], pk) {
		t.Fatalf("not a tinysshd key directory: %v %v %d %d", err1, err2, len(pk), len(sk))
	}
	if st, _ := os.Stat(hk.Dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("key directory mode %v", st.Mode().Perm())
	}
	if hk.Throwaway == "" || hk.Fingerprint != hostKeyFingerprint(pk) {
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

// Released by the phone (or the hold's end) with a session in: the newest
// session takes the prompt; with none in, the server stops.
func TestRemoteReleaseElsewhere(t *testing.T) {
	srv, socket, _ := testRemote(t)
	_, r1 := session(t, socket)
	_, r2 := session(t, socket)
	for srv.count() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if !srv.release(false) {
		t.Fatal("no session took the prompt")
	}
	until(t, r2, "Confirmed.")
	_ = r1

	srv2, socket2, _ := testRemote(t)
	if srv2.release(false) {
		t.Fatal("a prompt target without a session")
	}
	if _, err := os.Stat(socket2); !os.IsNotExist(err) {
		t.Fatal("the server did not stop without a session")
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

// The session answers cryptsetup's own prompt when systemd has one pending.
func TestPendingPasswordQuestion(t *testing.T) {
	dir := t.TempDir()
	old := askPasswordDir
	askPasswordDir = dir
	defer func() { askPasswordDir = old }()
	if pendingPasswordQuestion() {
		t.Fatal("an empty directory asks")
	}
	os.WriteFile(filepath.Join(dir, "sck.123"), nil, 0o600)
	if pendingPasswordQuestion() {
		t.Fatal("a socket is not a question")
	}
	os.WriteFile(filepath.Join(dir, "ask.abc"), nil, 0o600)
	if !pendingPasswordQuestion() {
		t.Fatal("a pending question was not seen")
	}
}
