//go:build integration
// +build integration

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
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

	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"golang.org/x/crypto/ssh"
)

// syncBuffer is run's output, read while it is written.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// remoteBoot is 'tpm2-kira-boot run --ssh' against a software TPM with a sealed
// slot and a LUKS2 header marked recovery recipe (0x1100): the chain of the image -
// SSH to the unprivileged 'ssh-child', the session handed to 'run',
// the code screen, the key socket.
type remoteBoot struct {
	run     *exec.Cmd
	out     *syncBuffer
	stdin   io.WriteCloser
	port    int
	unlock  string
	key     ssh.Signer // may log in
	volume  string
	cleanup func()
}

func startRemoteBoot(t *testing.T) *remoteBoot {
	t.Helper()
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Skip("cryptsetup not installed")
	}
	tpmPath, stopTPM := setupSoftwareTPM(t)
	testSeal(t, tpmPath, "0x01803010")

	dir := t.TempDir()
	img := filepath.Join(dir, "disk.img")
	os.WriteFile(img, nil, 0o600)
	os.Truncate(img, 20<<20)
	key, _ := diskkey.Combine([]byte("correct horse"), []byte("battery staple"))
	format := exec.Command("cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", "-", img)
	format.Stdin = bytes.NewReader(key)
	if out, err := format.CombinedOutput(); err != nil {
		t.Fatalf("luksFormat: %v: %s", err, out)
	}
	if out, err := exec.Command("./tpm2-kira", "luks", "mark", "--keyslot", "0", "--salt", "typed", img).CombinedOutput(); err != nil || !bytes.Contains(out, []byte("marked")) {
		t.Fatalf("luks mark: %v: %s", err, out)
	}
	volume := "cryptroot"
	crypttab := filepath.Join(dir, "crypttab")
	os.WriteFile(crypttab, []byte(volume+" "+img+" none luks\n"), 0o600)
	conf := filepath.Join(dir, "control.conf")
	os.WriteFile(conf, []byte("# nothing\n"), 0o600)

	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	login, _ := ssh.NewSignerFromKey(sk)
	auth := filepath.Join(dir, "authorized_keys")
	os.WriteFile(auth, ssh.MarshalAuthorizedKey(login.PublicKey()), 0o600)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	b := &remoteBoot{out: &syncBuffer{}, port: port, unlock: filepath.Join(dir, "unlock.sock"), volume: volume, key: login}
	asshConf := filepath.Join(dir, "assh.conf")
	os.WriteFile(asshConf, []byte(fmt.Sprintf("ASSH_LISTEN=127.0.0.1:%d\nASSH_CA=%s\nASSH_AUTHORIZED_KEYS=%s\n", port, filepath.Join(dir, "none.json"), auth)), 0o644)
	b.run = exec.Command("./tpm2-kira-boot", "run", "--tpm", tpmPath, "--nvram", "0x01803010", "--unlock", b.unlock,
		"--ssh", "--ssh-conf", asshConf)
	b.run.Env = append(os.Environ(), "TPM2_KIRA_CRYPTTAB="+crypttab,
		"TPM2_KIRA_CONTROL_CONF="+conf, "TPM2_KIRA_CONSOLE="+filepath.Join(dir, "console"))
	b.run.Stdout, b.run.Stderr = b.out, b.out
	b.stdin, _ = b.run.StdinPipe()
	if err := b.run.Start(); err != nil {
		t.Fatal(err)
	}
	b.cleanup = func() {
		b.run.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- b.run.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			b.run.Process.Kill()
			<-done
		}
		stopTPM()
	}
	t.Cleanup(b.cleanup)
	b.waitOutput(t, "The code screen over SSH")
	return b
}

func (b *remoteBoot) waitOutput(t *testing.T, want string) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); !strings.Contains(b.out.String(), want); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("run never said %q:\n%s", want, b.out.String())
		}
	}
}

// login logs in as 'ssh root@host' does, with a terminal and the shell.
func (b *remoteBoot) login(t *testing.T) (io.Writer, *bufio.Reader, *ssh.Client) {
	t.Helper()
	c, err := ssh.Dial("tcp", "127.0.0.1:"+strconv.Itoa(b.port), &ssh.ClientConfig{
		User: "root", Auth: []ssh.AuthMethod{ssh.PublicKeys(b.key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // a temporary key: no SSH CA in this test
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
	sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{})
	in, _ := sess.StdinPipe()
	out, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	return in, bufio.NewReader(out), c
}

// keyRequest asks for the volume's key as systemd-cryptsetup does (its
// abstract source address names the volume) and returns what it read.
func (b *remoteBoot) keyRequest(t *testing.T) chan []byte {
	t.Helper()
	got := make(chan []byte, 1)
	c, err := net.DialUnix("unix", &net.UnixAddr{Name: "@1234/cryptsetup/" + b.volume, Net: "unix"}, &net.UnixAddr{Name: b.unlock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer c.Close()
		key, _ := io.ReadAll(c)
		got <- key
	}()
	return got
}

func readUntil(t *testing.T, r *bufio.Reader, want string) string {
	t.Helper()
	var got []byte
	for !bytes.Contains(got, []byte(want)) {
		c, err := r.ReadByte()
		if err != nil {
			t.Fatalf("waiting for %q: %v; got %q", want, err, got)
		}
		got = append(got, c)
	}
	return string(got)
}

// The code is shown in the SSH session, not at the console; Enter there
// releases the boot, and the password and the salt are asked in the
// session: the key systemd-cryptsetup reads is theirs.
func TestRemoteSSHConfirmsAndUnlocks(t *testing.T) {
	b := startRemoteBoot(t)
	c, r, _ := b.login(t)
	screen := readUntil(t, r, "asked here")
	if !strings.Contains(screen, "#0") || !strings.Contains(screen, "Does the code match your authenticator?") {
		t.Fatalf("the session's screen:\n%s", screen)
	}
	if strings.Contains(b.out.String(), "Does the code match") {
		t.Fatalf("the console shows the codes:\n%s", b.out.String())
	}
	b.waitOutput(t, "An SSH session is connected")
	b.waitOutput(t, "a temporary key, the SSH CA did not certify one") // none in this image

	key := b.keyRequest(t)
	c.Write([]byte("\r"))
	readUntil(t, r, "Password for disk "+b.volume)
	c.Write([]byte("correct horse\r"))
	readUntil(t, r, "Salt for disk "+b.volume)
	c.Write([]byte("battery staple\r"))
	want, _ := diskkey.Combine([]byte("correct horse"), []byte("battery staple"))
	select {
	case k := <-key:
		if !bytes.Equal(k, want) {
			t.Fatalf("the key read: %d bytes, not the password's and salt's", len(k))
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("no key:\n%s", b.out.String())
	}
	b.waitOutput(t, "Confirmed over SSH")
	b.waitOutput(t, "asked in the SSH session")

	// Stopped at switch-root: the unprivileged half goes with it, and the
	// port with that.
	b.run.Process.Signal(os.Interrupt)
	b.run.Wait()
	if c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(b.port)); err == nil {
		c.Close()
		t.Fatal("the port still answers after the stop")
	}
}

// Enter at the console continues there: the session is told and closed,
// and the port no longer answers.
func TestRemoteSSHEnterAtConsoleStops(t *testing.T) {
	b := startRemoteBoot(t)
	_, r, _ := b.login(t)
	readUntil(t, r, "asked here")
	b.stdin.Write([]byte("\n"))
	readUntil(t, r, "the SSH server stops")
	if rest, err := io.ReadAll(r); err != nil {
		t.Fatalf("the session stayed open: %v %q", err, rest)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(b.port))
		if err != nil {
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("the port still answers after Enter at the console")
		}
	}
}
