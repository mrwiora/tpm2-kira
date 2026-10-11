package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// askFile writes a question as systemd-ask-password does, and listens on
// its socket for the answer.
func askFile(t *testing.T, dir, name string) (string, *net.UnixConn) {
	t.Helper()
	sock := filepath.Join(dir, "sck."+name)
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	path := filepath.Join(dir, "ask."+name)
	tmp := filepath.Join(dir, "tmp."+name)
	os.WriteFile(tmp, []byte(fmt.Sprintf("[Ask]\nPID=1\nSocket=%s\nAcceptCached=1\nEcho=0\nNotAfter=0\nMessage=Please enter passphrase for disk cryptroot:\nId=cryptsetup:/dev/vda2\n", sock)), 0o600)
	os.Rename(tmp, path)
	return path, c
}

// cryptsetup's own question is asked in the session that has the prompt
// and answered on its socket; a question answered at the console while it
// is asked is withdrawn from the session; one whose session left is asked
// again in the next.
func TestRemoteAnswersCryptsetupsQuestion(t *testing.T) {
	dir := t.TempDir()
	old := askPasswordDir
	askPasswordDir = dir
	t.Cleanup(func() { askPasswordDir = old })
	srv, key, _ := testRemote(t)
	in, r, sess := login(t, srv, key)
	for srv.count() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	in.Write([]byte("\r"))
	<-srv.releases
	srv.release(false)

	_, sock := askFile(t, dir, "1")
	until(t, r, "cryptsetup asks: Please enter passphrase for disk cryptroot:")
	until(t, r, "Passphrase:")
	in.Write([]byte("hunter2\r"))
	sock.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	n, err := sock.Read(buf)
	if err != nil || string(buf[:n]) != "+hunter2" {
		t.Fatalf("answer %q %v", buf[:n], err)
	}

	path, _ := askFile(t, dir, "2")
	until(t, r, "Passphrase:")
	os.Remove(path) // the console answered
	until(t, r, "Answered at the console.")

	_, sock3 := askFile(t, dir, "3")
	until(t, r, "Passphrase:")
	sess.Close()
	in2, r2, _ := login(t, srv, key)
	until(t, r2, "cryptsetup asks:")
	until(t, r2, "Passphrase:")
	in2.Write([]byte("again\r"))
	sock3.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err := sock3.Read(buf); err != nil || string(buf[:n]) != "+again" {
		t.Fatalf("answer in the next session %q %v", buf[:n], err)
	}
}

// A question names its socket and its time limit; a file without a socket
// is none.
func TestReadPasswordQuestion(t *testing.T) {
	dir := t.TempDir()
	old := askPasswordDir
	askPasswordDir = dir
	t.Cleanup(func() { askPasswordDir = old })
	if len(pendingPasswordQuestions()) != 0 {
		t.Fatal("an empty directory asks")
	}
	os.WriteFile(filepath.Join(dir, "sck.123"), nil, 0o600)
	os.WriteFile(filepath.Join(dir, "ask.bad"), []byte("[Ask]\nMessage=x\n"), 0o600)
	qs := pendingPasswordQuestions()
	if len(qs) != 1 {
		t.Fatalf("questions %v", qs)
	}
	if _, err := readPasswordQuestion(qs[0]); err == nil {
		t.Fatal("a question without a socket")
	}
	os.WriteFile(filepath.Join(dir, "ask.old"), []byte("[Ask]\nSocket=/x\nNotAfter=1\nMessage=m\n"), 0o600)
	q, err := readPasswordQuestion(filepath.Join(dir, "ask.old"))
	if err != nil || q.socket != "/x" || q.message != "m" || !q.expired() {
		t.Fatalf("%+v %v", q, err)
	}
}

// fakeAskpass makes dir/proc/PID look like initramfs-tools' askpass with
// the FIFO open, started at start, asking prompt.
func fakeAskpass(t *testing.T, dir string, pid int, start, prompt string) string {
	t.Helper()
	p := filepath.Join(dir, "proc", fmt.Sprint(pid))
	os.MkdirAll(filepath.Join(p, "fd"), 0o755)
	os.Symlink(askpassBin, filepath.Join(p, "exe"))
	os.Symlink(askpassFIFO, filepath.Join(p, "fd", "3"))
	os.WriteFile(filepath.Join(p, "cmdline"), []byte("/lib/cryptsetup/askpass\x00"+prompt+"\x00"), 0o644)
	setStart(t, p, start)
	return p
}

func setStart(t *testing.T, p, start string) {
	t.Helper()
	// pid (comm) state, then fields 4..21, then starttime (22).
	os.WriteFile(filepath.Join(p, "stat"), []byte("1 (ask pass) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 "+start+" 0 0\n"), 0o644)
}

// initramfs-tools: cryptsetup's own askpass is found by its open FIFO and
// asked in the session; the answer goes into the FIFO. One that ends
// while it is asked (answered at the console) is withdrawn.
func TestRemoteAnswersAskpass(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	oldProc, oldBin, oldFIFO, oldDir := procDir, askpassBin, askpassFIFO, askPasswordDir
	procDir, askpassBin, askpassFIFO, askPasswordDir = filepath.Join(dir, "proc"), filepath.Join(dir, "askpass"), filepath.Join(dir, "passfifo"), filepath.Join(dir, "none")
	t.Cleanup(func() { procDir, askpassBin, askpassFIFO, askPasswordDir = oldProc, oldBin, oldFIFO, oldDir })
	os.WriteFile(askpassBin, nil, 0o755)
	if err := unix.Mkfifo(askpassFIFO, 0o600); err != nil {
		t.Fatal(err)
	}
	// askpass' end: read and write, so it never sees an end of file.
	fifo, err := os.OpenFile(askpassFIFO, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fifo.Close() })
	os.MkdirAll(filepath.Join(dir, "proc", "1"), 0o755) // not askpass

	srv, key, _ := testRemote(t)
	in, r, _ := login(t, srv, key)
	for srv.count() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	in.Write([]byte("\r"))
	<-srv.releases
	srv.release(false)

	fakeAskpass(t, dir, 4242, "777", "Please unlock disk vda3_crypt (recovery passphrase): ")
	until(t, r, "cryptsetup asks: Please unlock disk vda3_crypt (recovery passphrase)")
	until(t, r, "Passphrase:")
	in.Write([]byte("hunter2\r"))
	fifo.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	if n, err := fifo.Read(buf); err != nil || string(buf[:n]) != "hunter2" {
		t.Fatalf("answer %q %v", buf[:n], err)
	}

	p := fakeAskpass(t, dir, 4243, "900", "Please unlock disk vda3_crypt (recovery passphrase): ")
	until(t, r, "Passphrase:")
	setStart(t, p, "901") // ended, and the pid taken again
	until(t, r, "Answered at the console.")
}
