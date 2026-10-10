package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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
