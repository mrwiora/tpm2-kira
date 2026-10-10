package cmd

// 'run''s side of the SSH server's privilege separation (remote_serve.go):
// it starts 'remote serve' without privileges, signs its key exchanges
// with the host key, and takes the sessions it hands over.

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// serveUID is who 'remote serve' runs as: nobody, owning no file.
const serveUID = 65534

// serveCommand is the command line of 'remote serve'; a var for the tests,
// which start their own binary.
var serveCommand = func(self string) *exec.Cmd { return exec.Command(self, "remote", "serve") }

// serveNamespaces are the namespaces 'remote serve' gets of its own: no
// network but the socket it is handed, no other process to see.
const serveNamespaces = syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWPID |
	syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS

// serveChild is the running 'remote serve'.
type serveChild struct {
	cmd    *exec.Cmd
	ctl    *serveConn
	exited chan struct{}
}

// startServe starts 'remote serve' on the listener, which it takes over:
// 'run' keeps no copy, so the port closes when the child ends. As root
// the child runs as nobody in namespaces of its own; a test run as a
// user starts it as that user. sessions gets each login's end of the code
// screen. It returns when the child is ready, with what it runs with.
func startServe(tcp *net.TCPListener, key ed25519.PrivateKey, authorized []string, log func(string), sessions func(net.Conn, string)) (*serveChild, string, error) {
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, "", err
	}
	lf, err := tcp.File()
	tcp.Close()
	if err != nil {
		return nil, "", err
	}
	defer lf.Close()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, "", err
	}
	mine, theirs := os.NewFile(uintptr(fds[0]), "control"), os.NewFile(uintptr(fds[1]), "control")
	defer theirs.Close()
	c, err := net.FileConn(mine)
	mine.Close()
	if err != nil {
		return nil, "", err
	}
	ctl := &serveConn{c: c.(*net.UnixConn)}

	self, err := os.Executable()
	if err != nil {
		c.Close()
		return nil, "", err
	}
	build := func(namespaces bool) *exec.Cmd {
		cmd := serveCommand(self)
		if cmd.Env == nil {
			cmd.Env = []string{"PATH=/usr/bin"}
		}
		cmd.Stderr = os.Stderr                  // a panic, for the journal
		cmd.ExtraFiles = []*os.File{lf, theirs} // serveListenFD, serveControlFD
		attr := &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
		if os.Geteuid() == 0 {
			attr.Credential = &syscall.Credential{Uid: serveUID, Gid: serveUID, Groups: []uint32{}}
			if namespaces {
				attr.Cloneflags = serveNamespaces
			}
		}
		cmd.SysProcAttr = attr
		return cmd
	}
	cmd := build(true)
	if err := cmd.Start(); err != nil && os.Geteuid() == 0 {
		// A kernel without one of the namespaces: nobody and Landlock
		// still hold.
		log("ssh: remote serve without namespaces of its own: " + err.Error())
		cmd = build(false)
		err = cmd.Start()
		if err != nil {
			c.Close()
			return nil, "", err
		}
	} else if err != nil {
		c.Close()
		return nil, "", err
	}
	child := &serveChild{cmd: cmd, ctl: ctl, exited: make(chan struct{})}
	go func() {
		cmd.Wait()
		close(child.exited)
	}()

	ready := make(chan string, 1)
	go child.serve(signer, log, sessions, ready)
	if err := ctl.send(serveMsg{T: "init", HostKey: signer.PublicKey().Marshal(), AuthorizedKeys: authorized}, -1); err != nil {
		child.stop()
		return nil, "", err
	}
	select {
	case how := <-ready:
		return child, how, nil
	case <-child.exited:
		c.Close()
		return nil, "", errors.New("remote serve ended at its start")
	case <-time.After(10 * time.Second):
		child.stop()
		return nil, "", errors.New("remote serve did not start")
	}
}

// serve answers the child: signatures, sessions, its lines for the
// journal. The host key signs only while the child runs.
func (c *serveChild) serve(signer ssh.Signer, log func(string), sessions func(net.Conn, string), ready chan<- string) {
	for {
		m, fd, err := c.ctl.recv()
		if err != nil {
			if fd >= 0 {
				unix.Close(fd)
			}
			return
		}
		switch m.T {
		case "ready":
			ready <- m.Text
		case "log":
			log("ssh: " + m.Text)
		case "sign":
			reply := serveMsg{T: "signed", ID: m.ID}
			if sig, err := signer.Sign(rand.Reader, m.Data); err != nil {
				reply.Err = err.Error()
			} else {
				reply.Format, reply.Data = sig.Format, sig.Blob
			}
			c.ctl.send(reply, -1)
		case "session":
			if fd < 0 {
				continue
			}
			f := os.NewFile(uintptr(fd), "session")
			conn, err := net.FileConn(f)
			f.Close()
			if err != nil {
				continue
			}
			fd = -1
			sessions(conn, m.Text)
		}
		if fd >= 0 {
			unix.Close(fd)
		}
	}
}

// stop closes the control socket - the child then stops accepting, lets
// its relays end and exits - and kills it if it has not ended in time.
func (c *serveChild) stop() {
	c.ctl.c.Close()
	select {
	case <-c.exited:
	case <-time.After(3 * time.Second):
		c.cmd.Process.Kill()
		<-c.exited
	}
}

// describeServe is the journal's line for the child's start.
func describeServe(c *serveChild, how string) string {
	return fmt.Sprintf("ssh: remote serve (pid %d) runs with %s", c.cmd.Process.Pid, how)
}
