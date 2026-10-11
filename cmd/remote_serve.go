package cmd

// 'tpm2-kira remote serve': the SSH server of the code screen, in a
// process of its own without privileges (docs/SSH.md).
//
// 'run' holds the TPM, the disk's key and the code screen; it must not
// parse what arrives from the network before a login. So it opens the
// port (as root) and starts this binary again as 'remote serve', handing
// it the listening socket and one end of a control socket. This process
// then gives up everything it does not need - it runs as nobody, in
// network, IPC, PID and mount namespaces of its own, with no new
// privileges and, where the kernel has Landlock, no access to any file -
// and only then speaks SSH (golang.org/x/crypto/ssh).
//
// It holds no host key: the key exchange is signed by 'run', asked over
// the control socket. It holds no password: a login becomes a session of
// the code screen - one end of a socket pair, handed to 'run' with
// SCM_RIGHTS - and this process relays bytes between it and the SSH
// channel. A compromise of the SSH code here gets what a login gets: the
// code screen and its prompt, no TPM, no key, no root.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// The descriptors 'run' hands to 'remote serve' (exec.Cmd.ExtraFiles).
const (
	serveListenFD  = 3 // the listening TCP socket
	serveControlFD = 4 // SOCK_SEQPACKET to 'run'
)

// Limits of the server: connections that have not logged in yet, how
// long they get for it, and sessions at once.
const (
	servePreAuthMax   = 8
	servePreAuthLimit = 30 * time.Second
	serveSessionMax   = 8
)

// serveMsg is one message on the control socket, either way.
type serveMsg struct {
	T string `json:"t"` // init, ready, sign, signed, session, log

	ID   uint64 `json:"id,omitempty"`   // sign/signed
	Data []byte `json:"data,omitempty"` // sign: what to sign; signed: the signature blob

	Format string `json:"format,omitempty"` // signed: the signature's format
	Text   string `json:"text,omitempty"`   // log, ready, session: for the journal
	Err    string `json:"err,omitempty"`    // signed

	HostKey        []byte   `json:"host_key,omitempty"`        // init: the public key, SSH wire format
	AuthorizedKeys []string `json:"authorized_keys,omitempty"` // init
}

// serveConn is the control socket, with messages and descriptors.
type serveConn struct {
	c  *net.UnixConn
	mu sync.Mutex
}

func (s *serveConn) send(m serveMsg, fd int) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var oob []byte
	if fd >= 0 {
		oob = unix.UnixRights(fd)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _, err = s.c.WriteMsgUnix(b, oob, nil)
	return err
}

// recv reads one message, and the descriptor that came with it (-1: none).
func (s *serveConn) recv() (serveMsg, int, error) {
	buf := make([]byte, 1<<20)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := s.c.ReadMsgUnix(buf, oob)
	if err != nil {
		return serveMsg{}, -1, err
	}
	if n == 0 {
		return serveMsg{}, -1, io.EOF
	}
	fd := -1
	if oobn > 0 {
		if cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
			for _, cm := range cmsgs {
				if fds, err := unix.ParseUnixRights(&cm); err == nil {
					for i, f := range fds {
						if i == 0 && fd < 0 {
							fd = f
						} else {
							unix.Close(f)
						}
					}
				}
			}
		}
	}
	var m serveMsg
	if err := json.Unmarshal(buf[:n], &m); err != nil {
		if fd >= 0 {
			unix.Close(fd)
		}
		return serveMsg{}, -1, err
	}
	return m, fd, nil
}

// RemoteServeCommand is 'remote serve'. It only runs as 'run' starts it.
func RemoteServeCommand() error {
	if os.Geteuid() == 0 {
		return errors.New("remote serve refuses to run as root: 'run' starts it without privileges")
	}
	f := os.NewFile(serveControlFD, "control")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("no control socket (remote serve is started by 'run --ssh'): %w", err)
	}
	ctl := &serveConn{c: c.(*net.UnixConn)}
	lf := os.NewFile(serveListenFD, "listen")
	ln, err := net.FileListener(lf)
	lf.Close()
	if err != nil {
		return fmt.Errorf("no listening socket: %w", err)
	}
	sandbox := sandboxSelf()

	init, fd, err := ctl.recv()
	if fd >= 0 {
		unix.Close(fd)
	}
	if err != nil || init.T != "init" {
		return fmt.Errorf("no init from run: %v", err)
	}
	s, err := newServeServer(ctl, init)
	if err != nil {
		return err
	}
	ctl.send(serveMsg{T: "ready", Text: sandbox}, -1)
	go s.control()
	s.accept(ln)
	return nil
}

// sandboxSelf takes what is left to take from this process - no new
// privileges, no file - and describes what it runs with, for the journal.
func sandboxSelf() string {
	desc := fmt.Sprintf("uid %d", os.Geteuid())
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err == nil {
		desc += ", no new privileges"
	}
	if os.Getpid() == 1 {
		// The first process of its own PID namespace: 'run' asked for
		// network, IPC, PID, mount and UTS namespaces at once.
		desc += ", namespaces of its own"
	}
	if abi, err := landlockDenyAll(); err != nil {
		desc += ", no Landlock (" + err.Error() + ")"
	} else {
		desc += fmt.Sprintf(", Landlock ABI %d: no file access", abi)
	}
	return desc
}

// landlockDenyAll restricts this process to no file system access at all
// (and no TCP bind or connect, no signals or abstract sockets beyond it,
// where the kernel knows those): a ruleset that handles every right and
// allows none. It reports the kernel's Landlock ABI.
func landlockDenyAll() (int, error) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, errno
	}
	var attr unix.LandlockRulesetAttr
	size := uintptr(8) // access_fs alone, ABI 1-3
	attr.Access_fs = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	if abi >= 2 {
		attr.Access_fs |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		attr.Access_fs |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 4 {
		attr.Access_net = unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
		size = 16
	}
	if abi >= 5 {
		attr.Access_fs |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	if abi >= 6 {
		attr.Scoped = unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL
		size = 24
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0)
	if errno != 0 {
		return int(abi), errno
	}
	defer unix.Close(int(fd))
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return int(abi), errno
	}
	return int(abi), nil
}

// serveServer is the SSH side of 'remote serve'.
type serveServer struct {
	ctl     *serveConn
	config  *ssh.ServerConfig
	preAuth chan struct{} // a slot per connection that has not logged in
	slots   chan struct{} // a slot per session

	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]chan serveMsg // sign requests waiting for 'run'
	relays  sync.WaitGroup
	closing atomic.Bool
}

func newServeServer(ctl *serveConn, init serveMsg) (*serveServer, error) {
	pub, err := ssh.ParsePublicKey(init.HostKey)
	if err != nil {
		return nil, fmt.Errorf("host key from run: %w", err)
	}
	allowed := map[string]bool{}
	for _, l := range init.AuthorizedKeys {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err == nil {
			allowed[string(k.Marshal())] = true
		}
	}
	s := &serveServer{ctl: ctl, pending: map[uint64]chan serveMsg{},
		preAuth: make(chan struct{}, servePreAuthMax), slots: make(chan struct{}, serveSessionMax)}
	s.config = &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-tpm2-kira",
		MaxAuthTries:  6,
		// The key the client proved it holds is the one passed here; the
		// login's Permissions carry its fingerprint, never a key kept from
		// an earlier call (CVE-2024-45337).
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !allowed[string(key.Marshal())] {
				return nil, errors.New("not an authorized key")
			}
			return &ssh.Permissions{Extensions: map[string]string{"key": ssh.FingerprintSHA256(key)}}, nil
		},
		AuthLogCallback: func(meta ssh.ConnMetadata, method string, err error) {
			if err != nil && method != "none" {
				s.log(fmt.Sprintf("refused %s login of %s from %s", method, meta.User(), meta.RemoteAddr()))
			}
		},
	}
	s.config.AddHostKey(&remoteSigner{s: s, pub: pub})
	return s, nil
}

func (s *serveServer) log(text string) { s.ctl.send(serveMsg{T: "log", Text: text}, -1) }

// control reads 'run”s answers. When 'run' closes the socket the server
// stops: no new connection, the sessions' relays finish (run has closed
// their ends), and the process ends.
func (s *serveServer) control() {
	for {
		m, fd, err := s.ctl.recv()
		if fd >= 0 {
			unix.Close(fd)
		}
		if err != nil {
			s.closing.Store(true)
			done := make(chan struct{})
			go func() { s.relays.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
			os.Exit(0)
		}
		if m.T != "signed" {
			continue
		}
		s.mu.Lock()
		ch := s.pending[m.ID]
		delete(s.pending, m.ID)
		s.mu.Unlock()
		if ch != nil {
			ch <- m
		}
	}
}

// remoteSigner signs the key exchange with the host key 'run' holds.
type remoteSigner struct {
	s   *serveServer
	pub ssh.PublicKey
}

func (r *remoteSigner) PublicKey() ssh.PublicKey { return r.pub }

func (r *remoteSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	s := r.s
	ch := make(chan serveMsg, 1)
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	s.pending[id] = ch
	s.mu.Unlock()
	if err := s.ctl.send(serveMsg{T: "sign", ID: id, Data: data}, -1); err != nil {
		return nil, err
	}
	select {
	case m := <-ch:
		if m.Err != "" {
			return nil, errors.New(m.Err)
		}
		return &ssh.Signature{Format: m.Format, Blob: m.Data}, nil
	case <-time.After(10 * time.Second):
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, errors.New("run did not sign")
	}
}

// accept takes the connections, as many at once as have a pre-login slot.
func (s *serveServer) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if s.closing.Load() {
			c.Close()
			continue
		}
		select {
		case s.preAuth <- struct{}{}:
		default:
			c.Close() // too many at once that have not logged in
			continue
		}
		go s.serve(c)
	}
}

// serve is one connection: the login, then its channels.
func (s *serveServer) serve(c net.Conn) {
	s.log(fmt.Sprintf("connection from %s", c.RemoteAddr()))
	c.SetDeadline(time.Now().Add(servePreAuthLimit))
	conn, chans, reqs, err := ssh.NewServerConn(c, s.config)
	<-s.preAuth
	if err != nil {
		c.Close()
		return
	}
	c.SetDeadline(time.Time{})
	defer conn.Close()
	who := fmt.Sprintf("%s from %s, key %s", conn.User(), conn.RemoteAddr(), conn.Permissions.Extensions["key"])
	s.log("login of " + who)
	go ssh.DiscardRequests(reqs) // no forwarding, no keepalive answers needed
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.Prohibited, "only the code screen is served")
			s.log(fmt.Sprintf("refused the %s channel of %s", nc.ChannelType(), who))
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.session(ch, creqs, who)
	}
}

// session waits for the shell request - the only one served besides the
// terminal's - and relays the channel to a session of the code screen.
func (s *serveServer) session(ch ssh.Channel, reqs <-chan *ssh.Request, who string) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "pty-req", "env", "window-change":
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			go ssh.DiscardRequests(reqs)
			s.relay(ch, who)
			return
		case "exec", "subsystem":
			// Accepted only to say why nothing runs: a refused request
			// leaves the client with "request failed" and no reason.
			req.Reply(true, nil)
			s.log(fmt.Sprintf("refused the %s request of %s", req.Type, who))
			fmt.Fprint(ch.Stderr(), "tpm2-kira: only the code screen is served here (ssh without a command)\r\n")
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
			return
		default:
			req.Reply(false, nil)
			s.log(fmt.Sprintf("refused the %s request of %s", req.Type, who))
		}
	}
}

// relay hands a socket pair's end to 'run' as a session of the code
// screen and copies between it and the channel until either side ends.
func (s *serveServer) relay(ch ssh.Channel, who string) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		fmt.Fprint(ch, "tpm2-kira: too many sessions at once\r\n")
		return
	}
	if s.closing.Load() {
		return
	}
	s.relays.Add(1)
	defer s.relays.Done()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return
	}
	err = s.ctl.send(serveMsg{T: "session", Text: who}, fds[1])
	unix.Close(fds[1])
	f := os.NewFile(uintptr(fds[0]), "session")
	conn, cerr := net.FileConn(f)
	f.Close()
	if err != nil || cerr != nil {
		return
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		io.Copy(conn, ch) // what is typed
		conn.(*net.UnixConn).CloseWrite()
		close(done)
	}()
	io.Copy(ch, conn) // the screen; ends when run closes the session
	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	ch.Close()
	<-done
}
