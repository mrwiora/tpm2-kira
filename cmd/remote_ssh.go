package cmd

// The SSH server of the code screen (docs/REMOTE-SSH.md). With TPM2_KIRA_SSH
// on, the image's tpm2-kira.service runs 'tpm2-kira run --ssh=PORT': the
// process that holds the boot listens on the port itself and starts one
// tinysshd per connection (inetd style, the connection on its stdin and
// stdout), whose only command is 'tpm2-kira remote session'. That session
// connects back to this process on a local socket and becomes a terminal
// of the code screen: it sees the codes, and Enter there confirms them and
// releases the boot, as Enter at the console does. The password prompt
// then opens in the session that released, and cryptsetup's own prompt,
// should it follow, is answered there through systemd's password agent.
//
// The console is told where to log in instead of being shown the codes,
// and Enter there continues at the console: the SSH server stops, every
// session is closed, and the prompt is the console's - no remote
// confirmation can hold a person at the machine (AGENTS.md, no enforced
// mode). A release over SSH keeps the server running until switch-root,
// so a dropped session can come back for the prompt.

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultRemoteSocket is where the sessions reach the code screen.
const DefaultRemoteSocket = "/run/tpm2-kira/remote.sock"

// tinysshdPath is the server binary: /usr/bin/tinysshd, or for tests the
// program in TPM2_KIRA_TINYSSHD.
var tinysshdPath = func() string {
	if p := os.Getenv("TPM2_KIRA_TINYSSHD"); p != "" {
		return p
	}
	return "/usr/bin/tinysshd"
}()

// RemoteOptions are run's SSH settings; Port 0 is no SSH server.
type RemoteOptions struct {
	Port    int
	Hold    time.Duration // 0: until a confirmation comes
	TPM     string        // the TPM the host key is unsealed with
	HostKey string        // the sealed host key (ImageSealedHostKey)
	KeyDir  string        // where it is unsealed to for tinysshd (DefaultHostKeyDir)
	Socket  string        // DefaultRemoteSocket
}

// remoteServer is the SSH server and its sessions.
type remoteServer struct {
	opts    RemoteOptions
	self    string // this executable, for the session command
	tcp     net.Listener
	local   net.Listener
	log     func(string)
	console io.Writer // the console's own lines
	hostKey hostKeyAtBoot

	mu       sync.Mutex
	procs    map[*exec.Cmd]chan struct{} // closed when the tinysshd has ended
	sessions []*remoteSession            // in the order they came
	screen   []byte                      // the last code screen, for a session that comes in
	released bool                        // the boot is released; keys go to prompts now
	stopped  bool                        // released at the console: nothing is served
	target   *remoteSession              // the session that released, for the prompt
	done     chan struct{}               // closed when stop has ended
	releases chan struct{}               // a session confirmed
	changed  chan struct{}               // a session came or went
}

// remoteSession is one 'tpm2-kira remote session' on the local socket.
type remoteSession struct {
	conn   net.Conn
	keys   chan byte // what is typed once the boot is released, for a prompt
	closed chan struct{}
	once   sync.Once
}

func (s *remoteSession) close() {
	s.once.Do(func() {
		close(s.closed)
		s.conn.Close()
	})
}

func (s *remoteSession) write(b []byte) {
	s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.conn.Write(b); err != nil {
		s.close()
	}
}

// startRemote opens the port and the local socket. A port that cannot be
// opened is said on the console and the code screen goes on without SSH.
func startRemote(o RemoteOptions, console io.Writer, log func(string)) (*remoteServer, error) {
	if o.Socket == "" {
		o.Socket = DefaultRemoteSocket
	}
	if o.KeyDir == "" {
		o.KeyDir = DefaultHostKeyDir
	}
	if _, err := os.Stat(tinysshdPath); err != nil {
		return nil, fmt.Errorf("%s is not in the image (rebuild with TPM2_KIRA_SSH=on): %w", tinysshdPath, err)
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// Unsealed now, while the code screen holds the boot ahead of the OS
	// separator: after it, PCR 0 and 7 no longer fit the policy.
	hk, err := prepareHostKey(o.TPM, o.HostKey, o.KeyDir)
	if err != nil {
		return nil, fmt.Errorf("SSH host key: %w", err)
	}
	if hk.Throwaway != "" {
		log("ssh: serving a throwaway host key: " + hk.Throwaway)
	}
	local, err := listenGate(o.Socket)
	if err != nil {
		os.RemoveAll(hk.Dir)
		return nil, err
	}
	tcp, err := net.Listen("tcp", ":"+strconv.Itoa(o.Port))
	if err != nil {
		local.Close()
		os.Remove(o.Socket)
		os.RemoveAll(hk.Dir)
		return nil, err
	}
	r := &remoteServer{opts: o, self: self, tcp: tcp, local: local, log: log, console: console, hostKey: hk,
		procs: map[*exec.Cmd]chan struct{}{}, done: make(chan struct{}), releases: make(chan struct{}, 1), changed: make(chan struct{}, 1)}
	go r.acceptSSH()
	go r.acceptSessions()
	log(fmt.Sprintf("ssh: listening on port %d, host key %s", o.Port, hk.Fingerprint))
	return r, nil
}

// acceptSSH hands every connection to a tinysshd of its own.
func (r *remoteServer) acceptSSH() {
	for {
		c, err := r.tcp.Accept()
		if err != nil {
			return
		}
		r.log(fmt.Sprintf("ssh: connection from %s", c.RemoteAddr()))
		f, err := c.(*net.TCPConn).File()
		c.Close()
		if err != nil {
			continue
		}
		cmd := exec.Command(tinysshdPath, "-e", "exec "+r.self+" remote session --socket "+r.opts.Socket, r.hostKey.Dir)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = f, f, os.Stderr
		cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin"}
		// A session of its own: this process gives the console up when the
		// boot is released, and as the console's session leader that sends
		// SIGHUP to everything in its session - the tinysshd of the
		// session that is to ask the password among them.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		r.mu.Lock()
		if r.stopped {
			r.mu.Unlock()
			f.Close()
			return
		}
		err = cmd.Start()
		ended := make(chan struct{})
		if err == nil {
			r.procs[cmd] = ended
		}
		r.mu.Unlock()
		f.Close()
		if err != nil {
			r.log("ssh: tinysshd: " + err.Error())
			continue
		}
		go func() {
			cmd.Wait()
			close(ended)
			r.mu.Lock()
			delete(r.procs, cmd)
			r.mu.Unlock()
		}()
	}
}

// acceptSessions takes the sessions tinysshd started.
func (r *remoteServer) acceptSessions() {
	for {
		c, err := r.local.Accept()
		if err != nil {
			return
		}
		if err := peerIsUs(c); err != nil {
			r.log("ssh: refusing a session: " + err.Error())
			c.Close()
			continue
		}
		s := &remoteSession{conn: c, keys: make(chan byte, maxPassphrase), closed: make(chan struct{})}
		r.mu.Lock()
		if r.stopped {
			r.mu.Unlock()
			c.Close()
			continue
		}
		r.sessions = append(r.sessions, s)
		screen, released := r.screen, r.released
		r.mu.Unlock()
		r.log("ssh: a session is in")
		r.signal(r.changed)
		if released {
			s.write([]byte(fmt.Sprintf("%s The boot is released; the password is asked here when a disk asks for its key.\r\n", kiraTag(tagYellow))))
		} else if len(screen) > 0 {
			s.write(screen)
		}
		go r.read(s)
	}
}

// read follows what is typed in a session: while the boot is held, Enter
// confirms and q (or Ctrl-C, Ctrl-D) leaves; afterwards every byte is for
// the prompt.
func (r *remoteServer) read(s *remoteSession) {
	defer func() {
		s.close()
		r.mu.Lock()
		for i, x := range r.sessions {
			if x == s {
				r.sessions = append(r.sessions[:i], r.sessions[i+1:]...)
				break
			}
		}
		r.mu.Unlock()
		r.log("ssh: a session has left")
		r.signal(r.changed)
	}()
	buf := make([]byte, 64)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			return
		}
		for _, c := range buf[:n] {
			r.mu.Lock()
			released := r.released
			if !released && (c == '\r' || c == '\n') {
				r.released, r.target = true, s
			}
			r.mu.Unlock()
			switch {
			case released:
				select {
				case s.keys <- c:
				default: // nobody asks; a full buffer is not kept
				}
			case c == '\r' || c == '\n':
				r.log("ssh: the code screen was confirmed in a session")
				r.signal(r.releases)
			case c == 'q' || c == 3 || c == 4:
				s.write([]byte("\r\n"))
				return
			}
		}
	}
}

func (r *remoteServer) signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// show sends the code screen to every session, and keeps it for those that
// come in later. Line ends become CRLF: the session's terminal is raw.
func (r *remoteServer) show(screen []byte) {
	screen = bytes.ReplaceAll(screen, []byte("\n"), []byte("\r\n"))
	r.mu.Lock()
	r.screen = screen
	sessions := append([]*remoteSession(nil), r.sessions...)
	r.mu.Unlock()
	for _, s := range sessions {
		s.write(screen)
	}
}

// count is the number of sessions in.
func (r *remoteServer) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// release ends the hold on the server's side: the boot is
// released, and when nobody confirmed in a session (the console, the
// phone) the newest session takes the prompt - or none is in, and the
// server stops: the prompt is the console's. Reports whether a session
// has the prompt.
func (r *remoteServer) release(atConsole bool) bool {
	r.mu.Lock()
	r.released = true
	if atConsole {
		r.target = nil
	} else if r.target == nil && len(r.sessions) > 0 {
		r.target = r.sessions[len(r.sessions)-1]
	}
	target := r.target
	r.mu.Unlock()
	if target == nil {
		r.stop("The boot continues at the console; the SSH server stops.")
		return false
	}
	target.write([]byte(fmt.Sprintf("\r\n%s Confirmed. The password is asked here when the disk asks for its key.\r\n", kiraTag(tagYellow))))
	return true
}

// stop closes the port, tells every session why, and ends them and their
// tinysshd.
func (r *remoteServer) stop(why string) {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	sessions := r.sessions
	r.sessions = nil
	procs := map[*exec.Cmd]chan struct{}{}
	for p, ended := range r.procs {
		procs[p] = ended
	}
	r.mu.Unlock()
	r.tcp.Close()
	r.local.Close()
	os.Remove(r.opts.Socket)
	for _, s := range sessions {
		s.write([]byte(fmt.Sprintf("\r\n%s %s\r\n", kiraTag(tagYellow), why)))
		s.close()
	}
	// A closed session ends its client, which hands the notice on and
	// exits, and tinysshd with it; what is still there then is killed.
	deadline, expired := time.After(2*time.Second), false
	for p, ended := range procs {
		if !expired {
			select {
			case <-ended:
				continue
			case <-deadline:
				expired = true
			}
		}
		p.Process.Kill()
	}
	// No tinysshd is left to read the key.
	os.RemoveAll(r.hostKey.Dir)
	r.log("ssh: stopped")
	close(r.done)
}

// promptTarget is the session the password is asked in, nil for the
// console: the one that confirmed, or after it left the newest one.
func (r *remoteServer) promptTarget() *remoteSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return nil
	}
	if r.target != nil {
		select {
		case <-r.target.closed:
			r.target = nil
		default:
			return r.target
		}
	}
	if n := len(r.sessions); n > 0 {
		r.target = r.sessions[n-1]
	}
	return r.target
}

// ask is consoleAsk in the session that has the prompt, or at the console
// when none has it.
func (r *remoteServer) ask(volume, what, note string) ([]byte, error) {
	s := r.promptTarget()
	if s == nil {
		return consoleAsk(volume, what, note)
	}
	r.log(fmt.Sprintf("ssh: asking for the %s of %s in the session", strings.ToLower(what), volume))
	fmt.Fprintf(r.console, "%s %s for disk %s: asked in the SSH session.\n", kiraTag(tagYellow), what, volume)
	var b strings.Builder
	if note != "" {
		lines := strings.Split(note, "\n")
		fmt.Fprintf(&b, "\r\n%s Disk %s: %s\r\n", kiraTag(tagYellow), volume, lines[0])
		for _, l := range lines[1:] {
			fmt.Fprintf(&b, "         %s\r\n", l)
		}
	}
	// What was typed before the question is not part of the answer.
	for drained := false; !drained; {
		select {
		case <-s.keys:
		default:
			drained = true
		}
	}
	for {
		s.write([]byte(b.String() + fmt.Sprintf("\r\n%s \033[1m%s for disk %s:\033[0m ", kiraTag(tagBlue), what, volume)))
		b.Reset()
		pw, err := readRawPassphrase(func() (byte, error) {
			select {
			case c := <-s.keys:
				return c, nil
			case <-s.closed:
				return 0, io.EOF
			}
		}, s.conn)
		s.write([]byte("\r\n"))
		if err != nil {
			return nil, err
		}
		if len(pw) > 0 {
			return pw, nil
		}
	}
}

// addresses are the machine's addresses an SSH client can reach, as the
// console names them: IPv4 first, no link-local ones.
func addresses() []string {
	ifs, _ := net.Interfaces()
	var v4, v6 []string
	for _, it := range ifs {
		if it.Flags&net.FlagUp == 0 || it.Flags&net.FlagLoopback != 0 {
			continue
		}
		as, _ := it.Addrs()
		for _, a := range as {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			if ipn.IP.To4() != nil {
				v4 = append(v4, ipn.IP.String()+" ("+it.Name+")")
			} else {
				v6 = append(v6, ipn.IP.String()+" ("+it.Name+")")
			}
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return append(v4, v6...)
}

// consoleHint is what the console shows instead of the codes: where to log
// in, that the boot waits for it, and that Enter continues here.
func consoleHint(port int, addrs []string, hk hostKeyAtBoot, sessions int, remaining time.Duration) string {
	var b strings.Builder
	p := ""
	if port != 22 {
		p = fmt.Sprintf(" -p %d", port)
	}
	fmt.Fprintf(&b, "%s Remote attestation over SSH:", kiraTag(tagYellow))
	if len(addrs) == 0 {
		fmt.Fprintf(&b, " waiting for a network address (port %d) ...\n", port)
	} else {
		b.WriteString("\n")
		for _, a := range addrs {
			ip, iface, _ := strings.Cut(a, " ")
			fmt.Fprintf(&b, "           ssh root@%s%s   %s\n", ip, p, iface)
		}
	}
	if hk.Throwaway != "" {
		fmt.Fprintf(&b, "         Host key %s: a throwaway key, the sealed one did not unseal\n", hk.Fingerprint)
		fmt.Fprintf(&b, "         (%s); ssh warns of a changed host key. Rebuild the image after this boot.\n", hk.Throwaway)
	} else if hk.Fingerprint != "" {
		fmt.Fprintf(&b, "         Host key %s (unsealed from the TPM)\n", hk.Fingerprint)
	}
	b.WriteString("         The codes are shown and confirmed in the SSH session; the boot waits for it")
	if remaining >= 0 {
		fmt.Fprintf(&b, " (%d s)", int(remaining.Round(time.Second)/time.Second))
	}
	b.WriteString(".\n")
	switch sessions {
	case 0:
	case 1:
		b.WriteString("         An SSH session is connected.\n")
	default:
		fmt.Fprintf(&b, "         %d SSH sessions are connected.\n", sessions)
	}
	b.WriteString("         Enter here: continue at this console instead - the SSH server stops.\n")
	return b.String()
}

// RemoteSessionCommand is 'tpm2-kira remote session', the command tinysshd
// runs for a login: a terminal of the code screen. It relays the terminal
// to the code screen's socket (raw: every key goes there, the screen does
// the echo), and answers cryptsetup's own prompt through systemd's
// password agent whenever one is pending. Without a code screen to reach
// it is the agent alone.
func RemoteSessionCommand(socket string) error {
	c, err := net.Dial("unix", socket)
	if err != nil {
		fmt.Printf("tpm2-kira: no code screen to reach (%v); answering systemd's password questions.\n", err)
		return runPasswordAgent(true)
	}
	defer c.Close()
	fd := int(os.Stdin.Fd())
	old, terr := unix.IoctlGetTermios(fd, unix.TCGETS)
	setRaw := func() {}
	restore := func() {}
	if terr == nil {
		raw := *old
		raw.Lflag &^= unix.ECHO | unix.ICANON | unix.ISIG
		raw.Cc[unix.VMIN], raw.Cc[unix.VTIME] = 1, 0
		setRaw = func() { unix.IoctlSetTermios(fd, unix.TCSETS, &raw) }
		restore = func() { unix.IoctlSetTermios(fd, unix.TCSETS, old) }
	}
	setRaw()
	defer restore()

	done := make(chan struct{})
	go func() {
		io.Copy(os.Stdout, c)
		close(done)
	}()
	buf := make([]byte, 256)
	for {
		select {
		case <-done:
			return nil
		default:
		}
		if pendingPasswordQuestion() {
			restore()
			fmt.Print("\r\n")
			runPasswordAgent(false)
			setRaw()
			continue
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 300)
		if err == unix.EINTR || (err == nil && n == 0) {
			continue
		}
		if err != nil || fds[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
			return err
		}
		m, err := unix.Read(fd, buf)
		if err != nil || m <= 0 {
			return nil
		}
		if _, err := c.Write(buf[:m]); err != nil {
			return nil
		}
	}
}

// askPasswordDir is where systemd puts its pending password questions; a
// var for the tests.
var askPasswordDir = "/run/systemd/ask-password"

// pendingPasswordQuestion says whether systemd asks for a password now
// (cryptsetup's own prompt, after tpm2-kira gave no key or a wrong one).
func pendingPasswordQuestion() bool {
	ents, err := os.ReadDir(askPasswordDir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "ask.") {
			return true
		}
	}
	return false
}

// runPasswordAgent answers systemd's pending password questions on this
// terminal - and with watch, every later one as well.
func runPasswordAgent(watch bool) error {
	args := []string{"--query"}
	if watch {
		args = append(args, "--watch")
	}
	cmd := exec.Command("systemd-tty-ask-password-agent", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// RemoteStatusLines is control's view of the image's network and SSH
// settings: one line each, and what is missing for them.
func RemoteStatusLines(r RemoteConfig) []string {
	var out []string
	if r.Net.Mode == "off" {
		return []string{"Network at boot: off"}
	}
	out = append(out, "Network at boot: "+r.Net.Describe())
	if r.SSH.On {
		s := fmt.Sprintf("SSH at boot: port %d", r.SSH.Port)
		if r.SSH.Hold > 0 {
			s += fmt.Sprintf(", the boot waits %d s for a confirmation", r.SSH.Hold)
		} else {
			s += ", the boot waits until it is confirmed (or Enter at the console)"
		}
		out = append(out, s)
	}
	return out
}

// authorizedKeyCount is the number of keys tinysshd would accept from the
// file, -1 when it cannot be read.
func authorizedKeyCount(path string) int {
	keys, err := ed25519AuthorizedKeys(path)
	if err != nil {
		return -1
	}
	return len(keys)
}
