package cmd

// The SSH server of the code screen (docs/REMOTE-SSH.md). With TPM2_KIRA_SSH
// on, the image's tpm2-kira.service runs 'tpm2-kira run --ssh=PORT': the
// process that holds the boot opens the port and starts 'tpm2-kira remote
// serve' on it, without privileges (remote_serve.go, remote_privsep.go).
// That process speaks SSH and hands every login over as a session of the
// code screen: it sees the codes, and Enter there confirms them and
// releases the boot, as Enter at the console does. The password prompt
// then opens in the session that released, and cryptsetup's own prompt,
// should it follow, is answered there too (remote_agent.go).
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RemoteOptions are run's SSH settings; Port 0 is no SSH server.
type RemoteOptions struct {
	Port           int
	Hold           time.Duration // 0: until a confirmation comes
	TPM            string        // the TPM the host key is unsealed with
	HostKey        string        // the sealed host key (ImageSealedHostKey)
	AuthorizedKeys string        // who may log in (ImageAuthorizedKeys)
}

// remoteServer is the SSH server and its sessions.
type remoteServer struct {
	opts    RemoteOptions
	child   *serveChild
	log     func(string)
	console io.Writer // the console's own lines
	hostKey hostKeyAtBoot

	mu       sync.Mutex
	sessions []*remoteSession // in the order they came
	screen   []byte           // the last code screen, for a session that comes in
	released bool             // the boot is released; keys go to prompts now
	stopped  bool             // released at the console: nothing is served
	target   *remoteSession   // the session that released, for the prompt
	done     chan struct{}    // closed when stop has ended
	releases chan struct{}    // a session confirmed
	changed  chan struct{}    // a session came or went
}

// remoteSession is one login, handed over by 'remote serve'.
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

// startRemote unseals the host key, opens the port and starts 'remote
// serve' on it. A server that cannot start is said on the console and the
// code screen goes on without SSH.
func startRemote(o RemoteOptions, console io.Writer, log func(string)) (*remoteServer, error) {
	if o.AuthorizedKeys == "" {
		o.AuthorizedKeys = ImageAuthorizedKeys
	}
	authorized, _, err := authorizedKeys(o.AuthorizedKeys)
	if err != nil {
		return nil, err
	}
	if len(authorized) == 0 {
		return nil, fmt.Errorf("%s holds no key: nobody could log in", o.AuthorizedKeys)
	}
	// Unsealed now, while the code screen holds the boot ahead of the OS
	// separator: after it, PCR 0 and 7 no longer fit the policy. The key
	// stays in this process; 'remote serve' asks it for signatures.
	hk, err := prepareHostKey(o.TPM, o.HostKey)
	if err != nil {
		return nil, fmt.Errorf("SSH host key: %w", err)
	}
	if hk.Throwaway != "" {
		log("ssh: serving a throwaway host key: " + hk.Throwaway)
	}
	tcp, err := net.Listen("tcp", ":"+strconv.Itoa(o.Port))
	if err != nil {
		return nil, err
	}
	if o.Port == 0 {
		o.Port = tcp.Addr().(*net.TCPAddr).Port
	}
	r := &remoteServer{opts: o, log: log, console: console, hostKey: hk,
		done: make(chan struct{}), releases: make(chan struct{}, 1), changed: make(chan struct{}, 1)}
	child, how, err := startServe(tcp.(*net.TCPListener), hk.key, authorized, log, r.addSession)
	if err != nil {
		return nil, fmt.Errorf("remote serve: %w", err)
	}
	r.child = child
	log(describeServe(child, how))
	log(fmt.Sprintf("ssh: listening on port %d, host key %s", o.Port, hk.Fingerprint))
	go r.answerPasswordQuestions()
	return r, nil
}

// addSession takes a login 'remote serve' handed over.
func (r *remoteServer) addSession(c net.Conn, who string) {
	s := &remoteSession{conn: c, keys: make(chan byte, maxPassphrase), closed: make(chan struct{})}
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		c.Close()
		return
	}
	r.sessions = append(r.sessions, s)
	screen, released := r.screen, r.released
	r.mu.Unlock()
	r.log("ssh: a session is in: " + who)
	r.signal(r.changed)
	if released {
		s.write([]byte(fmt.Sprintf("%s The boot is released; the password is asked here when a disk asks for its key.\r\n", kiraTag(tagYellow))))
	} else if len(screen) > 0 {
		s.write(screen)
	}
	go r.read(s)
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

// stop tells every session why and closes it, then ends 'remote serve',
// which closes the port.
func (r *remoteServer) stop(why string) {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	sessions := r.sessions
	r.sessions = nil
	r.mu.Unlock()
	for _, s := range sessions {
		s.write([]byte(fmt.Sprintf("\r\n%s %s\r\n", kiraTag(tagYellow), why)))
		s.close()
	}
	// The closed sessions end their relays in the child, which hands the
	// notice on; then the child goes.
	r.child.stop()
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
	return askIn(s, b.String(), fmt.Sprintf("%s for disk %s:", what, volume), nil)
}

// askIn asks in session s until something is typed: header once, then
// the prompt. It fails when the session leaves or cancel is closed.
func askIn(s *remoteSession, header, prompt string, cancel <-chan struct{}) ([]byte, error) {
	// What was typed before the question is not part of the answer.
	for drained := false; !drained; {
		select {
		case <-s.keys:
		default:
			drained = true
		}
	}
	for {
		s.write([]byte(header + fmt.Sprintf("\r\n%s \033[1m%s\033[0m ", kiraTag(tagBlue), prompt)))
		header = ""
		pw, err := readRawPassphrase(func() (byte, error) {
			select {
			case c := <-s.keys:
				return c, nil
			case <-s.closed:
				return 0, io.EOF
			case <-cancel:
				return 0, errAskCancelled
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

// authorizedKeyCount is the number of keys that may log in from the file,
// -1 when it cannot be read.
func authorizedKeyCount(path string) int {
	keys, _, err := authorizedKeys(path)
	if err != nil {
		return -1
	}
	return len(keys)
}
