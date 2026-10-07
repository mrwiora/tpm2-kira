package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// The key provider for systemd-cryptsetup (crypttab(5), "AF_UNIX KEY
// FILES"). When a volume's key field names a stream socket in the file
// system, systemd-cryptsetup connects to it at the moment it activates the
// volume and reads the key from the connection; the peer name of its
// abstract socket says which volume (and whether it wants the key itself or
// a saved token key). tpm2-kira listens there in the initrd, so the unlock
// of the disk is a question to tpm2-kira and not a prompt of its own:
// today it answers with what the person types at its own prompt, later
// with a key derived from that and a factor the phone released
// (PLAN-FACTORRELEASE.md). systemd-cryptsetup waits for the answer for as
// long as it takes, and a wrong or missing answer sends it to its own
// prompt for the remaining tries (UNLOCK-DISK.md §4): the passphrase can
// always be entered by hand, which is why there is no enforced mode.

// DefaultUnlockSocket is where the initrd units put the key socket.
const DefaultUnlockSocket = "/run/tpm2-kira/unlock.sock"

// unlockRequest is one connection from systemd-cryptsetup.
type unlockRequest struct {
	Volume string
	// Kind is "cryptsetup" when the key itself is wanted; for the token
	// logics it is "cryptsetup-tpm2", "cryptsetup-fido2-salt" or
	// "cryptsetup-pkcs11", which want a saved token key, not a passphrase.
	Kind string
}

// Direct reports whether the request is for the volume's key (passphrase).
func (r unlockRequest) Direct() bool { return r.Kind == "cryptsetup" }

// parseUnlockPeer reads the volume out of systemd-cryptsetup's abstract
// source socket name: NUL ‖ random ‖ "/cryptsetup/" ‖ volume (crypttab(5)).
func parseUnlockPeer(name string) (unlockRequest, error) {
	name = strings.TrimPrefix(name, "@")
	name = strings.TrimPrefix(name, "\x00")
	// Go renders abstract names with a leading '@'; a connection from a
	// path-bound socket, which systemd never makes, has none of this.
	i := strings.Index(name, "/cryptsetup")
	if i < 0 {
		return unlockRequest{}, fmt.Errorf("not a systemd-cryptsetup connection (peer %q)", name)
	}
	rest := name[i+1:] // "cryptsetup.../volume"
	kind, volume, ok := strings.Cut(rest, "/")
	if !ok || volume == "" || strings.Contains(volume, "/") {
		return unlockRequest{}, fmt.Errorf("malformed systemd-cryptsetup peer %q", name)
	}
	switch kind {
	case "cryptsetup", "cryptsetup-tpm2", "cryptsetup-fido2-salt", "cryptsetup-pkcs11":
	default:
		return unlockRequest{}, fmt.Errorf("unknown systemd-cryptsetup request %q", kind)
	}
	return unlockRequest{Volume: volume, Kind: kind}, nil
}

// unlockServer answers systemd-cryptsetup's key requests on one socket.
type unlockServer struct {
	l    net.Listener
	key  func(volume string) ([]byte, error) // the key for a volume, or why not
	log  func(string)
	mu   sync.Mutex // one answer at a time: the prompt is one terminal
	gate chan struct{}
	done chan struct{}
	// prompting is set while a key is being asked for: the display must
	// not draw over the prompt (Prompting reports it).
	prompting atomic.Bool
}

// Prompting reports whether a prompt is open on the console right now.
func (s *unlockServer) Prompting() bool { return s.prompting.Load() }

// serveUnlock answers on l. Requests wait until release is called (the
// hold: the code screen is confirmed) and are then answered one after the
// other with key.
func serveUnlock(l net.Listener, key func(volume string) ([]byte, error), log func(string)) *unlockServer {
	noCoreDump()
	s := &unlockServer{l: l, key: key, log: log, gate: make(chan struct{}), done: make(chan struct{})}
	go s.run()
	return s
}

// release lets requests be answered from now on.
func (s *unlockServer) release() {
	select {
	case <-s.gate:
	default:
		s.log("unlock: the hold has ended; key requests are answered from now on")
		close(s.gate)
	}
}

// Close stops answering; connections in progress are cut.
func (s *unlockServer) Close() {
	s.l.Close()
	<-s.done
}

func (s *unlockServer) run() {
	defer close(s.done)
	var wg sync.WaitGroup
	for {
		c, err := s.l.Accept()
		if err != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.answer(c)
		}()
	}
	wg.Wait()
}

func (s *unlockServer) answer(c net.Conn) {
	defer c.Close()
	if err := peerIsUs(c); err != nil {
		s.log("unlock: refusing a connection: " + err.Error())
		return
	}
	req, err := parseUnlockPeer(c.RemoteAddr().String())
	if err != nil {
		s.log("unlock: refusing a connection: " + err.Error())
		return
	}
	if !req.Direct() {
		// A token's saved key lives in the LUKS header or a file; this
		// provider holds none. Closing without data lets systemd-cryptsetup
		// go on without it.
		s.log(fmt.Sprintf("unlock: %s asks for a %s key, which this provider does not hold", req.Volume, req.Kind))
		return
	}
	s.log(fmt.Sprintf("unlock: %s asks for its key", req.Volume))
	<-s.gate
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log(fmt.Sprintf("unlock: asking at the prompt for %s", req.Volume))
	s.prompting.Store(true)
	key, err := s.key(req.Volume)
	s.prompting.Store(false)
	if err != nil {
		s.log(fmt.Sprintf("unlock: no key for %s: %v", req.Volume, err))
		return
	}
	defer wipe(key)
	if _, err := c.Write(key); err != nil {
		s.log(fmt.Sprintf("unlock: writing the key for %s failed: %v", req.Volume, err))
		return
	}
	s.log(fmt.Sprintf("unlock: answered for %s (%d bytes)", req.Volume, len(key)))
}

// peerIsUs checks that the connection comes from a process of this user
// (SO_PEERCRED): root in the initrd, which is what systemd's password agent
// requires of a sender too. The socket's mode already says so; this does
// not depend on it.
func peerIsUs(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if int(cred.Uid) != os.Getuid() {
		return fmt.Errorf("peer is uid %d, not %d", cred.Uid, os.Getuid())
	}
	return nil
}

// wipe overwrites a key where it is; the full capacity, in case a shorter
// view of it is handed in.
func wipe(b []byte) {
	b = b[:cap(b)]
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// noCoreDump keeps a crash of this process from writing its memory, with
// a passphrase in it, to a file (PR_SET_DUMPABLE), as the cryptsetup
// tools do while they hold key material.
func noCoreDump() {
	unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

// listenUnlock is the key socket: the one systemd passed with the socket
// unit (LISTEN_FDS, tpm2-kira-unlock.socket) when it did, else a new one at
// path. Nil with no error when neither is wanted.
func listenUnlock(path string) (net.Listener, error) {
	if l := listenFromSystemd(); l != nil {
		return l, nil
	}
	if path == "" {
		return nil, nil
	}
	return listenGate(path)
}

// listenFromSystemd returns the first socket systemd handed over, if this
// process was started for a socket unit (sd_listen_fds(3)).
func listenFromSystemd() net.Listener {
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		return nil
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n < 1 {
		return nil
	}
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	return listenerFromFD(3) // SD_LISTEN_FDS_START
}

// listenerFromFD adopts a listening socket on fd.
func listenerFromFD(fd int) net.Listener {
	unix.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "unlock.sock")
	l, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return nil
	}
	return l
}

// consolePath is where the passphrase is asked: the console, or for tests
// the path in TPM2_KIRA_CONSOLE (a file, a pipe or a listening socket).
func consolePath() string {
	if p := os.Getenv("TPM2_KIRA_CONSOLE"); p != "" {
		return p
	}
	return "/dev/console"
}

// openConsole opens the console for a prompt; a socket is connected to.
func openConsole() (io.ReadWriteCloser, int, error) {
	path := consolePath()
	if st, err := os.Stat(path); err == nil && st.Mode()&os.ModeSocket != 0 {
		c, err := net.Dial("unix", path)
		return c, -1, err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, -1, err
	}
	return f, int(f.Fd()), nil
}

// consolePassphrase asks on the console for the passphrase of a volume,
// the way systemd's agent does: on /dev/console, echo off, a '*' per
// character, Backspace deletes, an empty line asks again. Ctrl-C gives up
// (no key: systemd-cryptsetup falls back to its own prompt).
func consolePassphrase(volume string) ([]byte, error) {
	return consoleAsk(volume, "passphrase", "")
}

// errUnlockSkipped: mode skip, or no remote salt in a mode that needs
// one: tpm2-kira gives no key, and cryptsetup's own prompt follows.
var errUnlockSkipped = errors.New("not tpm2-kira's to answer; cryptsetup's own prompt follows")

// diskKey is the key provider's answer, as unlock.conf says (unlock_config.go):
//
//	skip                 no answer: cryptsetup's own prompt, tpm2-kira untouched
//	password+salt        a typed password and a typed salt, combined (hashpwd2's derivation)
//	password+remotesalt  a typed password and the salt the verifier released in this boot
//	                     and the TPM opened (factor.go); without one, no answer
//
// salt returns the released salt or nil; the key is for the caller to wipe.
func diskKey(salt func() []byte, mode string) func(volume string) ([]byte, error) {
	return func(volume string) ([]byte, error) {
		var s []byte
		var note string
		switch mode {
		case UnlockPasswordSalt:
			note = "The key is derived from your password and salt (Argon2id, some seconds).\n" +
				"   (Ctrl-C skips to cryptsetup's own prompt, where the recovery passphrase works.)"
		case UnlockPasswordRemoteSalt:
			if s = salt(); s == nil {
				return nil, errors.New("no remote salt was released in this boot: " + errUnlockSkipped.Error())
			}
			note = "The verifier released the disk's salt: the key is derived from it and your password.\n" +
				"   (Ctrl-C skips to cryptsetup's own prompt, where the recovery passphrase works.)"
		default:
			return nil, errUnlockSkipped
		}
		pw, err := consoleAsk(volume, "password", note)
		if err != nil {
			return nil, err
		}
		defer wipe(pw)
		if s == nil {
			if s, err = consoleAsk(volume, "salt", ""); err != nil {
				return nil, err
			}
		}
		defer wipe(s)
		return Combine(pw, s)
	}
}

// consoleAsk asks on the console for a volume's passphrase or password,
// with a note above the prompt when there is one.
func consoleAsk(volume, what, note string) ([]byte, error) {
	con, fd, err := openConsole()
	if err != nil {
		return nil, fmt.Errorf("cannot open the console: %w", err)
	}
	defer con.Close()
	if note != "" {
		fmt.Fprintf(con, "\n🔑 %s\n", note)
	}
	for {
		fmt.Fprintf(con, "\n🔐 Please enter %s for disk %s: ", what, volume)
		pw, err := readPassphrase(con, fd)
		fmt.Fprintln(con)
		if err != nil {
			return nil, err
		}
		if len(pw) > 0 {
			return pw, nil
		}
	}
}

var errPassphraseCancelled = errors.New("cancelled at the passphrase prompt")

// readPassphrase reads one line with echo off from a terminal (fd), or a
// plain line from anything else (tests, a pipe, a socket: fd < 0).
func readPassphrase(f io.ReadWriter, fd int) ([]byte, error) {
	var old *unix.Termios
	if fd >= 0 {
		if t, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil {
			old = t
		}
	}
	if old == nil {
		// Not a terminal: one line, without its end, read a byte at a
		// time so that nothing past the line is taken from the input -
		// the next prompt reads the same pipe.
		var line []byte
		buf := make([]byte, 1)
		for {
			n, err := f.Read(buf)
			if n == 1 {
				if buf[0] == '\n' {
					break
				}
				line = append(line, buf[0])
				continue
			}
			if err != nil {
				if errors.Is(err, io.EOF) && len(line) > 0 {
					break
				}
				wipe(line)
				return nil, err
			}
		}
		return bytes.TrimRight(line, "\r"), nil
	}
	raw := *old
	// No echo, no line discipline, and no signals: Ctrl-C must arrive as
	// a byte to cancel the prompt, because the display has given up its
	// controlling terminal and a SIGINT from the tty would reach nobody.
	raw.Lflag &^= unix.ECHO | unix.ICANON | unix.ISIG
	raw.Cc[unix.VMIN], raw.Cc[unix.VTIME] = 1, 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return nil, err
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, old)
	// One buffer of the final size, so the passphrase is in one place
	// only: no growing slice leaves earlier copies behind for the garbage
	// collector to find. Locked in memory, as libcryptsetup locks its key
	// buffers; a page that the initrd could not swap out anyway.
	pw := make([]byte, 0, maxPassphrase)
	unix.Mlock(pw[:maxPassphrase])
	buf := make([]byte, 1)
	for {
		n, err := f.Read(buf)
		if err != nil || n == 0 {
			wipe(pw)
			if errors.Is(err, io.EOF) {
				return nil, errPassphraseCancelled
			}
			return nil, err
		}
		switch c := buf[0]; c {
		case '\n', '\r':
			return pw, nil
		case 3, 4: // Ctrl-C, Ctrl-D
			wipe(pw)
			return nil, errPassphraseCancelled
		case 127, 8: // Backspace
			if len(pw) > 0 {
				pw[len(pw)-1] = 0
				pw = pw[:len(pw)-1]
				fmt.Fprint(f, "\b \b")
			}
		default:
			if len(pw) == maxPassphrase {
				fmt.Fprint(f, "\a")
				continue
			}
			pw = append(pw, c)
			fmt.Fprint(f, "*")
		}
	}
}

// maxPassphrase is cryptsetup's own limit for a typed passphrase.
const maxPassphrase = 512

// unlockLogger writes to stderr, with the time: the journal or the
// initramfs log (Debian) is read after the boot.
func unlockLogger(debug bool) func(string) {
	return func(msg string) {
		fmt.Fprintf(os.Stderr, "tpm2-kira: %s %s\n", time.Now().UTC().Format("15:04:05.000"), msg)
	}
}
