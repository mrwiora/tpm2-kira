package cmd

// cryptsetup's own prompt in the SSH session. When tpm2-kira has no key to
// give (no token on the volume, Ctrl-C, a wrong answer), cryptsetup asks
// for itself, and 'run' asks the same question in the session that has the
// prompt, beside the console. Whichever answers first wins. A session that
// leaves in the middle answers nothing: the question stays for the console
// and the next session.
//
//   - systemd (mkinitcpio): systemd-cryptsetup asks through systemd's
//     password agents (the "Password Agents" specification): a question is
//     a file /run/systemd/ask-password/ask.*, the answer a datagram to the
//     socket it names - "+" and the password. systemd removes the question
//     once it is answered.
//   - initramfs-tools: the keyscript's last try is cryptsetup's own
//     /lib/cryptsetup/askpass, which reads the console and the FIFO
//     /lib/cryptsetup/passfifo at once (as cryptroot-unlock answers it). A
//     question is an askpass process with the FIFO open, its prompt its
//     argument; the answer is written into the FIFO, and the question is
//     gone when the process is.

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// askPasswordDir is where systemd puts its pending password questions; a
// var for the tests.
var askPasswordDir = "/run/systemd/ask-password"

// errAskCancelled: the question was answered elsewhere while it was asked.
var errAskCancelled = errors.New("answered elsewhere")

// Where initramfs-tools' askpass and its FIFO are, and the processes are
// looked for; vars for the tests.
var (
	procDir     = "/proc"
	askpassBin  = "/lib/cryptsetup/askpass"
	askpassFIFO = "/lib/cryptsetup/passfifo"
)

// passwordQuestion is one ask.* file, or one askpass process (pid > 0).
type passwordQuestion struct {
	path     string // the ask.* file; for askpass, its /proc directory
	socket   string
	message  string
	notAfter uint64 // CLOCK_MONOTONIC µs, 0: no limit
	pid      int    // askpass
	start    string // askpass: its start time, so a reused pid is no question
}

// id names the question while it is pending.
func (q passwordQuestion) id() string {
	if q.pid > 0 {
		return "askpass:" + strconv.Itoa(q.pid) + ":" + q.start
	}
	return q.path
}

// gone says whether the question was answered elsewhere, or timed out.
func (q passwordQuestion) gone() bool {
	if q.pid > 0 {
		return processStart(q.path) != q.start
	}
	_, err := os.Stat(q.path)
	return err != nil || q.expired()
}

// readPasswordQuestion parses an ask.* file ([Ask] Socket=, Message=,
// NotAfter=).
func readPasswordQuestion(path string) (passwordQuestion, error) {
	f, err := os.Open(path)
	if err != nil {
		return passwordQuestion{}, err
	}
	defer f.Close()
	q := passwordQuestion{path: path}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "Socket":
			q.socket = v
		case "Message":
			q.message = v
		case "NotAfter":
			q.notAfter, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	if q.socket == "" {
		return q, fmt.Errorf("%s names no socket", path)
	}
	return q, sc.Err()
}

// expired says whether the question's time is up.
func (q passwordQuestion) expired() bool {
	if q.notAfter == 0 {
		return false
	}
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) != nil {
		return false
	}
	return uint64(ts.Nano()/1000) > q.notAfter
}

// answer sends the password to the question's socket, or into askpass'
// FIFO.
func (q passwordQuestion) answer(pw []byte) error {
	if q.pid > 0 {
		// Non-blocking: with no reader any more (askpass just ended), the
		// open fails instead of hanging.
		f, err := os.OpenFile(askpassFIFO, os.O_WRONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write(pw)
		return err
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: q.socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer c.Close()
	msg := append([]byte("+"), pw...)
	_, err = c.Write(msg)
	clear(msg)
	return err
}

// pendingPasswordQuestions lists the ask.* files there are now.
func pendingPasswordQuestions() []string {
	ents, err := os.ReadDir(askPasswordDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "ask.") {
			out = append(out, filepath.Join(askPasswordDir, e.Name()))
		}
	}
	return out
}

// processStart is a process' start time (proc_pid_stat(5), field 22), ""
// when it is gone.
func processStart(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return ""
	}
	_, rest, ok := strings.Cut(string(b), ") ") // the name may hold spaces
	if f := strings.Fields(rest); ok && len(f) > 19 {
		return f[19]
	}
	return ""
}

// pendingAskpass lists the askpass processes that read the FIFO now.
func pendingAskpass() []passwordQuestion {
	bin, err := filepath.EvalSymlinks(askpassBin)
	if err != nil {
		return nil
	}
	fifo, err := filepath.EvalSymlinks(askpassFIFO)
	if err != nil {
		return nil
	}
	ents, _ := os.ReadDir(procDir)
	var out []passwordQuestion
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join(procDir, e.Name())
		if exe, err := os.Readlink(filepath.Join(dir, "exe")); err != nil || exe != bin {
			continue
		}
		if !holdsFile(dir, fifo) {
			continue
		}
		q := passwordQuestion{path: dir, pid: pid, start: processStart(dir)}
		if q.start == "" {
			continue
		}
		// askpass PROMPT: the prompt is its argument.
		if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
			if args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00"); len(args) > 1 {
				q.message = strings.TrimSuffix(strings.TrimSpace(args[1]), ":")
			}
		}
		if q.message == "" {
			q.message = "the disk's passphrase"
		}
		out = append(out, q)
	}
	return out
}

// holdsFile says whether the process in dir has path open.
func holdsFile(dir, path string) bool {
	fds, _ := os.ReadDir(filepath.Join(dir, "fd"))
	for _, fd := range fds {
		if l, err := os.Readlink(filepath.Join(dir, "fd", fd.Name())); err == nil && l == path {
			return true
		}
	}
	return false
}

// pendingQuestions are the questions of both kinds there are now.
func pendingQuestions() []passwordQuestion {
	var out []passwordQuestion
	for _, path := range pendingPasswordQuestions() {
		q, err := readPasswordQuestion(path)
		if err != nil || q.expired() {
			continue
		}
		out = append(out, q)
	}
	return append(out, pendingAskpass()...)
}

// answerPasswordQuestions is the session's agent: from the release until
// the server stops, every question systemd asks while a session has the
// prompt is asked there, one at a time.
func (r *remoteServer) answerPasswordQuestions() {
	seen := map[string]bool{}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-tick.C:
		}
		r.mu.Lock()
		released := r.released
		r.mu.Unlock()
		if !released {
			continue
		}
		for _, q := range pendingQuestions() {
			if seen[q.id()] {
				continue
			}
			s := r.promptTarget()
			if s == nil {
				break // the console's agent asks
			}
			seen[q.id()] = true
			if !r.askQuestion(s, q) {
				// The session left: the question is the next session's.
				delete(seen, q.id())
			}
		}
	}
}

// askQuestion asks one question in session s, and answers it unless the
// session left or the question was answered elsewhere meanwhile. It
// reports false when the session left without an answer.
func (r *remoteServer) askQuestion(s *remoteSession, q passwordQuestion) bool {
	gone := make(chan struct{})
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stopWatch:
				return
			case <-r.done:
			case <-t.C:
				if !q.gone() {
					continue
				}
			}
			close(gone)
			return
		}
	}()
	r.log("ssh: asking cryptsetup's own question in the session")
	fmt.Fprintf(r.console, "%s cryptsetup's own prompt: asked in the SSH session too.\n", kiraTag(tagYellow))
	header := fmt.Sprintf("\r\n%s cryptsetup asks: %s\r\n         (the console asks it too; the first answer counts)\r\n", kiraTag(tagYellow), q.message)
	pw, err := askIn(s, header, "Passphrase:", gone)
	if errors.Is(err, errAskCancelled) {
		s.write([]byte(fmt.Sprintf("%s Answered at the console.\r\n", kiraTag(tagYellow))))
		return true
	}
	if err != nil {
		return false
	}
	defer clear(pw)
	if err := q.answer(pw); err != nil {
		r.log("ssh: answering cryptsetup: " + err.Error())
	}
	return true
}
