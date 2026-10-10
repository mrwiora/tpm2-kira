package cmd

// cryptsetup's own prompt in the SSH session. When tpm2-kira has no key to
// give (no token on the volume, Ctrl-C, a wrong answer), systemd-cryptsetup
// asks through systemd's password agents (the "Password Agents"
// specification): a question is a file /run/systemd/ask-password/ask.*,
// the answer a datagram to the socket it names - "+" and the password, or
// "-" to cancel. The console's agent asks there; 'run' is the session's
// agent, answering in the session that has the prompt. Whichever answers
// first wins, and systemd removes the question. A session that leaves in
// the middle answers nothing: the question stays for the console.

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

// passwordQuestion is one ask.* file.
type passwordQuestion struct {
	path     string
	socket   string
	message  string
	notAfter uint64 // CLOCK_MONOTONIC µs, 0: no limit
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

// answer sends the password to the question's socket.
func (q passwordQuestion) answer(pw []byte) error {
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
		for _, path := range pendingPasswordQuestions() {
			if seen[path] {
				continue
			}
			s := r.promptTarget()
			if s == nil {
				break // the console's agent asks
			}
			seen[path] = true
			q, err := readPasswordQuestion(path)
			if err != nil || q.expired() {
				continue
			}
			if !r.askQuestion(s, q) {
				// The session left: the question is the next session's.
				delete(seen, path)
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
				if _, err := os.Stat(q.path); err == nil && !q.expired() {
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
