package cmd

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

// The boot's narrative - what the key provider and the gate did and when -
// is for the journal, where it survives the boot and can be read in
// order; the console at boot is the code screen's, and a line of
// narrative landing between the code and the prompt is noise there. Under
// systemd (JOURNAL_STREAM is set) narrate writes straight to journald's
// socket, with a priority, so nothing of it reaches the console; in an
// initramfs without a journal (Debian) the scripts set TPM2_KIRA_LOG to a
// file that survives into the booted system; run by hand it is plain
// stdout. Failures and warnings keep going to stderr, which the units
// send to the console as well. With debug on, the narrative is also
// written to stderr: whoever asked for it wants to see it live.

var journalSocket = "/run/systemd/journal/socket" // a var: tests point it elsewhere

// Priorities, as syslog(3) and journald have them.
const (
	prioInfo  = 6
	prioDebug = 7
)

var (
	journalOnce sync.Once
	journalConn *net.UnixConn // nil: not under systemd, or no journald
	logFile     *os.File      // TPM2_KIRA_LOG, when set and writable
	// narrateOut is where the narrative goes without a journal (tests
	// replace it).
	narrateOut io.Writer = os.Stdout
	// narrateDebug: the narrative is also written to stderr.
	narrateDebug bool
)

func journal() *net.UnixConn {
	journalOnce.Do(func() {
		if path := os.Getenv("TPM2_KIRA_LOG"); path != "" {
			if f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err == nil {
				logFile = f
			}
			return
		}
		if os.Getenv("JOURNAL_STREAM") == "" {
			return
		}
		c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: journalSocket, Net: "unixgram"})
		if err != nil {
			return
		}
		journalConn = c
	})
	return journalConn
}

// narrate writes one line of the narrative (priority info).
func narrate(format string, args ...any) {
	narrateAt(prioInfo, format, args...)
}

// narrateAt writes one line of the narrative at the priority.
func narrateAt(prio int, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	c := journal()
	switch {
	case c != nil:
		c.Write(journalEntry(msg, prio))
	case logFile != nil:
		fmt.Fprintln(logFile, msg)
	default:
		fmt.Fprintln(narrateOut, msg)
		return
	}
	if narrateDebug {
		fmt.Fprintln(os.Stderr, msg)
	}
}

// journalEntry is the native journal protocol: FIELD=value lines, or, for
// a value with a newline, FIELD, a little-endian 64-bit length, the bytes.
func journalEntry(msg string, prio int) []byte {
	var b strings.Builder
	b.WriteString("SYSLOG_IDENTIFIER=tpm2-kira\n")
	fmt.Fprintf(&b, "PRIORITY=%d\n", prio)
	if strings.Contains(msg, "\n") {
		b.WriteString("MESSAGE\n")
		var n [8]byte
		binary.LittleEndian.PutUint64(n[:], uint64(len(msg)))
		b.Write(n[:])
		b.WriteString(msg)
		b.WriteString("\n")
	} else {
		b.WriteString("MESSAGE=" + msg + "\n")
	}
	return []byte(b.String())
}

// narrator is an io.Writer whose every line is narrated.
type narrator struct{ prio int }

func (n narrator) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		narrateAt(n.prio, "%s", line)
	}
	return len(p), nil
}
