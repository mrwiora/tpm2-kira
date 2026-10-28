package journal

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

var JournalSocket = "/run/systemd/journal/socket" // a var: tests point it elsewhere

// Priorities, as syslog(3) and journald have them.
const (
	PrioInfo  = 6
	PrioDebug = 7
)

var (
	JournalOnce sync.Once
	JournalConn *net.UnixConn // nil: not under systemd, or no journald
	LogFile     *os.File      // TPM2_KIRA_LOG, when set and writable
	// NarrateOut is where the narrative goes without a journal (tests
	// replace it).
	NarrateOut io.Writer = os.Stdout
	// NarrateDebug: the narrative is also written to stderr.
	NarrateDebug bool
)

func journal() *net.UnixConn {
	JournalOnce.Do(func() {
		if path := os.Getenv("TPM2_KIRA_LOG"); path != "" {
			if f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err == nil {
				LogFile = f
			}
			return
		}
		if os.Getenv("JOURNAL_STREAM") == "" {
			return
		}
		c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: JournalSocket, Net: "unixgram"})
		if err != nil {
			return
		}
		JournalConn = c
	})
	return JournalConn
}

// Narrate writes one line of the narrative (priority info).
func Narrate(format string, args ...any) {
	NarrateAt(PrioInfo, format, args...)
}

// NarrateAt writes one line of the narrative at the priority.
func NarrateAt(prio int, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	c := journal()
	switch {
	case c != nil:
		c.Write(journalEntry(msg, prio))
	case LogFile != nil:
		fmt.Fprintln(LogFile, msg)
	default:
		fmt.Fprintln(NarrateOut, msg)
		return
	}
	if NarrateDebug {
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

// Narrator is an io.Writer whose every line is narrated.
type Narrator struct{ Prio int }

func (n Narrator) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		NarrateAt(n.Prio, "%s", line)
	}
	return len(p), nil
}
