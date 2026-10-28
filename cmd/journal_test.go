package cmd

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/journal"
)

// Under systemd the narrative goes to journald's socket with a priority
// and never to the console; by hand it is stdout.
func TestNarrateGoesToTheJournal(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "j.sock")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	oldSock, oldOut := journal.JournalSocket, journal.NarrateOut
	journal.JournalSocket = sock
	var out bytes.Buffer
	journal.NarrateOut = &out
	journal.JournalOnce = sync.Once{}
	journal.JournalConn = nil
	defer func() {
		journal.JournalSocket, journal.NarrateOut = oldSock, oldOut
		journal.JournalOnce = sync.Once{}
		journal.JournalConn = nil
	}()

	t.Setenv("JOURNAL_STREAM", "9:12345")
	journal.Narrate("tpm2-kira: %s asks for its key", "cryptroot")
	buf := make([]byte, 4096)
	n, _, err := l.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := string(buf[:n])
	for _, want := range []string{"SYSLOG_IDENTIFIER=tpm2-kira\n", "PRIORITY=6\n", "MESSAGE=tpm2-kira: cryptroot asks for its key\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("journal entry lacks %q:\n%s", want, got)
		}
	}
	if out.Len() != 0 {
		t.Errorf("the narrative reached stdout under systemd: %q", out.String())
	}
	journal.NarrateAt(journal.PrioDebug, "two\nlines")
	n, _, _ = l.ReadFromUnix(buf)
	if got := buf[:n]; !bytes.Contains(got, []byte("PRIORITY=7\n")) || !bytes.Contains(got, []byte("MESSAGE\n\x09\x00\x00\x00\x00\x00\x00\x00two\nlines\n")) {
		t.Errorf("a two-line message is not in the binary form:\n%q", got)
	}

	// By hand: stdout.
	journal.JournalOnce = sync.Once{}
	journal.JournalConn = nil
	t.Setenv("JOURNAL_STREAM", "")
	journal.Narrate("by hand")
	if out.String() != "by hand\n" {
		t.Errorf("by hand: %q", out.String())
	}

	// An initramfs without a journal (Debian): the log file, and nothing
	// on stdout.
	journal.JournalOnce = sync.Once{}
	logPath := filepath.Join(t.TempDir(), "tpm2-kira.log")
	t.Setenv("TPM2_KIRA_LOG", logPath)
	t.Setenv("JOURNAL_STREAM", "9:1")
	out.Reset()
	journal.Narrate("to the file")
	journal.LogFile.Close()
	journal.LogFile = nil
	journal.JournalOnce = sync.Once{}
	if b, _ := os.ReadFile(logPath); string(b) != "to the file\n" || out.Len() != 0 {
		t.Errorf("log file: %q, stdout: %q", b, out.String())
	}
}
