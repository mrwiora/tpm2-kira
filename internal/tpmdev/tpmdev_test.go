package tpmdev

import (
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTPM answers every command on a socket: rc for the first busy
// answers, then a GetCapability response with the manufacturer.
func fakeTPM(t *testing.T, busy int32, rc uint32) (string, *atomic.Int32) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tpm.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var asked atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			// The whole command: its header says how long it is.
			hdr := make([]byte, 10)
			if _, err := io.ReadFull(c, hdr); err != nil {
				c.Close()
				continue
			}
			io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint32(hdr[2:6]))-10)
			var rsp []byte
			if asked.Add(1) <= busy {
				rsp = binary.BigEndian.AppendUint16(nil, 0x8001) // TPM_ST_NO_SESSIONS
				rsp = binary.BigEndian.AppendUint32(rsp, 10)
				rsp = binary.BigEndian.AppendUint32(rsp, rc)
			} else {
				rsp = binary.BigEndian.AppendUint16(nil, 0x8001)
				rsp = binary.BigEndian.AppendUint32(rsp, 27)
				rsp = binary.BigEndian.AppendUint32(rsp, 0) // TPM_RC_SUCCESS
				rsp = append(rsp, 0)                        // moreData
				rsp = binary.BigEndian.AppendUint32(rsp, 6) // TPM_CAP_TPM_PROPERTIES
				rsp = binary.BigEndian.AppendUint32(rsp, 1) // one property
				rsp = binary.BigEndian.AppendUint32(rsp, 0x105)
				rsp = binary.BigEndian.AppendUint32(rsp, 0x49424d00) // "IBM"
			}
			c.Write(rsp)
			c.Close()
		}
	}()
	return path, &asked
}

// A TPM that is still busy when the boot opens it is asked again until it
// answers.
func TestOpenWaitsForATPMThatIsBusy(t *testing.T) {
	defer func(w, r time.Duration) { openWait, openRetry = w, r }(openWait, openRetry)
	openWait, openRetry = 5*time.Second, 10*time.Millisecond
	path, asked := fakeTPM(t, 3, 0x90A) // TPM_RC_TESTING: the self-test runs
	tpm, err := Open(path)
	if err != nil {
		t.Fatalf("a TPM that answers on the fourth question: %v", err)
	}
	tpm.Close()
	if n := asked.Load(); n != 4 {
		t.Fatalf("asked %d times, want 4", n)
	}
}

// One that never answers is an error with the TPM's own answer, not a
// guess about the device.
func TestOpenSaysWhatTheTPMAnswered(t *testing.T) {
	defer func(w, r time.Duration) { openWait, openRetry = w, r }(openWait, openRetry)
	openWait, openRetry = 50*time.Millisecond, 10*time.Millisecond
	path, _ := fakeTPM(t, 1<<30, 0x101) // TPM_RC_FAILURE
	_, err := Open(path)
	if err == nil || !strings.Contains(err.Error(), "does not answer") || !strings.Contains(err.Error(), "TPM_RC_FAILURE") {
		t.Fatalf("a TPM that never answers: %v", err)
	}
}

// A path where nothing is fails at once, without waiting.
func TestOpenOfNothingFailsAtOnce(t *testing.T) {
	start := time.Now()
	if _, err := Open(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("opened nothing")
	}
	if time.Since(start) > time.Second {
		t.Fatal("waited for a TPM that is not there")
	}
}
