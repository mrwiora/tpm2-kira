// Package bootwait is one wait per boot for the TPM's device, however many steps
// ask: machine-id, run and the close each say how long after the first of them
// began to wait they still care, and the time already spent counts.
//
// Dir holds when the first wait began, by the boot's clock. It lives in the
// initrd's own tmpfs, written before anything that parses outside input runs, and
// only what is confined and has no write there runs beside it. It only ever
// shortens a wait: the device is looked for all the same, and what follows from
// its absence (the close's ladder, the firmware's signs, the late closer) reads
// nothing here. A file that lies can cost a boot a wait, never a close.
package bootwait

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// SinceFile holds when the first wait began, in nanoseconds of CLOCK_BOOTTIME.
const SinceFile = "tpm-wait-since"

// Dir survives from one step of the boot to the next; a var for the tests.
var Dir = "/run/tpm2-kira"

// Await reports whether the device is there, waiting at most until wait after the
// first wait of this boot began. A device that is there writes nothing.
func Await(path string, wait time.Duration) bool {
	if tpmdev.AwaitNode(path, 0) {
		return true
	}
	if wait <= 0 {
		return false
	}
	return tpmdev.AwaitNode(path, left(wait))
}

// left is what remains of wait. Whatever cannot be read as a time of this boot
// counts as no wait so far: a wait too long, never one too short by its own fault.
func left(wait time.Duration) time.Duration {
	now, err := boottime()
	if err != nil {
		return wait
	}
	since, err := readSince()
	if errors.Is(err, fs.ErrNotExist) {
		writeSince(now)
		return wait
	}
	if err != nil || since > now {
		return wait
	}
	return max(since+wait-now, 0)
}

func boottime() (time.Duration, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return time.Duration(ts.Nano()), nil
}

func readSince() (time.Duration, error) {
	b, err := os.ReadFile(filepath.Join(Dir, SinceFile))
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("not a time of this boot")
	}
	return time.Duration(n), nil
}

// writeSince keeps the first word: a step that cannot write waits its own wait, as
// each does then.
func writeSince(now time.Duration) {
	if err := os.MkdirAll(Dir, 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(Dir, SinceFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(strconv.FormatInt(int64(now), 10) + "\n")
}
