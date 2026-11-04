package signing

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/tpm2-trust/tpm2-kira/internal/diskkey"
	"github.com/tpm2-trust/tpm2-kira/internal/piv"
	"github.com/tpm2-trust/tpm2-kira/internal/termguard"
	"github.com/tpm2-trust/tpm2-kira/internal/wipe"
	"golang.org/x/sys/unix"
)

// The YubiKey's PIN: where it comes from and what holds it. It is bytes, in a locked
// buffer of the final size, from its source to the card, and wiped: no string, no
// growing slice, no copy but the one VERIFY's command takes (internal/piv wipes it).
// Sources in order: the descriptor a script named, the PIN file, the terminal. A source
// that was asked for and fails is the error: nothing falls through to the next.

// pinBuffer is what a PIN is read into; a var for the tests.
var pinBuffer = diskkey.PassphraseBuffer

// readPINLine reads one line, without its end, a byte at a time and into pinBuffer. A
// line longer than a PIV PIN can be is an error at once, with nothing kept; what it
// returns the caller wipes, and is empty when the input was.
func readPINLine(r io.Reader) ([]byte, error) {
	line := pinBuffer()
	one := make([]byte, 1)
	defer wipe.Bytes(one)
	for {
		n, err := r.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				break
			}
			// One byte past the limit, for the \r of a line that ends in \r\n.
			if len(line) == piv.MaxPINLength+1 {
				wipe.Bytes(line)
				return nil, errPINTooLong()
			}
			line = append(line, one[0])
			continue
		}
		if err == nil || errors.Is(err, io.EOF) {
			break
		}
		wipe.Bytes(line)
		return nil, err
	}
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line[n-1] = 0
		line = line[:n-1]
	}
	if len(line) > piv.MaxPINLength {
		wipe.Bytes(line)
		return nil, errPINTooLong()
	}
	return line, nil
}

// errPINTooLong is a function: the boot binary links this package, and a variable's
// initializer would bring a piece of this file into it (boot_binary_test.go).
func errPINTooLong() error {
	return fmt.Errorf("more than %d bytes on the line: a PIV PIN is %d to %d", piv.MaxPINLength, piv.MinPINLength, piv.MaxPINLength)
}

// descriptorPIN is what --pin-fd read. given stays once it is: the signer asks no other
// source then, also when the PIN has been used.
var descriptorPIN struct {
	given  bool
	source string
	pin    []byte
}

// UsePINDescriptor reads the PIN from an open descriptor, one line, now, and closes it:
// before the command starts anything that would inherit it. A command calls it once,
// after its flags, and any error ends the command: a script asked for this source.
func UsePINDescriptor(fd int) error {
	pin, err := readPINDescriptor(fd)
	if err != nil {
		return fmt.Errorf("--pin-fd %d: %w", fd, err)
	}
	forgetDescriptorPIN()
	descriptorPIN.given, descriptorPIN.source, descriptorPIN.pin = true, fmt.Sprintf("descriptor %d", fd), pin
	return nil
}

func forgetDescriptorPIN() {
	wipe.Bytes(descriptorPIN.pin)
	descriptorPIN.given, descriptorPIN.source, descriptorPIN.pin = false, "", nil
}

// readPINDescriptor takes a pipe, a socket or a file. The standard streams are the
// command's, and a descriptor closed in the parent can by now be the Go runtime's own
// (its poller's, not a file of any of these types): neither is read or closed here. A
// file others may read is refused as the PIN file is, unread.
func readPINDescriptor(fd int) ([]byte, error) {
	if fd < 3 {
		return nil, errors.New("3 or above: 0, 1 and 2 are the command's own streams")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("the descriptor is not open: %w", err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFIFO, unix.S_IFSOCK, unix.S_IFREG:
	default:
		return nil, errors.New("the descriptor is not open on a pipe, a socket or a file")
	}
	f := os.NewFile(uintptr(fd), "the descriptor")
	defer f.Close()
	if st.Mode&unix.S_IFMT == unix.S_IFREG && looseFile(st.Mode&0o777, st.Uid) {
		return nil, fmt.Errorf("the file on it can be read by other users, or root does not own it (mode %03o, owner %d),\n"+
			"  so it is not read. Make it readable by root only, chown root: and chmod 600, and consider\n"+
			"  changing the PIN, since it may already have been read", st.Mode&0o777, st.Uid)
	}
	pin, err := readPINLine(f)
	if err != nil {
		return nil, err
	}
	if len(pin) == 0 {
		wipe.Bytes(pin)
		return nil, errors.New("no PIN on the descriptor")
	}
	return pin, nil
}

// PromptPIN asks for the PIN on the terminal; tests replace it. What it returns the
// caller wipes.
var PromptPIN = promptPINOnTTY

// readPIN finds the PIN without asking when it can: what --pin-fd read, then the PIN
// file control stores, where the unattended reseal finds it, and only then the terminal. source names where the PIN came from, for messages;
// the session owns the PIN from here.
func readPIN(s *YubiKeySigner) (pin []byte, source string, err error) {
	if descriptorPIN.given {
		pin, descriptorPIN.pin = descriptorPIN.pin, nil
		if pin == nil {
			return nil, "", errors.New("--pin-fd's PIN is used")
		}
		return pin, descriptorPIN.source, nil
	}
	pin, ok, err := pinFromFile()
	if err != nil {
		return nil, "", err
	}
	if ok {
		return pin, PINPath(), nil
	}
	pin, err = PromptPIN(s)
	return pin, "the terminal", err
}

// pinFromFile returns the PIN the PIN file stores, if it may be used. A
// PIN in a file that others can read, or that root does not own, is refused
// rather than used: it has to be treated as already disclosed.
func pinFromFile() ([]byte, bool, error) {
	path := PINPath()
	pin, loose, err := StoredPIN(path)
	if loose {
		wipe.Bytes(pin)
		return nil, false, fmt.Errorf("%s holds the YubiKey PIN but other users can read it, or root does not own it,\n"+
			"  so tpm2-kira does not use it. Make it readable by root only:\n"+
			"      chown root: %s && chmod 600 %s\n"+
			"  and consider changing the PIN, since it may already have been read",
			path, path, path)
	}
	if err != nil {
		return nil, false, err
	}
	return pin, pin != nil, nil
}

// warnIfNoUnattendedPIN tells the user, right after the PIN was accepted for
// a manual seal or reseal, when the automatic reseal after an initramfs
// rebuild will not have it. Silent when the PIN file provides the PIN.
func warnIfNoUnattendedPIN(w io.Writer) {
	if stored, _ := PINStored(PINPath()); stored {
		return
	}
	fmt.Fprintf(w, "WARNING: there is no PIN in %s.\n", PINPath())
	fmt.Fprintln(w, "         The automatic approval after kernel and initramfs updates will therefore")
	fmt.Fprintln(w, "         have no PIN: it will be SKIPPED, and the next boot will show a PCR")
	fmt.Fprintln(w, "         mismatch until you approve by hand. 'tpm2-kira control' stores the PIN")
	fmt.Fprintln(w, "         (the signing key step), readable by root alone.")
}

// ignoredPINEnv held the PIN once: a string, not wipeable, inherited by every child,
// readable in /proc/PID/environ.
const ignoredPINEnv = "TPM2_KIRA_PIN"

// pinEnvIgnored: this command found the variable set. Without a PIN, that is part of the
// reason, as a hook captures the output and shows the reason alone.
var pinEnvIgnored bool

// IgnorePINEnv is for a script that still sets the variable: it finds out here, once,
// also in what the command starts, as the variable goes from the environment they get.
func IgnorePINEnv(w io.Writer) {
	if _, set := os.LookupEnv(ignoredPINEnv); !set {
		return
	}
	os.Unsetenv(ignoredPINEnv)
	pinEnvIgnored = true
	fmt.Fprintf(w, "tpm2-kira: WARNING: %s is set and ignored: the YubiKey's PIN comes from --pin-fd N, from %s or from the terminal\n", ignoredPINEnv, PINPath())
}

// noTerminalPIN is the reason when no source has a PIN and there is no terminal to ask on.
func noTerminalPIN() error {
	const reason = "no PIN: store it with tpm2-kira control, or give it with --pin-fd N (there is no terminal to ask on)"
	if pinEnvIgnored {
		return errors.New(reason + "\n" + ignoredPINEnv + " is set and ignored: it gives no PIN")
	}
	return errors.New(reason)
}

func promptPINOnTTY(s *YubiKeySigner) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, noTerminalPIN()
	}
	defer tty.Close()
	fmt.Fprintf(tty, "PIN for %s: ", s.Describe())
	pin, err := readNoEcho(tty)
	fmt.Fprintln(tty)
	if err != nil {
		return nil, fmt.Errorf("reading the PIN: %w", err)
	}
	if len(pin) == 0 {
		wipe.Bytes(pin)
		return nil, errors.New("no PIN entered")
	}
	return pin, nil
}

// readNoEcho reads the PIN's line from a terminal, in lines as the terminal has them and
// with Ctrl-C and Ctrl-\ still signals. The terminal is given back with its input
// flushed on every way out, a signal's too: the rest of a line too long or half typed
// must not answer whoever reads next, a shell. Ctrl-Z does nothing here: a shell takes a
// stopped job's terminal back, and the prompt would go on with the echo on.
func readNoEcho(tty *os.File) ([]byte, error) {
	restore, err := termguard.Hold{
		Change: func(t *unix.Termios) {
			t.Lflag &^= unix.ECHO
			t.Lflag |= unix.ICANON | unix.ISIG
			t.Cc[unix.VSUSP] = 0
		},
		OnSignal: func() { fmt.Fprintln(tty) },
		Flush:    true,
	}.Take(int(tty.Fd()))
	if err != nil {
		return nil, err
	}
	defer restore()
	return readPINLine(tty)
}

// PINPath is the YubiKey's PIN, next to control.conf: the PIN alone,
// root's and readable by root alone. It is no setting of the image, so it
// has a file of its own: control.conf holds what the image is built with,
// and only that.
func PINPath() string {
	// TPM2_KIRA_CONTROL_CONF moves control.conf for the tests, and the PIN
	// with it.
	conf := "/etc/tpm2-kira/control.conf"
	if p := os.Getenv("TPM2_KIRA_CONTROL_CONF"); p != "" {
		conf = p
	}
	return filepath.Join(filepath.Dir(conf), "pin")
}

// StorePIN writes the PIN, readable by root alone.
func StorePIN(path string, pin []byte) error {
	for _, c := range pin {
		if c == '\n' {
			return errors.New("the PIN cannot hold a newline")
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(pin); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString("\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// StoredPIN is the PIN the file at path stores, which the caller wipes: nil when there
// is none; loose when the file is not root's, or group or others may read it - such a
// PIN is refused, it has to be treated as already disclosed. An error: the file holds
// something that is no PIN, or does not read, which is no reason to ask elsewhere. For
// the signer only (pinFromFile).
func StoredPIN(path string) (pin []byte, loose bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, false, nil
	}
	uid, owned := ownerOf(st)
	loose = !owned || looseFile(uint32(st.Mode().Perm()), uid)
	pin, err = readPINLine(f)
	if err != nil {
		return nil, loose, fmt.Errorf("%s: %w", path, err)
	}
	if len(pin) == 0 {
		wipe.Bytes(pin)
		return nil, false, nil
	}
	return pin, loose, nil
}

// looseFile says a file's permissions or owner disclose what it holds: group or others
// may read it, or it is neither root's nor this user's.
func looseFile(perm, uid uint32) bool {
	return perm&0o077 != 0 || !trustedOwner(uid)
}

// PINStored says whether the file at path stores a PIN, and whether it is
// loose (readable by others): the PIN's value stays out of it.
func PINStored(path string) (stored, loose bool) {
	pin, loose, err := StoredPIN(path)
	defer wipe.Bytes(pin)
	return pin != nil || err != nil, loose
}
