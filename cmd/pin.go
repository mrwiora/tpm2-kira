package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// PIN resolution for hardware-token signing keys.
//
// The PIN never appears in output, including under --debug. Only its source is
// ever named.

// PINEnvVar is the environment variable a token PIN is read from.
const PINEnvVar = "TPM2_KIRA_PIN"

// PINProvider supplies the PIN for a token that needs one.
//
// PIN may be called many times in one run: a PIV slot with PIN policy ALWAYS
// discards its verified state after every signature, so each signature needs a
// fresh verification. Implementations must therefore cache rather than prompt
// repeatedly.
type PINProvider interface {
	PIN() (string, error)
	// Source names where the PIN came from, for diagnostics. It never
	// contains the PIN itself.
	Source() string
}

// pinResolver resolves a PIN from the environment, a file, or a terminal
// prompt, in that order, and caches the result for the life of the process.
type pinResolver struct {
	filePath    string
	allowPrompt bool

	resolved bool
	pin      string
	source   string
}

// NewPINProvider builds the standard resolver.
//
// pinFile may be empty. Prompting is attempted only when stdin is a terminal,
// so an unattended hook fails with a usable message instead of hanging on a
// prompt nobody will ever see.
func NewPINProvider(pinFile string) PINProvider {
	return &pinResolver{
		filePath:    pinFile,
		allowPrompt: isTerminal(int(os.Stdin.Fd())),
	}
}

// StaticPIN returns a provider that always yields the given PIN. It exists for
// tests and for callers that already hold one.
func StaticPIN(pin, source string) PINProvider {
	return &pinResolver{resolved: true, pin: pin, source: source}
}

func (p *pinResolver) Source() string {
	if p.source == "" {
		return "unresolved"
	}
	return p.source
}

func (p *pinResolver) PIN() (string, error) {
	if p.resolved {
		return p.pin, nil
	}

	if pin, ok := os.LookupEnv(PINEnvVar); ok {
		if pin == "" {
			return "", fmt.Errorf("%s is set but empty", PINEnvVar)
		}
		p.set(pin, "$"+PINEnvVar)
		return p.pin, nil
	}

	if p.filePath != "" {
		pin, err := readPINFile(p.filePath)
		if err != nil {
			return "", err
		}
		p.set(pin, p.filePath)
		return p.pin, nil
	}

	if p.allowPrompt {
		pin, err := promptForPIN()
		if err != nil {
			return "", err
		}
		p.set(pin, "terminal prompt")
		return p.pin, nil
	}

	return "", &KeyUnavailableError{
		Reason: "no PIN available",
		Hint: fmt.Sprintf("set %s, pass --pin-file <path>, or run this from a terminal.\n"+
			"  For unattended reseals after an initramfs rebuild, put it in\n"+
			"  /etc/tpm2-kira/reseal.conf (mode 0600, root-owned).", PINEnvVar),
	}
}

func (p *pinResolver) set(pin, source string) {
	p.pin = pin
	p.source = source
	p.resolved = true
}

// readPINFile reads a PIN from a file, refusing one that others can read.
//
// The check is not paranoia about the PIN alone — a PIN authorises nothing
// without the token — but a PIN file readable by every user on the machine
// removes one of the two factors for anyone who later gets hold of the token.
func readPINFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", &KeyUnavailableError{
				Reason: fmt.Sprintf("PIN file %s does not exist", path),
				Err:    err,
			}
		}
		return "", fmt.Errorf("cannot read PIN file %s: %w", path, err)
	}

	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return "", fmt.Errorf("refusing to read PIN file %s: mode is %04o, which lets other users read it.\n"+
			"  Fix it with: chmod 600 %s", path, mode, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read PIN file %s: %w", path, err)
	}

	pin := strings.TrimRight(string(data), "\r\n")
	if pin == "" {
		return "", fmt.Errorf("PIN file %s is empty", path)
	}

	return pin, nil
}

// promptForPIN reads a PIN from the terminal with echo disabled.
func promptForPIN() (string, error) {
	fd := int(os.Stdin.Fd())

	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", fmt.Errorf("cannot read terminal settings to disable echo: %w", err)
	}

	noEcho := *termios
	noEcho.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &noEcho); err != nil {
		return "", fmt.Errorf("cannot disable terminal echo: %w", err)
	}
	defer func() {
		// Restoring matters more than the read succeeding: leaving the
		// terminal without echo makes the shell unusable afterwards.
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, termios)
		fmt.Fprintln(os.Stderr)
	}()

	fmt.Fprint(os.Stderr, "YubiKey PIN: ")

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("failed to read PIN: %w", err)
	}

	pin := strings.TrimRight(line, "\r\n")
	if pin == "" {
		return "", fmt.Errorf("no PIN entered")
	}

	return pin, nil
}

func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}
