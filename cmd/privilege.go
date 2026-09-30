package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"syscall"

	"github.com/google/go-tpm/tpm2/transport"
)

// Privilege checks and the messages that go with them.
//
// tpm2-kira talks to /dev/tpm0 directly and keeps its signing key under
// /var/lib/tpm2-kira, both of which are root-owned on a normal system. Without
// root, the underlying failure is a bare "permission denied" from a syscall,
// several layers below anything that knows what the user was trying to do. These
// helpers turn that into a sentence naming the command and the fix.

// IsRoot reports whether the process has an effective UID of 0, which covers
// both a root login and sudo.
func IsRoot() bool { return os.Geteuid() == 0 }

// RequireRoot returns an error explaining that a command needs root.
//
// reason completes the sentence "... needs root, because it ...", so it should
// say what the command does that requires the privilege rather than restating
// that it needs it.
func RequireRoot(command, reason string) error {
	if IsRoot() {
		return nil
	}

	return fmt.Errorf("'tpm2-kira %s' needs root, because it %s.\n"+
		"  Run it again with sudo:\n"+
		"      sudo tpm2-kira %s ...\n"+
		"  Current user has UID %d.",
		command, reason, command, os.Geteuid())
}

// OpenTPMDevice opens the TPM and explains why it could not be opened.
//
// Every command that touches the TPM goes through here, so the same explanation
// appears wherever the device cannot be opened — including for the commands that
// deliberately are not gated on root, since a udev rule can grant a group access
// to /dev/tpm0 and those are the ones worth granting.
func OpenTPMDevice(tpmPath string) (transport.TPMCloser, error) {
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err == nil {
		return tpmDev, nil
	}

	if isPermissionError(err) {
		return nil, tpmPermissionError(tpmPath)
	}

	if errors.Is(err, fs.ErrNotExist) {
		return nil, tpmMissingError(tpmPath)
	}

	// go-tpm checks the file mode before opening, so a path that is neither a
	// character device nor a socket never reaches a permission or existence
	// check. Its own message ("unsupported TPM file mode") does not say what was
	// expected.
	//
	// Only a regular file or a directory is called out. A socket is how swtpm is
	// reached, so a failure on one is about the simulator rather than the path,
	// and saying "that is a socket" would send the reader the wrong way.
	if info, statErr := os.Stat(tpmPath); statErr == nil {
		if mode := info.Mode(); mode.IsRegular() || mode.IsDir() {
			return nil, fmt.Errorf("%s is not a TPM device.\n"+
				"  A TPM is a character device such as /dev/tpm0 or /dev/tpmrm0 — or a socket,\n"+
				"  for a software TPM — but %s is %s.\n"+
				"  Pass the right path with --tpm.", tpmPath, tpmPath, describeFileType(mode))
		}
	}

	return nil, fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
}

// tpmPermissionError explains that the TPM device cannot be opened by this user.
func tpmPermissionError(tpmPath string) error {
	suffix := ""
	if !IsRoot() {
		suffix = fmt.Sprintf("\n  This command is running as UID %d, not root.", os.Geteuid())
	}

	return fmt.Errorf("cannot open the TPM at %s: permission denied.\n"+
		"  tpm2-kira talks to the TPM directly, and %s is normally root-only,\n"+
		"  so most commands have to be run with sudo:\n"+
		"      sudo tpm2-kira ...\n"+
		"  A udev rule granting a group access to %s is the alternative if you\n"+
		"  want read-only commands such as 'reveal' to work without root.%s",
		tpmPath, tpmPath, tpmPath, suffix)
}

// tpmMissingError explains that there is no TPM device at the given path.
func tpmMissingError(tpmPath string) error {
	return fmt.Errorf("no TPM device at %s.\n"+
		"  Check that a TPM 2.0 is enabled in the firmware settings and that the\n"+
		"  kernel found it:\n"+
		"      ls -l /dev/tpm*\n"+
		"      sudo dmesg | grep -i tpm\n"+
		"  Use --tpm to point at a different device, for example /dev/tpmrm0.", tpmPath)
}

// describeFileType names what a path actually is, for the message above.
func describeFileType(mode os.FileMode) string {
	if mode.IsDir() {
		return "a directory"
	}
	return "a regular file"
}

// isPermissionError reports whether err is ultimately EACCES or EPERM, however
// deeply it has been wrapped.
func isPermissionError(err error) bool {
	return errors.Is(err, fs.ErrPermission) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPERM)
}

// ── Signing key file permissions ──────────────────────────────────────────

// warnedKeyModes remembers which key files have already been reported, so a
// multi-slot reseal — which opens the key once per slot — says it once.
var (
	warnedKeyModesMu sync.Mutex
	warnedKeyModes   = map[string]bool{}
)

// WarnAboutKeyPermissions reports a signing key file that others can reach.
//
// The private key is the recovery master key: anyone holding it can unseal
// regardless of PCR state (SECURITY-BACKGROUND §4.6). Its protection on disk is
// filesystem permissions and nothing else, so a mode that lets another account
// read it undoes the PCR policy entirely for that account.
//
// This is advisory. The key still works, and refusing to use a readable key
// would be worse than saying so — it would leave someone unable to reseal at the
// moment they most need to.
func WarnAboutKeyPermissions(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}

	mode := info.Mode().Perm()

	groupOrOther := mode & 0o077
	ownerWritable := mode&0o200 != 0

	if groupOrOther == 0 && !ownerWritable {
		return
	}

	warnedKeyModesMu.Lock()
	already := warnedKeyModes[path]
	warnedKeyModes[path] = true
	warnedKeyModesMu.Unlock()

	if already {
		return
	}

	if groupOrOther != 0 {
		fmt.Printf("WARNING: the signing key %s is mode %04o.\n", path, mode)
		fmt.Println("  Other accounts on this machine can read it. The signing key is the recovery")
		fmt.Println("  master key: whoever holds it can unseal the secret whatever the PCRs say, so")
		fmt.Println("  its only protection on disk is this mode.")
		fmt.Printf("      sudo chmod 400 %s\n", path)

		if owner := fileOwner(info); owner >= 0 && owner != 0 {
			fmt.Printf("  It is also owned by UID %d rather than root.\n", owner)
			fmt.Printf("      sudo chown root %s\n", path)
		}

		fmt.Println()
		return
	}

	// Owner-writable only: no exposure, just an easy accident.
	fmt.Printf("Note: the signing key %s is mode %04o; 0400 would protect it from\n", path, mode)
	fmt.Printf("  accidental modification, since it is only ever read:  sudo chmod 400 %s\n\n", path)
}

// fileOwner extracts the owning UID, or -1 where that is not available.
func fileOwner(info os.FileInfo) int {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid)
	}
	return -1
}
