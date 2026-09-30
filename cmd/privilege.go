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
// appears wherever the device cannot be opened. Commands are gated on root before
// they get this far, so reaching the permission branch means either an unusual
// device path or a system where root itself cannot open it.
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
		"  tpm2-kira talks to the TPM directly, and the TPM device is root-only —\n"+
		"  deliberately, since anything that can reach it can ask the TPM to unseal.\n"+
		"  Run the command with sudo:\n"+
		"      sudo tpm2-kira ...%s",
		tpmPath, suffix)
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

// rootCommands are the commands that need root, with the reason completing
// "... needs root, because it ...".
//
// Every command that opens the TPM is here. The device is root-only by design:
// anything that can reach it can ask the TPM to unseal while the PCRs still
// match, which is why the threat model puts non-root userspace outside the trust
// boundary (SECURITY-BACKGROUND §8). So there is no read-only tier to exempt —
// reading the TPM is exactly the capability being protected.
//
// Absent from this list: version, help and pcrtips, which touch nothing, and the
// yubikey subcommands that only inspect a token through pcscd.
var rootCommands = map[string]string{
	"setup":        "writes the signing key to /var/lib/tpm2-kira",
	"seal":         "writes to TPM NVRAM and reads the signing key from /var/lib/tpm2-kira",
	"reseal":       "writes to TPM NVRAM and reads the signing key from /var/lib/tpm2-kira",
	"reveal":       "reads the sealed secret from the TPM",
	"reveal-plain": "reads the sealed secret from the TPM",
	"run":          "reads the sealed secret from the TPM",
	"info":         "reads the sealed blob from TPM NVRAM",
}

// rootNVRAMSubcommands covers the nvram subcommands, all of which open the TPM.
var rootNVRAMSubcommands = map[string]string{
	"list":    "reads TPM NVRAM",
	"status":  "reads TPM NVRAM",
	"delete":  "removes a sealed secret from TPM NVRAM",
	"restore": "writes a sealed secret back to TPM NVRAM",
}

// rootYubiKeySubcommands are the yubikey subcommands that need root: adopt
// caches a public key under /var/lib and checks the key against the TPM.
// Listing and inspecting a token needs only pcscd.
var rootYubiKeySubcommands = map[string]string{
	"adopt": "caches the public key under /var/lib/tpm2-kira and checks it against the TPM",
}

// CheckPrivilege refuses a command that cannot work without root.
func CheckPrivilege(command string, args []string) error {
	if reason, ok := rootCommands[command]; ok {
		return RequireRoot(command, reason)
	}

	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}

	switch command {
	case "nvram":
		if reason, ok := rootNVRAMSubcommands[sub]; ok {
			return RequireRoot("nvram "+sub, reason)
		}
	case "yubikey":
		if reason, ok := rootYubiKeySubcommands[sub]; ok {
			return RequireRoot("yubikey "+sub, reason)
		}
	}

	return nil
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
