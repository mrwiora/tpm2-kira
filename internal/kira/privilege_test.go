package kira

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRequireRoot(t *testing.T) {
	err := RequireRoot("seal", "writes to TPM NVRAM")

	if IsRoot() {
		if err != nil {
			t.Errorf("running as root should be permitted, got: %v", err)
		}
		t.Skip("running as root; the refusal path cannot be exercised here")
	}

	if err == nil {
		t.Fatal("a non-root user should be refused")
	}

	message := err.Error()
	for _, want := range []string{
		"tpm2-kira seal",                    // names the command
		"writes to TPM NVRAM",               // says why
		"sudo tpm2-kira seal",               // gives the fix
		fmt.Sprintf("UID %d", os.Geteuid()), // says what it saw
	} {
		if !strings.Contains(message, want) {
			t.Errorf("the message should contain %q, got:\n%s", want, message)
		}
	}
}

// TestIsPermissionError covers the wrapping that matters: the syscall error
// arrives several layers down, and a check that only handles the bare value
// would miss it and fall through to an unhelpful message.
func TestIsPermissionError(t *testing.T) {
	permissionErrors := []error{
		syscall.EACCES,
		syscall.EPERM,
		fs.ErrPermission,
		&os.PathError{Op: "open", Path: "/dev/tpm0", Err: syscall.EACCES},
		fmt.Errorf("failed to open TPM: %w",
			&os.PathError{Op: "open", Path: "/dev/tpm0", Err: syscall.EACCES}),
		fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", syscall.EPERM)),
	}

	for i, err := range permissionErrors {
		if !isPermissionError(err) {
			t.Errorf("case %d: %v should be recognised as a permission error", i, err)
		}
	}

	otherErrors := []error{
		errors.New("something else"),
		syscall.ENOENT,
		&os.PathError{Op: "open", Path: "/dev/tpm0", Err: syscall.ENOENT},
		fmt.Errorf("wrapped: %w", syscall.ENODEV),
	}

	for i, err := range otherErrors {
		if isPermissionError(err) {
			t.Errorf("case %d: %v should not be treated as a permission error", i, err)
		}
	}
}

// TestOpenTPMDeviceMissingDevice checks the other common failure, which is not
// about privilege at all and must not be reported as though it were.
func TestOpenTPMDeviceMissingDevice(t *testing.T) {
	_, err := OpenTPMDevice("/nonexistent/tpm-device")
	if err == nil {
		t.Fatal("opening a device that does not exist should fail")
	}

	message := err.Error()
	if !strings.Contains(message, "no TPM device at") {
		t.Errorf("a missing device should be reported as such, got:\n%s", message)
	}
	if strings.Contains(message, "permission denied") {
		t.Errorf("a missing device must not be blamed on privilege, got:\n%s", message)
	}
	if !strings.Contains(message, "dmesg") {
		t.Errorf("the message should suggest how to look, got:\n%s", message)
	}
}

// TestTPMPermissionMessage checks the wording of the privilege explanation,
// which cannot be produced on demand through OpenTPMDevice: go-tpm rejects a
// path by file mode before it ever tries to open it, so only a real root-only
// character device reaches the permission branch.
func TestTPMPermissionMessage(t *testing.T) {
	message := tpmPermissionError("/dev/tpm0").Error()

	for _, want := range []string{
		"permission denied",
		"sudo tpm2-kira",
		"/dev/tpm0",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("the message should contain %q, got:\n%s", want, message)
		}
	}

	// Loosening the device permissions is never the advice: anything that can
	// reach the TPM can ask it to unseal, which is why the threat model puts
	// non-root userspace outside the boundary.
	for _, unwanted := range []string{"udev", "chmod", "GROUP="} {
		if strings.Contains(message, unwanted) {
			t.Errorf("the message must not suggest %q, got:\n%s", unwanted, message)
		}
	}

	// The UID is only worth reporting when it is the likely cause.
	if IsRoot() {
		if strings.Contains(message, "not root") {
			t.Errorf("running as root, the message should not blame the UID:\n%s", message)
		}
	} else if !strings.Contains(message, "not root") {
		t.Errorf("a non-root user should be told so:\n%s", message)
	}
}

// TestOpenTPMDeviceRejectsNonDevice covers a plausible typo — pointing --tpm at
// a file or a directory. go-tpm reports only "unsupported TPM file mode", which
// does not say what it expected.
func TestOpenTPMDeviceRejectsNonDevice(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "not-a-tpm")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatalf("failed to create the test file: %v", err)
	}

	for path, want := range map[string]string{
		regular:     "a regular file",
		t.TempDir(): "a directory",
	} {
		_, err := OpenTPMDevice(path)
		if err == nil {
			t.Fatalf("%s should not open as a TPM", path)
		}

		message := err.Error()
		if !strings.Contains(message, "is not a TPM device") {
			t.Errorf("%s: expected a clear rejection, got:\n%s", path, message)
		}
		if !strings.Contains(message, want) {
			t.Errorf("%s: the message should say it is %s, got:\n%s", path, want, message)
		}
		if !strings.Contains(message, "/dev/tpm0") {
			t.Errorf("%s: the message should name what is expected, got:\n%s", path, message)
		}
	}
}

// TestOpenTPMDeviceRealDevice exercises the permission branch for real when
// /dev/tpm0 exists and this user cannot open it, which is the case the message
// was written for.
func TestOpenTPMDeviceRealDevice(t *testing.T) {
	if IsRoot() {
		t.Skip("running as root; /dev/tpm0 is openable")
	}

	info, err := os.Stat("/dev/tpm0")
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		t.Skip("no /dev/tpm0 character device here")
	}

	if _, err := OpenTPMDevice("/dev/tpm0"); err != nil {
		if !strings.Contains(err.Error(), "sudo tpm2-kira") {
			t.Errorf("expected the privilege explanation, got:\n%s", err)
		}
	}
}

// captureStdout runs fn and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create a pipe: %v", err)
	}
	os.Stdout = write

	done := make(chan string, 1)
	go func() {
		var buf strings.Builder
		io.Copy(&buf, read)
		done <- buf.String()
	}()

	fn()

	write.Close()
	os.Stdout = original
	return <-done
}

// writeKey creates a key file with a given mode and returns its path.
func writeKey(t *testing.T, mode os.FileMode) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "seal.key")
	if err := os.WriteFile(path, []byte("not really a key"), mode); err != nil {
		t.Fatalf("failed to write the test key: %v", err)
	}
	// WriteFile is subject to umask, so set the mode explicitly.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("failed to chmod the test key: %v", err)
	}

	forgetKeyWarning(path)
	return path
}

// forgetKeyWarning clears the once-per-file guard so a test can observe output.
func forgetKeyWarning(path string) {
	warnedKeyModesMu.Lock()
	delete(warnedKeyModes, path)
	warnedKeyModesMu.Unlock()
}

// TestWarnAboutKeyPermissions covers the three tiers: a mode that exposes the
// key to other accounts, one that merely allows accidental modification, and the
// recommended one that should say nothing at all.
func TestWarnAboutKeyPermissions(t *testing.T) {
	t.Run("0400 is silent", func(t *testing.T) {
		path := writeKey(t, 0o400)
		if out := captureStdout(t, func() { WarnAboutKeyPermissions(path) }); out != "" {
			t.Errorf("0400 is the recommended mode and should say nothing, got:\n%s", out)
		}
	})

	t.Run("0600 gets a note, not a warning", func(t *testing.T) {
		path := writeKey(t, 0o600)
		out := captureStdout(t, func() { WarnAboutKeyPermissions(path) })

		if !strings.Contains(out, "chmod 400") {
			t.Errorf("expected the fix to be given, got:\n%s", out)
		}
		if strings.Contains(out, "WARNING") {
			t.Errorf("0600 exposes the key to nobody, so it should not be a WARNING:\n%s", out)
		}
		if strings.Contains(out, "can read it") {
			t.Errorf("0600 is not readable by others; the message should not say so:\n%s", out)
		}
	})

	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o444} {
		t.Run("group or other access warns: "+mode.String(), func(t *testing.T) {
			path := writeKey(t, mode)
			out := captureStdout(t, func() { WarnAboutKeyPermissions(path) })

			if !strings.Contains(out, "WARNING") {
				t.Errorf("mode %04o lets others reach the key and should warn, got:\n%s", mode, out)
			}
			if !strings.Contains(out, "recovery") {
				t.Errorf("the message should say why it matters, got:\n%s", out)
			}
			if !strings.Contains(out, "chmod 400") {
				t.Errorf("the message should give the fix, got:\n%s", out)
			}
		})
	}
}

// TestWarnAboutKeyPermissionsWarnsOnce matters because a reseal with no --nvram
// walks every populated slot and opens the key for each one; repeating the same
// warning sixteen times would bury everything else.
func TestWarnAboutKeyPermissionsWarnsOnce(t *testing.T) {
	path := writeKey(t, 0o644)

	first := captureStdout(t, func() { WarnAboutKeyPermissions(path) })
	if !strings.Contains(first, "WARNING") {
		t.Fatalf("the first call should warn, got:\n%s", first)
	}

	second := captureStdout(t, func() { WarnAboutKeyPermissions(path) })
	if second != "" {
		t.Errorf("the second call should be silent, got:\n%s", second)
	}

	// A different file is a different key and warns on its own.
	other := writeKey(t, 0o644)
	if out := captureStdout(t, func() { WarnAboutKeyPermissions(other) }); !strings.Contains(out, "WARNING") {
		t.Errorf("a second key should warn on its own, got:\n%s", out)
	}
}

// TestWarnAboutKeyPermissionsMissingFile checks that a path that is not there is
// not reported as a permission problem — OpenSigningKey already explains that
// case, and a second, wrong explanation would be worse than none.
func TestWarnAboutKeyPermissionsMissingFile(t *testing.T) {
	out := captureStdout(t, func() {
		WarnAboutKeyPermissions(filepath.Join(t.TempDir(), "absent.key"))
	})
	if out != "" {
		t.Errorf("a missing file should produce no permission warning, got:\n%s", out)
	}
}

// TestOpenSigningKeyWarnsAboutMode checks the wiring: the warning has to reach
// the path that actually signs.
func TestOpenSigningKeyWarnsAboutMode(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	path := filepath.Join(t.TempDir(), "seal.key")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatalf("failed to write the key: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	forgetKeyWarning(path)

	var opened SigningKey
	out := captureStdout(t, func() {
		var openErr error
		opened, openErr = OpenSigningKey(KeyRef{Kind: KeyRefFile, Path: path}, nil, false)
		if openErr != nil {
			t.Errorf("OpenSigningKey failed: %v", openErr)
		}
	})
	if opened != nil {
		opened.Close()
	}

	if !strings.Contains(out, "WARNING") {
		t.Errorf("opening a world-readable key should warn, got:\n%s", out)
	}
}

// TestRequireTPMAccessGatesDeviceNotCommand is the regression guard for where
// this check belongs. Root is required to open the TPM character device, and a
// software TPM on a socket needs no privilege — keying the requirement off the
// command name instead broke the whole integration suite for a non-root user.
func TestRequireTPMAccessGatesDeviceNotCommand(t *testing.T) {
	if IsRoot() {
		t.Skip("running as root; nothing is refused")
	}

	t.Run("a socket is allowed", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "swtpm.sock")

		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Skipf("cannot create a unix socket here: %v", err)
		}
		defer listener.Close()

		if err := RequireTPMAccess(path); err != nil {
			t.Errorf("a software TPM socket this user owns must not be refused: %v", err)
		}
	})

	t.Run("an absent path is allowed through to the open", func(t *testing.T) {
		if err := RequireTPMAccess(filepath.Join(t.TempDir(), "nothing")); err != nil {
			t.Errorf("a missing path should be reported by the open, not here: %v", err)
		}
	})

	t.Run("a regular file is allowed through to the open", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("failed to write the test file: %v", err)
		}
		if err := RequireTPMAccess(path); err != nil {
			t.Errorf("a regular file should be reported by the open, not here: %v", err)
		}
	})

	t.Run("a character device is refused", func(t *testing.T) {
		// /dev/null is a character device present everywhere, which is what
		// this check keys off.
		info, err := os.Stat("/dev/null")
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			t.Skip("/dev/null is not a character device here")
		}

		err = RequireTPMAccess("/dev/null")
		if err == nil {
			t.Fatal("a TPM character device must be refused for a non-root user")
		}

		message := err.Error()
		for _, want := range []string{"only root may open", "sudo tpm2-kira", "/dev/null"} {
			if !strings.Contains(message, want) {
				t.Errorf("the message should contain %q, got:\n%s", want, message)
			}
		}
		for _, unwanted := range []string{"udev", "chmod", "GROUP="} {
			if strings.Contains(message, unwanted) {
				t.Errorf("the message must not suggest %q, got:\n%s", unwanted, message)
			}
		}
	})

	t.Run("the message names the command when one is known", func(t *testing.T) {
		info, err := os.Stat("/dev/null")
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			t.Skip("/dev/null is not a character device here")
		}

		previous := InvokedCommand
		InvokedCommand = "reveal"
		defer func() { InvokedCommand = previous }()

		err = RequireTPMAccess("/dev/null")
		if err == nil || !strings.Contains(err.Error(), "sudo tpm2-kira reveal") {
			t.Errorf("expected the command to be named, got: %v", err)
		}
	})
}

// TestCheckPrivilegeGatesOnlyFilesystemCommands checks the small remaining
// up-front gate: setup always writes under /var/lib, so it needs root whatever
// its TPM path is, while the rest are decided at the device.
func TestCheckPrivilegeGatesOnlyFilesystemCommands(t *testing.T) {
	if IsRoot() {
		t.Skip("running as root; nothing is refused")
	}

	if err := CheckPrivilege("setup", nil); err == nil {
		t.Error("setup writes to /var/lib and must require root")
	} else if !strings.Contains(err.Error(), "needs root") {
		t.Errorf("expected a root explanation, got: %v", err)
	}

	// These may legitimately run without root against a software TPM, so they
	// must not be refused before the device is even known.
	for _, argv := range [][]string{
		{"seal"}, {"reseal"}, {"reveal"}, {"reveal-plain"}, {"run"}, {"info"},
		{"nvram", "list"}, {"nvram", "status"}, {"nvram", "delete"}, {"nvram", "restore"},
		{"version"}, {"help"}, {"pcrtips"},
		{"yubikey", "list"}, {"yubikey", "status"},
	} {
		if err := CheckPrivilege(argv[0], argv[1:]); err != nil {
			t.Errorf("%q must not be refused before its TPM path is known: %v",
				strings.Join(argv, " "), err)
		}
	}
}
