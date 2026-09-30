package cmd

import (
	"errors"
	"fmt"
	"io/fs"
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
		"udev rule",
		"/dev/tpm0",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("the message should contain %q, got:\n%s", want, message)
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
