package cmd

import (
	"fmt"
	"io/fs"
	"os"
)

// SigningKeyFileMode is the only permission mode accepted for the signing key
// files: readable by the owner, writable by no one.
const SigningKeyFileMode fs.FileMode = 0400

// WriteSigningKeyFile creates path with data and SigningKeyFileMode.
//
// The file must not exist yet: O_EXCL refuses to overwrite a key or to follow a
// symlink planted at the path. The mode is set with fchmod after creation,
// because the mode passed to open is filtered through the umask.
func WriteSigningKeyFile(path string, data []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, SigningKeyFileMode)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			os.Remove(path)
		}
	}()

	if err = f.Chmod(SigningKeyFileMode); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

// CheckSigningKeyFileMode fails unless path is a regular file with exactly
// SigningKeyFileMode.
func CheckSigningKeyFileMode(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot check permissions of signing key file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("signing key file %s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm != SigningKeyFileMode {
		return fmt.Errorf("signing key file %s has permissions %04o, want %04o.\n"+
			"  Fix with: chmod %o %s",
			path, perm, SigningKeyFileMode, SigningKeyFileMode, path)
	}
	return nil
}
