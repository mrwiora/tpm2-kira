package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// SigningKeyFileMode is the only permission mode accepted for the signing key
// files: readable by the owner, writable by no one.
const SigningKeyFileMode fs.FileMode = 0400

// maxSigningKeyFileSize bounds what is read from a key file. PEM keys and the
// YubiKey key file are a few kilobytes at most.
const maxSigningKeyFileSize = 64 * 1024

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

// ReadSigningKeyFile reads a signing key file after checking it.
//
// The file is opened without following a symlink, and the checks run on the
// open descriptor, so the content returned is from the file that was
// checked: it cannot be swapped between check and read. The file must be a
// regular file with exactly SigningKeyFileMode, owned by root or by the
// caller, in a directory that only root or the caller can write to.
func ReadSigningKeyFile(path string) ([]byte, error) {
	// O_NONBLOCK keeps a FIFO planted at the path from blocking the open;
	// it has no effect on a regular file.
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("signing key file %s is a symbolic link; point to the file itself", path)
		}
		return nil, fmt.Errorf("cannot open signing key file %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot check signing key file %s: %w", path, err)
	}
	if err := checkSigningKeyFileInfo(path, info); err != nil {
		return nil, err
	}
	if err := checkSigningKeyDir(filepath.Dir(path)); err != nil {
		return nil, err
	}

	data, err := io.ReadAll(io.LimitReader(f, maxSigningKeyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read signing key file %s: %w", path, err)
	}
	if len(data) > maxSigningKeyFileSize {
		return nil, fmt.Errorf("signing key file %s is larger than %d bytes", path, maxSigningKeyFileSize)
	}
	return data, nil
}

// CheckSigningKeyFile reports whether path would be accepted by
// ReadSigningKeyFile, without returning the content.
func CheckSigningKeyFile(path string) error {
	_, err := ReadSigningKeyFile(path)
	return err
}

// trustedOwner reports whether uid may own a signing key file or its
// directory: root, or the user running tpm2-kira.
func trustedOwner(uid uint32) bool {
	return uid == 0 || uid == uint32(os.Geteuid())
}

func ownerOf(info fs.FileInfo) (uint32, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

func checkSigningKeyFileInfo(path string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("signing key file %s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm != SigningKeyFileMode {
		return fmt.Errorf("signing key file %s has permissions %04o, want %04o.\n"+
			"  Fix with: chmod %o %s",
			path, perm, SigningKeyFileMode, SigningKeyFileMode, path)
	}
	uid, ok := ownerOf(info)
	if !ok {
		return fmt.Errorf("cannot determine the owner of signing key file %s", path)
	}
	if !trustedOwner(uid) {
		return fmt.Errorf("signing key file %s is owned by uid %d; it must be owned by root.\n"+
			"  Fix with: chown root: %s", path, uid, path)
	}
	return nil
}

// checkSigningKeyDir refuses a directory in which someone other than root or
// the caller could replace the key file.
func checkSigningKeyDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("cannot check directory %s of the signing key: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	uid, ok := ownerOf(info)
	if !ok {
		return fmt.Errorf("cannot determine the owner of directory %s", dir)
	}
	if !trustedOwner(uid) {
		return fmt.Errorf("signing key directory %s is owned by uid %d; anyone owning it can replace the key.\n"+
			"  Move the key to a directory owned by root", dir, uid)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("signing key directory %s has permissions %04o: others can replace the key in it.\n"+
			"  Fix with: chmod go-w %s", dir, perm, dir)
	}
	return nil
}
