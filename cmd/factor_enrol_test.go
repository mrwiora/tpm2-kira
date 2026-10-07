package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The key file for luksAddKey goes nowhere but tmpfs, in a directory root
// owns and nobody else enters, and never over an existing file.
func TestCheckKeyOut(t *testing.T) {
	if err := checkKeyOut(filepath.Join(".", "luks.key")); err == nil || !strings.Contains(err.Error(), "not on tmpfs") {
		t.Fatalf("a key file on the repository's disk: %v", err)
	}
	dir := t.TempDir() // /tmp, usually tmpfs; owned by this user
	err := checkKeyOut(filepath.Join(dir, "luks.key"))
	switch {
	case err == nil && os.Geteuid() == 0:
	case err != nil && strings.Contains(err.Error(), "not on tmpfs"):
		t.Skip("the temporary directory is not on tmpfs here")
	case err != nil && os.Geteuid() != 0 && strings.Contains(err.Error(), "owned by root"):
	default:
		t.Fatalf("%v (uid %d)", err, os.Geteuid())
	}
	if err := writeKeyOut(filepath.Join(dir, "k"), []byte("key\n")); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(dir, "k")); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if _, err := os.Stat(filepath.Join(dir, "k.tmp")); err == nil {
		t.Fatal("the temporary file was left behind")
	}
}
