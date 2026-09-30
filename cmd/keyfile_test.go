package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWriteSigningKeyFile(t *testing.T) {
	t.Run("Creates file with mode 0400 regardless of umask", func(t *testing.T) {
		old := syscall.Umask(0)
		defer syscall.Umask(old)

		path := filepath.Join(t.TempDir(), "seal.key")
		if err := WriteSigningKeyFile(path, []byte("key")); err != nil {
			t.Fatalf("WriteSigningKeyFile() error = %v", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0400 {
			t.Errorf("mode = %04o, want 0400", perm)
		}
		if data, _ := os.ReadFile(path); string(data) != "key" {
			t.Errorf("content = %q, want %q", data, "key")
		}
	})

	t.Run("Refuses to overwrite an existing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "seal.key")
		if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := WriteSigningKeyFile(path, []byte("new")); err == nil {
			t.Error("WriteSigningKeyFile() expected error for existing file, got nil")
		}
		if data, _ := os.ReadFile(path); string(data) != "original" {
			t.Errorf("existing file was modified: %q", data)
		}
	})
}

func TestCheckSigningKeyFileMode(t *testing.T) {
	dir := t.TempDir()

	for _, mode := range []os.FileMode{0400, 0600, 0440, 0444, 0644, 0000} {
		path := filepath.Join(dir, "key-"+mode.String())
		if err := os.WriteFile(path, []byte("k"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		err := CheckSigningKeyFileMode(path)
		if mode == 0400 && err != nil {
			t.Errorf("mode %04o: unexpected error %v", mode, err)
		}
		if mode != 0400 {
			if err == nil {
				t.Errorf("mode %04o: expected error, got nil", mode)
			} else if !strings.Contains(err.Error(), "chmod 400") {
				t.Errorf("mode %04o: error %q should suggest 'chmod 400'", mode, err)
			}
		}
	}

	if err := CheckSigningKeyFileMode(filepath.Join(dir, "missing")); err == nil {
		t.Error("expected error for missing file, got nil")
	}
	if err := CheckSigningKeyFileMode(dir); err == nil {
		t.Error("expected error for directory, got nil")
	}
}

func TestSealRejectsKeyFileMode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		privMode os.FileMode
		pubMode  os.FileMode
		badPath  string
	}{
		{name: "private key 0600", privMode: 0600, pubMode: 0400, badPath: "seal.key"},
		{name: "public key 0644", privMode: 0400, pubMode: 0644, badPath: "seal.pub"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			priv := filepath.Join(dir, "seal.key")
			pub := filepath.Join(dir, "seal.pub")
			for path, mode := range map[string]os.FileMode{priv: tc.privMode, pub: tc.pubMode} {
				if err := os.WriteFile(path, []byte("k"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
			}

			err := Seal("/nonexistent/tpm", "0,7", NVRAMSlotStart, pub, priv, false, PCRHashAlgoSHA256, false)
			if err == nil {
				t.Fatal("Seal() expected error, got nil")
			}
			if !strings.Contains(err.Error(), "cannot seal") || !strings.Contains(err.Error(), tc.badPath) {
				t.Errorf("Seal() error = %q, want permission error naming %s", err, tc.badPath)
			}
		})
	}
}
