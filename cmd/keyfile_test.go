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

func TestCheckSigningKeyFile(t *testing.T) {
	dir := t.TempDir()

	for _, mode := range []os.FileMode{0400, 0600, 0440, 0444, 0644, 0000} {
		path := filepath.Join(dir, "key-"+mode.String())
		if err := os.WriteFile(path, []byte("k"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		err := CheckSigningKeyFile(path)
		if mode == 0400 && err != nil {
			t.Errorf("mode %04o: unexpected error %v", mode, err)
		}
		if mode != 0400 {
			if err == nil {
				t.Errorf("mode %04o: expected error, got nil", mode)
			} else if mode == 0000 && os.Geteuid() != 0 {
				// Not even readable by its owner: the open fails first.
			} else if !strings.Contains(err.Error(), "chmod 400") {
				t.Errorf("mode %04o: error %q should suggest 'chmod 400'", mode, err)
			}
		}
	}

	if err := CheckSigningKeyFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("expected error for missing file, got nil")
	}
	if err := CheckSigningKeyFile(dir); err == nil {
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

func TestSealRequiresUsableSigningKey(t *testing.T) {
	t.Run("Missing private key asks for setup", func(t *testing.T) {
		dir := t.TempDir()
		pub := filepath.Join(dir, "seal.pub")
		if err := WriteSigningKeyFile(pub, []byte("k")); err != nil {
			t.Fatal(err)
		}
		err := Seal("/nonexistent/tpm", "0,7", NVRAMSlotStart, pub, filepath.Join(dir, "seal.key"), false, PCRHashAlgoSHA256, false)
		if err == nil || !strings.Contains(err.Error(), "tpm2-kira setup") {
			t.Errorf("Seal() error = %v, want it to ask for 'tpm2-kira setup'", err)
		}
	})

	t.Run("Unparseable private key is rejected", func(t *testing.T) {
		dir := t.TempDir()
		priv := filepath.Join(dir, "seal.key")
		pub := filepath.Join(dir, "seal.pub")
		for _, p := range []string{priv, pub} {
			if err := WriteSigningKeyFile(p, []byte("not a key")); err != nil {
				t.Fatal(err)
			}
		}
		err := Seal("/nonexistent/tpm", "0,7", NVRAMSlotStart, pub, priv, false, PCRHashAlgoSHA256, false)
		if err == nil || !strings.Contains(err.Error(), "signing private key is not usable") {
			t.Errorf("Seal() error = %v, want 'signing private key is not usable'", err)
		}
	})
}

func TestReadSigningKeyFile(t *testing.T) {
	newKeyDir := func(t *testing.T) string {
		dir := filepath.Join(t.TempDir(), "keys")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("Returns the content of an acceptable file", func(t *testing.T) {
		path := filepath.Join(newKeyDir(t), "seal.key")
		if err := WriteSigningKeyFile(path, []byte("key")); err != nil {
			t.Fatal(err)
		}
		data, err := ReadSigningKeyFile(path)
		if err != nil || string(data) != "key" {
			t.Fatalf("ReadSigningKeyFile() = %q, %v; want \"key\", nil", data, err)
		}
	})

	t.Run("Refuses a symlink", func(t *testing.T) {
		dir := newKeyDir(t)
		target := filepath.Join(dir, "real.key")
		if err := WriteSigningKeyFile(target, []byte("key")); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "seal.key")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		_, err := ReadSigningKeyFile(link)
		if err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Errorf("ReadSigningKeyFile(symlink) error = %v, want a symlink refusal", err)
		}
	})

	t.Run("Refuses a group- or world-writable directory", func(t *testing.T) {
		for _, mode := range []os.FileMode{0770, 0757, 0777} {
			dir := newKeyDir(t)
			path := filepath.Join(dir, "seal.key")
			if err := WriteSigningKeyFile(path, []byte("key")); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			_, err := ReadSigningKeyFile(path)
			if err == nil || !strings.Contains(err.Error(), "chmod go-w") {
				t.Errorf("directory mode %04o: error = %v, want a directory refusal", mode, err)
			}
		}
	})

	t.Run("Refuses a FIFO without blocking", func(t *testing.T) {
		path := filepath.Join(newKeyDir(t), "seal.key")
		if err := syscall.Mkfifo(path, 0400); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSigningKeyFile(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("ReadSigningKeyFile(fifo) error = %v, want 'not a regular file'", err)
		}
	})

	t.Run("Refuses a file owned by another user", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("needs root to chown")
		}
		path := filepath.Join(newKeyDir(t), "seal.key")
		if err := WriteSigningKeyFile(path, []byte("key")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSigningKeyFile(path); err == nil || !strings.Contains(err.Error(), "owned by uid 65534") {
			t.Errorf("ReadSigningKeyFile(foreign owner) error = %v, want an owner refusal", err)
		}
	})

	t.Run("Refuses a directory owned by another user", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("needs root to chown")
		}
		dir := newKeyDir(t)
		path := filepath.Join(dir, "seal.key")
		if err := WriteSigningKeyFile(path, []byte("key")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(dir, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSigningKeyFile(path); err == nil || !strings.Contains(err.Error(), "owned by uid 65534") {
			t.Errorf("ReadSigningKeyFile(foreign directory) error = %v, want an owner refusal", err)
		}
	})
}
