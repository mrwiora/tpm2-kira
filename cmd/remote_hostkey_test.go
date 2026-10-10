package cmd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The host key is read from an OpenSSH private key file - the running
// system's host key - or from a tinysshd key directory; only an
// unencrypted ed25519 key serves, the only kind tinysshd takes.
func TestLoadHostKey(t *testing.T) {
	dir := t.TempDir()
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	writePEM := func(name string, key any, passphrase string) string {
		t.Helper()
		b, err := ssh.MarshalPrivateKey(key, "root@host")
		if passphrase != "" {
			b, err = ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte(passphrase))
		}
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		os.WriteFile(p, pem.EncodeToMemory(b), 0o600)
		return p
	}

	openssh := writePEM("ssh_host_ed25519_key", sk, "")
	if got, err := loadHostKey(openssh); err != nil || !got.Equal(sk) {
		t.Fatalf("OpenSSH key: %v", err)
	}

	tiny := filepath.Join(dir, "sshkeydir")
	if err := writeTinysshKey(tiny, sk); err != nil {
		t.Fatal(err)
	}
	if got, err := loadHostKey(tiny); err != nil || !got.Equal(sk) {
		t.Fatalf("tinysshd key directory: %v", err)
	}

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for path, want := range map[string]string{
		writePEM("ecdsa", ec, ""):        "not an ed25519 key",
		writePEM("locked", sk, "secret"): "protected by a passphrase",
		filepath.Join(dir, "missing"):    "no SSH host key at",
		func() string { p := filepath.Join(dir, "empty"); os.Mkdir(p, 0o700); return p }(): "tinysshd-makekey",
	} {
		if _, err := loadHostKey(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", filepath.Base(path), err, want)
		}
	}
}
