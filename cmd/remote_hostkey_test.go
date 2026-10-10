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
// system's host key, or one control created; only an unencrypted ed25519
// key is sealed.
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

	own := filepath.Join(dir, "own", "ssh_host_ed25519_key")
	if err := createHostKey(own); err != nil {
		t.Fatal(err)
	}
	got, err := loadHostKey(own)
	if err != nil {
		t.Fatalf("created key: %v", err)
	}
	pub, _ := os.ReadFile(own + ".pub")
	if pk, _, _, _, err := ssh.ParseAuthorizedKey(pub); err != nil || hostKeyFingerprint(got.Public().(ed25519.PublicKey)) != ssh.FingerprintSHA256(pk) {
		t.Fatalf("the .pub does not fit: %v", err)
	}
	if st, _ := os.Stat(own); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for path, want := range map[string]string{
		writePEM("ecdsa", ec, ""):        "not an ed25519 key",
		writePEM("locked", sk, "secret"): "protected by a passphrase",
		filepath.Join(dir, "missing"):    "no SSH host key at",
	} {
		if _, err := loadHostKey(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", filepath.Base(path), err, want)
		}
	}
}
