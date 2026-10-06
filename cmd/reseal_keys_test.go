//go:build unit || !integration

package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// writeTestKeyPair writes an ECDSA P-256 pair into dir the way setup does.
func writeTestKeyPair(t *testing.T, dir string) (*ecdsa.PrivateKey, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	priv := filepath.Join(dir, "seal.key")
	pub := filepath.Join(dir, "seal.pub")
	if err := WriteSigningKeyFile(priv, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	pubPEM, err := PublicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteSigningKeyFile(pub, pubPEM); err != nil {
		t.Fatal(err)
	}
	return key, priv, pub
}

func newTestKeyDir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// signedTestBlob returns a blob signed by key and naming the given key paths.
func signedTestBlob(t *testing.T, key *ecdsa.PrivateKey, privPath, pubPath string) ([]byte, *SealedBlob) {
	t.Helper()
	sb := &SealedBlob{Version: CurrentBlobVersion, Payload: SealedBlobPayload{
		AppVersion: "test", Public: []byte{1}, Private: []byte{2},
		PCRDigests:    []PCRDigestPair{{Index: 7, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}}},
		PolicyRef:     make([]byte, 32),
		PublicKeyPath: pubPath, PrivateKeyPath: privPath,
	}}
	unsigned, err := sb.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	data, err := SignBlobPayload(unsigned, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := UnmarshalSealedBlob(data)
	if err != nil {
		t.Fatal(err)
	}
	return data, parsed
}

func TestResolveResealKeysIgnoresBlobKeyPaths(t *testing.T) {
	_, ownPriv, _ := writeTestKeyPair(t, newTestKeyDir(t, "owner"))

	// The attacker's key sits in a directory the planted blob points at.
	// It is made unreadable, so any attempt to open it would surface as a
	// permission error instead of the integrity failure checked for below.
	attackerDir := newTestKeyDir(t, "attacker")
	attackerKey, attackerPriv, attackerPub := writeTestKeyPair(t, attackerDir)
	if err := os.Chmod(attackerDir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(attackerDir, 0700) })

	data, blob := signedTestBlob(t, attackerKey, attackerPriv, attackerPub)

	_, err := resolveResealKeys(data, blob, ownPriv, "", false)
	if err == nil {
		t.Fatal("a blob signed by another key was accepted")
	}
	msg := err.Error()
	if !strings.Contains(msg, "blob integrity check failed") {
		t.Errorf("error = %q, want the integrity failure", msg)
	}
	if strings.Contains(msg, "permission denied") {
		t.Errorf("the attacker's key file was opened: %q", msg)
	}
	if !strings.Contains(msg, "(unverified)") || !strings.Contains(msg, attackerPriv) {
		t.Errorf("error should name the blob's key path as unverified: %q", msg)
	}
}

func TestResolveResealKeysAcceptsOwnBlob(t *testing.T) {
	key, priv, pub := writeTestKeyPair(t, newTestKeyDir(t, "owner"))
	data, blob := signedTestBlob(t, key, priv, pub)

	keys, err := resolveResealKeys(data, blob, priv, pub, false)
	if err != nil {
		t.Fatalf("resolveResealKeys() error = %v", err)
	}
	if keys.privKeyPath != priv || keys.pubKey == nil || !publicKeysEqual(keys.signer.Public(), &key.PublicKey) {
		t.Errorf("unexpected keys: %+v", keys)
	}
}

func TestResolveResealKeysRejectsMismatchedPubkey(t *testing.T) {
	key, priv, _ := writeTestKeyPair(t, newTestKeyDir(t, "owner"))
	_, _, otherPub := writeTestKeyPair(t, newTestKeyDir(t, "other"))
	data, blob := signedTestBlob(t, key, priv, "")

	_, err := resolveResealKeys(data, blob, priv, otherPub, false)
	if err == nil || !strings.Contains(err.Error(), "not a key pair") {
		t.Errorf("error = %v, want 'not a key pair'", err)
	}
}

func TestResolveResealKeysMissingKeyNamesBlobPath(t *testing.T) {
	key, priv, pub := writeTestKeyPair(t, newTestKeyDir(t, "owner"))
	data, blob := signedTestBlob(t, key, priv, pub)

	missing := filepath.Join(t.TempDir(), "absent.key")
	_, err := resolveResealKeys(data, blob, missing, "", false)
	if err == nil || !strings.Contains(err.Error(), "no signing private key at "+missing) ||
		!strings.Contains(err.Error(), "--privkey "+priv) {
		t.Errorf("error = %v, want a missing-key error that suggests --privkey %s", err, priv)
	}
}
