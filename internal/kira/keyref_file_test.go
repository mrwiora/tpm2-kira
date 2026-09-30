package kira

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tokenRef() KeyRef {
	return KeyRef{Kind: KeyRefYubiKey, Serial: 33261813, Slot: 0x9a}
}

// writeRealKey puts an actual usable private key on disk, which is what must
// never be silently replaced by a reference.
func writeRealKey(t *testing.T, path string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("cannot marshal the key: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o400); err != nil {
		t.Fatalf("cannot write the key: %v", err)
	}
}

func TestKeyReferenceRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seal.key")

	if err := InstallKeyReference(path, tokenRef()); err != nil {
		t.Fatalf("InstallKeyReference failed: %v", err)
	}

	got, ok, err := ReadKeyReference(path)
	if err != nil {
		t.Fatalf("ReadKeyReference failed: %v", err)
	}
	if !ok {
		t.Fatal("the file just written is not recognised as a reference")
	}
	if got != tokenRef() {
		t.Errorf("read back %v, want %v", got, tokenRef())
	}
}

// The file sits at the private key path, so anyone inspecting it must be able to
// tell at a glance that it holds no key material.
func TestKeyReferenceFileExplainsItself(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seal.key")

	if err := InstallKeyReference(path, tokenRef()); err != nil {
		t.Fatalf("InstallKeyReference failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read it back: %v", err)
	}
	text := string(data)

	if !strings.Contains(text, "NOT a private key") {
		t.Error("the file does not say that it is not a private key")
	}
	if !strings.Contains(text, tokenRef().String()) {
		t.Errorf("the file does not name the token in readable form:\n%s", text)
	}
	if !strings.Contains(text, KeyReferencePEMType) {
		t.Error("the PEM block type is missing, so nothing can identify the file")
	}

	// A slot number is not a secret; marking it 0400 would make the permission
	// warning complain about a file with nothing to protect.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode is %o, want 644", info.Mode().Perm())
	}
}

func TestReadKeyReferenceIgnoresRealKeysAndAbsentFiles(t *testing.T) {
	dir := t.TempDir()

	real := filepath.Join(dir, "real.key")
	writeRealKey(t, real)

	if _, ok, err := ReadKeyReference(real); err != nil || ok {
		t.Errorf("a real key was read as a reference (ok=%v, err=%v)", ok, err)
	}

	if _, ok, err := ReadKeyReference(filepath.Join(dir, "absent.key")); err != nil || ok {
		t.Errorf("an absent file yielded ok=%v, err=%v; want false, nil", ok, err)
	}

	junk := filepath.Join(dir, "junk.key")
	if err := os.WriteFile(junk, []byte("not pem at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadKeyReference(junk); err != nil || ok {
		t.Errorf("a non-PEM file yielded ok=%v, err=%v; want false, nil", ok, err)
	}
}

// The reference is only a pointer, so repointing it is fine.
func TestInstallKeyReferenceReplacesAnOlderReference(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seal.key")

	if err := InstallKeyReference(path, tokenRef()); err != nil {
		t.Fatal(err)
	}

	moved := KeyRef{Kind: KeyRefYubiKey, Serial: 12345678, Slot: 0x9c}
	if err := InstallKeyReference(path, moved); err != nil {
		t.Fatalf("repointing an existing reference failed: %v", err)
	}

	got, ok, err := ReadKeyReference(path)
	if err != nil || !ok {
		t.Fatalf("ReadKeyReference after repointing: ok=%v, err=%v", ok, err)
	}
	if got != moved {
		t.Errorf("got %v, want %v", got, moved)
	}
}

// The regression that matters most: the key file may be the only copy of a key
// that cannot be regenerated, so a reference must never overwrite it.
func TestInstallKeyReferenceRefusesToDestroyAKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seal.key")
	writeRealKey(t, path)

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	err = InstallKeyReference(path, tokenRef())
	if !errors.Is(err, ErrRealKeyPresent) {
		t.Fatalf("got %v, want it to wrap ErrRealKeyPresent", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the private key was modified despite the refusal")
	}
}

func TestMarshalKeyReferenceRejectsAFilePath(t *testing.T) {
	if _, err := MarshalKeyReference(KeyRef{Kind: KeyRefFile, Path: "/tmp/x.key"}); err == nil {
		t.Error("a file reference was accepted; only a token can be pointed at")
	}
}

// A reference file naming something other than a token would otherwise recurse
// or resolve to itself.
func TestReadKeyReferenceRejectsANonTokenTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seal.key")

	bad := pem.EncodeToMemory(&pem.Block{
		Type:  KeyReferencePEMType,
		Bytes: []byte("/var/lib/tpm2-kira/keys/seal.key"),
	})
	if err := os.WriteFile(path, bad, 0o644); err != nil {
		t.Fatal(err)
	}

	_, ok, err := ReadKeyReference(path)
	if err == nil {
		t.Fatal("a reference to a file path was accepted")
	}
	if ok {
		t.Error("ok should be false when the reference is unusable")
	}
	if !strings.Contains(err.Error(), "rather than a token slot") {
		t.Errorf("the error does not explain the problem: %v", err)
	}
}

// The bug this whole mechanism fixes: 'setup' chose a token, wrote no key, and
// 'seal' then failed on the default path. Opening that path must now reach the
// token rather than report a missing file.
func TestOpenSigningKeyFollowsAReferenceToTheToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seal.key")

	if err := InstallKeyReference(path, tokenRef()); err != nil {
		t.Fatal(err)
	}

	ref, err := ParseKeyRef(path)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Kind != KeyRefFile {
		t.Fatalf("a bare path should parse as a file reference, got %v", ref.Kind)
	}

	_, err = OpenSigningKey(ref, NewPINProvider(""), false)
	if err == nil {
		t.Skip("a token answered, so there is nothing to assert about the failure")
	}

	// No token is attached in a unit test, so the call must fail — but it has to
	// fail trying to reach the token, not reading the file.
	if strings.Contains(err.Error(), "no such file") {
		t.Errorf("the reference was not followed; still looking for a key file: %v", err)
	}

	var unavailable *KeyUnavailableError
	if errors.As(err, &unavailable) && unavailable.Ref.Kind != KeyRefYubiKey {
		t.Errorf("failed against %v, want the token reference", unavailable.Ref)
	}
}
