package kira

import (
	"bytes"
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

func TestMarshalKeyReferenceRejectsNothingToPointAt(t *testing.T) {
	if _, err := MarshalKeyReference(KeyRef{}); err == nil {
		t.Error("an empty reference was accepted")
	}
	if _, err := MarshalKeyReference(KeyRef{Kind: KeyRefFile}); err == nil {
		t.Error("a file reference with no path was accepted")
	}
}

// A reference may name another file, which is what keeps the well-known path a
// complete answer for a key shared with something else, such as sbctl.
func TestKeyReferenceCanNameAFile(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "db.key")
	writeRealKey(t, shared)

	refPath := filepath.Join(dir, "seal.key")
	if err := InstallKeyReference(refPath, KeyRef{Kind: KeyRefFile, Path: shared}); err != nil {
		t.Fatalf("InstallKeyReference failed: %v", err)
	}

	got, ok, err := ReadKeyReference(refPath)
	if err != nil || !ok {
		t.Fatalf("ReadKeyReference: ok=%v, err=%v", ok, err)
	}
	if got.Kind != KeyRefFile || got.Path != shared {
		t.Errorf("read back %+v, want a file reference to %s", got, shared)
	}

	data, err := os.ReadFile(refPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), shared) {
		t.Errorf("the file does not name the target readably:\n%s", data)
	}

	// Opening the well-known path must reach the shared key itself.
	opened, err := OpenSigningKey(KeyRef{Kind: KeyRefFile, Path: refPath}, NewPINProvider(""), false)
	if err != nil {
		t.Fatalf("the reference was not followed to the key: %v", err)
	}
	defer opened.Close()

	direct, err := LoadSigningPrivateKeyFromPEM(shared)
	if err != nil {
		t.Fatal(err)
	}
	wantFP, _ := KeyFingerprint(direct.Public())
	gotFP, _ := KeyFingerprint(opened.Public())
	if !bytes.Equal(gotFP, wantFP) {
		t.Error("the reference resolved to a different key than the one it names")
	}
}

// A reference naming itself would recurse. Only one level is ever followed, so
// the loop is refused where it can be seen.
func TestReadKeyReferenceRejectsSelfReference(t *testing.T) {
	dir := t.TempDir()
	refPath := filepath.Join(dir, "seal.key")

	if err := os.WriteFile(refPath, pem.EncodeToMemory(&pem.Block{
		Type:  KeyReferencePEMType,
		Bytes: []byte(refPath),
	}), 0o644); err != nil {
		t.Fatal(err)
	}

	_, ok, err := ReadKeyReference(refPath)
	if err == nil {
		t.Fatal("a self-reference was accepted")
	}
	if ok {
		t.Error("ok should be false when the reference is unusable")
	}
	if !strings.Contains(err.Error(), "pointing at itself") {
		t.Errorf("the error does not explain the problem: %v", err)
	}
}

// A reference pointing at a second reference file resolves one level and then
// treats the target as key material, so it fails on the target rather than
// looping.
func TestKeyReferenceFollowsOnlyOneLevel(t *testing.T) {
	dir := t.TempDir()

	second := filepath.Join(dir, "second.key")
	if err := InstallKeyReference(second, tokenRef()); err != nil {
		t.Fatal(err)
	}

	first := filepath.Join(dir, "seal.key")
	if err := InstallKeyReference(first, KeyRef{Kind: KeyRefFile, Path: second}); err != nil {
		t.Fatal(err)
	}

	_, err := OpenSigningKey(KeyRef{Kind: KeyRefFile, Path: first}, NewPINProvider(""), false)
	if err == nil {
		t.Fatal("a chain of reference files should not resolve")
	}
	if !strings.Contains(err.Error(), second) {
		t.Errorf("the error should name the target it gave up on, got: %v", err)
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
