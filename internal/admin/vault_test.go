package admin

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrwiora/tpm2-kira/core/attest/attesttest"
	"github.com/mrwiora/tpm2-kira/core/vaultproto"
	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/vaultkey"
)

// The vault's parts as the combiner's inputs are fixed by the parts, the
// label and the pepper: the contract with every enrolled keyslot. An
// unattended recipe's key is the combiner's of the two.
func TestVaultKey(t *testing.T) {
	l, r := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	salt, pw := vaultkey.Salt(r, "luks", nil), vaultkey.Password(l, "luks")
	for _, v := range [][]byte{salt, pw} {
		if len(v) != 64 || strings.Trim(string(v), "0123456789abcdef") != "" {
			t.Fatalf("%q", v)
		}
	}
	if !bytes.Equal(salt, vaultkey.Salt(r, "", nil)) || !bytes.Equal(pw, vaultkey.Password(l, "")) {
		t.Fatal("the default label is luks")
	}
	for name, other := range map[string][]byte{
		"another label":    vaultkey.Salt(r, "home", nil),
		"with a pepper":    vaultkey.Salt(r, "luks", []byte("p")),
		"another pepper":   vaultkey.Salt(r, "luks", []byte("q")),
		"another remote":   vaultkey.Salt(bytes.Repeat([]byte{3}, 32), "luks", nil),
		"the password's":   vaultkey.Salt(l, "luks", nil),
		"the phone salt's": phonegate.FactorSalt(r, "luks"),
	} {
		if bytes.Equal(salt, other) {
			t.Errorf("%s gives the same salt", name)
		}
	}
	if bytes.Equal(pw, vaultkey.Password(r, "luks")) || bytes.Equal(pw, salt) {
		t.Error("the password is not the TPM part's alone")
	}
	key, err := vaultkey.Key(l, r, "luks", nil)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := diskkey.Combine(pw, salt); !bytes.Equal(key, want) {
		t.Fatal("the unattended key is not the combiner's of the TPM's part and the vault's")
	}
}

// The vault method survives the blob: written, read, the same.
func TestVaultMethodInTheBlob(t *testing.T) {
	soft, err := attesttest.NewSoftTPM()
	if err != nil {
		t.Fatal(err)
	}
	a := &nvslot.Attestation{
		DeviceID: bytes.Repeat([]byte{7}, 16), FriendlyName: "db-03", AKPublic: soft.AKPub, AKPrivate: []byte{1},
		PCRAlg: 0x000b, PCRSelection: []uint8{7, 11},
		Vault: nvslot.VaultAttestation{URL: "https://vault:8443", Pin: "sha256:" + strings.Repeat("ab", 32), Label: "luks",
			Local: nvslot.WrappedFactor{Credential: []byte{1, 2, 3}, EncryptedSecret: []byte{4, 5}}},
	}
	raw, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b, err := nvslot.UnmarshalAttestation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if b.Phone.Enabled() || !b.Vault.Enabled() || b.Vault.URL != a.Vault.URL || b.Vault.Pin != a.Vault.Pin ||
		b.Vault.Label != a.Vault.Label || !bytes.Equal(b.Vault.Local.Credential, a.Vault.Local.Credential) ||
		!bytes.Equal(b.Vault.Local.EncryptedSecret, a.Vault.Local.EncryptedSecret) {
		t.Fatalf("read back %+v", b.Vault)
	}
	js, _ := json.Marshal(b.Json())
	if !strings.Contains(string(js), `"vault":{"url":"https://vault:8443"`) || !strings.Contains(string(js), `"pepper":false`) || strings.Contains(string(js), "credential") {
		t.Fatalf("json %s", js)
	}

	// The pin is kept as its 32 bytes: the text's case does not matter,
	// a pin that is not one is not written.
	upper := *a
	upper.Vault.Pin = "sha256:" + strings.Repeat("AB", 32)
	if raw2, err := upper.Marshal(); err != nil || len(raw2) != len(raw) {
		t.Fatalf("an upper-case pin: %d bytes, %v", len(raw2), err)
	} else if b, err := nvslot.UnmarshalAttestation(raw2); err != nil || b.Vault.Pin != a.Vault.Pin {
		t.Fatalf("an upper-case pin read back as %q, %v", b.Vault.Pin, err)
	}
	if bytes.Contains(raw, []byte("sha256:")) {
		t.Fatal("the pin is kept as text")
	}
	for _, pin := range []string{"", "sha256:" + strings.Repeat("ab", 31), "sha256:" + strings.Repeat("zz", 32), "sha1:" + strings.Repeat("ab", 32), strings.Repeat("ab", 32)} {
		bad := *a
		bad.Vault.Pin = pin
		if _, err := bad.Marshal(); err == nil {
			t.Errorf("the pin %q was written", pin)
		}
	}

	// With a pepper the check comes along, 16 bytes; a check of another
	// size is neither written nor read.
	a.Vault.Pepper, a.Vault.PepperCheck = true, vaultkey.PepperCheck([]byte("key"))
	raw, _ = a.Marshal()
	if b, err = nvslot.UnmarshalAttestation(raw); err != nil || !bytes.Equal(b.Vault.PepperCheck, a.Vault.PepperCheck) {
		t.Fatalf("pepper check: %v", err)
	}
	if len(a.Vault.PepperCheck) != nvslot.PepperCheckSize {
		t.Fatalf("the pepper check is %d bytes", len(a.Vault.PepperCheck))
	}
	good := len(raw)
	a.Vault.PepperCheck = []byte{1, 2, 3}
	if _, err := a.Marshal(); err == nil {
		t.Fatal("a 3-byte pepper check was written")
	}
	// Read: the check cut to 3 bytes, its prefix and the vault method's
	// length (the last method: [type 2][len:4], its data to the end) told
	// so - the record is whole but for the check's size.
	short := append([]byte(nil), raw[:good-nvslot.PepperCheckSize-2]...)
	short = append(short, 3, 0, 1, 2, 3)
	header := -1
	for i := len(raw) - 5; i >= 0; i-- {
		if raw[i] == nvslot.AttestMethodVault && int(binary.LittleEndian.Uint32(raw[i+1:])) == good-(i+5) {
			header = i
			break
		}
	}
	if header < 0 {
		t.Fatal("the vault method's header not found")
	}
	binary.LittleEndian.PutUint32(short[header+1:], uint32(len(short)-(header+5)))
	if _, err := nvslot.UnmarshalAttestation(short); err == nil || !strings.Contains(err.Error(), "pepper check") {
		t.Fatalf("a 3-byte pepper check: %v", err)
	}
}

// The client talks to the vault whose key is pinned, and to no other.
func TestVaultClientPin(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == vaultproto.PathChallenge {
			json.NewEncoder(w).Encode(vaultproto.ChallengeResponse{RequestID: "r", Nonce: make([]byte, 32), ExpiresIn: 120})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(vaultproto.ErrorResponse{Error: "unknown device\x1b[2J"})
	}))
	defer srv.Close()
	trustTestVault(t, srv)
	pin := vaultproto.PinOf(srv.Certificate().RawSubjectPublicKeyInfo)

	c, err := vaultkey.NewClient(srv.URL, pin)
	if err != nil {
		t.Fatal(err)
	}
	var ch vaultproto.ChallengeResponse
	if err := c.Post(context.Background(), vaultproto.PathChallenge, vaultproto.ChallengeRequest{}, &ch); err != nil || ch.RequestID != "r" {
		t.Fatalf("the pinned vault: %v", err)
	}
	err = c.Post(context.Background(), vaultproto.PathRelease, vaultproto.ReleaseRequest{}, &ch)
	if err == nil || !strings.Contains(err.Error(), "unknown device") || strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("the vault's error, without its escape sequences: %v", err)
	}
	if vaultkey.Retryable(err) {
		t.Fatal("an answer is not a reason to try again")
	}

	other, _ := vaultkey.NewClient(srv.URL, "sha256:"+strings.Repeat("00", 32))
	err = other.Post(context.Background(), vaultproto.PathChallenge, vaultproto.ChallengeRequest{}, &ch)
	if err == nil || !strings.Contains(err.Error(), "pinned key") {
		t.Fatalf("another key: %v", err)
	}
	if vaultkey.Retryable(err) {
		t.Fatal("a vault with another key is not tried again")
	}

	// A vault whose chain ends at no root of the bundle is refused like one
	// with another key; without a bundle there is no client.
	path := vaultkey.RootsPath
	vaultkey.RootsPath = writeTestRoot(t)
	foreign, _ := vaultkey.NewClient(srv.URL, pin)
	err = foreign.Post(context.Background(), vaultproto.PathChallenge, vaultproto.ChallengeRequest{}, &ch)
	if err == nil || vaultkey.Retryable(err) || !strings.Contains(vaultkey.Problem(err), "does not end at a root") {
		t.Fatalf("another root: %v (%s)", err, vaultkey.Problem(err))
	}
	vaultkey.RootsPath = filepath.Join(t.TempDir(), "none.pem")
	if _, err := vaultkey.NewClient(srv.URL, pin); err == nil || !strings.Contains(err.Error(), "--ca FILE") {
		t.Fatalf("no bundle: %v", err)
	}
	vaultkey.RootsPath = path

	srv.Close()
	err = c.Post(context.Background(), vaultproto.PathChallenge, vaultproto.ChallengeRequest{}, &ch)
	if err == nil || !vaultkey.Retryable(err) {
		t.Fatalf("a vault not reached is tried again: %v", err)
	}

	for _, bad := range [][2]string{{"http://vault:80", pin}, {"https://vault/x", pin}, {srv.URL, "sha256:12"}, {srv.URL, ""}} {
		if _, err := vaultkey.NewClient(bad[0], bad[1]); err == nil {
			t.Errorf("accepted %q %q", bad[0], bad[1])
		}
	}
}

// A volume with a unattended vault recipe (0x2400) keyslot takes the vault's key, which needs
// nobody; without one, cryptsetup's own prompt follows.
func TestDiskKeyFromTheVault(t *testing.T) {
	if got := diskkey.RecipeOfTokens([]diskkey.LuksToken{{Recipe: diskkey.RecipeRecovery}, {Recipe: diskkey.RecipeUnattendedVault}, {Recipe: diskkey.RecipePhoneSalt}}); got != diskkey.RecipeUnattendedVault {
		t.Fatalf("recipe %q", got)
	}
	if got := diskkey.RecipeOfTokens([]diskkey.LuksToken{{Recipe: diskkey.RecipeRecovery}, {Recipe: diskkey.RecipePhoneSalt}}); got != diskkey.RecipePhoneSalt {
		t.Fatalf("recipe %q", got)
	}
	noAsk := func(volume, what, note string) ([]byte, error) {
		t.Fatalf("asked for %s", what)
		return nil, nil
	}
	key, err := diskkey.DiskKey(nil, func(string) ([]byte, error) { return []byte("k"), nil }, recipeOf(diskkey.RecipeUnattendedVault), noAsk)("cryptroot")
	if err != nil || string(key) != "k" {
		t.Fatalf("%q %v", key, err)
	}
	_, err = diskkey.DiskKey(nil, func(string) ([]byte, error) { return nil, errors.New("the vault refused") }, recipeOf(diskkey.RecipeUnattendedVault), noAsk)("cryptroot")
	if !errors.Is(err, diskkey.ErrUnlockSkipped) || !strings.Contains(err.Error(), "the vault refused") {
		t.Fatalf("%v", err)
	}
	if _, err := diskkey.DiskKey(nil, nil, recipeOf(diskkey.RecipeUnattendedVault), noAsk)("cryptroot"); !errors.Is(err, diskkey.ErrUnlockSkipped) {
		t.Fatalf("no vault in this boot: %v", err)
	}
}

// A volume with a recovery recipe (0x1100) keyslot beside its unattended vault recipe (0x2400) one: when
// the vault gives no key, tpm2-kira asks for the password and the salt at
// its own prompt (at the console or over SSH), and says why - not
// cryptsetup's prompt with the recovery passphrase.
func TestTheTypedKeyslotIsTheVaultsFallback(t *testing.T) {
	modes := diskkey.RecipesOfTokens([]diskkey.LuksToken{{Recipe: diskkey.RecipeRecovery}, {Recipe: diskkey.RecipeUnattendedVault}})
	if len(modes) != 2 || modes[0] != diskkey.RecipeUnattendedVault || modes[1] != diskkey.RecipeRecovery {
		t.Fatalf("the order: %q", modes)
	}
	var asked []string
	var note string
	ask := func(volume, what, n string) ([]byte, error) {
		asked = append(asked, what)
		if what == "Password" {
			note = n
		}
		return []byte("typed-" + what), nil
	}
	refused := func(string) ([]byte, error) { return nil, errors.New("the device is revoked") }
	key, err := diskkey.DiskKey(nil, refused, recipeOf(modes...), ask)("cryptroot")
	if err != nil || len(key) == 0 {
		t.Fatalf("no key from the typed keyslot: %v", err)
	}
	if strings.Join(asked, ",") != "Password,Salt" || !strings.Contains(note, "no key from the vault (the device is revoked)") {
		t.Fatalf("asked %q, note %q", asked, note)
	}
	want, _ := diskkey.DiskKey(nil, nil, recipeOf(diskkey.RecipeRecovery), ask)("cryptroot")
	if string(key) != string(want) {
		t.Fatal("the fallback's key is not the recovery recipe's key")
	}
}

// The token of an unattended vault keyslot names its recipe and is bound
// to a slot.
func TestVaultToken(t *testing.T) {
	tok, ok := diskkey.ParseKiraToken(json.RawMessage(`{"type":"tpm2-kira-2400","keyslots":["2"],"recipe":9216,"slot":0,"label":"luks","created":"x"}`))
	if !ok || tok.Obsolete || tok.Recipe != diskkey.RecipeUnattendedVault || !tok.BoundTo(0) {
		t.Fatalf("%+v", tok)
	}
	if d := describeKeyslot(KeyslotStatus{Token: &tok}); !strings.Contains(d, "password in this TPM · salt from the vault") {
		t.Fatal(d)
	}
}

// control's check of a vault: it answers with the pinned key and knows the
// device; it answers but refuses; another key; not reachable at all.
func TestCheckVault(t *testing.T) {
	known := []byte("0123456789abcdef")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req vaultproto.ChallengeRequest
		json.NewDecoder(r.Body).Decode(&req)
		if bytes.Equal(req.DeviceID, known) {
			json.NewEncoder(w).Encode(vaultproto.ChallengeResponse{RequestID: "r", Nonce: make([]byte, 32), ExpiresIn: 120})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(vaultproto.ErrorResponse{Error: "unknown device"})
	}))
	defer srv.Close()
	trustTestVault(t, srv)
	pin := vaultproto.PinOf(srv.Certificate().RawSubjectPublicKeyInfo)

	if v := vaultkey.Check(srv.URL, pin, known, 5*time.Second); !v.Answers || !v.Knows || v.Problem != "" {
		t.Fatalf("the known device: %+v", v)
	}
	if v := vaultkey.Check(srv.URL, pin, nil, 5*time.Second); !v.Answers || v.Knows || !strings.Contains(v.Problem, "unknown device") {
		t.Fatalf("before the enrolment, any answer: %+v", v)
	}
	if v := vaultkey.Check(srv.URL, "sha256:"+strings.Repeat("00", 32), nil, 5*time.Second); v.Answers || !strings.Contains(v.Problem, "without the pinned key") {
		t.Fatalf("another key: %+v", v)
	}
	vaultkey.RootsPath = writeTestRoot(t)
	if v := vaultkey.Check(srv.URL, pin, nil, 5*time.Second); v.Answers || !strings.Contains(v.Problem, "does not end at a root") {
		t.Fatalf("another root: %+v", v)
	}
	trustTestVault(t, srv)
	if v := vaultkey.Check("https://vault", "sha256:12", nil, 5*time.Second); v.Answers || !strings.Contains(v.Problem, "pin") {
		t.Fatalf("a bad pin: %+v", v)
	}
	srv.Close()
	if v := vaultkey.Check(srv.URL, pin, known, 5*time.Second); v.Answers || !strings.Contains(v.Problem, "not reachable") {
		t.Fatalf("not reached: %+v", v)
	}
}

// recipeOf is a volume-independent recipe, for the prompt tests.
func recipeOf(recipes ...diskkey.Recipe) func(string) ([]diskkey.Recipe, string) {
	return func(string) ([]diskkey.Recipe, string) { return recipes, "" }
}

// trustTestVault makes the test server's certificate - a self-signed CA
// for 127.0.0.1 - the root of the machine's vaults, for this test.
func trustTestVault(t *testing.T, srv *httptest.Server) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	old := vaultkey.RootsPath
	vaultkey.RootsPath = path
	t.Cleanup(func() { vaultkey.RootsPath = old })
}

// writeTestRoot writes a bundle with a root nobody's vault ends at.
func writeTestRoot(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "another root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "other-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// AddRoot takes from a file the root whose key is the pin, and only it,
// into the bundle, once; a file without the pin's root changes nothing.
func TestAddRoot(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	pin := vaultproto.PinOf(srv.Certificate().RawSubjectPublicKeyInfo)
	other := writeTestRoot(t)
	file := filepath.Join(t.TempDir(), "from-the-vault.pem")
	otherPEM, _ := os.ReadFile(other)
	os.WriteFile(file, append(otherPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})...), 0o644)

	old := vaultkey.RootsPath
	vaultkey.RootsPath = filepath.Join(t.TempDir(), "etc", "vault-ca.pem")
	defer func() { vaultkey.RootsPath = old }()
	if err := vaultkey.AddRoot(other, pin); err == nil || !strings.Contains(err.Error(), "not this vault's") {
		t.Fatalf("a file without the pin's root: %v", err)
	}
	if _, err := os.Stat(vaultkey.RootsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused root left a bundle")
	}
	for i := 0; i < 2; i++ {
		if err := vaultkey.AddRoot(file, pin); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(vaultkey.RootsPath)
	_, certs, err := vaultproto.ParseRoots(b)
	if err != nil || len(certs) != 1 || !certs[0].Equal(srv.Certificate()) {
		t.Fatalf("the bundle: %d roots, %v", len(certs), err)
	}
	if c, err := vaultkey.NewClient(srv.URL, pin); err != nil || c == nil {
		t.Fatalf("a client with the added root: %v", err)
	}
}

// A pin is sha256: and the 64 hexadecimal characters of a digest; what is
// not is refused where it is given, before any record is written.
func TestCheckPin(t *testing.T) {
	for _, pin := range []string{"sha256:" + strings.Repeat("ab", 32), "sha256:" + strings.Repeat("AB", 32)} {
		if err := vaultkey.CheckPin(pin); err != nil {
			t.Errorf("%q: %v", pin, err)
		}
	}
	for _, pin := range []string{"", "sha256:", "sha256:" + strings.Repeat("zz", 32), "sha256:" + strings.Repeat("ab", 33), "sha512:" + strings.Repeat("ab", 32)} {
		if vaultkey.CheckPin(pin) == nil {
			t.Errorf("%q taken", pin)
		}
	}
}
