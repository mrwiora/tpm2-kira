package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrwiora/tpm2-kira/core/attest/attesttest"
	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/vaultkey"
	"github.com/mrwiora/tpm2-kira/core/vaultproto"
)

// The key is fixed by its parts, its label and the pepper: the contract
// with every enrolled keyslot.
func TestVaultKey(t *testing.T) {
	l, r := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	k := vaultkey.Key(l, r, "luks", nil)
	if len(k) != 64 || strings.Trim(string(k), "0123456789abcdef") != "" {
		t.Fatalf("key %q", k)
	}
	if !bytes.Equal(k, vaultkey.Key(l, r, "", nil)) {
		t.Fatal("the default label is luks")
	}
	for name, other := range map[string][]byte{
		"another label":    vaultkey.Key(l, r, "home", nil),
		"parts swapped":    vaultkey.Key(r, l, "luks", nil),
		"with a pepper":    vaultkey.Key(l, r, "luks", []byte("p")),
		"an empty pepper":  vaultkey.Key(l, r, "luks", []byte{}),
		"another remote":   vaultkey.Key(l, bytes.Repeat([]byte{3}, 32), "luks", nil),
		"the phone salt's": phonegate.FactorSalt(append(append([]byte(nil), l...), r...), "luks"),
	} {
		if bytes.Equal(k, other) {
			t.Errorf("%s gives the same key", name)
		}
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

	// With a pepper the check comes along; a check of another size does
	// not parse.
	a.Vault.PepperCheck = vaultkey.PepperCheck([]byte("key"))
	raw, _ = a.Marshal()
	if b, err = nvslot.UnmarshalAttestation(raw); err != nil || !bytes.Equal(b.Vault.PepperCheck, a.Vault.PepperCheck) {
		t.Fatalf("pepper check: %v", err)
	}
	a.Vault.PepperCheck = []byte{1, 2, 3}
	raw, _ = a.Marshal()
	if _, err := nvslot.UnmarshalAttestation(raw); err == nil {
		t.Fatal("a 3-byte pepper check parsed")
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
	if err == nil || !strings.Contains(err.Error(), "not the pinned one") {
		t.Fatalf("another key: %v", err)
	}
	if vaultkey.Retryable(err) {
		t.Fatal("a vault with another key is not tried again")
	}

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

// A volume with a tpm+vault keyslot takes the vault's key, which needs
// nobody; without one, cryptsetup's own prompt follows.
func TestDiskKeyFromTheVault(t *testing.T) {
	if got := diskkey.RecipeOfTokens([]diskkey.LuksToken{{Mode: diskkey.LuksModePasswordSalt}, {Mode: diskkey.LuksModeTPMVault}, {Mode: diskkey.LuksModePasswordPhoneSalt}}); got != diskkey.LuksModeTPMVault {
		t.Fatalf("recipe %q", got)
	}
	if got := diskkey.RecipeOfTokens([]diskkey.LuksToken{{Mode: diskkey.LuksModePasswordSalt}, {Mode: diskkey.LuksModePasswordPhoneSalt}}); got != diskkey.LuksModePasswordPhoneSalt {
		t.Fatalf("recipe %q", got)
	}
	noAsk := func(volume, what, note string) ([]byte, error) {
		t.Fatalf("asked for %s", what)
		return nil, nil
	}
	key, err := diskkey.DiskKey(nil, func(string) ([]byte, error) { return []byte("k"), nil }, recipeOf(diskkey.LuksModeTPMVault), noAsk)("cryptroot")
	if err != nil || string(key) != "k" {
		t.Fatalf("%q %v", key, err)
	}
	_, err = diskkey.DiskKey(nil, func(string) ([]byte, error) { return nil, errors.New("the vault refused") }, recipeOf(diskkey.LuksModeTPMVault), noAsk)("cryptroot")
	if !errors.Is(err, diskkey.ErrUnlockSkipped) || !strings.Contains(err.Error(), "the vault refused") {
		t.Fatalf("%v", err)
	}
	if _, err := diskkey.DiskKey(nil, nil, recipeOf(diskkey.LuksModeTPMVault), noAsk)("cryptroot"); !errors.Is(err, diskkey.ErrUnlockSkipped) {
		t.Fatalf("no vault in this boot: %v", err)
	}
}

// A volume with a password+salt keyslot beside its tpm+vault one: when
// the vault gives no key, tpm2-kira asks for the password and the salt at
// its own prompt (at the console or over SSH), and says why - not
// cryptsetup's prompt with the recovery passphrase.
func TestTheTypedKeyslotIsTheVaultsFallback(t *testing.T) {
	modes := diskkey.RecipesOfTokens([]diskkey.LuksToken{{Mode: diskkey.LuksModePasswordSalt}, {Mode: diskkey.LuksModeTPMVault}})
	if len(modes) != 2 || modes[0] != diskkey.LuksModeTPMVault || modes[1] != diskkey.LuksModePasswordSalt {
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
	want, _ := diskkey.DiskKey(nil, nil, recipeOf(diskkey.LuksModePasswordSalt), ask)("cryptroot")
	if string(key) != string(want) {
		t.Fatal("the fallback's key is not the password+salt key")
	}
}

// The token of a tpm+vault keyslot has its own type and is bound to a slot.
func TestVaultToken(t *testing.T) {
	tok, ok := diskkey.ParseKiraToken(json.RawMessage(`{"type":"tpm2-kira-vault","keyslots":["2"],"slot":0,"label":"luks","created":"x"}`))
	if !ok || tok.Mode != diskkey.LuksModeTPMVault || !tok.BoundTo(0) || diskkey.TokenTypeOf(diskkey.LuksModeTPMVault) != diskkey.LuksTokenTypeVault {
		t.Fatalf("%+v", tok)
	}
	if !strings.Contains(describeKeyslot(KeyslotStatus{Token: &tok}), "nothing typed") {
		t.Fatal(describeKeyslot(KeyslotStatus{Token: &tok}))
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
	pin := vaultproto.PinOf(srv.Certificate().RawSubjectPublicKeyInfo)

	if v := vaultkey.Check(srv.URL, pin, known, 5*time.Second); !v.Answers || !v.Knows || v.Problem != "" {
		t.Fatalf("the known device: %+v", v)
	}
	if v := vaultkey.Check(srv.URL, pin, nil, 5*time.Second); !v.Answers || v.Knows || !strings.Contains(v.Problem, "unknown device") {
		t.Fatalf("before the enrolment, any answer: %+v", v)
	}
	if v := vaultkey.Check(srv.URL, "sha256:"+strings.Repeat("00", 32), nil, 5*time.Second); v.Answers || !strings.Contains(v.Problem, "another key") {
		t.Fatalf("another key: %+v", v)
	}
	if v := vaultkey.Check("https://vault", "sha256:12", nil, 5*time.Second); v.Answers || !strings.Contains(v.Problem, "pin") {
		t.Fatalf("a bad pin: %+v", v)
	}
	srv.Close()
	if v := vaultkey.Check(srv.URL, pin, known, 5*time.Second); v.Answers || !strings.Contains(v.Problem, "not reachable") {
		t.Fatalf("not reached: %+v", v)
	}
}

// recipeOf is a volume-independent recipe, for the prompt tests.
func recipeOf(modes ...string) func(string) ([]string, string) {
	var ms []string
	for _, m := range modes {
		if m != "" {
			ms = append(ms, m)
		}
	}
	return func(string) ([]string, string) { return ms, "" }
}
