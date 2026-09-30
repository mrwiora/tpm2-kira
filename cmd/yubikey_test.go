package cmd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/matthias/tpm2-kira/internal/piv"
	"github.com/matthias/tpm2-kira/internal/piv/pivtest"
)

// fakeTokens makes dialTokens return the given emulated cards and records
// how each connection was closed.
type fakeTokens struct {
	cards  []*pivtest.Card
	resets int
	dials  int
	err    error
}

func (f *fakeTokens) install(t *testing.T) {
	t.Helper()
	oldDial, oldPIN := dialTokens, pinSource
	t.Cleanup(func() {
		CloseTokenSessions()
		dialTokens, pinSource = oldDial, oldPIN
	})
	dialTokens = func(time.Duration) ([]*tokenConn, func(), error) {
		f.dials++
		if f.err != nil {
			return nil, nil, f.err
		}
		var conns []*tokenConn
		for i, c := range f.cards {
			conns = append(conns, &tokenConn{
				reader:    "Yubico YubiKey OTP+FIDO+CCID 0" + string(rune('0'+i)),
				transport: c,
				close: func(reset bool) error {
					if reset {
						f.resets++
					}
					return nil
				},
			})
		}
		return conns, func() {}, nil
	}
	pinSource = func(*yubiKeySigner) (string, error) {
		pin, ok := os.LookupEnv(PINEnvVar)
		if !ok {
			return "", errors.New("no PIN: set " + PINEnvVar)
		}
		return pin, nil
	}
}

// writeStub writes the key file setup --yubikey would write for slot.
func writeStub(t *testing.T, serial uint32, slot TokenSlot) string {
	t.Helper()
	data, err := MarshalYubiKeyStub(serial, slot)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "seal.key")
	if err := WriteSigningKeyFile(path, data); err != nil {
		t.Fatal(err)
	}
	return path
}

func probeSlot(t *testing.T, serial uint32, id piv.Slot) TokenSlot {
	t.Helper()
	tokens, err := ProbeYubiKeys(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range tokens {
		if tok.Serial == serial {
			if s, ok := tok.SlotByID(id); ok {
				return s
			}
		}
	}
	t.Fatalf("slot %s of %d not found", id, serial)
	return TokenSlot{}
}

func TestStubRoundTrip(t *testing.T) {
	card := pivtest.New(12345678)
	key := card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	(&fakeTokens{cards: []*pivtest.Card{card}}).install(t)

	path := writeStub(t, 12345678, probeSlot(t, 12345678, piv.SlotAuthentication))
	data, _ := os.ReadFile(path)
	for _, want := range []string{`"backend": "yubikey"`, `"serial": 12345678`, `"slot": "9a"`,
		`"algorithm": "ECCP256"`, `"pinPolicy": "once"`, `"touchPolicy": "never"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("stub lacks %s:\n%s", want, data)
		}
	}
	if err := CheckSigningKeyFileMode(path); err != nil {
		t.Errorf("stub mode: %v", err)
	}

	card.Log = nil
	card.Unplugged = true // loading and Public() must not need the token
	signer, err := LoadSigningPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(signer.Public()) {
		t.Fatal("stub public key differs from the slot key")
	}
	if desc, ok := YubiKeyDescription(signer); !ok || desc != "YubiKey 12345678, slot 9a" {
		t.Errorf("description %q", desc)
	}
	if len(card.Log) != 0 {
		t.Errorf("loading the key file sent %d APDUs", len(card.Log))
	}
}

func TestStubRefusals(t *testing.T) {
	good := `{"backend":"yubikey","version":1,"serial":5,"slot":"9a","algorithm":"ECCP256","pinPolicy":"once","touchPolicy":"never","publicKey":"%s"}`
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	der := base64.StdEncoding.EncodeToString(raw)
	cases := map[string]string{
		"unknown backend": strings.Replace(good, `"yubikey"`, `"nitrokey"`, 1),
		"unknown version": strings.Replace(good, `"version":1`, `"version":2`, 1),
		"no serial":       strings.Replace(good, `"serial":5`, `"serial":0`, 1),
		"bad slot":        strings.Replace(good, `"9a"`, `"9b"`, 1),
		"unknown field":   strings.Replace(good, `"slot"`, `"reader":"x","slot"`, 1),
		"bad public key":  strings.Replace(good, `%s`, "AAAA", 1),
	}
	for name, content := range cases {
		content = strings.Replace(content, "%s", der, 1)
		path := filepath.Join(t.TempDir(), "seal.key")
		os.WriteFile(path, []byte(content), 0400)
		if _, err := LoadSigningPrivateKey(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	path := filepath.Join(t.TempDir(), "seal.key")
	os.WriteFile(path, []byte(strings.Replace(good, "%s", der, 1)), 0400)
	if _, err := LoadSigningPrivateKey(path); err != nil {
		t.Errorf("valid stub refused: %v", err)
	}
}

// signForTPM through a token must produce what the TPM verifies: raw r and s,
// each padded to the curve size. Checked against the public key.
func TestSignForTPMThroughToken(t *testing.T) {
	card := pivtest.New(1)
	key := card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	rkey := card.AddRSAKey(piv.SlotSignature, 2048, piv.PINPolicyAlways, piv.TouchPolicyNever, true)
	(&fakeTokens{cards: []*pivtest.Card{card}}).install(t)
	t.Setenv(PINEnvVar, "123456")

	ecSigner, err := LoadSigningPrivateKey(writeStub(t, 1, probeSlot(t, 1, piv.SlotAuthentication)))
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := LoadSigningPrivateKey(writeStub(t, 1, probeSlot(t, 1, piv.SlotSignature)))
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 20; i++ { // enough runs to hit short r or s values
		digest := sha256.Sum256([]byte{byte(i)})
		sig, err := signForTPM(ecSigner, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		ecc, err := sig.Signature.ECDSA()
		if err != nil || sig.SigAlg != tpm2.TPMAlgECDSA {
			t.Fatalf("not an ECDSA signature: %v", err)
		}
		if len(ecc.SignatureR.Buffer) != 32 || len(ecc.SignatureS.Buffer) != 32 {
			t.Fatalf("r/s not padded: %d/%d", len(ecc.SignatureR.Buffer), len(ecc.SignatureS.Buffer))
		}
		r := new(big.Int).SetBytes(ecc.SignatureR.Buffer)
		s := new(big.Int).SetBytes(ecc.SignatureS.Buffer)
		if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
			t.Fatal("token ECDSA signature does not verify")
		}
	}

	digest := sha256.Sum256([]byte("rsa"))
	for i := 0; i < 3; i++ { // PIN policy ALWAYS: every signature re-verifies
		sig, err := signForTPM(rsaSigner, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		rs, err := sig.Signature.RSASSA()
		if err != nil {
			t.Fatal(err)
		}
		if err := rsa.VerifyPKCS1v15(&rkey.PublicKey, crypto.SHA256, digest[:], rs.Sig.Buffer); err != nil {
			t.Fatalf("token RSA signature does not verify: %v", err)
		}
	}
	if card.Retries != 3 {
		t.Errorf("repeated verification spent attempts: %d left", card.Retries)
	}
}

func TestBlobSignatureThroughToken(t *testing.T) {
	card := pivtest.New(1)
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	(&fakeTokens{cards: []*pivtest.Card{card}}).install(t)
	t.Setenv(PINEnvVar, "123456")

	signer, err := LoadSigningPrivateKey(writeStub(t, 1, probeSlot(t, 1, piv.SlotAuthentication)))
	if err != nil {
		t.Fatal(err)
	}
	blob := &SealedBlob{Version: CurrentBlobVersion, Payload: SealedBlobPayload{
		AppVersion: "test", Public: []byte("pub"), Private: []byte("priv"),
		PCRDigests: []PCRDigestPair{{Index: 0, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}}},
	}}
	unsigned, err := blob.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignBlobPayload(unsigned, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := UnmarshalSealedBlob(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBlobSignature(signed, parsed, signer.Public()); err != nil {
		t.Fatalf("blob signed on the token does not verify: %v", err)
	}
}

func TestWrongPINStopsEverything(t *testing.T) {
	card := pivtest.New(1)
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	(&fakeTokens{cards: []*pivtest.Card{card}}).install(t)
	t.Setenv(PINEnvVar, "000000")

	signer, err := LoadSigningPrivateKey(writeStub(t, 1, probeSlot(t, 1, piv.SlotAuthentication)))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(nil)
	// Stands in for reseal walking four NVRAM slots.
	for i := 0; i < 4; i++ {
		if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, ErrTokenUnavailable) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if card.Retries != 2 {
		t.Fatalf("a wrong PIN was tried %d times, want once", 3-card.Retries)
	}
}

func TestLastPINAttemptIsNotSpent(t *testing.T) {
	card := pivtest.New(1)
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	(&fakeTokens{cards: []*pivtest.Card{card}}).install(t)
	t.Setenv(PINEnvVar, "123456")
	signer, err := LoadSigningPrivateKey(writeStub(t, 1, probeSlot(t, 1, piv.SlotAuthentication)))
	if err != nil {
		t.Fatal(err)
	}
	card.Retries = 1
	digest := sha256.Sum256(nil)
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err == nil || !strings.Contains(err.Error(), "only one PIN attempt") {
		t.Fatalf("got %v", err)
	}
	for _, apdu := range card.Log {
		if apdu[1] == 0x20 && len(apdu) > 4 {
			t.Fatal("a PIN was sent with one attempt left")
		}
	}
}

func TestNoPINIsUnavailable(t *testing.T) {
	card := pivtest.New(1)
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	(&fakeTokens{cards: []*pivtest.Card{card}}).install(t)
	os.Unsetenv(PINEnvVar)
	signer, err := LoadSigningPrivateKey(writeStub(t, 1, probeSlot(t, 1, piv.SlotAuthentication)))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(nil)
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, ErrTokenUnavailable) {
		t.Fatalf("got %v", err)
	}
	if card.Retries != 3 {
		t.Fatal("an attempt was spent without a PIN")
	}
}

func TestWrongTokenAndReplacedKey(t *testing.T) {
	card := pivtest.New(1)
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	fake := &fakeTokens{cards: []*pivtest.Card{card}}
	fake.install(t)
	t.Setenv(PINEnvVar, "123456")
	path := writeStub(t, 1, probeSlot(t, 1, piv.SlotAuthentication))
	signer, _ := LoadSigningPrivateKey(path)
	digest := sha256.Sum256(nil)

	// A different YubiKey is plugged in.
	fake.cards = []*pivtest.Card{pivtest.New(2)}
	_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if !errors.Is(err, ErrTokenUnavailable) || !strings.Contains(err.Error(), "found: 2") {
		t.Fatalf("wrong token: %v", err)
	}

	// The right token, but the slot key was regenerated since setup.
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	card.Log = nil
	fake.cards = []*pivtest.Card{card}
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err == nil || !strings.Contains(err.Error(), "is not the key in") {
		t.Fatalf("replaced key: %v", err)
	}
	if card.Sent(0x20) && card.Retries != 3 {
		t.Fatal("a PIN was spent on a token holding the wrong key")
	}

	// No pcscd at all.
	fake.err = errors.New("no PC/SC daemon")
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, ErrTokenUnavailable) {
		t.Fatalf("no daemon: %v", err)
	}
}

func TestSessionIsSharedAndReset(t *testing.T) {
	card := pivtest.New(1)
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	fake := &fakeTokens{cards: []*pivtest.Card{card}}
	fake.install(t)
	t.Setenv(PINEnvVar, "123456")
	path := writeStub(t, 1, probeSlot(t, 1, piv.SlotAuthentication))
	dialsBefore := fake.dials

	digest := sha256.Sum256(nil)
	for i := 0; i < 3; i++ { // separate loads, like seal loading the key twice
		signer, _ := LoadSigningPrivateKey(path)
		if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			t.Fatal(err)
		}
	}
	if fake.dials-dialsBefore != 1 {
		t.Errorf("token opened %d times, want once per process", fake.dials-dialsBefore)
	}
	CloseTokenSessions()
	if fake.resets != 1 {
		t.Errorf("unlocked token was not reset on close (%d resets)", fake.resets)
	}
}

func TestProbeNeverSendsPIN(t *testing.T) {
	card := pivtest.New(7)
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, true)
	card.AddRSAKey(piv.SlotSignature, 4096, piv.PINPolicyAlways, piv.TouchPolicyAlways, false)
	old := pivtest.New(8)
	old.NoMetadata = true
	old.AddECKey(piv.SlotKeyManagement, piv.PINPolicyOnce, piv.TouchPolicyNever, true)
	(&fakeTokens{cards: []*pivtest.Card{card, old}}).install(t)

	tokens, err := ProbeYubiKeys(time.Second)
	if err != nil || len(tokens) != 2 {
		t.Fatalf("%v %+v", err, tokens)
	}
	if card.Sent(0x20) || old.Sent(0x20) {
		t.Fatal("probe sent VERIFY")
	}
	if s, _ := tokens[0].SlotByID(piv.SlotSignature); s.Unsuitable == "" {
		t.Error("RSA-4096 reported as usable")
	}
	if s, ok := tokens[1].SlotByID(piv.SlotKeyManagement); !ok || !s.CertOnly || s.Unsuitable != "" {
		t.Errorf("firmware without metadata: %+v", s)
	}
}

func TestSetupReport(t *testing.T) {
	var buf bytes.Buffer
	reportTokens(&buf, nil, errors.New("no PC/SC daemon at /run/pcscd/pcscd.comm"), false)
	if !strings.Contains(buf.String(), "No YubiKey could be found, so the signing key will be created as local files.") {
		t.Errorf("no daemon:\n%s", buf.String())
	}

	buf.Reset()
	reportTokens(&buf, nil, nil, false)
	if !strings.Contains(buf.String(), "No YubiKey could be found") {
		t.Errorf("no token:\n%s", buf.String())
	}

	card := pivtest.New(12345678)
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	card.AddRSAKey(piv.SlotSignature, 2048, piv.PINPolicyAlways, piv.TouchPolicyAlways, false)
	empty := pivtest.New(99)
	(&fakeTokens{cards: []*pivtest.Card{card, empty}}).install(t)
	tokens, _ := ProbeYubiKeys(time.Second)

	buf.Reset()
	reportTokens(&buf, tokens, nil, false)
	out := buf.String()
	t.Logf("report:\n%s", out)
	for _, want := range []string{"found one suitable", "serial 12345678", "slot 9a", "<- recommended",
		"slot 9c", "setup --yubikey=12345678", "no keys in any PIV slot", "Continuing with local key files.",
		"before sealing"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}

	buf.Reset()
	reportTokens(&buf, tokens[1:], nil, false)
	if !strings.Contains(buf.String(), "none is suitable") || !strings.Contains(buf.String(), "ykman piv keys generate") {
		t.Errorf("unsuitable report:\n%s", buf.String())
	}
}

func TestChooseToken(t *testing.T) {
	a := pivtest.New(1)
	a.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	b := pivtest.New(2)
	b.AddRSAKey(piv.SlotSignature, 2048, piv.PINPolicyAlways, piv.TouchPolicyNever, false)
	(&fakeTokens{cards: []*pivtest.Card{a, b}}).install(t)
	tokens, _ := ProbeYubiKeys(time.Second)
	var sink bytes.Buffer

	if _, _, err := chooseToken(&sink, tokens, nil, SetupOptions{UseYubiKey: true}); err == nil ||
		!strings.Contains(err.Error(), "several") {
		t.Errorf("two tokens without a serial: %v", err)
	}
	tok, slot, err := chooseToken(&sink, tokens, nil, SetupOptions{UseYubiKey: true, Serial: 1})
	if err != nil || tok.Serial != 1 || slot.Slot != piv.SlotAuthentication {
		t.Errorf("serial 1: %v", err)
	}
	// A shared slot is never taken implicitly.
	if _, _, err := chooseToken(&sink, tokens, nil, SetupOptions{UseYubiKey: true, Serial: 2}); err == nil ||
		!strings.Contains(err.Error(), "--slot") {
		t.Errorf("9c without --slot: %v", err)
	}
	if _, slot, err := chooseToken(&sink, tokens, nil, SetupOptions{UseYubiKey: true, Serial: 2, Slot: "9c"}); err != nil ||
		slot.Slot != piv.SlotSignature {
		t.Errorf("9c with --slot: %v", err)
	}
	if _, _, err := chooseToken(&sink, tokens, nil, SetupOptions{UseYubiKey: true, Serial: 3}); err == nil ||
		!strings.Contains(err.Error(), "found: 1, 2") {
		t.Errorf("absent serial: %v", err)
	}
	if _, _, err := chooseToken(&sink, nil, errors.New("no PC/SC daemon"), SetupOptions{UseYubiKey: true}); err == nil {
		t.Error("no daemon accepted")
	}
}

func TestVerifyKeyPairMatchThroughToken(t *testing.T) {
	card := pivtest.New(1)
	key := card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	(&fakeTokens{cards: []*pivtest.Card{card}}).install(t)
	signer, _ := LoadSigningPrivateKey(writeStub(t, 1, probeSlot(t, 1, piv.SlotAuthentication)))
	card.Log = nil
	if err := verifyKeyPairMatch(&key.PublicKey, signer); err != nil {
		t.Errorf("matching pair refused: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := verifyKeyPairMatch(&other.PublicKey, signer); err == nil {
		t.Error("mismatched pair accepted")
	}
	if len(card.Log) != 0 {
		t.Error("comparing keys touched the token")
	}
}
