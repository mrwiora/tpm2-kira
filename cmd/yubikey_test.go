package cmd

import (
	"bufio"
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
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/mrwiora/tpm2-kira/internal/piv"
	"github.com/mrwiora/tpm2-kira/internal/piv/pivtest"
)

// fakeTokens makes dialTokens return the given emulated cards and records
// how each connection was closed.
type fakeTokens struct {
	cards   []*pivtest.Card
	resets  int
	dials   int
	err     error
	typed   string // what the fake terminal answers; "" means no terminal
	prompts int
}

func (f *fakeTokens) install(t *testing.T) {
	t.Helper()
	oldDial, oldPrompt := dialTokens, promptPIN
	t.Cleanup(func() {
		CloseTokenSessions()
		dialTokens, promptPIN = oldDial, oldPrompt
	})
	// Keep the host's control.conf out of the tests.
	t.Setenv("TPM2_KIRA_CONTROL_CONF", filepath.Join(t.TempDir(), "absent-control.conf"))
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
						c.Reset()
					}
					return nil
				},
			})
		}
		return conns, func() {}, nil
	}
	// Never touch the real terminal; tests that want a typed PIN set
	// f.typed.
	promptPIN = func(*yubiKeySigner) (string, error) {
		f.prompts++
		if f.typed == "" {
			return "", errors.New("no PIN: no terminal in tests")
		}
		return f.typed, nil
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
	if err := CheckSigningKeyFile(path); err != nil {
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
		Public: []byte("pub"), Private: []byte("priv"),
		TOTPAlgorithm: tpm2.TPMAlgSHA1,
		PCRDigests:    []PCRDigestPair{{Index: 0, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}}},
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
	if reportTokens(&buf, nil, errors.New("no PC/SC daemon at /run/pcscd/pcscd.comm"), false) ||
		!strings.Contains(buf.String(), "No YubiKey could be found, so the signing key will be created as local files.") {
		t.Errorf("no daemon:\n%s", buf.String())
	}

	buf.Reset()
	if reportTokens(&buf, nil, nil, false) || !strings.Contains(buf.String(), "No YubiKey could be found") {
		t.Errorf("no token:\n%s", buf.String())
	}

	empty := pivtest.New(99)
	(&fakeTokens{cards: []*pivtest.Card{empty}}).install(t)
	tokens, _ := ProbeYubiKeys(time.Second)
	buf.Reset()
	if reportTokens(&buf, tokens, nil, false) || !strings.Contains(buf.String(), "none is suitable") ||
		!strings.Contains(buf.String(), "ykman piv keys generate") {
		t.Errorf("unsuitable report:\n%s", buf.String())
	}
}

// setupTokens is one token with a recommended 9a key, a shared 9c key and a
// key without PIN, plus an empty token.
func setupTokens(t *testing.T) []TokenInfo {
	t.Helper()
	card := pivtest.New(12345678)
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	card.AddRSAKey(piv.SlotSignature, 2048, piv.PINPolicyAlways, piv.TouchPolicyAlways, false)
	card.AddECKey(piv.SlotKeyManagement, piv.PINPolicyNever, piv.TouchPolicyNever, false)
	(&fakeTokens{cards: []*pivtest.Card{card, pivtest.New(99)}}).install(t)
	tokens, err := ProbeYubiKeys(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

func TestAskKeyLocation(t *testing.T) {
	tokens := setupTokens(t)
	ask := func(input string) (*TokenInfo, TokenSlot, string, error) {
		var out bytes.Buffer
		tok, slot, err := askKeyLocation(&out, bufio.NewReader(strings.NewReader(input)), tokens, nil, false)
		return tok, slot, out.String(), err
	}

	tok, slot, out, err := ask("\n")
	if err != nil || tok == nil || slot.Slot != piv.SlotAuthentication {
		t.Fatalf("default choice: %v %v\n%s", err, slot.Slot, out)
	}
	t.Logf("menu:\n%s", out)
	for _, want := range []string{"Where should the signing key live?", "1) YubiKey 12345678, slot 9a",
		"2) YubiKey 12345678, slot 9c", "3) YubiKey 12345678, slot 9d", "[no PIN required: insecure]",
		"4) Local key files", "Choice [1]:", "WARNING: no PIN required (insecure)"} {
		if !strings.Contains(out, want) {
			t.Errorf("menu lacks %q", want)
		}
	}

	if tok, _, _, err := ask("4\n"); err != nil || tok != nil {
		t.Errorf("local choice: %v %v", tok, err)
	}
	if _, slot, _, err := ask("2\n"); err != nil || slot.Slot != piv.SlotSignature {
		t.Errorf("explicit 9c: %v %v", slot.Slot, err)
	}
	if _, slot, out, err := ask("x\n7\n2\n"); err != nil || slot.Slot != piv.SlotSignature ||
		strings.Count(out, "Please enter a number from 1 to 4.") != 2 {
		t.Errorf("retry after bad input: %v %v\n%s", slot.Slot, err, out)
	}
	if _, _, _, err := ask("x\ny\nz\n"); err == nil {
		t.Error("three bad answers accepted")
	}
	if _, _, _, err := ask(""); err == nil || !strings.Contains(err.Error(), "nothing was written") {
		t.Errorf("EOF: %v", err)
	}

	// Without a terminal: local files, and how to choose without one.
	var buf bytes.Buffer
	tok, _, err = askKeyLocation(&buf, nil, tokens, nil, false)
	if err != nil || tok != nil || !strings.Contains(buf.String(), "--yubikey=SERIAL") {
		t.Errorf("no terminal: %v %v\n%s", tok, err, buf.String())
	}
}

// Even a single candidate is a question, and without 9a the default is local.
func TestAskKeyLocationSingleNon9a(t *testing.T) {
	card := pivtest.New(5)
	card.AddRSAKey(piv.SlotSignature, 2048, piv.PINPolicyAlways, piv.TouchPolicyNever, false)
	(&fakeTokens{cards: []*pivtest.Card{card}}).install(t)
	tokens, _ := ProbeYubiKeys(time.Second)
	var out bytes.Buffer
	tok, _, err := askKeyLocation(&out, bufio.NewReader(strings.NewReader("\n")), tokens, nil, false)
	if err != nil || tok != nil || !strings.Contains(out.String(), "Choice [2]:") {
		t.Errorf("single 9c: %v %v\n%s", tok, err, out.String())
	}
}

func TestPINGuidance(t *testing.T) {
	tokens := setupTokens(t)
	s9a, _ := tokens[0].SlotByID(piv.SlotAuthentication)
	s9d, _ := tokens[0].SlotByID(piv.SlotKeyManagement)

	if w := pinPolicyWarning(s9a); w != "" {
		t.Errorf("PIN once warned: %s", w)
	}
	if w := pinPolicyWarning(s9d); !strings.Contains(w, "needs no PIN") {
		t.Errorf("PIN never not warned: %q", w)
	}
	if w := pinPolicyWarning(TokenSlot{Slot: piv.SlotAuthentication}); !strings.Contains(w, "cannot be read") {
		t.Errorf("unknown policy: %q", w)
	}

	conf := filepath.Join(t.TempDir(), "control.conf")
	t.Setenv("TPM2_KIRA_CONTROL_CONF", conf)

	// No PIN stored: control stores it; the terminal or the environment meanwhile.
	var buf bytes.Buffer
	printPINInstructions(&buf, tokens[0], s9a)
	t.Logf("instructions:\n%s", buf.String())
	for _, want := range []string{"tpm2-kira control", "TPM2_KIRA_PIN='<your PIN>' in " + conf, "read -rs TPM2_KIRA_PIN && export TPM2_KIRA_PIN", "SKIPPED"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("instructions lack %q", want)
		}
	}

	// Stored: nothing to do, apart from the file mode.
	os.WriteFile(conf, []byte("TPM2_KIRA_PIN='123456'\n"), 0644)
	buf.Reset()
	printPINInstructions(&buf, tokens[0], s9a)
	if !strings.Contains(buf.String(), "stores the PIN") || !strings.Contains(buf.String(), "chmod 600") ||
		strings.Contains(buf.String(), "<your PIN>") {
		t.Errorf("PIN already configured:\n%s", buf.String())
	}
	os.Chmod(conf, 0600)
	buf.Reset()
	printPINInstructions(&buf, tokens[0], s9a)
	if strings.Contains(buf.String(), "chmod") {
		t.Errorf("mode 600 still told to chmod:\n%s", buf.String())
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

func TestPINFromControlConf(t *testing.T) {
	card := pivtest.New(1)
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	fake := &fakeTokens{cards: []*pivtest.Card{card}}
	fake.install(t)
	os.Unsetenv(PINEnvVar)
	conf := filepath.Join(t.TempDir(), "control.conf")
	t.Setenv("TPM2_KIRA_CONTROL_CONF", conf)
	signer, _ := LoadSigningPrivateKey(writeStub(t, 1, probeSlot(t, 1, piv.SlotAuthentication)))
	digest := sha256.Sum256(nil)

	capture := func(fn func()) string {
		r, w, _ := os.Pipe()
		old := os.Stderr
		os.Stderr = w
		fn()
		w.Close()
		os.Stderr = old
		out, _ := io.ReadAll(r)
		return string(out)
	}

	// PIN in control.conf: used without asking, and no warning.
	os.WriteFile(conf, []byte("TPM2_KIRA_PIN='123456'\n"), 0600)
	out := capture(func() {
		if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			t.Fatal(err)
		}
	})
	if fake.prompts != 0 || strings.Contains(out, "WARNING") {
		t.Errorf("prompts %d, output:\n%s", fake.prompts, out)
	}
	CloseTokenSessions()

	// The environment wins over the file.
	os.WriteFile(conf, []byte("TPM2_KIRA_PIN='999999'\n"), 0600)
	t.Setenv(PINEnvVar, "123456")
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("environment PIN not preferred: %v", err)
	}
	CloseTokenSessions()
	os.Unsetenv(PINEnvVar)

	// A wrong PIN in the file names the file, and costs one attempt.
	_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err == nil || !strings.Contains(err.Error(), "PIN from "+conf) || card.Retries != 2 {
		t.Fatalf("wrong PIN from the file: %v, retries %d", err, card.Retries)
	}
	card.Retries = 3
	CloseTokenSessions()

	// A world-readable file with the PIN in it: refused, no attempt spent,
	// and no fallback to the terminal.
	os.WriteFile(conf, []byte("TPM2_KIRA_PIN='123456'\n"), 0600)
	os.Chmod(conf, 0644)
	prompts := fake.prompts
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err == nil || !errors.Is(err, ErrTokenUnavailable) || !strings.Contains(err.Error(), "chmod 600 "+conf) {
		t.Errorf("world-readable file: err = %v, want an unavailable-token error naming the fix", err)
	}
	if card.Retries != 3 || fake.prompts != prompts {
		t.Errorf("world-readable file: retries %d, prompts %d → %d; want no attempt and no prompt", card.Retries, prompts, fake.prompts)
	}
	CloseTokenSessions()

	// A file that does not load - a line this version refuses next to the
	// PIN - is named with the reason, and nothing is asked: the reseal of
	// an image build must not wait at a terminal nobody watches.
	CloseTokenSessions()
	os.WriteFile(conf, []byte("TPM2_KIRA_ATTEST_TIMEOUT=0\nTPM2_KIRA_PIN='123456'\n"), 0600)
	prompts = fake.prompts
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err == nil || !strings.Contains(err.Error(), "does not load, so the PIN in it is not read") ||
		!strings.Contains(err.Error(), "TPM2_KIRA_ATTEST_TIMEOUT is gone") || fake.prompts != prompts {
		t.Errorf("a file that does not load: err = %v, prompts %d → %d", err, prompts, fake.prompts)
	}
	CloseTokenSessions()

	// No PIN in the file: asked on the terminal, then warned once.
	os.WriteFile(conf, []byte("TPM2_KIRA_ATTEST_ADAPTER=0\n"), 0600)
	fake.typed = "123456"
	out = capture(func() {
		if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			t.Fatal(err)
		}
	})
	if fake.prompts != 1 || strings.Count(out, "holds no TPM2_KIRA_PIN") != 1 {
		t.Errorf("prompts %d, output:\n%s", fake.prompts, out)
	}
}

// The seal that failed on a real YubiKey 5 (slot 9a, PIN policy 'always'):
// the blob signature worked, the next signature was refused with "PIN
// verification required" because an empty VERIFY keeps reporting the PIN as
// verified. Every signature of a seal must work, whatever the key file
// records, and no attempt may be spent.
func TestPINPolicyAlwaysLikeRealYubiKey(t *testing.T) {
	for _, recorded := range []string{"always", "once", "unknown"} {
		t.Run("key file says "+recorded, func(t *testing.T) {
			card := pivtest.New(33261813)
			card.AddECKey(piv.SlotAuthentication, piv.PINPolicyAlways, piv.TouchPolicyNever, false)
			fake := &fakeTokens{cards: []*pivtest.Card{card}}
			fake.install(t)
			t.Setenv(PINEnvVar, "123456")

			slot := probeSlot(t, 33261813, piv.SlotAuthentication)
			path := writeStub(t, 33261813, slot)
			data, _ := os.ReadFile(path)
			data = bytes.Replace(data, []byte(`"pinPolicy": "always"`), []byte(`"pinPolicy": "`+recorded+`"`), 1)
			os.Chmod(path, 0600)
			os.WriteFile(path, data, 0400)
			signer, err := LoadSigningPrivateKey(path)
			if err != nil {
				t.Fatal(err)
			}

			// Blob signature, NV write pre-flight, two NV chunks.
			for i := 0; i < 4; i++ {
				digest := sha256.Sum256([]byte{byte(i)})
				if _, err := signForTPM(signer, digest[:]); err != nil {
					t.Fatalf("signature %d: %v", i+1, err)
				}
			}
			if card.Retries != 3 || card.SignCount != 4 {
				t.Errorf("retries %d, signatures %d", card.Retries, card.SignCount)
			}
		})
	}
}

// Another process left the PIN verified; a key with PIN policy 'always'
// still needs this process to verify it.
func TestPINAlwaysWithPINLeftVerified(t *testing.T) {
	card := pivtest.New(1)
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyAlways, piv.TouchPolicyNever, false)
	fake := &fakeTokens{cards: []*pivtest.Card{card}}
	fake.install(t)
	t.Setenv(PINEnvVar, "123456")
	signer, _ := LoadSigningPrivateKey(writeStub(t, 1, probeSlot(t, 1, piv.SlotAuthentication)))

	other, err := piv.Open(card)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.VerifyPIN("123456"); err != nil {
		t.Fatal(err)
	}
	other.Sign(piv.SlotAuthentication, signer.Public(), make([]byte, 32)) // consumes the fresh VERIFY

	digest := sha256.Sum256(nil)
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("sign after another process: %v", err)
	}
	if card.Retries != 3 {
		t.Errorf("retries %d", card.Retries)
	}
}
