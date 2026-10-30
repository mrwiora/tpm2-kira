//go:build integration

package admin

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/core/vaultproto"
	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/internal/vaultkey"
)

// testVault is the vault's protocol and nothing else: the token, the AK
// proof, the challenge and vaultproto.VerifyRelease. tpm2-kira-vault is
// the real one; this is what the machine's side is tested against.
type testVault struct {
	mu      sync.Mutex
	token   string
	secret  []byte
	enrol   *vaultproto.EnrolRequest
	dev     *vaultproto.Device
	remote  vaultproto.Wrapped
	minGen  uint64
	nonces  map[string][]byte
	refused []string
	peppers [][]byte // given with the releases of a pepper device, in turn
	gave    int
}

func (v *testVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()
	fail := func(msg string) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(vaultproto.ErrorResponse{Error: msg})
	}
	switch r.URL.Path {
	case vaultproto.PathEnrol:
		var req vaultproto.EnrolRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Token != v.token || req.Check() != nil {
			fail("enrolment refused")
			return
		}
		akPub, _ := tpm2.Unmarshal[tpm2.TPMTPublic](req.AKPublic)
		name, _ := tpm2.ObjectName(akPub)
		v.secret = make([]byte, 32)
		rand.Read(v.secret)
		cred, enc, err := attest.MakeCredential(nil, req.EKPublic, name.Buffer, v.secret)
		if err != nil {
			fail(err.Error())
			return
		}
		v.enrol = &req
		json.NewEncoder(w).Encode(vaultproto.EnrolChallenge{EnrolID: "e1", Challenge: vaultproto.Wrapped{Credential: cred, EncryptedSecret: enc}})
	case vaultproto.PathEnrolConfirm:
		var c vaultproto.EnrolConfirm
		if json.NewDecoder(r.Body).Decode(&c) != nil || v.enrol == nil || subtle.ConstantTimeCompare(c.Secret, v.secret) != 1 {
			fail("the attestation key is not proven")
			return
		}
		v.dev, v.remote, v.minGen, v.token = vaultproto.DeviceOf(v.enrol), v.enrol.Remote, v.enrol.Generation, ""
		json.NewEncoder(w).Encode(vaultproto.EnrolResult{DeviceID: v.dev.DeviceID, Mode: vaultproto.ModeAuto})
	case vaultproto.PathChallenge:
		var c vaultproto.ChallengeRequest
		if json.NewDecoder(r.Body).Decode(&c) != nil || v.dev == nil || !bytes.Equal(c.DeviceID, v.dev.DeviceID) {
			fail("unknown device")
			return
		}
		n := make([]byte, 32)
		rand.Read(n)
		id := randHex(8)
		v.nonces[id] = n
		json.NewEncoder(w).Encode(vaultproto.ChallengeResponse{RequestID: id, Nonce: n, ExpiresIn: 120})
	case vaultproto.PathRelease:
		var req vaultproto.ReleaseRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			fail("malformed")
			return
		}
		nonce := v.nonces[req.RequestID]
		delete(v.nonces, req.RequestID)
		checked, err := vaultproto.VerifyRelease(v.dev, nonce, &req, v.minGen)
		if err != nil {
			v.refused = append(v.refused, err.Error())
			json.NewEncoder(w).Encode(vaultproto.ReleaseResponse{Status: vaultproto.StatusDenied, Reason: err.Error()})
			return
		}
		v.minGen = checked.Generation
		rsp := vaultproto.ReleaseResponse{Status: vaultproto.StatusReleased, Remote: &v.remote}
		if v.enrol.Pepper && v.gave < len(v.peppers) {
			name, err := v.enrol.ReleaseKeyName()
			if err != nil {
				fail(err.Error())
				return
			}
			if rsp.Pepper, err = vaultproto.WrapPepper(rand.Reader, v.enrol.EKPublic, name, v.enrol.DeviceID, v.peppers[v.gave]); err != nil {
				fail(err.Error())
				return
			}
		}
		v.gave++
		json.NewEncoder(w).Encode(rsp)
	default:
		http.NotFound(w, r)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// signingKeyFiles writes a fresh ECDSA signing key pair, as 'setup' does.
func signingKeyFiles(t *testing.T) (privPath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	privPath, pubPath = filepath.Join(dir, "seal.key"), filepath.Join(dir, "seal.pub")
	if err := signing.WriteSigningKeyFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	pubPEM, _ := signing.PublicKeyToPEM(&key.PublicKey)
	if err := signing.WriteSigningKeyFile(pubPath, pubPEM); err != nil {
		t.Fatal(err)
	}
	return privPath, pubPath
}

// The whole unattended vault recipe (0x2400) path on swtpm: enrolment with a vault (the AK
// proven, the slot's approval pinned), then the boot's release - the
// local part from the blob, the remote part from the vault after it
// verified the quote against the approval - to the same key as at
// enrolment. A moved PCR of the selection opens neither part; the TPM is
// the one that says no.
func TestVaultKeyRoundTrip(t *testing.T) {
	sock := startSWTPM(t)
	const slot = nvslot.NVRAMSlotStart + 2
	privPath, pubPath := signingKeyFiles(t)
	if err := Seal(sock, "23", slot, pubPath, privPath, false, measure.PCRHashAlgoSHA256, false); err != nil {
		t.Fatal(err)
	}

	tv := &testVault{token: "tok-1", nonces: map[string][]byte{}}
	srv := httptest.NewTLSServer(tv)
	defer srv.Close()
	trustTestVault(t, srv)
	pin := vaultproto.PinOf(srv.Certificate().RawSubjectPublicKeyInfo)

	opts := VaultEnrolOptions{TPMPath: sock, SealIndex: slot, URL: srv.URL, Pin: pin, Token: "tok-1", Name: "box", PrivKeyPath: privPath}
	bad := opts
	bad.Token = "guessed"
	if _, _, err := vaultEnrolKey(bad); err == nil || !strings.Contains(err.Error(), "enrolment refused") {
		t.Fatalf("a wrong token: %v", err)
	}
	key, n, err := vaultEnrolKey(opts)
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if n != slot-nvslot.NVRAMSlotStart || len(key) != 87 || key[86] != '\n' {
		t.Fatalf("slot %d, key %d bytes", n, len(key))
	}
	if _, _, err := vaultEnrolKey(opts); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("a second enrolment of the slot: %v", err)
	}

	tpmDev, err := transport.OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tpmDev.Close()
	slots := vaultkey.Slots(tpmDev, false)
	if len(slots) != 1 || slots[0].Idx != slot || !slots[0].Att.Vault.Enabled() || slots[0].Att.Phone.Enabled() {
		t.Fatalf("vault slots %+v", slots)
	}
	vs := slots[0]

	// The vault's policy computation is the TPM's: PolicyPCR over the
	// sealed values, computed in a trial session, equals vaultproto's.
	vals, err := phonegate.ReadPCRBank(tpmDev, attest.PCRSelection{Alg: attest.AlgSHA256, Indices: []uint8{23}})
	if err != nil {
		t.Fatal(err)
	}
	trial, err := measure.ComputePolicyDigestFromPCRValues(tpmDev, []int{23}, map[int][]byte{23: vals[0].Digest}, measure.PCRHashAlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if soft := vaultproto.PolicyPCRDigest(vaultkey.SealedSelection(vs.Sealed), []vaultproto.PCRValue{{Index: 23, Value: vals[0].Digest}}); !bytes.Equal(trial.Buffer, soft) {
		t.Fatalf("PolicyPCR: the TPM %x, vaultproto %x", trial.Buffer, soft)
	}

	var said []string
	say := func(s string) { said = append(said, s) }
	got, _, err := vaultkey.Open(context.Background(), tpmDev, vs, say)
	if err != nil {
		t.Fatalf("the boot's key: %v (vault refused: %v)", err, tv.refused)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("the boot made another key than the enrolment")
	}

	// A boot state the signing key never approved: the TPM refuses the
	// local part, and the vault is not even asked.
	asked := len(tv.nonces)
	if err := extendPCR(tpmDev, 23, "a kernel nobody approved"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := vaultkey.Open(context.Background(), tpmDev, vs, say); err == nil || !strings.Contains(err.Error(), "the local part") {
		t.Fatalf("after a PCR moved: %v", err)
	}
	if len(tv.nonces) != asked {
		t.Fatal("the vault was asked although the local part did not open")
	}

	// The vault refuses that state on its own as well: the quote's values
	// are not the approved ones. (Asked directly, past the local part.)
	c, _ := vaultkey.NewClient(srv.URL, pin)
	if _, err := vaultkey.FetchRemote(context.Background(), tpmDev, vs, c, say); err == nil || !strings.Contains(err.Error(), "approval does not cover") {
		t.Fatalf("the vault on a moved PCR: %v", err)
	}
	tpmDev.Close()

	// Unenrolled, the slot has no vault, and nothing else uses the part.
	if err := VaultUnenrol(sock, slot, privPath, false); err != nil {
		t.Fatal(err)
	}
	tpmDev, _ = transport.OpenTPM(sock)
	defer tpmDev.Close()
	if _, sb, err := phonegate.ReadSlot(tpmDev, slot); err != nil || sb.Payload.Attestation != nil {
		t.Fatalf("after unenrol: %v %+v", err, sb.Payload.Attestation)
	}
}

// A key with an operator's pepper: asked at enrolment and never sent, only
// its check kept in the blob; at boot the pepper the vault passes on makes
// the key - a mistyped one is caught by the check and the vault is asked
// again, a release without one is refused.
func TestVaultPepper(t *testing.T) {
	sock := startSWTPM(t)
	const slot = nvslot.NVRAMSlotStart + 3
	privPath, pubPath := signingKeyFiles(t)
	if err := Seal(sock, "23", slot, pubPath, privPath, false, measure.PCRHashAlgoSHA256, false); err != nil {
		t.Fatal(err)
	}
	tv := &testVault{token: "tok-p", nonces: map[string][]byte{}}
	srv := httptest.NewTLSServer(tv)
	defer srv.Close()
	trustTestVault(t, srv)

	old := terminalAsk
	terminalAsk = func(string) ([]byte, error) { return []byte("s3cret pepper"), nil }
	defer func() { terminalAsk = old }()
	key, _, err := vaultEnrolKey(VaultEnrolOptions{TPMPath: sock, SealIndex: slot, URL: srv.URL,
		Pin: vaultproto.PinOf(srv.Certificate().RawSubjectPublicKeyInfo), Token: "tok-p", PrivKeyPath: privPath, Pepper: true})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if !tv.enrol.Pepper {
		t.Fatal("the vault was not told the key needs a pepper")
	}
	if raw, _ := json.Marshal(tv.enrol); bytes.Contains(raw, []byte("s3cret")) {
		t.Fatal("the pepper went to the vault")
	}

	tpmDev, err := transport.OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tpmDev.Close()
	vs := vaultkey.Slots(tpmDev, false)[0]
	if len(vs.Att.Vault.PepperCheck) != nvslot.PepperCheckSize {
		t.Fatal("no pepper check in the blob")
	}

	tv.peppers = [][]byte{[]byte("s3cret pepprr"), []byte("s3cret pepper")}
	var said []string
	got, _, err := vaultkey.Open(context.Background(), tpmDev, vs, func(s string) { said = append(said, s) })
	if err != nil {
		t.Fatalf("the boot's key: %v", err)
	}
	if !bytes.Equal(got, key) || tv.gave != 2 || !strings.Contains(strings.Join(said, "\n"), "does not fit") {
		t.Fatalf("key equal %v, releases %d, said %q", bytes.Equal(got, key), tv.gave, said)
	}

	tv.peppers, tv.gave = nil, 0
	if _, _, err := vaultkey.Open(context.Background(), tpmDev, vs, func(string) {}); err == nil || !strings.Contains(err.Error(), "without a pepper") {
		t.Fatalf("a release without the pepper: %v", err)
	}
}

// A typed password with the vault's salt and a pepper (0x1401): the vault
// method keeps no TPM part and no pepper check; at boot the vault's
// release is the salt - with the pepper in it - and the key is the
// combiner's of the password typed later and that salt.
func TestVaultTypedPassword(t *testing.T) {
	sock := startSWTPM(t)
	const slot = nvslot.NVRAMSlotStart + 4
	privPath, pubPath := signingKeyFiles(t)
	if err := Seal(sock, "23", slot, pubPath, privPath, false, measure.PCRHashAlgoSHA256, false); err != nil {
		t.Fatal(err)
	}
	tv := &testVault{token: "tok-t", nonces: map[string][]byte{}}
	srv := httptest.NewTLSServer(tv)
	defer srv.Close()
	trustTestVault(t, srv)

	old := terminalAsk
	answers := map[string]string{"Pepper": "s3cret pepper", "The same pepper": "s3cret pepper", "Password": "hunter2", "The same password": "hunter2"}
	terminalAsk = func(prompt string) ([]byte, error) {
		for _, k := range []string{"The same pepper", "The same password", "Pepper", "Password"} {
			if strings.HasPrefix(prompt, k) {
				return []byte(answers[k]), nil
			}
		}
		return nil, fmt.Errorf("unexpected prompt %q", prompt)
	}
	defer func() { terminalAsk = old }()
	key, _, err := vaultEnrolKey(VaultEnrolOptions{TPMPath: sock, SealIndex: slot, URL: srv.URL, TypedPassword: true,
		Pin: vaultproto.PinOf(srv.Certificate().RawSubjectPublicKeyInfo), Token: "tok-t", PrivKeyPath: privPath, Pepper: true})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	tpmDev, err := transport.OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tpmDev.Close()
	vs := vaultkey.Slots(tpmDev, false)[0]
	if v := vs.Att.Vault; v.Unattended() || !v.Pepper || len(v.PepperCheck) != 0 || vaultRecipeOf(&v) != diskkey.RecipeVaultSaltPepper {
		t.Fatalf("the vault method %+v", v)
	}

	tv.peppers = [][]byte{[]byte("s3cret pepper")}
	gotKey, salt, err := vaultkey.Open(context.Background(), tpmDev, vs, func(string) {})
	if err != nil || gotKey != nil || salt == nil {
		t.Fatalf("the boot's salt: %v (key %v)", err, gotKey != nil)
	}
	if want, _ := diskkey.Combine([]byte("hunter2"), salt); !bytes.Equal(want, key) {
		t.Fatal("password and released salt do not make the enrolled key")
	}
}

// A slot with a TPM salt and a vault: the vault is told the name given
// at its enrolment, and unenrolling the vault keeps the attestation part -
// the TPM salt and the device ID stay.
func TestVaultBesideATPMSalt(t *testing.T) {
	sock := startSWTPM(t)
	const slot = nvslot.NVRAMSlotStart
	privPath, pubPath := signingKeyFiles(t)
	if err := Seal(sock, "23", slot, pubPath, privPath, false, measure.PCRHashAlgoSHA256, false); err != nil {
		t.Fatal(err)
	}
	old := terminalAsk
	terminalAsk = func(string) ([]byte, error) { return []byte("hunter2"), nil }
	defer func() { terminalAsk = old }()
	if _, _, err := tpmSaltKey(FactorEnrolOptions{TPMPath: sock, SealIndex: slot, PrivKeyPath: privPath}); err != nil {
		t.Fatalf("the TPM salt: %v", err)
	}

	tv := &testVault{token: "tok-n", nonces: map[string][]byte{}}
	srv := httptest.NewTLSServer(tv)
	defer srv.Close()
	trustTestVault(t, srv)
	if _, _, err := vaultEnrolKey(VaultEnrolOptions{TPMPath: sock, SealIndex: slot, URL: srv.URL, Name: "box",
		Pin: vaultproto.PinOf(srv.Certificate().RawSubjectPublicKeyInfo), Token: "tok-n", PrivKeyPath: privPath}); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if tv.enrol.Name != "box" {
		t.Fatalf("the vault was told the name %q, not the one given", tv.enrol.Name)
	}
	tpmDev, err := transport.OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	_, sb, err := phonegate.ReadSlot(tpmDev, slot)
	tpmDev.Close()
	if err != nil {
		t.Fatal(err)
	}
	id := sb.Payload.Attestation.DeviceID

	if err := VaultUnenrol(sock, slot, privPath, false); err != nil {
		t.Fatal(err)
	}
	tpmDev, _ = transport.OpenTPM(sock)
	defer tpmDev.Close()
	_, sb, err = phonegate.ReadSlot(tpmDev, slot)
	if err != nil {
		t.Fatal(err)
	}
	att := sb.Payload.Attestation
	if att == nil || att.Vault.Enabled() || len(att.TPMSalt.Credential) == 0 || !bytes.Equal(att.DeviceID, id) {
		t.Fatalf("after the vault's unenrol: %+v", att)
	}
	tpmDev.Close()

	// The TPM salt out as well (its last keyslot removed): nothing uses
	// the attestation part any more.
	if err := removeTPMSalt(sock, 0, privPath); err != nil {
		t.Fatal(err)
	}
	tpmDev, _ = transport.OpenTPM(sock)
	if _, sb, err = phonegate.ReadSlot(tpmDev, slot); err != nil || sb.Payload.Attestation != nil {
		t.Fatalf("after the TPM salt's removal: %v %+v", err, sb.Payload.Attestation)
	}
}

// A blob that would not fit is named before anything is sent, with what
// the slot holds and how to make room.
func TestBlobFullSaysWhatTheSlotHolds(t *testing.T) {
	att := &nvslot.Attestation{Vault: nvslot.VaultAttestation{URL: "https://v"}, TPMSalt: nvslot.WrappedFactor{Credential: []byte{1}}}
	err := blobFull(0, 2065, 2048, att)
	for _, want := range []string{"2065 bytes", "at most 2048", "the vault method", "a TPM salt", "another slot", "luks remove"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q not in %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "phone") {
		t.Errorf("phones named for a slot without any: %v", err)
	}
}
