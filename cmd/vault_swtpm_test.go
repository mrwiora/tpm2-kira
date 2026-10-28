//go:build integration

package cmd

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
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/attest"
	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/vaultproto"
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
			rsp.Pepper = v.peppers[v.gave]
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

// The whole tpm+vault path on swtpm: enrolment with a vault (the AK
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
	if n != slot-nvslot.NVRAMSlotStart || len(key) != 64 {
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
	slots := vaultSlots(tpmDev, false)
	if len(slots) != 1 || slots[0].idx != slot || !slots[0].att.Vault.Enabled() || slots[0].att.Phone.Enabled() {
		t.Fatalf("vault slots %+v", slots)
	}
	vs := slots[0]

	// The vault's policy computation is the TPM's: PolicyPCR over the
	// sealed values, computed in a trial session, equals vaultproto's.
	vals, err := readPCRBank(tpmDev, attest.PCRSelection{Alg: attest.AlgSHA256, Indices: []uint8{23}})
	if err != nil {
		t.Fatal(err)
	}
	trial, err := measure.ComputePolicyDigestFromPCRValues(tpmDev, []int{23}, map[int][]byte{23: vals[0].Digest}, measure.PCRHashAlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if soft := vaultproto.PolicyPCRDigest(sealedSelection(vs.sealed), []vaultproto.PCRValue{{Index: 23, Value: vals[0].Digest}}); !bytes.Equal(trial.Buffer, soft) {
		t.Fatalf("PolicyPCR: the TPM %x, vaultproto %x", trial.Buffer, soft)
	}

	var said []string
	say := func(s string) { said = append(said, s) }
	got, err := openVaultKey(context.Background(), tpmDev, vs, say)
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
	if _, err := openVaultKey(context.Background(), tpmDev, vs, say); err == nil || !strings.Contains(err.Error(), "the local part") {
		t.Fatalf("after a PCR moved: %v", err)
	}
	if len(tv.nonces) != asked {
		t.Fatal("the vault was asked although the local part did not open")
	}

	// The vault refuses that state on its own as well: the quote's values
	// are not the approved ones. (Asked directly, past the local part.)
	c, _ := newVaultClient(srv.URL, pin)
	if _, err := fetchRemote(context.Background(), tpmDev, vs, c, say); err == nil || !strings.Contains(err.Error(), "approval does not cover") {
		t.Fatalf("the vault on a moved PCR: %v", err)
	}
	tpmDev.Close()

	// Unenrolled, the slot has no vault, and nothing else uses the part.
	if err := VaultUnenrol(sock, slot, privPath, false); err != nil {
		t.Fatal(err)
	}
	tpmDev, _ = transport.OpenTPM(sock)
	defer tpmDev.Close()
	if _, sb, err := readSlot(tpmDev, slot); err != nil || sb.Payload.Attestation != nil {
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
	vs := vaultSlots(tpmDev, false)[0]
	if len(vs.att.Vault.PepperCheck) != 32 {
		t.Fatal("no pepper check in the blob")
	}

	tv.peppers = [][]byte{[]byte("s3cret pepprr"), []byte("s3cret pepper")}
	var said []string
	got, err := openVaultKey(context.Background(), tpmDev, vs, func(s string) { said = append(said, s) })
	if err != nil {
		t.Fatalf("the boot's key: %v", err)
	}
	if !bytes.Equal(got, key) || tv.gave != 2 || !strings.Contains(strings.Join(said, "\n"), "does not fit") {
		t.Fatalf("key equal %v, releases %d, said %q", bytes.Equal(got, key), tv.gave, said)
	}

	tv.peppers, tv.gave = nil, 0
	if _, err := openVaultKey(context.Background(), tpmDev, vs, func(string) {}); err == nil || !strings.Contains(err.Error(), "without a pepper") {
		t.Fatalf("a release without the pepper: %v", err)
	}
}
