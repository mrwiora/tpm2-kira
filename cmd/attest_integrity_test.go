package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/matthias/tpm2-kira/attest"
)

func signedAttestBlob(t *testing.T, key *ecdsa.PrivateKey, name string) []byte {
	t.Helper()
	b := &AttestBlob{
		AppVersion: "test", DeviceID: make([]byte, 16), FriendlyName: name,
		AKPublic: []byte{1}, AKPrivate: []byte{2}, AKName: []byte{3},
		NoisePrivate: make([]byte, 32), AdvKey: make([]byte, 32),
		PCRAlg: attest.AlgSHA256, PCRSelection: []uint8{0, 7},
		Verifiers: []attest.EnrolledVerifier{{ID: "phone", AnchorPub: []byte{4}, NoisePub: make([]byte, 32)}},
	}
	unsigned, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignBlobPayload(unsigned, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAttestBlobSignature(t *testing.T) {
	mine, theirs := newKey(t), newKey(t)
	blob := signedAttestBlob(t, mine, "box")
	if err := VerifyAttestBlobSignature(blob, &mine.PublicKey); err != nil {
		t.Fatalf("own blob rejected: %v", err)
	}
	if VerifyAttestBlobSignature(blob, &theirs.PublicKey) == nil {
		t.Fatal("blob accepted with another machine's key")
	}
	if VerifyAttestBlobSignature(signedAttestBlob(t, theirs, "box"), &mine.PublicKey) == nil {
		t.Fatal("attacker-signed blob accepted")
	}
	edited := append([]byte(nil), blob...)
	i := strings.Index(string(edited), "box")
	edited[i] = 'f' // payload changed after signing
	if VerifyAttestBlobSignature(edited, &mine.PublicKey) == nil {
		t.Fatal("edited payload accepted")
	}
	unsigned, _ := (&AttestBlob{AppVersion: "x", DeviceID: make([]byte, 16), NoisePrivate: make([]byte, 32), AdvKey: make([]byte, 32)}).Marshal()
	if VerifyAttestBlobSignature(unsigned, &mine.PublicKey) == nil {
		t.Fatal("unsigned blob accepted")
	}
}

func TestSlotIntegrityState(t *testing.T) {
	key := newKey(t)
	dir := t.TempDir()
	idx := uint32(AttestNVRAMStart + 3)
	v1 := signedAttestBlob(t, key, "box")
	v2 := signedAttestBlob(t, key, "box2")

	res, err := checkSlotIntegrity(v1, &key.PublicKey, dir, idx, false)
	if res != integrityFirstSeen || err != nil {
		t.Fatalf("first check: %v %v", res, err)
	}
	if res, _ = checkSlotIntegrity(v1, &key.PublicKey, dir, idx, false); res != integrityOK {
		t.Fatalf("unchanged blob: %v", res)
	}
	// A different blob, validly signed (an older one put back): changed.
	if res, _ = checkSlotIntegrity(v2, &key.PublicKey, dir, idx, false); res != integrityChanged {
		t.Fatalf("changed blob: %v", res)
	}
	// --accept records it; afterwards it is OK.
	if res, err = checkSlotIntegrity(v2, &key.PublicKey, dir, idx, true); res != integrityOK || err != nil {
		t.Fatalf("accept: %v %v", res, err)
	}
	if res, _ = checkSlotIntegrity(v2, &key.PublicKey, dir, idx, false); res != integrityOK {
		t.Fatalf("after accept: %v", res)
	}
	// --accept never records a blob with a bad signature.
	other := signedAttestBlob(t, newKey(t), "box")
	if res, _ = checkSlotIntegrity(other, &key.PublicKey, dir, idx, true); res != integrityBadSig {
		t.Fatalf("accept of a foreign blob: %v", res)
	}
	if res, _ = checkSlotIntegrity(v2, &key.PublicKey, dir, idx, false); res != integrityOK {
		t.Fatal("foreign blob replaced the recorded state")
	}
	st, err := os.Stat(attestStateFile(dir, idx))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", st, err)
	}
}

func TestEnrolRefusesToExtendAForeignBlob(t *testing.T) {
	mine, theirs := newKey(t), newKey(t)
	if err := verifyBeforeExtending(signedAttestBlob(t, mine, "box"), &mine.PublicKey, 0); err != nil {
		t.Fatalf("own blob: %v", err)
	}
	err := verifyBeforeExtending(signedAttestBlob(t, theirs, "box"), &mine.PublicKey, 2)
	if err == nil || !strings.Contains(err.Error(), "attest unenrol --nvram 2") {
		t.Fatalf("foreign blob: %v", err)
	}
}
