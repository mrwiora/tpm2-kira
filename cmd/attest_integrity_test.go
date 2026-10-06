package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// The count is part of what is signed: it survives a round trip, and a
// record with another count is another record.
func TestAttestBlobCarriesItsCount(t *testing.T) {
	key := newKey(t)
	b := &AttestBlob{
		AppVersion: "test", DeviceID: make([]byte, 16), FriendlyName: "box",
		AKPublic: []byte{1}, AKPrivate: []byte{2}, AKName: []byte{3},
		NoisePrivate: make([]byte, 32), AdvKey: make([]byte, 32),
		PCRAlg: attest.AlgSHA256, PCRSelection: []uint8{0, 7},
		Verifiers: []attest.EnrolledVerifier{{ID: "phone", AnchorPub: []byte{4}, NoisePub: make([]byte, 32)}},
		Count:     41,
	}
	sign := func() []byte {
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
	first := sign()
	got, err := UnmarshalAttestBlob(first)
	if err != nil || got.Count != 41 {
		t.Fatalf("count lost: %+v %v", got, err)
	}
	if err := VerifyAttestBlobSignature(first, &key.PublicKey); err != nil {
		t.Fatal(err)
	}
	// Changing the count in a signed record breaks its signature.
	tampered := append([]byte(nil), first...)
	b.Count = 42
	second := sign()
	for i := range first {
		if i < len(second) && first[i] != second[i] {
			tampered[i] = second[i] // the first differing byte is in the count
			break
		}
	}
	if VerifyAttestBlobSignature(tampered, &key.PublicKey) == nil {
		t.Fatal("a record with an altered count still verifies")
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
