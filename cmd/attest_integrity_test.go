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

// The gate serves only the record whose fingerprint its initramfs carries: another record signed
// by the same key (a phone added since, or an older record put back), a
// foreign one, and a slot the image knows nothing about are all refused.
func TestRecordFingerprints(t *testing.T) {
	key := newKey(t)
	idx := uint32(AttestNVRAMStart)
	built := signedAttestBlob(t, key, "box")

	fps, err := ParseRecordFingerprints(FormatRecordFingerprints(RecordFingerprints{idx: blobDigest(built)}))
	if err != nil || len(fps) != 1 {
		t.Fatalf("round trip: %v %v", fps, err)
	}
	if checkRecordFingerprint(fps, idx, built) != fingerprintMatches {
		t.Fatal("the record the image was built for must match")
	}
	if checkRecordFingerprint(fps, idx, signedAttestBlob(t, key, "box-as-it-was")) != fingerprintDiffers {
		t.Fatal("another record signed by the same key must not match")
	}
	if checkRecordFingerprint(fps, idx, signedAttestBlob(t, newKey(t), "box")) != fingerprintDiffers {
		t.Fatal("a foreign record must not match")
	}
	if checkRecordFingerprint(fps, idx+1, built) != fingerprintDiffers {
		t.Fatal("a slot the image does not know must not be served")
	}
	if checkRecordFingerprint(nil, idx, built) != fingerprintAbsent {
		t.Fatal("an image without a fingerprint file is 'absent', not a mismatch")
	}

	digest := blobDigest(built)
	for _, bad := range []string{
		"0x01803020",                  // no digest
		"0x01803020 zz",               // not hex
		"0x01803020 " + digest[:10],   // too short
		"0x00000001 " + digest,        // not an attestation index
		"0x01803020 " + digest + " x", // trailing field
	} {
		if _, err := ParseRecordFingerprints([]byte(bad + "\n")); err == nil {
			t.Errorf("fingerprint line %q should be refused", bad)
		}
	}
	if fps, err := LoadRecordFingerprints(t.TempDir() + "/none"); fps != nil || err != nil {
		t.Fatalf("a missing fingerprint file is not an error: %v %v", fps, err)
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
