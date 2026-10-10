package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// signatureSizes bounds what the keys really produce: the size check before
// a seal relies on it never to underestimate.
func TestSignatureSizesBoundRealSignatures(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	r2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, key := range map[string]crypto.Signer{"P-256": p256, "P-384": p384, "RSA-2048": r2048} {
		approvalMax, blobMax, err := signatureSizes(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 64; i++ {
			approval, err := signApproval(key, randBytes(32), randBytes(32))
			if err != nil {
				t.Fatal(err)
			}
			signed, err := SignBlobPayload(make([]byte, 8), key)
			if err != nil {
				t.Fatal(err)
			}
			if len(approval) > approvalMax || len(signed)-8-2 > blobMax {
				t.Fatalf("%s: approval %d > %d or blob signature %d > %d",
					name, len(approval), approvalMax, len(signed)-10, blobMax)
			}
		}
	}
}

// Before a phone answers, enrolment counts only what is certain: a phone
// more for a slot without one, none for a slot that has some (the phone may
// be one of them enrolling again), and empty strings either way.
func TestEnrolmentSizeIsALowerBound(t *testing.T) {
	sb := testSlotBlob()
	sb.BlobSignature = make([]byte, 72)
	none := testEnrolment("box")
	none.Phone.Verifiers = nil
	bare := *sb
	bare.Payload.Attestation = none
	unsigned, err := bare.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	withPhone, err := enrolmentSize(sb, none)
	if err != nil {
		t.Fatal(err)
	}
	if grown := withPhone - (len(unsigned) + 2 + 72); grown <= 0 || grown > 2+2+2+91+32+2 {
		t.Fatalf("a first phone adds %d bytes to the estimate", grown)
	}

	one := testEnrolment("box")
	sb1 := *sb
	sb1.Payload.Attestation = one
	unsigned, err = sb1.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if again, err := enrolmentSize(sb, one); err != nil || again != len(unsigned)+2+72 {
		t.Fatalf("a slot with a phone: estimate %d, the blob as it is %d (%v)", again, len(unsigned)+2+72, err)
	}
}
