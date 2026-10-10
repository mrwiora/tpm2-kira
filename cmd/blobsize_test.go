package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/mrwiora/tpm2-kira/attest"
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
// more for a slot without one (whose TOTP key then goes), none for a slot
// that has some (the phone may be one of them enrolling again), and empty
// strings either way.
func TestEnrolmentSizeIsALowerBound(t *testing.T) {
	sb := testSlotBlob()
	sb.BlobSignature = make([]byte, 72)
	none := testEnrolment("box")
	none.Phone.Verifiers = nil
	minimal := testEnrolment("box")
	minimal.Phone.Verifiers = []attest.EnrolledVerifier{{AnchorPub: make([]byte, 91), NoisePub: make([]byte, 32)}}
	first := testSlotBlob()
	withPhones(first, minimal)
	unsigned, err := first.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := enrolmentSize(sb, none); err != nil || got != len(unsigned)+2+72 {
		t.Fatalf("a first phone: estimate %d, the smallest such blob %d (%v)", got, len(unsigned)+2+72, err)
	}

	one := testSlotBlob()
	withPhones(one, testEnrolment("box"))
	unsigned, err = one.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if again, err := enrolmentSize(sb, one.Payload.Attestation); err != nil || again != len(unsigned)+2+72 {
		t.Fatalf("a slot with a phone: estimate %d, the blob as it is %d (%v)", again, len(unsigned)+2+72, err)
	}
}
