package cmd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/matthias/tpm2-kira/attest"
)

// testSlotBlob is a slot's blob with a stand-in TOTP key: everything the
// format needs, nothing a TPM would accept.
func testSlotBlob() *SealedBlob {
	return &SealedBlob{
		Version: CurrentBlobVersion,
		Payload: SealedBlobPayload{
			AppVersion: "test", Public: []byte{1, 2, 3}, Private: []byte{4, 5},
			PCRDigests: []PCRDigestPair{
				{Index: 0, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: bytes.Repeat([]byte{0xA0}, 32)}},
				{Index: 7, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: bytes.Repeat([]byte{0xA7}, 32)}},
			},
			TOTPAlgorithm: tpm2.TPMAlgSHA1, Generation: 3,
			PolicyRef: []byte("policy-ref"), SigningPublic: []byte{6}, ApprovalSignature: []byte{7},
		},
	}
}

func testEnrolment(name string) *AttestBlob {
	return &AttestBlob{
		AppVersion: "test", DeviceID: bytes.Repeat([]byte{0xD1}, 16), FriendlyName: name,
		AKPublic: []byte{1}, AKPrivate: []byte{2}, AKName: []byte{3}, EKAlg: 0x23,
		NoisePrivate: bytes.Repeat([]byte{0x11}, 32), AdvKey: bytes.Repeat([]byte{0x22}, 32),
		PCRAlg: attest.AlgSHA256, PCRSelection: []uint8{0, 7},
		Verifiers: []attest.EnrolledVerifier{{ID: "phone", Name: "Pixel", AnchorPub: []byte{4}, NoisePub: make([]byte, 32), PolicyID: "p"}},
	}
}

func signSlot(t *testing.T, sb *SealedBlob, key crypto.Signer) []byte {
	t.Helper()
	unsigned, err := sb.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignBlobPayload(unsigned, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// signedAttestBlob is a slot's blob with one phone enrolled, signed by key.
func signedAttestBlob(t *testing.T, key *ecdsa.PrivateKey, name string) []byte {
	t.Helper()
	sb := testSlotBlob()
	sb.Payload.Attest = testEnrolment(name)
	return signSlot(t, sb, key)
}

// writeTestSlot puts a slot's blob (TOTP key stand-in, no phones) into the
// TPM at idx, the way 'seal' leaves it.
func writeTestSlot(t *testing.T, tpmDev transport.TPM, idx uint32, key crypto.Signer) {
	t.Helper()
	if err := WriteToNVRAM(tpmDev, idx, signSlot(t, testSlotBlob(), key), key.Public(), key); err != nil {
		t.Fatalf("writing the slot's blob: %v", err)
	}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// One blob per slot: the phone enrolment is a section of the blob that
// holds the TOTP key. Without phones the blob is exactly what it was
// before the section existed.
func TestSlotBlobCarriesTheEnrolment(t *testing.T) {
	key := newKey(t)

	// No phones: version and bytes as before, readable as version 9.
	plain := signSlot(t, testSlotBlob(), key)
	if v := binary.LittleEndian.Uint32(plain); v != CurrentBlobVersion {
		t.Fatalf("a slot without phones is written as version %d", v)
	}
	got, err := UnmarshalSealedBlob(plain)
	if err != nil || got.Payload.Attest != nil || got.Version != CurrentBlobVersion {
		t.Fatalf("slot without phones: %+v %v", got, err)
	}
	payloadLen := binary.LittleEndian.Uint32(plain[4:])
	if _, err := UnmarshalPayload(plain[8 : 8+payloadLen]); err != nil {
		t.Fatalf("the payload of a slot without phones no longer parses as version 9: %v", err)
	}

	// With phones: another version, so a build that would drop the section
	// on its next reseal refuses the blob instead.
	sb := testSlotBlob()
	sb.Payload.Attest = testEnrolment("box")
	sb.Payload.Attest.Count = 41
	enrolled := signSlot(t, sb, key)
	if v := binary.LittleEndian.Uint32(enrolled); v != EnrolledBlobVersion {
		t.Fatalf("a slot with phones is written as version %d", v)
	}
	got, err = UnmarshalSealedBlob(enrolled)
	if err != nil {
		t.Fatal(err)
	}
	a := got.Payload.Attest
	if a == nil || a.Count != 41 || a.FriendlyName != "box" || a.EKAlg != 0x23 || len(a.Verifiers) != 1 ||
		a.Verifiers[0].Name != "Pixel" || !bytes.Equal(a.NoisePrivate, sb.Payload.Attest.NoisePrivate) ||
		!bytes.Equal(a.DeviceID, sb.Payload.Attest.DeviceID) {
		t.Fatalf("enrolment did not survive: %+v", a)
	}
	// The TOTP half is untouched by the section.
	if !bytes.Equal(got.Payload.Public, sb.Payload.Public) || got.Payload.Generation != 3 || len(got.Payload.PCRDigests) != 2 ||
		string(got.Payload.PolicyRef) != "policy-ref" {
		t.Fatalf("TOTP part changed: %+v", got.Payload)
	}
	// Removing the phones gives the plain blob back, byte for byte.
	got.Payload.Attest = nil
	again, err := got.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, plain[:8+payloadLen]) {
		t.Fatal("a slot whose phones were removed differs from one that never had any")
	}

	// A version-9 header on a blob with a section, or the reverse, is not
	// quietly read as something else.
	lie := append([]byte(nil), enrolled...)
	binary.LittleEndian.PutUint32(lie, CurrentBlobVersion)
	if b, err := UnmarshalSealedBlob(lie); err == nil && b.Payload.Attest != nil {
		t.Fatal("an enrolment was read from a blob that says it has none")
	}
	lie = append([]byte(nil), plain...)
	binary.LittleEndian.PutUint32(lie, EnrolledBlobVersion)
	if _, err := UnmarshalSealedBlob(lie); err == nil {
		t.Fatal("a blob that announces an enrolment and has none was accepted")
	}
	for _, v := range []uint32{8, 11} {
		other := append([]byte(nil), plain...)
		binary.LittleEndian.PutUint32(other, v)
		if _, err := UnmarshalSealedBlob(other); err == nil {
			t.Fatalf("version %d accepted", v)
		} else if _, ok := IsBlobVersionError(err); !ok {
			t.Fatalf("version %d: %v", v, err)
		}
	}
}

// The blob's signature covers the enrolment: who is enrolled cannot be
// changed without the signing key.
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
	for _, target := range []string{"box", "Pixel", "phone"} {
		edited := append([]byte(nil), blob...)
		i := bytes.LastIndex(edited, []byte(target))
		edited[i] ^= 0x01 // the enrolment changed after signing
		if VerifyAttestBlobSignature(edited, &mine.PublicKey) == nil {
			t.Fatalf("edited %q accepted", target)
		}
	}
	// The section appended to somebody's plain blob, with its signature kept.
	plain := signSlot(t, testSlotBlob(), mine)
	section, _ := testEnrolment("attacker").marshalSection()
	payloadLen := binary.LittleEndian.Uint32(plain[4:])
	grafted := append([]byte(nil), plain[:8+payloadLen]...)
	grafted = binary.LittleEndian.AppendUint32(grafted, uint32(len(section)))
	grafted = append(grafted, section...)
	binary.LittleEndian.PutUint32(grafted, EnrolledBlobVersion)
	binary.LittleEndian.PutUint32(grafted[4:], payloadLen+4+uint32(len(section)))
	grafted = append(grafted, plain[8+payloadLen:]...)
	if b, err := UnmarshalSealedBlob(grafted); err != nil || b.Payload.Attest == nil {
		t.Fatalf("test construction: %v", err)
	}
	if VerifyAttestBlobSignature(grafted, &mine.PublicKey) == nil {
		t.Fatal("an enrolment grafted onto a signed blob was accepted")
	}
}

// The count is part of what is signed: a blob with another count is
// another blob.
func TestAttestBlobCarriesItsCount(t *testing.T) {
	key := newKey(t)
	sb := testSlotBlob()
	sb.Payload.Attest = testEnrolment("box")
	sb.Payload.Attest.Count = 41
	first := signSlot(t, sb, key)
	sb.Payload.Attest.Count = 42
	second := signSlot(t, sb, key)
	tampered := append([]byte(nil), first...)
	for i := range first {
		if i < len(second) && first[i] != second[i] {
			tampered[i] = second[i] // the first differing byte is in the count
			break
		}
	}
	if got, err := UnmarshalSealedBlob(tampered); err != nil || got.Payload.Attest.Count != 42 {
		t.Fatalf("test construction: %v", err)
	}
	if VerifyAttestBlobSignature(tampered, &key.PublicKey) == nil {
		t.Fatal("a blob with an altered count still verifies")
	}
}

func TestForeignSlotIsNamedAsSuch(t *testing.T) {
	err := foreignSlotError(2, bytes.ErrTooLarge)
	if !strings.Contains(err.Error(), "nvram delete --nvram 2") || !strings.Contains(err.Error(), "another signing key") {
		t.Fatalf("%v", err)
	}
}

// The size check before a phone is involved: every phone makes the slot's
// blob larger, and the TOTP key shares it.
func TestEnrolmentSize(t *testing.T) {
	sb := testSlotBlob()
	sb.BlobSignature = make([]byte, 72)
	e := testEnrolment("box")
	one, err := enrolmentSize(sb, e)
	if err != nil {
		t.Fatal(err)
	}
	e.Verifiers = append(e.Verifiers, attest.EnrolledVerifier{ID: "second", AnchorPub: make([]byte, 91), NoisePub: make([]byte, 32)})
	two, err := enrolmentSize(sb, e)
	if err != nil || two <= one {
		t.Fatalf("sizes %d then %d: %v", one, two, err)
	}
	// It is an upper bound for what is then written.
	grown := *e
	grown.Verifiers = append(grown.Verifiers, attest.EnrolledVerifier{ID: "third", Name: "x", AnchorPub: make([]byte, 91), NoisePub: make([]byte, 32)})
	real := *sb
	real.Payload.Attest = &grown
	if written := len(signSlot(t, &real, newKey(t))); written > two {
		t.Fatalf("estimated %d bytes for a blob of %d", two, written)
	}
	for len(e.Verifiers) < MaxVerifiers {
		e.Verifiers = append(e.Verifiers, attest.EnrolledVerifier{ID: "more", NoisePub: make([]byte, 32)})
	}
	if _, err := enrolmentSize(sb, e); err == nil {
		t.Fatal("a ninth phone was sized instead of refused")
	}
}
