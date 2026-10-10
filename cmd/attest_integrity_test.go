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

	"github.com/mrwiora/tpm2-kira/attest"
)

// testSlotBlob is a slot's blob with a stand-in TOTP key: everything the
// format needs, nothing a TPM would accept.
func testSlotBlob() *SealedBlob {
	return &SealedBlob{
		Version: CurrentBlobVersion,
		Payload: SealedBlobPayload{
			Public: []byte{1, 2, 3}, Private: []byte{4, 5},
			PCRDigests: []PCRDigestPair{
				{Index: 0, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: bytes.Repeat([]byte{0xA0}, 32)}},
				{Index: 7, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: bytes.Repeat([]byte{0xA7}, 32)}},
			},
			TOTPAlgorithm: tpm2.TPMAlgSHA1, Generation: 3,
			PolicyRef: []byte("policy-ref"), SigningPublic: []byte{6}, ApprovalSignature: []byte{7},
		},
	}
}

// testAKPublic is a well-formed attestation key public area and its Name,
// which the blob does not store but computes from it.
func testAKPublic() ([]byte, []byte) {
	pub := attest.AKTemplateECC()
	name, err := tpm2.ObjectName(&pub)
	if err != nil {
		panic(err)
	}
	return tpm2.Marshal(pub), name.Buffer
}

func testEnrolment(name string) *Attestation {
	akPub, akName := testAKPublic()
	return &Attestation{
		DeviceID: bytes.Repeat([]byte{0xD1}, 16), FriendlyName: name,
		AKPublic: akPub, AKPrivate: []byte{2}, AKName: akName, EKAlg: 0x23,
		PCRAlg: attest.AlgSHA256, PCRSelection: []uint8{0, 7},
		Phone: PhoneAttestation{
			NoisePrivate: bytes.Repeat([]byte{0x11}, 32), AdvKey: bytes.Repeat([]byte{0x22}, 32),
			Verifiers: []attest.EnrolledVerifier{{ID: "phone", Name: "Pixel", AnchorPub: []byte{4}, NoisePub: make([]byte, 32), PolicyID: "p"}},
		},
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
	sb.Payload.Attestation = testEnrolment(name)
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

// One blob per slot, one format: the TOTP key, then the optional
// attestation part with its typed methods.
func TestSlotBlobLayout(t *testing.T) {
	key := newKey(t)

	// Without attestation: the payload ends with a flag that says so.
	plain := signSlot(t, testSlotBlob(), key)
	payloadLen := binary.LittleEndian.Uint32(plain[4:])
	if v := binary.LittleEndian.Uint32(plain); v != CurrentBlobVersion {
		t.Fatalf("written as version %d", v)
	}
	if plain[8+payloadLen-1] != 0 {
		t.Fatal("a blob without attestation does not end its payload with the flag 0")
	}
	got, err := UnmarshalSealedBlob(plain)
	if err != nil || got.Payload.Attestation != nil || got.Version != CurrentBlobVersion {
		t.Fatalf("slot without attestation: %+v %v", got, err)
	}

	// With attestation and the phone method.
	sb := testSlotBlob()
	sb.Payload.Attestation = testEnrolment("box")
	sb.Payload.Attestation.Count = 41
	enrolled := signSlot(t, sb, key)
	got, err = UnmarshalSealedBlob(enrolled)
	if err != nil {
		t.Fatal(err)
	}
	a, want := got.Payload.Attestation, sb.Payload.Attestation
	if a == nil || a.Count != 41 || a.FriendlyName != "box" || a.EKAlg != 0x23 ||
		!bytes.Equal(a.DeviceID, want.DeviceID) || !bytes.Equal(a.AKName, want.AKName) ||
		a.PCRAlg != attest.AlgSHA256 || !bytes.Equal(a.PCRSelection, want.PCRSelection) {
		t.Fatalf("attestation part did not survive: %+v", a)
	}
	if !a.Phone.Enabled() || len(a.Phone.Verifiers) != 1 || a.Phone.Verifiers[0].Name != "Pixel" || a.Phone.Verifiers[0].PolicyID != "p" ||
		!bytes.Equal(a.Phone.NoisePrivate, want.Phone.NoisePrivate) || !bytes.Equal(a.Phone.AdvKey, want.Phone.AdvKey) {
		t.Fatalf("phone method did not survive: %+v", a.Phone)
	}
	// The TOTP half is untouched by it.
	if !bytes.Equal(got.Payload.Public, sb.Payload.Public) || got.Payload.Generation != 3 || len(got.Payload.PCRDigests) != 2 ||
		string(got.Payload.PolicyRef) != "policy-ref" {
		t.Fatalf("TOTP part changed: %+v", got.Payload)
	}
	// Removing the attestation gives the plain blob back, byte for byte.
	got.Payload.Attestation = nil
	again, err := got.Marshal()
	if err != nil || !bytes.Equal(again, plain[:8+payloadLen]) {
		t.Fatalf("a slot whose attestation was removed differs from one that never had any (%v)", err)
	}

	// An attestation part without any method is valid data, and nobody is
	// enrolled in it.
	bare := testSlotBlob()
	bare.Payload.Attestation = testEnrolment("box")
	bare.Payload.Attestation.Phone = PhoneAttestation{}
	got, err = UnmarshalSealedBlob(signSlot(t, bare, key))
	if err != nil || got.Payload.Attestation == nil || got.Payload.Attestation.Phone.Enabled() {
		t.Fatalf("attestation without methods: %+v %v", got, err)
	}

	// Exactly one version is read.
	for _, v := range []uint32{CurrentBlobVersion - 1, CurrentBlobVersion + 1} {
		other := append([]byte(nil), plain...)
		binary.LittleEndian.PutUint32(other, v)
		if _, err := UnmarshalSealedBlob(other); err == nil {
			t.Fatalf("version %d accepted", v)
		} else if _, ok := IsBlobVersionError(err); !ok {
			t.Fatalf("version %d: %v", v, err)
		}
	}
}

// What does not follow the layout is not read as something else.
func TestSlotBlobRejectsMalformedAttestation(t *testing.T) {
	sb := testSlotBlob()
	payload, err := sb.Payload.MarshalPayload()
	if err != nil {
		t.Fatal(err)
	}
	totp := payload[:len(payload)-1] // everything before the attestation flag
	att, _ := testEnrolment("box").marshal()
	phone, _ := (&testEnrolment("box").Phone).marshal()
	head := att[:len(att)-len(phone)-6] // up to, not including, the method count
	method := func(kind byte, data []byte) []byte {
		out := []byte{kind}
		out = binary.LittleEndian.AppendUint32(out, uint32(len(data)))
		return append(out, data...)
	}
	withAttestation := func(a []byte) []byte {
		out := append(append([]byte(nil), totp...), 1)
		out = binary.LittleEndian.AppendUint32(out, uint32(len(a)))
		return append(out, a...)
	}
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	if _, err := UnmarshalPayload(withAttestation(join(head, []byte{1}, method(attestMethodPhone, phone)))); err != nil {
		t.Fatalf("the test's own construction does not parse: %v", err)
	}
	for name, p := range map[string][]byte{
		"no attestation flag":                 totp,
		"an attestation flag that is no flag": append(append([]byte(nil), totp...), 2),
		"bytes after 'no attestation'":        append(append([]byte(nil), totp...), 0, 0xFF),
		"a flag without the part":             append(append([]byte(nil), totp...), 1),
		"an empty attestation part":           withAttestation(nil),
		"bytes after the attestation part":    append(withAttestation(att), 0xFF),
		"a length beyond the payload":         append(binary.LittleEndian.AppendUint32(append(append([]byte(nil), totp...), 1), uint32(len(att)+1)), att...),
		"a method this build does not know":   withAttestation(join(head, []byte{1}, method(7, phone))),
		"the phone method twice":              withAttestation(join(head, []byte{2}, method(attestMethodPhone, phone), method(attestMethodPhone, phone))),
		"fewer methods than announced":        withAttestation(join(head, []byte{2}, method(attestMethodPhone, phone))),
		"bytes after the last method":         withAttestation(join(head, []byte{1}, method(attestMethodPhone, phone), []byte{0})),
		"a truncated phone method":            withAttestation(join(head, []byte{1}, method(attestMethodPhone, phone[:len(phone)-1]))),
		"a phone method with a tail":          withAttestation(join(head, []byte{1}, method(attestMethodPhone, append(append([]byte(nil), phone...), 0)))),
	} {
		if got, err := UnmarshalPayload(p); err == nil {
			t.Errorf("%s was accepted: %+v", name, got.Attestation)
		}
	}
}

// A blob elsewhere must not put its generation index on a slot's record
// counter (both sit 0x800 above something).
func TestBlobIndexCannotCollideWithACounter(t *testing.T) {
	for _, idx := range []uint32{NVRAMSlotStart, NVRAMSlotEnd, 0x01803030, 0x01803100} {
		if err := ValidateBlobIndex(idx); err != nil {
			t.Errorf("0x%08X refused: %v", idx, err)
		}
	}
	for idx := AttestCounterIndex(NVRAMSlotStart) - GenerationIndexOffset; idx <= AttestCounterIndex(NVRAMSlotEnd)-GenerationIndexOffset; idx++ {
		if err := ValidateBlobIndex(idx); err == nil {
			t.Errorf("0x%08X accepted, though its generation index 0x%08X is a record counter", idx, GenerationIndex(idx))
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
	// An attestation part put into somebody's signed blob, signature kept.
	plain := signSlot(t, testSlotBlob(), mine)
	att, _ := testEnrolment("attacker").marshal()
	payloadLen := binary.LittleEndian.Uint32(plain[4:])
	grafted := append([]byte(nil), plain[:8+payloadLen-1]...) // without the flag "no attestation"
	grafted = append(grafted, 1)
	grafted = binary.LittleEndian.AppendUint32(grafted, uint32(len(att)))
	grafted = append(grafted, att...)
	binary.LittleEndian.PutUint32(grafted[4:], payloadLen+4+uint32(len(att)))
	grafted = append(grafted, plain[8+payloadLen:]...)
	if b, err := UnmarshalSealedBlob(grafted); err != nil || b.Payload.Attestation == nil {
		t.Fatalf("test construction: %v", err)
	}
	if VerifyAttestBlobSignature(grafted, &mine.PublicKey) == nil {
		t.Fatal("an attestation part grafted onto a signed blob was accepted")
	}
}

// The count is part of what is signed: a blob with another count is
// another blob.
func TestAttestBlobCarriesItsCount(t *testing.T) {
	key := newKey(t)
	sb := testSlotBlob()
	sb.Payload.Attestation = testEnrolment("box")
	sb.Payload.Attestation.Count = 41
	first := signSlot(t, sb, key)
	sb.Payload.Attestation.Count = 42
	second := signSlot(t, sb, key)
	tampered := append([]byte(nil), first...)
	for i := range first {
		if i < len(second) && first[i] != second[i] {
			tampered[i] = second[i] // the first differing byte is in the count
			break
		}
	}
	if got, err := UnmarshalSealedBlob(tampered); err != nil || got.Payload.Attestation.Count != 42 {
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
