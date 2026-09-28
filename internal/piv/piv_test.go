package piv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
)

// mockTransport replays scripted responses and records what was sent, so the
// APDUs can be asserted byte for byte without a card.
type mockTransport struct {
	sent      [][]byte
	responses [][]byte
	index     int
}

func (m *mockTransport) Transmit(apdu []byte) ([]byte, error) {
	m.sent = append(m.sent, append([]byte{}, apdu...))

	if m.index >= len(m.responses) {
		return nil, errors.New("mock transport ran out of scripted responses")
	}

	rsp := m.responses[m.index]
	m.index++
	return rsp, nil
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test hex %q: %v", s, err)
	}
	return b
}

// sw9000 appends a success status word to a response body.
func sw9000(body []byte) []byte {
	return append(append([]byte{}, body...), 0x90, 0x00)
}

func TestOpenSelectsPIVApplet(t *testing.T) {
	m := &mockTransport{responses: [][]byte{sw9000(nil)}}

	if _, err := Open(m); err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	want := mustHex(t, "00a4040009a0000003080000100000")
	if !bytes.Equal(m.sent[0], want) {
		t.Errorf("SELECT APDU = %x, want %x", m.sent[0], want)
	}
}

func TestPINRetries(t *testing.T) {
	tests := []struct {
		name    string
		status  []byte
		want    int
		wantErr bool
	}{
		{name: "two attempts left", status: []byte{0x63, 0xC2}, want: 2},
		{name: "one attempt left", status: []byte{0x63, 0xC1}, want: 1},
		{name: "blocked", status: []byte{0x69, 0x83}, want: 0},
		{name: "already verified", status: []byte{0x90, 0x00}, want: -1},
		{name: "unexpected status", status: []byte{0x6A, 0x80}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &mockTransport{responses: [][]byte{sw9000(nil), tc.status}}

			card, err := Open(m)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			got, err := card.PINRetries()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("PINRetries failed: %v", err)
			}
			if got != tc.want {
				t.Errorf("PINRetries = %d, want %d", got, tc.want)
			}

			// The query must carry no data, or it would consume an attempt.
			query := m.sent[1]
			if len(query) != 4 {
				t.Errorf("retry query APDU = %x, want a 4-byte header with no Lc", query)
			}
		})
	}
}

func TestVerifyPIN(t *testing.T) {
	m := &mockTransport{responses: [][]byte{sw9000(nil), {0x90, 0x00}}}

	card, err := Open(m)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if err := card.VerifyPIN("123456"); err != nil {
		t.Fatalf("VerifyPIN failed: %v", err)
	}

	// A PIV PIN is padded to eight bytes with 0xFF.
	want := mustHex(t, "0020008008313233343536ffff")
	if !bytes.Equal(m.sent[1], want) {
		t.Errorf("VERIFY APDU = %x, want %x", m.sent[1], want)
	}
}

func TestVerifyPINReportsRetries(t *testing.T) {
	m := &mockTransport{responses: [][]byte{sw9000(nil), {0x63, 0xC2}}}

	card, err := Open(m)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	err = card.VerifyPIN("999999")

	var pinErr *PINError
	if !errors.As(err, &pinErr) {
		t.Fatalf("expected a *PINError, got %v", err)
	}
	if pinErr.Retries != 2 {
		t.Errorf("Retries = %d, want 2", pinErr.Retries)
	}
}

func TestVerifyPINRejectsBadLength(t *testing.T) {
	m := &mockTransport{responses: [][]byte{sw9000(nil)}}

	card, err := Open(m)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	for _, pin := range []string{"12345", "123456789"} {
		if err := card.VerifyPIN(pin); err == nil {
			t.Errorf("expected VerifyPIN(%q) to fail on length", pin)
		}
	}
}

func TestSignECDSABuildsGeneralAuthenticate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// A plausible DER signature for the card to hand back.
	signature := mustHex(t, "3044"+
		"0220"+"1111111111111111111111111111111111111111111111111111111111111111"+
		"0220"+"2222222222222222222222222222222222222222222222222222222222222222")

	response := encodeTLV(0x7C, encodeTLV(0x82, signature))

	m := &mockTransport{responses: [][]byte{sw9000(nil), sw9000(response)}}

	card, err := Open(m)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	digest := sha256.Sum256([]byte("reseal"))

	got, err := card.Sign(0x9A, &key.PublicKey, digest[:])
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !bytes.Equal(got, signature) {
		t.Errorf("signature = %x, want %x", got, signature)
	}

	apdu := m.sent[1]

	// 00 87 <alg> <slot>, with ECCP256 and slot 9a.
	if apdu[0] != 0x00 || apdu[1] != insGeneralAuthenticate {
		t.Errorf("APDU header = %x, want 0087...", apdu[:2])
	}
	if apdu[2] != algECCP256 {
		t.Errorf("algorithm = %02x, want %02x (ECCP256)", apdu[2], algECCP256)
	}
	if apdu[3] != 0x9A {
		t.Errorf("slot = %02x, want 9a", apdu[3])
	}

	// The challenge must be the bare digest for an exact-fit curve.
	body := apdu[5 : len(apdu)-1]
	inner, err := tlvValue(body, 0x7C)
	if err != nil {
		t.Fatalf("no 7C template in the request: %v", err)
	}
	challenge, err := tlvValue(inner, 0x81)
	if err != nil {
		t.Fatalf("no 81 challenge in the request: %v", err)
	}
	if !bytes.Equal(challenge, digest[:]) {
		t.Errorf("challenge = %x, want the digest %x", challenge, digest[:])
	}
}

// TestSignRSAUsesExtendedAPDU covers the case a short APDU cannot express: an
// RSA-2048 signature request carries a 256-byte block, so Lc must be encoded in
// the three-byte extended form.
func TestSignRSAUsesExtendedAPDU(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signature := bytes.Repeat([]byte{0xAB}, 256)
	response := encodeTLV(0x7C, encodeTLV(0x82, signature))

	m := &mockTransport{responses: [][]byte{sw9000(nil), sw9000(response)}}

	card, err := Open(m)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	digest := sha256.Sum256([]byte("reseal"))

	if _, err := card.Sign(0x9C, &key.PublicKey, digest[:]); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	apdu := m.sent[1]

	if apdu[2] != algRSA2048 {
		t.Errorf("algorithm = %02x, want %02x (RSA2048)", apdu[2], algRSA2048)
	}
	if apdu[4] != 0x00 {
		t.Fatalf("expected an extended-length APDU (Lc starting with 00), got %x", apdu[:8])
	}

	lc := int(apdu[5])<<8 | int(apdu[6])
	body := apdu[7 : 7+lc]

	inner, err := tlvValue(body, 0x7C)
	if err != nil {
		t.Fatalf("no 7C template in the request: %v", err)
	}
	challenge, err := tlvValue(inner, 0x81)
	if err != nil {
		t.Fatalf("no 81 challenge in the request: %v", err)
	}

	// The card performs a raw private-key operation, so the padded PKCS#1
	// v1.5 block has to be built by this package.
	if len(challenge) != 256 {
		t.Fatalf("challenge is %d bytes, want the 256-byte modulus width", len(challenge))
	}
	if challenge[0] != 0x00 || challenge[1] != 0x01 {
		t.Errorf("challenge does not start with the 00 01 PKCS#1 v1.5 header: %x", challenge[:2])
	}
	if !bytes.HasSuffix(challenge, digest[:]) {
		t.Error("challenge does not end with the digest")
	}
	if !bytes.Contains(challenge, sha256DigestInfo) {
		t.Error("challenge does not contain the SHA-256 DigestInfo prefix")
	}
}

func TestPKCS1v15SHA256(t *testing.T) {
	digest := sha256.Sum256([]byte("x"))

	block, err := pkcs1v15SHA256(digest[:], 256)
	if err != nil {
		t.Fatalf("pkcs1v15SHA256 failed: %v", err)
	}

	if len(block) != 256 {
		t.Fatalf("block is %d bytes, want 256", len(block))
	}
	if block[0] != 0x00 || block[1] != 0x01 {
		t.Errorf("header = %x, want 0001", block[:2])
	}

	// Padding must be 0xFF up to a single 0x00 separator.
	sep := bytes.IndexByte(block[2:], 0x00) + 2
	for i := 2; i < sep; i++ {
		if block[i] != 0xFF {
			t.Fatalf("padding byte %d = %02x, want ff", i, block[i])
		}
	}
	if sep < 10 {
		t.Errorf("padding is only %d bytes, PKCS#1 requires at least 8", sep-2)
	}

	if !bytes.Equal(block[sep+1:], append(append([]byte{}, sha256DigestInfo...), digest[:]...)) {
		t.Error("the tail is not DigestInfo || digest")
	}

	if _, err := pkcs1v15SHA256(digest[:], 32); err == nil {
		t.Error("expected an error for a modulus too small to hold the block")
	}
	if _, err := pkcs1v15SHA256([]byte{1, 2, 3}, 256); err == nil {
		t.Error("expected an error for a digest that is not SHA-256 sized")
	}
}

func TestGetResponseChaining(t *testing.T) {
	// The card returns half the data with 61 04, then the rest on GET
	// RESPONSE. Losing this loop would truncate every certificate.
	m := &mockTransport{responses: [][]byte{
		sw9000(nil),
		append([]byte{0xAA, 0xBB}, 0x61, 0x04),
		sw9000([]byte{0xCC, 0xDD, 0xEE, 0xFF}),
	}}

	card, err := Open(m)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	got, err := card.send(0x00, insGetData, 0x3F, 0xFF, []byte{0x5C, 0x03, 0x5F, 0xC1, 0x05}, 256)
	if err != nil {
		t.Fatalf("send failed: %v", err)
	}

	want := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	if !bytes.Equal(got, want) {
		t.Errorf("chained response = %x, want %x", got, want)
	}

	if m.sent[2][1] != insGetResponse {
		t.Errorf("follow-up INS = %02x, want %02x (GET RESPONSE)", m.sent[2][1], insGetResponse)
	}
	if m.sent[2][4] != 0x04 {
		t.Errorf("GET RESPONSE Le = %02x, want 04", m.sent[2][4])
	}
}

func TestSendMapsStatusWords(t *testing.T) {
	tests := []struct {
		name   string
		status []byte
		check  func(error) bool
	}{
		{
			name:   "empty slot",
			status: []byte{0x6A, 0x82},
			check:  func(err error) bool { return errors.Is(err, errFileNotFound) },
		},
		{
			name:   "blocked PIN",
			status: []byte{0x69, 0x83},
			check:  func(err error) bool { return errors.Is(err, ErrPINBlocked) },
		},
		{
			name:   "PIN not verified",
			status: []byte{0x69, 0x82},
			check:  func(err error) bool { return err != nil },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &mockTransport{responses: [][]byte{sw9000(nil), tc.status}}

			card, err := Open(m)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			_, err = card.send(0x00, insGetData, 0x3F, 0xFF, []byte{0x5C}, 256)
			if !tc.check(err) {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestSlotObjectID(t *testing.T) {
	tests := map[byte]string{
		0x9A: "5fc105",
		0x9C: "5fc10a",
		0x9D: "5fc10b",
		0x9E: "5fc101",
		0x82: "5fc10d",
		0x95: "5fc120",
	}

	for slot, want := range tests {
		got, err := slotObjectID(slot)
		if err != nil {
			t.Fatalf("slotObjectID(%02x) failed: %v", slot, err)
		}
		if hex.EncodeToString(got) != want {
			t.Errorf("slotObjectID(%02x) = %x, want %s", slot, got, want)
		}
	}

	if _, err := slotObjectID(0x9B); err == nil {
		t.Error("expected an error for a slot that is not a key slot")
	}
}

func TestTLVRoundTrip(t *testing.T) {
	// The three length forms: short, 0x81 and 0x82. A certificate lands in
	// the last of them.
	for _, size := range []int{4, 0x7F, 0x80, 0xFF, 0x100, 2048} {
		value := bytes.Repeat([]byte{0x5A}, size)
		encoded := encodeTLV(0x70, value)

		decoded, err := tlvValue(encoded, 0x70)
		if err != nil {
			t.Fatalf("tlvValue failed for a %d-byte value: %v", size, err)
		}
		if !bytes.Equal(decoded, value) {
			t.Errorf("round trip of a %d-byte value changed it", size)
		}
	}
}

func TestTLVSkipsToRequestedTag(t *testing.T) {
	data := append(encodeTLV(0x71, []byte{0x01}), encodeTLV(0x70, []byte{0x02, 0x03})...)

	got, err := tlvValue(data, 0x70)
	if err != nil {
		t.Fatalf("tlvValue failed: %v", err)
	}
	if !bytes.Equal(got, []byte{0x02, 0x03}) {
		t.Errorf("got %x, want 0203", got)
	}

	if _, err := tlvValue(data, 0x7F); err == nil {
		t.Error("expected an error for a tag that is not present")
	}
}

func TestTLVRejectsTruncatedData(t *testing.T) {
	// A length that runs past the buffer must be an error, not a panic.
	for _, bad := range [][]byte{
		{0x70},
		{0x70, 0x05, 0x01},
		{0x70, 0x82, 0x01},
		{0x70, 0x84, 0x00, 0x00, 0x00, 0x01},
	} {
		if _, err := tlvValue(bad, 0x70); err == nil {
			t.Errorf("expected an error for %x", bad)
		}
	}
}

func TestParsePublicKeyTLVECC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	point := append([]byte{0x04}, append(pad(key.X, 32), pad(key.Y, 32)...)...)
	data := encodeTLV(0x86, point)

	pub, err := parsePublicKeyTLV(algECCP256, data)
	if err != nil {
		t.Fatalf("parsePublicKeyTLV failed: %v", err)
	}

	got, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsa.PublicKey", pub)
	}
	if got.X.Cmp(key.X) != 0 || got.Y.Cmp(key.Y) != 0 {
		t.Error("the decoded point does not match the key")
	}
}

func TestParsePublicKeyTLVRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	data := append(
		encodeTLV(0x81, key.N.Bytes()),
		encodeTLV(0x82, big.NewInt(int64(key.E)).Bytes())...,
	)

	pub, err := parsePublicKeyTLV(algRSA2048, data)
	if err != nil {
		t.Fatalf("parsePublicKeyTLV failed: %v", err)
	}

	got, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("got %T, want *rsa.PublicKey", pub)
	}
	if got.N.Cmp(key.N) != 0 || got.E != key.E {
		t.Error("the decoded modulus or exponent does not match the key")
	}
}

func pad(v *big.Int, length int) []byte {
	b := v.Bytes()
	if len(b) >= length {
		return b
	}
	out := make([]byte, length)
	copy(out[length-len(b):], b)
	return out
}
