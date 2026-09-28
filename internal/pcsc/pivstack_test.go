//go:build pcsc

// End-to-end test of the whole card stack against a real pcscd.
//
// The PIV layer has its own unit tests against a mock transport, and the
// transport has its own against a virtual reader. This file joins them: a
// virtual PIV card backed by a software key, reached through pcscd, driven by
// internal/piv. It is what proves the pieces fit — short and extended APDUs,
// response chaining across the real socket, and a signature that verifies.
package pcsc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/matthias/tpm2-kira/internal/piv"
)

// virtualPIV answers the APDUs internal/piv sends, using a software key.
type virtualPIV struct {
	t    *testing.T
	key  any // *ecdsa.PrivateKey or *rsa.PrivateKey
	cert []byte

	// pending holds bytes still to be fetched with GET RESPONSE, so the
	// chaining path is exercised the way a real card drives it.
	pending []byte

	pinVerified bool
	pinAttempts int
}

func newVirtualPIV(t *testing.T, key any, pub any) *virtualPIV {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tpm2-kira test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatalf("failed to build a test certificate: %v", err)
	}

	return &virtualPIV{t: t, key: key, cert: der}
}

func (v *virtualPIV) handle(apdu []byte) []byte {
	if len(apdu) < 4 {
		return []byte{0x6F, 0x00}
	}

	ins, p1, p2 := apdu[1], apdu[2], apdu[3]

	switch ins {
	case 0xA4: // SELECT
		return []byte{0x90, 0x00}

	case 0xC0: // GET RESPONSE
		return v.respond(v.pending)

	case 0xF7: // GET METADATA — answer "not supported" to force the cert path
		return []byte{0x6D, 0x00}

	case 0x20: // VERIFY
		if len(apdu) == 4 {
			// Retry counter query, which must not consume an attempt.
			return []byte{0x63, byte(0xC0 | (3 - v.pinAttempts))}
		}
		if string(apdu[5:]) == "123456\xff\xff" {
			v.pinVerified = true
			return []byte{0x90, 0x00}
		}
		v.pinAttempts++
		return []byte{0x63, byte(0xC0 | (3 - v.pinAttempts))}

	case 0xCB: // GET DATA
		if p1 != 0x3F || p2 != 0xFF {
			return []byte{0x6A, 0x86}
		}
		// 53 { 70 <cert> 71 <info> }
		body := append(tlv(0x70, v.cert), tlv(0x71, []byte{0x00})...)
		return v.respond(tlv(0x53, body))

	case 0x87: // GENERAL AUTHENTICATE
		if !v.pinVerified {
			return []byte{0x69, 0x82}
		}
		return v.sign(apdu, p1)

	default:
		return []byte{0x6D, 0x00}
	}
}

// sign extracts the challenge and signs it, mirroring what a PIV card does: an
// ECDSA card hashes nothing and signs the digest it is given, and an RSA card
// performs a raw private-key operation on the padded block.
func (v *virtualPIV) sign(apdu []byte, alg byte) []byte {
	body := commandData(apdu)

	template, err := tlvValueTest(body, 0x7C)
	if err != nil {
		v.t.Errorf("no 7C template in the signing request: %v", err)
		return []byte{0x6A, 0x80}
	}

	challenge, err := tlvValueTest(template, 0x81)
	if err != nil {
		v.t.Errorf("no 81 challenge in the signing request: %v", err)
		return []byte{0x6A, 0x80}
	}

	var signature []byte

	switch key := v.key.(type) {
	case *ecdsa.PrivateKey:
		signature, err = ecdsa.SignASN1(rand.Reader, key, challenge)
		if err != nil {
			v.t.Errorf("signing failed: %v", err)
			return []byte{0x6F, 0x00}
		}

	case *rsa.PrivateKey:
		// The raw operation the card performs: m^d mod n over the block the
		// caller padded. Decrypting the caller's block is the same maths.
		m := new(big.Int).SetBytes(challenge)
		c := new(big.Int).Exp(m, key.D, key.N)
		signature = c.FillBytes(make([]byte, key.Size()))

	default:
		return []byte{0x6F, 0x00}
	}

	return v.respond(tlv(0x7C, tlv(0x82, signature)))
}

// respond returns at most 256 bytes and reports the remainder with 61xx, which
// is how a real card paces a large reply.
func (v *virtualPIV) respond(data []byte) []byte {
	const chunk = 256

	if len(data) <= chunk {
		v.pending = nil
		return append(data, 0x90, 0x00)
	}

	v.pending = data[chunk:]

	remaining := len(v.pending)
	if remaining > 0xFF {
		remaining = 0xFF
	}

	return append(append([]byte{}, data[:chunk]...), 0x61, byte(remaining))
}

// commandData extracts the data field of a short or extended command APDU.
func commandData(apdu []byte) []byte {
	if len(apdu) < 5 {
		return nil
	}

	if apdu[4] != 0x00 {
		lc := int(apdu[4])
		if len(apdu) < 5+lc {
			return nil
		}
		return apdu[5 : 5+lc]
	}

	if len(apdu) < 7 {
		return nil
	}
	lc := int(apdu[5])<<8 | int(apdu[6])
	if len(apdu) < 7+lc {
		return nil
	}
	return apdu[7 : 7+lc]
}

func tlv(tag byte, value []byte) []byte {
	out := []byte{tag}
	switch n := len(value); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, value...)
}

// tlvValueTest is a local BER-TLV reader, so the test does not lean on the
// implementation it is checking.
func tlvValueTest(data []byte, tag byte) ([]byte, error) {
	for off := 0; off < len(data); {
		t := data[off]
		off++
		if off >= len(data) {
			return nil, errTLV
		}

		length := int(data[off])
		off++
		if length&0x80 != 0 {
			count := length & 0x7F
			if count == 0 || count > 3 || off+count > len(data) {
				return nil, errTLV
			}
			length = 0
			for i := 0; i < count; i++ {
				length = length<<8 | int(data[off+i])
			}
			off += count
		}

		if off+length > len(data) {
			return nil, errTLV
		}
		if t == tag {
			return data[off : off+length], nil
		}
		off += length
	}
	return nil, errTLV
}

var errTLV = errTLVType{}

type errTLVType struct{}

func (errTLVType) Error() string { return "tag not found" }

// cardTransport adapts a pcsc.Card to the piv.Transport interface.
type cardTransport struct{ card *Card }

func (c cardTransport) Transmit(apdu []byte) ([]byte, error) { return c.card.Transmit(apdu) }

// openStack wires a virtual card into pcscd and returns the PIV layer on top.
func openStack(t *testing.T, card *virtualPIV) (*piv.Card, func()) {
	t.Helper()

	requireDaemon(t)
	connectVirtualCard(t, card.handle)

	client, err := Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	readers, err := client.Readers(true)
	if err != nil || len(readers) == 0 {
		client.Close()
		t.Skip("no reader reports a card present")
	}

	connected, err := client.ConnectCard(readers[0])
	if err != nil {
		client.Close()
		t.Fatalf("ConnectCard failed: %v", err)
	}

	pivCard, err := piv.Open(cardTransport{card: connected})
	if err != nil {
		connected.Disconnect()
		client.Close()
		t.Fatalf("piv.Open failed: %v", err)
	}

	return pivCard, func() {
		connected.Disconnect()
		client.Close()
	}
}

// TestPIVStackECDSA drives the full path with an ECC P-256 key: read the public
// key out of a chained certificate response, verify a PIN, sign, and check the
// signature.
func TestPIVStackECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pivCard, cleanup := openStack(t, newVirtualPIV(t, key, &key.PublicKey))
	defer cleanup()

	// A certificate is larger than one short APDU response, so this also
	// exercises GET RESPONSE chaining over the real socket.
	pub, err := pivCard.PublicKey(0x9A)
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	got, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsa.PublicKey", pub)
	}
	if got.X.Cmp(key.X) != 0 || got.Y.Cmp(key.Y) != 0 {
		t.Fatal("the public key read from the card does not match")
	}

	if retries, err := pivCard.PINRetries(); err != nil {
		t.Errorf("PINRetries failed: %v", err)
	} else if retries != 3 {
		t.Errorf("PINRetries = %d, want 3", retries)
	}

	if err := pivCard.VerifyPIN("123456"); err != nil {
		t.Fatalf("VerifyPIN failed: %v", err)
	}

	digest := sha256.Sum256([]byte("measure point"))

	signature, err := pivCard.Sign(0x9A, &key.PublicKey, digest[:])
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], signature) {
		t.Error("the signature from the card does not verify")
	}
}

// TestPIVStackRSA covers the extended-length APDU path: an RSA-2048 signing
// request carries a 256-byte padded block, which a short APDU cannot express.
func TestPIVStackRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pivCard, cleanup := openStack(t, newVirtualPIV(t, key, &key.PublicKey))
	defer cleanup()

	pub, err := pivCard.PublicKey(0x9C)
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	if got, ok := pub.(*rsa.PublicKey); !ok || got.N.Cmp(key.N) != 0 {
		t.Fatalf("the public key read from the card does not match (%T)", pub)
	}

	if err := pivCard.VerifyPIN("123456"); err != nil {
		t.Fatalf("VerifyPIN failed: %v", err)
	}

	digest := sha256.Sum256([]byte("measure point"))

	signature, err := pivCard.Sign(0x9C, &key.PublicKey, digest[:])
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// The card only did the raw operation, so a verifiable PKCS#1 v1.5
	// signature proves internal/piv built the padded block correctly.
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, 0, hashedForVerify(digest), signature); err != nil {
		t.Errorf("the signature from the card does not verify: %v", err)
	}
}

// hashedForVerify returns the digest with the hash identified by DigestInfo, in
// the form VerifyPKCS1v15 expects when given crypto.Hash(0).
func hashedForVerify(digest [32]byte) []byte {
	prefix := []byte{
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
		0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
	}
	return append(prefix, digest[:]...)
}

// TestPIVStackWrongPINDoesNotSign checks that a rejected PIN both reports the
// remaining attempts and leaves signing refused.
func TestPIVStackWrongPINDoesNotSign(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pivCard, cleanup := openStack(t, newVirtualPIV(t, key, &key.PublicKey))
	defer cleanup()

	err = pivCard.VerifyPIN("999999")
	if err == nil {
		t.Fatal("expected a wrong PIN to be rejected")
	}

	var pinErr *piv.PINError
	if !asPINError(err, &pinErr) {
		t.Fatalf("expected a *piv.PINError, got %v", err)
	}
	if pinErr.Retries != 2 {
		t.Errorf("Retries = %d, want 2", pinErr.Retries)
	}

	digest := sha256.Sum256([]byte("x"))
	if _, err := pivCard.Sign(0x9A, &key.PublicKey, digest[:]); err == nil {
		t.Error("signing should be refused until the PIN is verified")
	}
}

func asPINError(err error, target **piv.PINError) bool {
	for err != nil {
		if pe, ok := err.(*piv.PINError); ok {
			*target = pe
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

var _ = binary.BigEndian
