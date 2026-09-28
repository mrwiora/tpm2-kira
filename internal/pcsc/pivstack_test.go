//go:build pcsc

// End-to-end test of the card stack against a real pcscd.
//
// The PIV layer has its own unit tests against a mock transport, and the
// transport has its own against a virtual reader. This file joins them: the
// virtual YubiKey from internal/virtualpiv, reached through pcscd, driven by
// internal/piv. It is what proves the pieces fit — short and extended APDUs,
// response chaining across the real socket, and a signature that verifies.
package pcsc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/matthias/tpm2-kira/internal/piv"
	"github.com/matthias/tpm2-kira/internal/virtualpiv"
)

// cardTransport adapts a pcsc.Card to the piv.Transport interface.
type cardTransport struct{ card *Card }

func (c cardTransport) Transmit(apdu []byte) ([]byte, error) { return c.card.Transmit(apdu) }

// openStack attaches a virtual card to pcscd and returns the PIV layer on top.
func openStack(t *testing.T, opts virtualpiv.Options) (*piv.Card, *virtualpiv.Card) {
	t.Helper()

	requireDaemon(t)

	card, err := virtualpiv.New(opts)
	if err != nil {
		t.Fatalf("failed to build the virtual card: %v", err)
	}
	if err := card.Attach(virtualpiv.DefaultAddr, 1500*time.Millisecond); err != nil {
		t.Skipf("cannot attach a virtual card (%v); is vsmartcard-vpcd configured?", err)
	}
	t.Cleanup(card.Close)

	client, err := Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	readers, err := client.Readers(true)
	if err != nil || len(readers) == 0 {
		t.Skip("no reader reports a card present")
	}

	connected, err := client.ConnectCard(readers[0])
	if err != nil {
		t.Fatalf("ConnectCard failed: %v", err)
	}
	t.Cleanup(func() { connected.Disconnect() })

	pivCard, err := piv.Open(cardTransport{card: connected})
	if err != nil {
		t.Fatalf("piv.Open failed: %v", err)
	}

	return pivCard, card
}

// TestPIVStackECDSA drives the full path with an ECC P-256 key: read the slot
// metadata, verify a PIN, sign, and check the signature.
func TestPIVStackECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pivCard, virtual := openStack(t, virtualpiv.Options{Key: key, Slot: 0x9A})

	md, err := pivCard.SlotMetadata(0x9A)
	if err != nil {
		t.Fatalf("SlotMetadata failed: %v", err)
	}
	got, ok := md.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsa.PublicKey", md.PublicKey)
	}
	if got.X.Cmp(key.X) != 0 || got.Y.Cmp(key.Y) != 0 {
		t.Fatal("the public key read from the card does not match")
	}
	if md.Imported {
		t.Error("the virtual key reports as imported, want generated on the card")
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

	if _, signatures, _ := virtual.Counters(); signatures != 1 {
		t.Errorf("the card performed %d signatures, want 1", signatures)
	}
}

// TestPIVStackCertificateFallback covers firmware older than 5.3, where GET
// METADATA is unsupported and the public key has to come from the slot
// certificate — which is larger than one short APDU response, so this also
// exercises GET RESPONSE chaining over the real socket.
func TestPIVStackCertificateFallback(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pivCard, _ := openStack(t, virtualpiv.Options{Key: key, Slot: 0x9A, NoMetadata: true})

	if _, err := pivCard.SlotMetadata(0x9A); !errors.Is(err, piv.ErrMetadataUnsupported) {
		t.Fatalf("expected ErrMetadataUnsupported, got %v", err)
	}

	pub, err := pivCard.PublicKey(0x9A)
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	got, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsa.PublicKey", pub)
	}
	if got.X.Cmp(key.X) != 0 || got.Y.Cmp(key.Y) != 0 {
		t.Error("the public key read from the certificate does not match")
	}
}

// TestPIVStackRSA covers the extended-length APDU path: an RSA-2048 signing
// request carries a 256-byte padded block, which a short APDU cannot express.
func TestPIVStackRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pivCard, _ := openStack(t, virtualpiv.Options{Key: key, Slot: 0x9C})

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

	// The card only performed the raw operation, so a verifiable PKCS#1 v1.5
	// signature proves internal/piv built the padded block correctly.
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, 0, hashedForVerify(digest), signature); err != nil {
		t.Errorf("the signature from the card does not verify: %v", err)
	}
}

// hashedForVerify returns the digest with its DigestInfo prefix, the form
// VerifyPKCS1v15 expects when given crypto.Hash(0).
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

	pivCard, virtual := openStack(t, virtualpiv.Options{Key: key, Slot: 0x9A})

	err = pivCard.VerifyPIN("999999")
	if err == nil {
		t.Fatal("expected a wrong PIN to be rejected")
	}

	var pinErr *piv.PINError
	if !errors.As(err, &pinErr) {
		t.Fatalf("expected a *piv.PINError, got %v", err)
	}
	if pinErr.Retries != 2 {
		t.Errorf("Retries = %d, want 2", pinErr.Retries)
	}

	digest := sha256.Sum256([]byte("x"))
	if _, err := pivCard.Sign(0x9A, &key.PublicKey, digest[:]); err == nil {
		t.Error("signing should be refused until the PIN is verified")
	}

	if verifications, signatures, _ := virtual.Counters(); verifications != 0 || signatures != 0 {
		t.Errorf("nothing should have succeeded: %d verifications, %d signatures", verifications, signatures)
	}
}

// TestPIVStackPINPolicyAlways checks that a slot which discards its verified
// state after every operation really does refuse a second signature.
func TestPIVStackPINPolicyAlways(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pivCard, _ := openStack(t, virtualpiv.Options{
		Key:       key,
		Slot:      0x9C,
		PINPolicy: virtualpiv.PINPolicyAlways,
	})

	md, err := pivCard.SlotMetadata(0x9C)
	if err != nil {
		t.Fatalf("SlotMetadata failed: %v", err)
	}
	if md.PINPolicy != piv.PINPolicyAlways {
		t.Errorf("PINPolicy = %02x, want %02x", md.PINPolicy, piv.PINPolicyAlways)
	}

	digest := sha256.Sum256([]byte("x"))

	if err := pivCard.VerifyPIN("123456"); err != nil {
		t.Fatalf("VerifyPIN failed: %v", err)
	}
	if _, err := pivCard.Sign(0x9C, &key.PublicKey, digest[:]); err != nil {
		t.Fatalf("the first signature should succeed: %v", err)
	}
	if _, err := pivCard.Sign(0x9C, &key.PublicKey, digest[:]); err == nil {
		t.Error("a second signature without re-verifying should be refused")
	}
}
