package piv_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/matthias/tpm2-kira/internal/piv"
	"github.com/matthias/tpm2-kira/internal/piv/pivtest"
)

func open(t *testing.T, card *pivtest.Card) *piv.Card {
	t.Helper()
	c, err := piv.Open(card)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return c
}

func TestIdentity(t *testing.T) {
	card := pivtest.New(12345678)
	c := open(t, card)
	v, err := c.Version()
	if err != nil || v.String() != "5.7.1" || !v.AtLeast(5, 3) || v.AtLeast(5, 8) {
		t.Fatalf("Version: %v %v", v, err)
	}
	s, err := c.Serial()
	if err != nil || s != 12345678 {
		t.Fatalf("Serial: %d %v", s, err)
	}
}

func TestMetadataAndCertificate(t *testing.T) {
	card := pivtest.New(1)
	ec := card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, true)
	rk := card.AddRSAKey(piv.SlotSignature, 2048, piv.PINPolicyAlways, piv.TouchPolicyAlways, true)
	c := open(t, card)

	md, err := c.Metadata(piv.SlotAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	if md.Algorithm != piv.AlgECCP256 || md.PINPolicy != piv.PINPolicyOnce || md.TouchPolicy != piv.TouchPolicyNever ||
		!md.Generated || !ec.PublicKey.Equal(md.PublicKey) {
		t.Fatalf("EC metadata: %+v", md)
	}
	md, err = c.Metadata(piv.SlotSignature)
	if err != nil || md.Algorithm != piv.AlgRSA2048 || !rk.PublicKey.Equal(md.PublicKey) {
		t.Fatalf("RSA metadata: %+v %v", md, err)
	}
	if _, err := c.Metadata(piv.SlotKeyManagement); !errors.Is(err, piv.ErrNotFound) {
		t.Fatalf("empty slot: %v", err)
	}

	// An RSA certificate is longer than one short response: exercises 61xx.
	cert, err := c.Certificate(piv.SlotSignature)
	if err != nil || !rk.PublicKey.Equal(cert.PublicKey) {
		t.Fatalf("Certificate: %v", err)
	}
	if _, err := c.Certificate(piv.SlotKeyManagement); !errors.Is(err, piv.ErrNotFound) {
		t.Fatalf("missing certificate: %v", err)
	}

	card.NoMetadata = true
	if _, err := c.Metadata(piv.SlotAuthentication); !errors.Is(err, piv.ErrNotSupported) {
		t.Fatalf("old firmware: %v", err)
	}
}

func TestPIN(t *testing.T) {
	card := pivtest.New(1)
	c := open(t, card)

	n, verified, err := c.PINRetries()
	if err != nil || n != 3 || verified {
		t.Fatalf("PINRetries: %d %v %v", n, verified, err)
	}
	var wrong *piv.WrongPINError
	if err := c.VerifyPIN("654321"); !errors.As(err, &wrong) || wrong.Remaining != 2 {
		t.Fatalf("wrong PIN: %v", err)
	}
	if err := c.VerifyPIN("12345"); err == nil || card.Retries != 2 {
		t.Fatalf("short PIN must be refused without reaching the card: %v, retries %d", err, card.Retries)
	}
	if err := c.VerifyPIN("123456"); err != nil {
		t.Fatal(err)
	}
	if _, verified, _ := c.PINRetries(); !verified || card.Retries != 3 {
		t.Fatal("a correct PIN must reset the counter and leave the PIN verified")
	}

	card.Retries = 1
	card.PIN = "999999"
	if err := c.VerifyPIN("123456"); !errors.Is(err, piv.ErrPINBlocked) {
		t.Fatalf("last attempt: %v", err)
	}
}

func TestSign(t *testing.T) {
	digest := sha256.Sum256([]byte("tpm2-kira"))
	card := pivtest.New(1)
	ec := card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	rk := card.AddRSAKey(piv.SlotSignature, 2048, piv.PINPolicyAlways, piv.TouchPolicyNever, false)
	c := open(t, card)

	if _, err := c.Sign(piv.SlotAuthentication, &ec.PublicKey, digest[:]); !errors.Is(err, piv.ErrPINRequired) {
		t.Fatalf("sign without PIN: %v", err)
	}
	if err := c.VerifyPIN("123456"); err != nil {
		t.Fatal(err)
	}
	sig, err := c.Sign(piv.SlotAuthentication, &ec.PublicKey, digest[:])
	if err != nil || !ecdsa.VerifyASN1(&ec.PublicKey, digest[:], sig) {
		t.Fatalf("ECDSA: %v", err)
	}

	// RSA-2048 needs command chaining: 256 bytes of padded digest plus TLVs.
	// PIN policy ALWAYS: the key needs a VERIFY right before it, although
	// the PIN is still reported as verified.
	if _, verified, _ := c.PINRetries(); !verified {
		t.Fatal("PIN status lost after a signature")
	}
	if _, err := c.Sign(piv.SlotSignature, &rk.PublicKey, digest[:]); !errors.Is(err, piv.ErrPINRequired) {
		t.Fatalf("PIN policy always without a fresh VERIFY: %v", err)
	}
	if err := c.VerifyPIN("123456"); err != nil {
		t.Fatal(err)
	}
	sig, err = c.Sign(piv.SlotSignature, &rk.PublicKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&rk.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("RSA signature does not verify: %v", err)
	}
	// PIN policy ALWAYS: the second signature needs a fresh VERIFY.
	if _, err := c.Sign(piv.SlotSignature, &rk.PublicKey, digest[:]); !errors.Is(err, piv.ErrPINRequired) {
		t.Fatalf("PIN policy always: %v", err)
	}
}

func TestParseSlot(t *testing.T) {
	for in, want := range map[string]piv.Slot{"9a": 0x9A, "0x9C": 0x9C, "82": 0x82, "95": 0x95} {
		if got, err := piv.ParseSlot(in); err != nil || got != want {
			t.Errorf("ParseSlot(%q) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "9b", "96", "f9", "zz"} {
		if _, err := piv.ParseSlot(in); err == nil {
			t.Errorf("ParseSlot(%q) accepted", in)
		}
	}
}
