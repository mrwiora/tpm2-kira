package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
)

// The embedded Intel certificates, cross-checked against
// https://tsci.intel.com/content/OnDieCA/certs/ and
// https://github.com/mrwiora/intel-ek-dechainer on 2026-10-05.
var ekRootFingerprints = map[string]string{
	"ekroots/intel-ondie-root.der":                 "beb40bb7507b33967226aa80e084749fbb6593893c642e818d682e9a8d07fc24",
	"ekroots/intel-ondie-csme-intermediate.der":    "5e3eee5748ac13e0b3d1227fcdc4751aa1402dde8031d21f63cb4ecf43f02440",
	"ekroots/intel-ondie-mcc-00001881-issuing.der": "d4a82dde06a12689ae22a50870003de03ac04205e921410c60eb0216fb15baff",
}

func TestEmbeddedEKRootsArePinned(t *testing.T) {
	entries, _ := ekRootFS.ReadDir("ekroots")
	if len(entries) != len(ekRootFingerprints) {
		t.Fatalf("%d embedded certificates, %d pinned", len(entries), len(ekRootFingerprints))
	}
	for name, want := range ekRootFingerprints {
		b, err := ekRootFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256.Sum256(b); hex.EncodeToString(got[:]) != want {
			t.Errorf("%s changed: %x", name, got)
		}
	}
}

func TestIntelChainLinks(t *testing.T) {
	load := func(n string) *x509.Certificate {
		b, _ := ekRootFS.ReadFile("ekroots/" + n)
		c, err := x509.ParseCertificate(b)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	root := load("intel-ondie-root.der")
	int1 := load("intel-ondie-csme-intermediate.der")
	int2 := load("intel-ondie-mcc-00001881-issuing.der")
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Errorf("root self-signature: %v", err)
	}
	if err := int1.CheckSignatureFrom(root); err != nil {
		t.Errorf("CSME intermediate under root: %v", err)
	}
	if err := int2.CheckSignatureFrom(int1); err != nil {
		t.Errorf("issuing CA under CSME intermediate: %v", err)
	}
}

// A synthetic vendor hierarchy shaped like a TPM vendor's: root, an
// intermediate the TPM carries, and an EK certificate with the critical
// directoryName subjectAltName and the TCG EK extended key usage.
type ekPKI struct {
	rootDER, interDER, leafDER []byte
	ekPub                      []byte
}

func newEKPKI(t *testing.T, ekKey *ecdsa.PrivateKey, mutate func(*x509.Certificate)) ekPKI {
	t.Helper()
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := func(serial int64, cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
	}
	rootT := ca(1, "Test TPM Root")
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootT, rootT, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	interT := ca(2, "Test TPM Intermediate")
	interDER, _ := x509.CreateCertificate(rand.Reader, interT, root, &interKey.PublicKey, rootKey)
	inter, _ := x509.ParseCertificate(interDER)

	dirName, _ := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 4, IsCompound: true, Bytes: mustMarshal(t, pkix.Name{CommonName: "TPM"}.ToRDNSequence())})
	san, _ := asn1.Marshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: dirName})
	leafT := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:           x509.KeyUsageKeyAgreement,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidTCGKPEKCert},
		ExtraExtensions:    []pkix.Extension{{Id: oidSubjectAltName, Critical: true, Value: san}},
	}
	if mutate != nil {
		mutate(leafT)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafT, inter, &ekKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	return ekPKI{rootDER: rootDER, interDER: interDER, leafDER: leafDER, ekPub: ekPublicArea(t, &ekKey.PublicKey)}
}

func mustMarshal(t *testing.T, v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ekPublicArea builds a TCG-style ECC EK TPMT_PUBLIC around pub.
func ekPublicArea(t *testing.T, pub *ecdsa.PublicKey) []byte {
	tmpl := EKTemplateECC
	tmpl.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: pub.X.FillBytes(make([]byte, 32))},
		Y: tpm2.TPM2BECCParameter{Buffer: pub.Y.FillBytes(make([]byte, 32))},
	})
	return tpm2.Marshal(tmpl)
}

func TestEKCertificateVerification(t *testing.T) {
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := newEKPKI(t, ek, nil)
	now := time.Now()
	roots := [][]byte{p.rootDER}
	padded := append(append([]byte(nil), p.interDER...), 0, 0, 0xFF, 0xFF)

	if err := verifyEKCertificateWith(p.ekPub, p.leafDER, p.interDER, roots, nil, now); err != nil {
		t.Fatalf("genuine EK rejected: %v", err)
	}
	if err := verifyEKCertificateWith(p.ekPub, p.leafDER, padded, roots, nil, now); err != nil {
		t.Fatalf("NV padding after the chain rejected: %v", err)
	}
	if err := verifyEKCertificateWith(p.ekPub, p.leafDER, nil, roots, [][]byte{p.interDER}, now); err != nil {
		t.Fatalf("embedded intermediate not used: %v", err)
	}

	// The certificate must be for the offered EK.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := verifyEKCertificateWith(ekPublicArea(t, &other.PublicKey), p.leafDER, p.interDER, roots, nil, now); err == nil ||
		!strings.Contains(err.Error(), "different key") {
		t.Fatalf("certificate for another key accepted: %v", err)
	}
	// Missing intermediate, unknown root, tampering, expiry.
	if verifyEKCertificateWith(p.ekPub, p.leafDER, nil, roots, nil, now) == nil {
		t.Fatal("verified without the intermediate")
	}
	if verifyEKCertificateWith(p.ekPub, p.leafDER, p.interDER, [][]byte{newEKPKI(t, ek, nil).rootDER}, nil, now) == nil {
		t.Fatal("verified under a foreign root")
	}
	bad := append([]byte(nil), p.leafDER...)
	bad[len(bad)-10] ^= 1
	if verifyEKCertificateWith(p.ekPub, bad, p.interDER, roots, nil, now) == nil {
		t.Fatal("tampered certificate verified")
	}
	if verifyEKCertificateWith(p.ekPub, p.leafDER, p.interDER, roots, nil, now.Add(2*time.Hour)) == nil {
		t.Fatal("expired certificate verified")
	}
	// A certificate under the right root whose usage says it is not an EK.
	notEK := newEKPKI(t, ek, func(c *x509.Certificate) {
		c.UnknownExtKeyUsage = nil
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	})
	if err := verifyEKCertificateWith(notEK.ekPub, notEK.leafDER, notEK.interDER, [][]byte{notEK.rootDER}, nil, now); err == nil {
		t.Fatal("non-EK certificate verified")
	}
	// No certificate at all, and the public entry point with real roots.
	if _, err := VerifyEKCertificate(p.ekPub, nil, nil, now); err == nil || EKCertNote(err) != "the TPM has no vendor certificate for its endorsement key" {
		t.Fatalf("missing certificate: %v", err)
	}
	if v, err := VerifyEKCertificate(p.ekPub, p.leafDER, p.interDER, now); err == nil || v != "" {
		t.Fatalf("test hierarchy verified as %q under the embedded roots", v)
	}
}

func TestSplitDERChain(t *testing.T) {
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := newEKPKI(t, ek, nil)
	chain := append(append([]byte(nil), p.rootDER...), p.interDER...)
	certs, err := SplitDERChain(chain)
	if err != nil || len(certs) != 2 {
		t.Fatalf("%d certificates, %v", len(certs), err)
	}
	if _, err := SplitDERChain(chain[:len(chain)-1]); err == nil {
		t.Error("truncated chain accepted")
	}
	if _, err := SplitDERChain(append(chain, 0x00, 0x30)); err == nil {
		t.Error("trailing garbage accepted")
	}
	if certs, err := SplitDERChain(nil); err != nil || len(certs) != 0 {
		t.Error("empty chain")
	}
}
