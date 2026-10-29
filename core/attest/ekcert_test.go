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
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/tpm2-trust/tpm2-verifier/ekroots"
	"github.com/tpm2-trust/tpm2-verifier/store"
)

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

	// A TPM's subject alternative name, as TCG's EK credential profile has
	// it: manufacturer, model, version (the manufacturer "TEST").
	tpmAttrs := pkix.RDNSequence{{
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 1}, Value: "id:54455354"},
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 2}, Value: "TEST-TPM"},
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 3}, Value: "id:00010000"},
	}}
	dirName, _ := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 4, IsCompound: true, Bytes: mustMarshal(t, tpmAttrs)})
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

// verifyWith is VerifyEKCertificate against an EK root store of roots and
// intermediates (a vendor of its own, as tpm2-verifier's store holds the
// real ones).
func verifyWith(t *testing.T, ekPub, leaf, chain []byte, roots, inter [][]byte, now time.Time) error {
	t.Helper()
	fsys := fstest.MapFS{}
	var y strings.Builder
	y.WriteString("id: test\nname: Test Vendor\nmanufacturer_ids: [TEST]\ncertificates:\n")
	add := func(name string, der []byte, role string) {
		sum := sha256.Sum256(der)
		fsys["test/"+name] = &fstest.MapFile{Data: der}
		fmt.Fprintf(&y, "  - file: %s\n    role: %s\n    source: test\n    sha256: %s\n", name, role, hex.EncodeToString(sum[:]))
	}
	for i, r := range roots {
		add(fmt.Sprintf("root%d.der", i), r, "root")
	}
	for i, c := range inter {
		add(fmt.Sprintf("int%d.der", i), c, "intermediate")
	}
	fsys["test/vendor.yaml"] = &fstest.MapFile{Data: []byte(y.String())}
	st := store.New()
	if err := st.AddFS(fsys, "test"); err != nil {
		t.Fatal(err)
	}
	_, err := verifyEK(ekPub, leaf, chain, now, func(l []byte, i [][]byte, n time.Time) ekroots.Result {
		return ekroots.CheckWith(st, l, i, n)
	})
	return err
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEKCertificateVerification(t *testing.T) {
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := newEKPKI(t, ek, nil)
	now := time.Now()
	roots := [][]byte{p.rootDER}
	padded := append(append([]byte(nil), p.interDER...), 0, 0, 0xFF, 0xFF)

	if err := verifyWith(t, p.ekPub, p.leafDER, p.interDER, roots, nil, now); err != nil {
		t.Fatalf("genuine EK rejected: %v", err)
	}
	if err := verifyWith(t, p.ekPub, p.leafDER, padded, roots, nil, now); err != nil {
		t.Fatalf("NV padding after the chain rejected: %v", err)
	}
	if err := verifyWith(t, p.ekPub, p.leafDER, nil, roots, [][]byte{p.interDER}, now); err != nil {
		t.Fatalf("embedded intermediate not used: %v", err)
	}

	// The certificate must be for the offered EK.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := verifyWith(t, ekPublicArea(t, &other.PublicKey), p.leafDER, p.interDER, roots, nil, now); err == nil ||
		!strings.Contains(err.Error(), "different key") {
		t.Fatalf("certificate for another key accepted: %v", err)
	}
	// Missing intermediate, unknown root, tampering, expiry.
	if verifyWith(t, p.ekPub, p.leafDER, nil, roots, nil, now) == nil {
		t.Fatal("verified without the intermediate")
	}
	if verifyWith(t, p.ekPub, p.leafDER, p.interDER, [][]byte{newEKPKI(t, ek, nil).rootDER}, nil, now) == nil {
		t.Fatal("verified under a foreign root")
	}
	bad := append([]byte(nil), p.leafDER...)
	bad[len(bad)-10] ^= 1
	if verifyWith(t, p.ekPub, bad, p.interDER, roots, nil, now) == nil {
		t.Fatal("tampered certificate verified")
	}
	if verifyWith(t, p.ekPub, p.leafDER, p.interDER, roots, nil, now.Add(2*time.Hour)) == nil {
		t.Fatal("expired certificate verified")
	}
	// A certificate under the right root whose usage says it is not an EK.
	notEK := newEKPKI(t, ek, func(c *x509.Certificate) {
		c.UnknownExtKeyUsage = nil
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	})
	if err := verifyWith(t, notEK.ekPub, notEK.leafDER, notEK.interDER, [][]byte{notEK.rootDER}, nil, now); err == nil {
		t.Fatal("non-EK certificate verified")
	}
	// No certificate at all, and the public entry point with real roots.
	if _, err := VerifyEKCertificate(p.ekPub, nil, nil, now); err == nil || EKCertNote(err) != "the TPM has no vendor certificate for its endorsement key" {
		t.Fatalf("missing certificate: %v", err)
	}
	// Under the real store the test hierarchy's vendor is not known: not
	// verified, and said so as a risk, not as a failure.
	v, err := VerifyEKCertificate(p.ekPub, p.leafDER, p.interDER, now)
	var unknown *VendorUnknownError
	if v != "" || !errors.As(err, &unknown) || !strings.Contains(EKCertNote(err), "not untrusted") {
		t.Fatalf("the test hierarchy under the EK root store: %q %v", v, err)
	}
}

// A certificate whose last byte is 0x00 or 0xFF must survive the padding trim
// (it was cut before: about one chain in 128 failed for no visible reason).
func TestTrimNVPaddingKeepsTrailingZeroBytes(t *testing.T) {
	for i := 0; i < 400; i++ {
		ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		p := newEKPKI(t, ek, nil)
		last := p.interDER[len(p.interDER)-1]
		if last != 0 && last != 0xFF {
			continue
		}
		padded := append(append([]byte(nil), p.interDER...), 0, 0xFF, 0)
		if got := trimNVPadding(padded); string(got) != string(p.interDER) {
			t.Fatalf("certificate ending in %#x was cut or padding kept", last)
		}
		if err := verifyWith(t, p.ekPub, p.leafDER, padded, [][]byte{p.rootDER}, nil, time.Now()); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Skip("no certificate ending in 0x00/0xFF generated")
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

// A TPM that carries no intermediate: the machine completes the chain from
// the caIssuers URL the EK certificate names, as for an Intel EK of a
// product family whose P_MCC issuing CA is not embedded. A fetched
// certificate that is not the named issuer is ignored, PEM is accepted,
// and what was fetched earns no trust: the chain must still end at the
// root.
func TestCompleteEKChainFromAIA(t *testing.T) {
	const url = "http://ca.example/issuing.cer"
	pki := newEKPKI(t, mustKey(t), func(c *x509.Certificate) { c.IssuingCertificateURL = []string{url} })
	if got := EKIssuerMissing(pki.leafDER, nil); got != "CN=Test TPM Intermediate" {
		t.Fatalf("the missing issuer: %q", got)
	}
	if err := verifyWith(t, pki.ekPub, pki.leafDER, nil, [][]byte{pki.rootDER}, nil, time.Now()); err == nil {
		t.Fatal("verified without the intermediate")
	}

	asked := 0
	pemOf := func(der []byte) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	chain := CompleteEKChain(pki.leafDER, nil, func(u string) ([]byte, error) {
		asked++
		if u != url {
			t.Errorf("fetched %q", u)
		}
		return pemOf(pki.interDER), nil
	})
	if asked != 1 || !slices.Equal(chain, pki.interDER) {
		t.Fatalf("completed chain: %d fetches, %d bytes", asked, len(chain))
	}
	if err := verifyWith(t, pki.ekPub, pki.leafDER, chain, [][]byte{pki.rootDER}, nil, time.Now()); err != nil {
		t.Fatalf("the completed chain does not verify: %v", err)
	}
	if got := EKIssuerMissing(pki.leafDER, chain); got != "CN=Test TPM Root" {
		t.Fatalf("after completion the break is at the root: %q", got)
	}

	// The wrong certificate at the URL is not taken.
	other := newEKPKI(t, mustKey(t), nil)
	if c := CompleteEKChain(pki.leafDER, nil, func(string) ([]byte, error) { return other.interDER, nil }); len(c) != 0 {
		t.Fatal("a certificate that is not the issuer was taken")
	}
	// A root that is not embedded stays untrusted however the chain is
	// completed: fetching the root itself does not make it an anchor.
	if c := CompleteEKChain(pki.leafDER, pki.interDER, func(string) ([]byte, error) { return pki.rootDER, nil }); !slices.Equal(c, pki.interDER) {
		t.Fatal("a chain without AIA on its top was extended")
	}
}
