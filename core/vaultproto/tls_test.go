package vaultproto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(20, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf is a server certificate for ip, signed by the CA, valid from
// notBefore to notAfter.
func (ca *testCA) leaf(t *testing.T, ip string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: ip},
		NotBefore: notBefore, NotAfter: notAfter, IPAddresses: []net.IP{net.ParseIP(ip)},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key, Leaf: leaf}
}

// serve answers one TLS handshake with cert on a local port.
func serve(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	return ln.Addr().String()
}

func dial(addr string, cfg *tls.Config) error {
	c, err := tls.Dial("tcp", addr, cfg)
	if err == nil {
		c.Close()
	}
	return err
}

// The client takes a vault whose chain ends at one of its roots, for the
// vault's address, within the dates, whose root (or leaf) key is the pin -
// and refuses each of these missing.
func TestClientConfigVerifiesTheChainAndThePin(t *testing.T) {
	ca, other := newTestCA(t, "vault root"), newTestCA(t, "another root")
	now := time.Now()
	good := ca.leaf(t, "127.0.0.1", now.Add(-time.Hour), now.AddDate(1, 0, 0))
	addr := serve(t, good)
	roots, _, err := ParseRoots(ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	rootPin, leafPin := PinOf(ca.cert.RawSubjectPublicKeyInfo), PinOf(good.Leaf.RawSubjectPublicKeyInfo)

	if err := dial(addr, ClientConfig(roots, "127.0.0.1", rootPin)); err != nil {
		t.Fatalf("the root's pin: %v", err)
	}
	if err := dial(addr, ClientConfig(roots, "127.0.0.1", strings.ToUpper(leafPin))); err != nil {
		t.Fatalf("the leaf's pin: %v", err)
	}
	otherRoots, _, _ := ParseRoots(other.pem)
	for what, c := range map[string]struct {
		cfg  *tls.Config
		want string
	}{
		"another root":   {ClientConfig(otherRoots, "127.0.0.1", rootPin), "unknown authority"},
		"another host":   {ClientConfig(roots, "127.0.0.2", rootPin), "127.0.0.2"},
		"another pin":    {ClientConfig(roots, "127.0.0.1", PinOf(other.cert.RawSubjectPublicKeyInfo)), "pinned key"},
		"another's root": {ClientConfig(otherRoots, "127.0.0.1", PinOf(other.cert.RawSubjectPublicKeyInfo)), "unknown authority"},
	} {
		if err := dial(addr, c.cfg); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", what, err, c.want)
		}
	}

	expired := serve(t, ca.leaf(t, "127.0.0.1", now.AddDate(-2, 0, 0), now.AddDate(-1, 0, 0)))
	if err := dial(expired, ClientConfig(roots, "127.0.0.1", rootPin)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("an expired leaf: %v", err)
	}
	early := serve(t, ca.leaf(t, "127.0.0.1", now.AddDate(1, 0, 0), now.AddDate(2, 0, 0)))
	if err := dial(early, ClientConfig(roots, "127.0.0.1", rootPin)); err == nil || !strings.Contains(err.Error(), "not yet valid") && !strings.Contains(err.Error(), "expired") {
		t.Errorf("a leaf not valid yet: %v", err)
	}
}

func TestParseRoots(t *testing.T) {
	a, b := newTestCA(t, "a"), newTestCA(t, "b")
	if _, certs, err := ParseRoots(append(append([]byte(nil), a.pem...), b.pem...)); err != nil || len(certs) != 2 {
		t.Fatalf("two roots: %d %v", len(certs), err)
	}
	now := time.Now()
	leaf := a.leaf(t, "127.0.0.1", now, now.Add(time.Hour))
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	for what, bundle := range map[string][]byte{
		"empty":       nil,
		"not PEM":     []byte("hello"),
		"a key":       pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}),
		"a leaf":      leafPEM,
		"PEM, then x": append(append([]byte(nil), a.pem...), "x"...),
	} {
		if _, _, err := ParseRoots(bundle); err == nil {
			t.Errorf("%s: taken", what)
		}
	}
}
