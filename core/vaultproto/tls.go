package vaultproto

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// The vault's TLS, from the machine's side (and every other client's): the
// standard verification - a chain to one of the roots, the vault's host
// name, the validity dates against the clock - and then the pin, which
// must be the key of a certificate in the verified chain. The roots lie
// unsigned in the boot image; the pin is in the slot's signed blob, so a
// root put there by somebody else gets no other vault accepted.

// ClientConfig is the TLS configuration of a client of the vault at host
// (a name or an address, as the vault's URL has it): TLS 1.3, the chain to
// one of roots, and pin.
func ClientConfig(roots *x509.CertPool, host, pin string) *tls.Config {
	pin = strings.ToLower(pin)
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: host,
		VerifyConnection: func(cs tls.ConnectionState) error {
			for _, chain := range cs.VerifiedChains {
				for _, c := range chain {
					if PinOf(c.RawSubjectPublicKeyInfo) == pin {
						return nil
					}
				}
			}
			return fmt.Errorf("no certificate of the vault's chain has the pinned key %s", pin)
		},
	}
}

// ParseRoots reads a bundle of PEM certificates: the roots a vault's chain
// may end at. Anything but certificates in it is an error, and so is a
// bundle without one.
func ParseRoots(bundle []byte) (*x509.CertPool, []*x509.Certificate, error) {
	pool := x509.NewCertPool()
	var certs []*x509.Certificate
	for rest := bundle; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			if len(strings.TrimSpace(string(rest))) != 0 {
				return nil, nil, errors.New("the root bundle holds something that is not PEM")
			}
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("the root bundle holds a %s, not only certificates", blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("a root does not parse: %w", err)
		}
		if !c.IsCA || !c.BasicConstraintsValid {
			return nil, nil, fmt.Errorf("%q is not a CA certificate", c.Subject.CommonName)
		}
		pool.AddCert(c)
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("the root bundle holds no certificate")
	}
	return pool, certs, nil
}
