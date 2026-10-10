package attest

// Endorsement key certificates: is the TPM that enrols genuine hardware?
//
// At enrolment the phone pins whatever TPM answers. Credential activation
// proves that the AK lives in the TPM that owns the EK, but not that this EK
// belongs to real TPM hardware: a machine that is already compromised could
// offer a software TPM. A vendor certificate chain for the EK closes that
// gap where the vendor provides one.
//
// The result is informational and never blocks enrolment: many firmware TPMs
// ship without a usable certificate, and revocation is not checked (the app
// has no network access). It is "verified by <vendor>" or "not verified".
//
// Trust anchors are embedded in ekroots/, listed with pinned SHA-256 values in
// ekroots/vendors.json; ekroots/README.md says how to add a vendor. Only roots
// are anchors; embedded intermediates merely complete chains the TPM does not
// carry in full.
//
//	Intel PTT (on-die CSME), chain documented in
//	https://github.com/mrwiora/intel-ek-dechainer and cross-checked against
//	https://tsci.intel.com/content/OnDieCA/certs/:
//	  OnDie CA Root Cert Signing                       ekroots/intel-ptt/root.der
//	  └ OnDie CA CSME Intermediate CA                  ekroots/intel-ptt/csme-intermediate.der
//	    └ On Die CSME P_MCC 00001881 Issuing CA        ekroots/intel-ptt/mcc-00001881-issuing.der
//	      └ CSME MCC ROM CA ┐ per machine, concatenated DER
//	        └ … Kernel CA   │ in NV index 0x01C00100
//	          └ … PTT SVN   ┘ (EKCertChainNVIndex)
//	            └ EK certificate (NV 0x01C00002 RSA / 0x01C0000A ECC)
//
// Other Intel product families use other P_MCC issuing CAs. The machine
// completes the chain with the one its EK names (CompleteEKChain, from
// the caIssuers URL at tsci.intel.com); trust still comes from the
// embedded root alone.

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
)

// EKCertChainNVIndex holds Intel PTT's per-machine intermediates.
const EKCertChainNVIndex = 0x01C00100

// MaxEKCertChain bounds the concatenated intermediates the attester sends.
const MaxEKCertChain = 16384

//go:embed ekroots/vendors.json ekroots/*/*.der
var ekRootFS embed.FS

var (
	ekVendorsOnce sync.Once
	ekVendors     []*trustVendor
	ekVendorErrs  []error // vendors left out because a file is missing or changed
)

// loadEKVendors reads the embedded manifest once.
func loadEKVendors() []*trustVendor {
	ekVendorsOnce.Do(func() {
		sub, err := fs.Sub(ekRootFS, "ekroots")
		if err != nil {
			ekVendorErrs = []error{err}
			return
		}
		ekVendors, ekVendorErrs = parseTrustStore(sub)
	})
	return ekVendors
}

// EKVendorNames lists the TPM vendors whose EK certificates the core can verify.
func EKVendorNames() []string {
	var out []string
	for _, v := range loadEKVendors() {
		out = append(out, v.Name)
	}
	return out
}

var (
	oidSubjectAltName  = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTCGKPEKCert     = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	errNoEKCertificate = errors.New("the TPM has no EK certificate")
)

// SplitDERChain splits concatenated DER certificates. Unlike a scan for the
// next 0x30 byte it reads each SEQUENCE header at its exact offset and
// rejects anything that is not a whole certificate.
func SplitDERChain(chain []byte) ([][]byte, error) {
	var out [][]byte
	for off := 0; off < len(chain); {
		rest := chain[off:]
		if len(rest) < 2 || rest[0] != 0x30 {
			return nil, fmt.Errorf("EK certificate chain: no certificate at offset %d", off)
		}
		var n, hdr int
		switch l := int(rest[1]); {
		case l < 0x80:
			n, hdr = l, 2
		case l == 0x81 && len(rest) >= 3:
			n, hdr = int(rest[2]), 3
		case l == 0x82 && len(rest) >= 4:
			n, hdr = int(rest[2])<<8|int(rest[3]), 4
		case l == 0x83 && len(rest) >= 5:
			n, hdr = int(rest[2])<<16|int(rest[3])<<8|int(rest[4]), 5
		default:
			return nil, fmt.Errorf("EK certificate chain: bad length at offset %d", off)
		}
		if hdr+n > len(rest) {
			return nil, fmt.Errorf("EK certificate chain: certificate at offset %d is truncated", off)
		}
		out = append(out, rest[:hdr+n])
		off += hdr + n
	}
	return out, nil
}

// trimNVPadding cuts the zero or 0xFF padding some TPMs leave after the last
// certificate in an NV index. It walks the certificates and trims only what
// follows a complete one: stripping trailing bytes greedily would also cut a
// certificate whose signature happens to end in 0x00 or 0xFF.
func trimNVPadding(b []byte) []byte {
	for off := 0; off < len(b); {
		if isPadding(b[off:]) {
			return b[:off]
		}
		n, ok := derLength(b[off:])
		if !ok {
			return b // not a chain; SplitDERChain reports why
		}
		off += n
	}
	return b
}

func isPadding(b []byte) bool {
	for _, c := range b {
		if c != 0 && c != 0xFF {
			return false
		}
	}
	return true
}

// derLength is the total length of the DER SEQUENCE at the start of b.
func derLength(b []byte) (int, bool) {
	if len(b) < 2 || b[0] != 0x30 {
		return 0, false
	}
	var n, hdr int
	switch l := int(b[1]); {
	case l < 0x80:
		n, hdr = l, 2
	case l == 0x81 && len(b) >= 3:
		n, hdr = int(b[2]), 3
	case l == 0x82 && len(b) >= 4:
		n, hdr = int(b[2])<<8|int(b[3]), 4
	case l == 0x83 && len(b) >= 5:
		n, hdr = int(b[2])<<16|int(b[3])<<8|int(b[4]), 5
	default:
		return 0, false
	}
	if hdr+n > len(b) {
		return 0, false
	}
	return hdr + n, true
}

func parseEKCert(der []byte) (*x509.Certificate, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	// EK certificates carry their subject (TPM manufacturer, model, version)
	// as a critical subjectAltName with a directoryName, which Go leaves in
	// UnhandledCriticalExtensions. Accept exactly that, once it has parsed.
	c.UnhandledCriticalExtensions = slices.DeleteFunc(c.UnhandledCriticalExtensions, func(o asn1.ObjectIdentifier) bool {
		if !o.Equal(oidSubjectAltName) {
			return false
		}
		for _, e := range c.Extensions {
			if e.Id.Equal(oidSubjectAltName) {
				var v asn1.RawValue
				rest, err := asn1.Unmarshal(e.Value, &v)
				return err == nil && len(rest) == 0
			}
		}
		return false
	})
	return c, nil
}

// sameKey reports whether the certificate's public key is the EK in ekPub.
func sameKey(cert *x509.Certificate, ekPub []byte) error {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](ekPub)
	if err != nil {
		return fmt.Errorf("EK public area does not parse: %w", err)
	}
	k, err := tpm2.Pub(*pub)
	if err != nil {
		return err
	}
	switch want := k.(type) {
	case *ecdsa.PublicKey:
		got, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if ok && got.Equal(want) {
			return nil
		}
	case *rsa.PublicKey:
		got, ok := cert.PublicKey.(*rsa.PublicKey)
		if ok && got.Equal(want) {
			return nil
		}
	}
	return errors.New("the EK certificate is for a different key than the EK the machine offered")
}

// VerifyEKCertificate checks ekCert against the embedded vendor roots, with
// chain (concatenated DER intermediates from the TPM) as extra
// intermediates, and that the certificate is for ekPub. It returns the
// vendor's name, or an error saying why the TPM is not verified.
func VerifyEKCertificate(ekPub, ekCert, chain []byte, now time.Time) (string, error) {
	if len(ekCert) == 0 {
		return "", errNoEKCertificate
	}
	var errs []error
	for _, v := range loadEKVendors() {
		if err := verifyEKCertificateWith(ekPub, ekCert, chain, v.roots, v.inter, now); err != nil {
			errs = append(errs, err)
			continue
		}
		return v.Name, nil
	}
	// Report the most specific reason: a key mismatch matters more than an
	// unknown vendor.
	for _, e := range errs {
		if !errors.As(e, new(x509.UnknownAuthorityError)) {
			return "", e
		}
	}
	if missing := EKIssuerMissing(ekCert, chain); missing != "" {
		return "", fmt.Errorf("the chain breaks off at %q: not embedded, and not sent by the machine (known: %s)", missing, strings.Join(EKVendorNames(), ", "))
	}
	return "", fmt.Errorf("the EK certificate is not issued by a vendor this app knows (%s)", strings.Join(EKVendorNames(), ", "))
}

func verifyEKCertificateWith(ekPub, ekCert, chain []byte, roots, inter [][]byte, now time.Time) error {
	if len(ekCert) == 0 {
		return errNoEKCertificate
	}
	leaf, err := parseEKCert(ekCert)
	if err != nil {
		return fmt.Errorf("the EK certificate does not parse: %w", err)
	}
	if err := sameKey(leaf, ekPub); err != nil {
		return err
	}
	if len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0 {
		if !slices.ContainsFunc(leaf.UnknownExtKeyUsage, oidTCGKPEKCert.Equal) {
			return errors.New("the certificate is not an EK certificate (extended key usage)")
		}
	}
	opts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	for _, r := range roots {
		c, err := x509.ParseCertificate(r)
		if err != nil {
			return err
		}
		opts.Roots.AddCert(c)
	}
	machine, err := SplitDERChain(trimNVPadding(chain))
	if err != nil {
		return err
	}
	for _, b := range append(slices.Clone(inter), machine...) {
		c, err := parseEKCert(b)
		if err != nil {
			return fmt.Errorf("an intermediate certificate does not parse: %w", err)
		}
		opts.Intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(opts); err != nil {
		return err
	}
	return nil
}

// EKCertNote is the short explanation the app shows for an unverified EK.
func EKCertNote(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errNoEKCertificate):
		return "the TPM has no vendor certificate for its endorsement key"
	default:
		return err.Error()
	}
}

// knownEKCerts are the embedded roots and intermediates, parsed.
func knownEKCerts() []*x509.Certificate {
	var out []*x509.Certificate
	for _, v := range loadEKVendors() {
		for _, b := range append(slices.Clone(v.roots), v.inter...) {
			if c, err := x509.ParseCertificate(b); err == nil {
				out = append(out, c)
			}
		}
	}
	return out
}

// MaxEKChainFetches bounds the issuers CompleteEKChain fetches: Intel's
// chain needs one (the P_MCC issuing CA), sometimes two.
const MaxEKChainFetches = 3

// CompleteEKChain adds to chain the issuers it lacks, fetched from the
// caIssuers URL (AIA) of the certificate that names them: Intel signs the
// EKs of each product family under its own "P_MCC" issuing CA, and only
// one of them is embedded. A fetched certificate is an intermediate like
// any the TPM carries - nothing is trusted for being fetched: the chain
// still has to end at an embedded root, which VerifyEKCertificate
// checks. The phone has no network; the machine does, and sends the
// completed chain. fetch returns a certificate's DER (or PEM); errors
// leave the chain as it is.
func CompleteEKChain(leaf, chain []byte, fetch func(url string) ([]byte, error)) []byte {
	if len(leaf) == 0 || fetch == nil {
		return chain
	}
	out := trimNVPadding(chain)
	have := func() []*x509.Certificate {
		all := knownEKCerts()
		if c, err := parseEKCert(leaf); err == nil {
			all = append(all, c)
		}
		if certs, err := SplitDERChain(out); err == nil {
			for _, b := range certs {
				if c, err := parseEKCert(b); err == nil {
					all = append(all, c)
				}
			}
		}
		return all
	}
	for i := 0; i < MaxEKChainFetches; i++ {
		missing := missingIssuer(have())
		if missing == nil || len(missing.IssuingCertificateURL) == 0 {
			return out
		}
		var got []byte
		for _, u := range missing.IssuingCertificateURL {
			b, err := fetch(u)
			if err != nil {
				continue
			}
			// The issuer by name and by key: it signed the certificate
			// that names it. A name alone could be anybody's.
			if c, err := parseEKCert(derOf(b)); err == nil && bytesEqualRDN(c.RawSubject, missing.RawIssuer) &&
				missing.CheckSignatureFrom(c) == nil {
				got = c.Raw
				break
			}
		}
		if got == nil || len(out)+len(got) > MaxEKCertChain {
			return out
		}
		out = append(slices.Clone(out), got...)
	}
	return out
}

// missingIssuer is a certificate whose issuer none of certs is, and
// which is not self-signed: where the chain breaks off.
func missingIssuer(certs []*x509.Certificate) *x509.Certificate {
	subjects := map[string]bool{}
	for _, c := range certs {
		subjects[string(c.RawSubject)] = true
	}
	for _, c := range certs {
		if bytesEqualRDN(c.RawSubject, c.RawIssuer) {
			continue // a root
		}
		if !subjects[string(c.RawIssuer)] {
			return c
		}
	}
	return nil
}

func bytesEqualRDN(a, b []byte) bool { return string(a) == string(b) }

// derOf accepts DER, or a PEM certificate as some CAs serve their AIA.
func derOf(b []byte) []byte {
	if blk, _ := pem.Decode(b); blk != nil && blk.Type == "CERTIFICATE" {
		return blk.Bytes
	}
	return b
}

// EKIssuerMissing names the issuer the chain of leaf and chain lacks, or
// "" when every issuer is there: the reason an Intel EK of another product
// family is not verified, said in Intel's own words ("On Die CSME P_MCC
// 0000xxxx Issuing CA").
func EKIssuerMissing(leaf, chain []byte) string {
	certs := knownEKCerts()
	if c, err := parseEKCert(leaf); err == nil {
		certs = append(certs, c)
	}
	if parts, err := SplitDERChain(trimNVPadding(chain)); err == nil {
		for _, b := range parts {
			if c, err := parseEKCert(b); err == nil {
				certs = append(certs, c)
			}
		}
	}
	if m := missingIssuer(certs); m != nil {
		return m.Issuer.String()
	}
	return ""
}
