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
// Other Intel product families use other P_MCC issuing CAs; until one is
// added, their EKs show as "not verified".

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
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

// ekVendor is one entry of ekroots/vendors.json, with its certificates read
// and their pinned fingerprints checked.
type ekVendor struct {
	Name          string        `json:"name"`
	Roots         []ekRootEntry `json:"roots"`         // trust anchors
	Intermediates []ekRootEntry `json:"intermediates"` // helpers, never anchors

	roots, inter [][]byte
}

type ekRootEntry struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

var (
	ekVendorsOnce sync.Once
	ekVendors     []*ekVendor
	ekVendorErrs  []error // vendors left out because a file is missing or changed
)

// loadEKVendors reads the embedded manifest once.
func loadEKVendors() []*ekVendor {
	ekVendorsOnce.Do(func() {
		sub, err := fs.Sub(ekRootFS, "ekroots")
		if err != nil {
			ekVendorErrs = []error{err}
			return
		}
		ekVendors, ekVendorErrs = parseEKVendors(sub)
	})
	return ekVendors
}

// parseEKVendors reads vendors.json from fsys. A vendor whose files do not
// match their pinned SHA-256 is left out: its TPMs then show as "not
// verified", which is safe, rather than trusted on an unchecked anchor.
func parseEKVendors(fsys fs.FS) ([]*ekVendor, []error) {
	var errs []error
	raw, err := fs.ReadFile(fsys, "vendors.json")
	if err != nil {
		return nil, []error{err}
	}
	var m struct {
		Vendors []*ekVendor `json:"vendors"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, []error{fmt.Errorf("vendors.json: %w", err)}
	}
	read := func(e ekRootEntry) ([]byte, error) {
		b, err := fs.ReadFile(fsys, e.File)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != strings.ToLower(e.SHA256) {
			return nil, fmt.Errorf("%s does not match its pinned SHA-256", e.File)
		}
		if _, err := x509.ParseCertificate(b); err != nil {
			return nil, fmt.Errorf("%s: %w", e.File, err)
		}
		return b, nil
	}
	var out []*ekVendor
vendors:
	for _, v := range m.Vendors {
		if v.Name == "" || len(v.Roots) == 0 {
			errs = append(errs, fmt.Errorf("vendor %q has no name or no roots", v.Name))
			continue
		}
		for _, e := range v.Roots {
			b, err := read(e)
			if err != nil {
				errs = append(errs, fmt.Errorf("vendor %s: %w", v.Name, err))
				continue vendors
			}
			v.roots = append(v.roots, b)
		}
		for _, e := range v.Intermediates {
			b, err := read(e)
			if err != nil {
				errs = append(errs, fmt.Errorf("vendor %s: %w", v.Name, err))
				continue vendors
			}
			v.inter = append(v.inter, b)
		}
		out = append(out, v)
	}
	return out, errs
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
// certificate in an NV index.
func trimNVPadding(b []byte) []byte {
	end := len(b)
	for end > 0 && (b[end-1] == 0 || b[end-1] == 0xFF) {
		end--
	}
	// Only padding after a complete chain is removed; SplitDERChain checks.
	if end < len(b) {
		if _, err := SplitDERChain(b[:end]); err == nil {
			return b[:end]
		}
	}
	return b
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
