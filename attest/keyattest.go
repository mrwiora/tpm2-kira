package attest

// Android Key Attestation: is the phone's anchor key really inside secure
// hardware? (TODO-SEC.md in the app repository, "both sides check each
// other's hardware".)
//
// At enrolment the phone creates its anchor key with an attestation challenge
// derived from the session, and sends the key's certificate chain in
// EnrolAccept. The machine checks it here: the chain ends at a pinned Google
// attestation root (phoneroots/), the certificate is for the anchor key the
// phone signed with, the attestation was made for this session, and the key
// was generated in StrongBox or the TEE, needs an unlock for every use, and
// lives on a phone that booted a locked, verified system.
//
// The result is shown to the person enrolling, who decides (policy in
// cmd/attest.go). Many legitimate phones fail one check: custom ROMs boot
// "self-signed", some ROMs cannot attest at all.

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"strings"
	"sync"
	"time"
)

// MaxAnchorAttestation bounds the certificate chain in EnrolAccept.
const MaxAnchorAttestation = 16384

var oidKeyAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

//go:embed phoneroots/vendors.json phoneroots/*/*.der
var phoneRootFS embed.FS

var (
	phoneRootsOnce sync.Once
	phoneRoots     []*trustVendor
	phoneRootErrs  []error
)

func loadPhoneRoots() []*trustVendor {
	phoneRootsOnce.Do(func() {
		sub, err := fs.Sub(phoneRootFS, "phoneroots")
		if err != nil {
			phoneRootErrs = []error{err}
			return
		}
		phoneRoots, phoneRootErrs = parseTrustStore(sub)
	})
	return phoneRoots
}

// AnchorAttestationChallenge is the attestation challenge the phone puts into
// its anchor key: bound to this enrolment session's channel binding.
func AnchorAttestationChallenge(cb []byte) []byte {
	h := sha256.New()
	h.Write([]byte("tpm2-kira/anchor-attest/v1"))
	h.Write(cb)
	return h.Sum(nil)
}

// PhoneAttestation is what the machine learnt about the phone's anchor key.
type PhoneAttestation struct {
	Verified      bool     // chains to a pinned root and every check passed
	Root          string   // the trust store vendor that vouches, e.g. "Google"
	SecurityLevel string   // "StrongBox", "TEE" or "Software"
	BootState     string   // "verified", "self-signed", "unverified", "failed" or ""
	DeviceLocked  bool     // bootloader locked
	Unlock        string   // what unlocks the key, e.g. "fingerprint/face or PIN"
	PatchLevel    string   // OS security patch level, YYYY-MM
	Problems      []string // why it is not verified, in plain words
	Serials       []string // certificate serial numbers (hex), for a revocation check
}

// Summary is one line for the machine's console.
func (a PhoneAttestation) Summary() string {
	if a.SecurityLevel == "" {
		return "not attested"
	}
	var parts []string
	parts = append(parts, a.SecurityLevel)
	if a.Unlock != "" {
		parts = append(parts, "unlock by "+a.Unlock+" for every use")
	}
	switch {
	case a.BootState == "verified" && a.DeviceLocked:
		parts = append(parts, "locked bootloader, verified boot")
	case a.BootState != "":
		lock := "unlocked"
		if a.DeviceLocked {
			lock = "locked"
		}
		parts = append(parts, fmt.Sprintf("%s bootloader, %s boot", lock, a.BootState))
	}
	if a.PatchLevel != "" {
		parts = append(parts, "patch level "+a.PatchLevel)
	}
	return strings.Join(parts, ", ")
}

// VerifyPhoneAttestation checks chain (concatenated DER, leaf first) for the
// anchor key anchorPub (PKIX DER) against the pinned phone roots.
func VerifyPhoneAttestation(chain, anchorPub, challenge []byte, now time.Time) PhoneAttestation {
	return verifyPhoneAttestationWith(chain, anchorPub, challenge, loadPhoneRoots(), now)
}

func verifyPhoneAttestationWith(chain, anchorPub, challenge []byte, roots []*trustVendor, now time.Time) PhoneAttestation {
	var a PhoneAttestation
	problem := func(f string, args ...any) { a.Problems = append(a.Problems, fmt.Sprintf(f, args...)) }
	if len(chain) == 0 {
		problem("the phone sent no key attestation (its Android version or ROM cannot attest keys)")
		return a
	}
	ders, err := SplitDERChain(chain)
	if err != nil || len(ders) == 0 {
		problem("the key attestation does not parse")
		return a
	}
	var certs []*x509.Certificate
	for _, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			problem("a certificate in the key attestation does not parse: %v", err)
			return a
		}
		certs = append(certs, c)
		a.Serials = append(a.Serials, strings.ToLower(c.SerialNumber.Text(16)))
	}
	leaf := certs[0]

	anchor, err := x509.ParsePKIXPublicKey(anchorPub)
	if err != nil {
		problem("the phone's anchor key does not parse")
		return a
	}
	ak, ok1 := anchor.(*ecdsa.PublicKey)
	lk, ok2 := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok1 || !ok2 || !ak.Equal(lk) {
		problem("the key attestation is for a different key than the one the phone signs with")
		return a
	}

	for _, v := range roots {
		if verifyChainTo(leaf, certs[1:], v.roots, now) == nil {
			a.Root = v.Name
			break
		}
	}
	if a.Root == "" {
		problem("the key attestation is not signed by a known attestation root (%s)", rootNames(roots))
	}

	kd, err := parseKeyDescription(leaf)
	if err != nil {
		problem("the key attestation carries no readable key description: %v", err)
		return a
	}
	a.SecurityLevel = securityLevelName(kd.KeyMintSecurityLevel)
	if kd.AttestationSecurityLevel < securityTEE || kd.KeyMintSecurityLevel < securityTEE {
		problem("the key is not in secure hardware (software keystore)")
	}
	if !equalBytes(kd.AttestationChallenge, challenge) {
		problem("the key attestation was not made for this enrolment")
	}
	hw := kd.HardwareEnforced
	if !hw.hasOrigin || hw.origin != originGenerated {
		problem("the key was not generated inside the phone's secure hardware")
	}
	if !hw.purposes[purposeSign] {
		problem("the key is not a signing key")
	}
	switch {
	case hw.noAuthRequired:
		problem("the key can be used without unlocking the phone")
	case hw.userAuthType == 0:
		problem("the secure hardware does not enforce an unlock for this key")
	case hw.hasAuthTimeout && hw.authTimeout > 0:
		problem("one unlock lets the key be used for %d seconds, not just once", hw.authTimeout)
	}
	a.Unlock = unlockMethods(hw.userAuthType)
	if hw.rootOfTrust != nil {
		a.DeviceLocked = hw.rootOfTrust.DeviceLocked
		a.BootState = bootStateName(hw.rootOfTrust.VerifiedBootState)
		if !a.DeviceLocked {
			problem("the phone's bootloader is unlocked")
		}
		if a.BootState != "verified" {
			problem("the phone did not boot a verified system (%s, e.g. a custom ROM)", a.BootState)
		}
	} else {
		problem("the key attestation does not say how the phone booted")
	}
	if hw.osPatchLevel > 0 {
		a.PatchLevel = fmt.Sprintf("%04d-%02d", hw.osPatchLevel/100, hw.osPatchLevel%100)
	}
	a.Verified = a.Root != "" && len(a.Problems) == 0
	return a
}

func verifyChainTo(leaf *x509.Certificate, inter []*x509.Certificate, roots [][]byte, now time.Time) error {
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
	for _, c := range inter {
		opts.Intermediates.AddCert(c)
	}
	// The key description is an extension Go does not know; it is not critical
	// in practice, but a critical one would otherwise fail verification.
	leaf.UnhandledCriticalExtensions = nil
	_, err := leaf.Verify(opts)
	return err
}

func rootNames(vs []*trustVendor) string {
	var n []string
	for _, v := range vs {
		n = append(n, v.Name)
	}
	if len(n) == 0 {
		return "none loaded"
	}
	return strings.Join(n, ", ")
}

// PhoneRootNames lists the attestation roots the machine accepts.
func PhoneRootNames() []string {
	var n []string
	for _, v := range loadPhoneRoots() {
		n = append(n, v.Name)
	}
	return n
}

// ---- KeyDescription (https://source.android.com/docs/security/features/keystore/attestation) ----

const (
	securitySoftware  = 0
	securityTEE       = 1
	securityStrongBox = 2

	originGenerated = 0
	purposeSign     = 2

	authPassword    = 1 // screen-lock PIN, pattern or password
	authFingerprint = 2 // any strong biometric
)

// keyDescriptionASN1 is the KeyDescription SEQUENCE as encoded.
type keyDescriptionASN1 struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeyMintVersion           int
	KeyMintSecurityLevel     asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	HardwareEnforced         asn1.RawValue
}

type keyDescription struct {
	AttestationSecurityLevel asn1.Enumerated
	KeyMintSecurityLevel     asn1.Enumerated
	AttestationChallenge     []byte
	HardwareEnforced         authorizationList
}

type rootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte `asn1:"optional"`
}

type authorizationList struct {
	purposes       map[int]bool
	noAuthRequired bool
	userAuthType   int
	hasAuthTimeout bool
	authTimeout    int
	hasOrigin      bool
	origin         int
	rootOfTrust    *rootOfTrust
	osPatchLevel   int
}

func parseKeyDescription(c *x509.Certificate) (*keyDescription, error) {
	var ext []byte
	for _, e := range c.Extensions {
		if e.Id.Equal(oidKeyAttestation) {
			ext = e.Value
		}
	}
	if ext == nil {
		return nil, errors.New("no key attestation extension")
	}
	var raw keyDescriptionASN1
	if rest, err := asn1.Unmarshal(ext, &raw); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("trailing data after the key description")
	}
	hw, err := parseAuthorizationList(raw.HardwareEnforced)
	if err != nil {
		return nil, fmt.Errorf("hardware-enforced list: %w", err)
	}
	return &keyDescription{
		AttestationSecurityLevel: raw.AttestationSecurityLevel,
		KeyMintSecurityLevel:     raw.KeyMintSecurityLevel,
		AttestationChallenge:     raw.AttestationChallenge,
		HardwareEnforced:         hw,
	}, nil
}

// parseAuthorizationList reads the tagged fields this check needs; every
// field is [tag] EXPLICIT, unknown tags are skipped.
func parseAuthorizationList(raw asn1.RawValue) (authorizationList, error) {
	al := authorizationList{purposes: map[int]bool{}}
	rest := raw.Bytes
	for len(rest) > 0 {
		var f asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &f); err != nil {
			return al, err
		}
		if f.Class != asn1.ClassContextSpecific {
			continue
		}
		one := func(v any) error {
			_, err := asn1.Unmarshal(f.Bytes, v)
			return err
		}
		switch f.Tag {
		case 1: // purpose SET OF INTEGER
			var set []int
			if _, err := asn1.UnmarshalWithParams(f.Bytes, &set, "set"); err != nil {
				return al, err
			}
			for _, p := range set {
				al.purposes[p] = true
			}
		case 503: // noAuthRequired NULL
			al.noAuthRequired = true
		case 504: // userAuthType
			var n *big.Int
			if err := one(&n); err != nil {
				return al, err
			}
			al.userAuthType = int(n.Int64())
		case 505: // authTimeout
			if err := one(&al.authTimeout); err != nil {
				return al, err
			}
			al.hasAuthTimeout = true
		case 702: // origin
			if err := one(&al.origin); err != nil {
				return al, err
			}
			al.hasOrigin = true
		case 704: // rootOfTrust
			var r rootOfTrust
			if err := one(&r); err != nil {
				return al, err
			}
			al.rootOfTrust = &r
		case 706: // osPatchLevel YYYYMM
			if err := one(&al.osPatchLevel); err != nil {
				return al, err
			}
		}
	}
	return al, nil
}

func securityLevelName(l asn1.Enumerated) string {
	switch l {
	case securityStrongBox:
		return "StrongBox"
	case securityTEE:
		return "TEE"
	}
	return "Software"
}

func bootStateName(s asn1.Enumerated) string {
	switch s {
	case 0:
		return "verified"
	case 1:
		return "self-signed"
	case 2:
		return "unverified"
	}
	return "failed"
}

func unlockMethods(t int) string {
	switch {
	case t&authFingerprint != 0 && t&authPassword != 0:
		return "fingerprint/face or PIN"
	case t&authFingerprint != 0:
		return "fingerprint/face"
	case t&authPassword != 0:
		return "PIN"
	}
	return ""
}

func equalBytes(a, b []byte) bool { return len(a) == len(b) && string(a) == string(b) }
