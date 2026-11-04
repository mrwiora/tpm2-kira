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
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func readChain(t *testing.T, dir string) []byte {
	var chain []byte
	for i := 0; i < 4; i++ {
		b, err := os.ReadFile(fmt.Sprintf("testdata/keyattest/%s/cert%d.der", dir, i))
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, b...)
	}
	return chain
}

func leafKey(t *testing.T, chain []byte) []byte {
	ders, _ := SplitDERChain(chain)
	c, err := x509.ParseCertificate(ders[0])
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(c.PublicKey)
	return pub
}

func TestPhoneRootsManifest(t *testing.T) {
	roots := loadPhoneRoots()
	if len(phoneRootErrs) > 0 {
		t.Fatal(phoneRootErrs)
	}
	if !slices.Equal(PhoneRootNames(), []string{"Google"}) || len(roots[0].roots) != 2 {
		t.Fatalf("phone roots: %v", PhoneRootNames())
	}
	files, _ := fs.Glob(phoneRootFS, "phoneroots/*/*.der")
	if len(files) != 2 {
		t.Fatalf("unpinned files? %v", files)
	}
}

// Real attestation chains from Google's android-key-attestation test data
// (testdata/keyattest, Apache-2.0). They come from development devices, so
// they are expected to fail the device checks, which they must report.
func TestRealAttestationChains(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

	tee := readChain(t, "google-ec-tee")
	a := VerifyPhoneAttestation(tee, leafKey(t, tee), []byte("abc"), now)
	if a.Root != "Google" || a.SecurityLevel != "TEE" || a.PatchLevel != "2019-07" {
		t.Fatalf("TEE chain: %+v", a)
	}
	for _, want := range []string{"without unlocking", "bootloader is unlocked", "did not boot a verified system"} {
		if !slices.ContainsFunc(a.Problems, func(p string) bool { return strings.Contains(p, want) }) {
			t.Errorf("TEE chain: missing %q in %v", want, a.Problems)
		}
	}
	if a.Verified {
		t.Fatal("development device verified")
	}
	if b := VerifyPhoneAttestation(tee, leafKey(t, tee), []byte("other"), now); !slices.Contains(b.Problems, "the key attestation was not made for this enrolment") {
		t.Fatalf("wrong challenge accepted: %v", b.Problems)
	}

	sb := readChain(t, "google-ec-strongbox-preprod")
	c := VerifyPhoneAttestation(sb, leafKey(t, sb), []byte("abc"), now)
	if c.Root != "" || c.SecurityLevel != "StrongBox" || !strings.Contains(c.Problems[0], "not signed by a known attestation root") {
		t.Fatalf("pre-production root accepted: %+v", c)
	}
}

// ---- synthetic attestations, for the paths no public chain covers ----

func explicit(tag int, v any) asn1.RawValue {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: b}
}

type authOpts struct {
	userAuth  int
	timeout   int // -1: absent
	noAuth    bool
	origin    int
	locked    bool
	bootState int
	level     int
}

func goodAuth() authOpts {
	return authOpts{userAuth: authFingerprint | authPassword, timeout: -1, locked: true, level: securityStrongBox}
}

func keyDescriptionExt(challenge []byte, o authOpts) []byte {
	var hw []asn1.RawValue
	set, _ := asn1.MarshalWithParams([]int{purposeSign}, "set")
	hw = append(hw, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: set})
	if o.noAuth {
		hw = append(hw, explicit(503, asn1.NullRawValue))
	}
	if o.userAuth != 0 {
		hw = append(hw, explicit(504, o.userAuth))
	}
	if o.timeout >= 0 {
		hw = append(hw, explicit(505, o.timeout))
	}
	hw = append(hw, explicit(702, o.origin))
	hw = append(hw, explicit(704, rootOfTrust{VerifiedBootKey: make([]byte, 32), DeviceLocked: o.locked, VerifiedBootState: asn1.Enumerated(o.bootState), VerifiedBootHash: make([]byte, 32)}))
	hw = append(hw, explicit(706, 202609))
	var hwBytes []byte
	for _, f := range hw {
		b, _ := asn1.Marshal(f)
		hwBytes = append(hwBytes, b...)
	}
	kd := keyDescriptionASN1{
		AttestationVersion: 300, AttestationSecurityLevel: asn1.Enumerated(o.level),
		KeyMintVersion: 300, KeyMintSecurityLevel: asn1.Enumerated(o.level),
		AttestationChallenge: challenge, UniqueID: []byte{},
		SoftwareEnforced: asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: []byte{}},
		HardwareEnforced: asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: hwBytes},
	}
	b, err := asn1.Marshal(kd)
	if err != nil {
		panic(err)
	}
	return b
}

// attestation builds root -> intermediate -> leaf for anchor, like a phone's.
func attestation(t *testing.T, anchor *ecdsa.PrivateKey, challenge []byte, o authOpts) (chain []byte, roots []*trustVendor) {
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := func(n int64, cn string) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign}
	}
	rootT := ca(1, "Test attestation root")
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootT, rootT, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	interT := ca(2, "Test StrongBox")
	interDER, _ := x509.CreateCertificate(rand.Reader, interT, root, &interKey.PublicKey, rootKey)
	inter, _ := x509.ParseCertificate(interDER)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidKeyAttestation, Value: keyDescriptionExt(challenge, o)}}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafT, inter, &anchor.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	chain = append(append(append([]byte(nil), leafDER...), interDER...), rootDER...)
	return chain, []*trustVendor{{Name: "Test", roots: [][]byte{rootDER}}}
}

func TestPhoneAttestationChecks(t *testing.T) {
	anchor, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	anchorPub, _ := x509.MarshalPKIXPublicKey(&anchor.PublicKey)
	ch := AnchorAttestationChallenge(make([]byte, 32))
	now := time.Now()
	check := func(o authOpts) PhoneAttestation {
		chain, roots := attestation(t, anchor, ch, o)
		return verifyPhoneAttestationWith(chain, anchorPub, ch, roots, now)
	}

	a := check(goodAuth())
	if !a.Verified || a.Root != "Test" || a.Summary() != "StrongBox, unlock by fingerprint/face or PIN for every use, locked bootloader, verified boot, patch level 2026-09" {
		t.Fatalf("a correct attestation: %+v\n%s", a, a.Summary())
	}
	bio := goodAuth()
	bio.userAuth = authFingerprint
	if a := check(bio); !a.Verified || a.Unlock != "fingerprint/face" {
		t.Fatalf("biometric-only key: %+v", a)
	}

	cases := []struct {
		name string
		mod  func(*authOpts)
		want string
	}{
		{"software keystore", func(o *authOpts) { o.level = securitySoftware }, "not in secure hardware"},
		{"imported key", func(o *authOpts) { o.origin = 2 }, "not generated inside"},
		{"no unlock", func(o *authOpts) { o.userAuth = 0; o.noAuth = true }, "without unlocking"},
		{"unlock window", func(o *authOpts) { o.timeout = 30 }, "30 seconds"},
		{"unlocked bootloader", func(o *authOpts) { o.locked = false }, "bootloader is unlocked"},
		{"custom ROM", func(o *authOpts) { o.bootState = 1 }, "self-signed"},
	}
	for _, c := range cases {
		o := goodAuth()
		c.mod(&o)
		a := check(o)
		if a.Verified || !slices.ContainsFunc(a.Problems, func(p string) bool { return strings.Contains(p, c.want) }) {
			t.Errorf("%s: %+v", c.name, a.Problems)
		}
	}

	// A chain for another key, or for another session, is not this phone's.
	chain, roots := attestation(t, anchor, ch, goodAuth())
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherPub, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if a := verifyPhoneAttestationWith(chain, otherPub, ch, roots, now); a.Verified || !strings.Contains(a.Problems[0], "different key") {
		t.Fatalf("other key: %v", a.Problems)
	}
	if a := verifyPhoneAttestationWith(chain, anchorPub, AnchorAttestationChallenge([]byte{1}), roots, now); a.Verified {
		t.Fatal("attestation of another session accepted")
	}
	if a := verifyPhoneAttestationWith(chain, anchorPub, ch, loadPhoneRoots(), now); a.Verified || a.Root != "" {
		t.Fatal("test root accepted as Google")
	}
	if a := VerifyPhoneAttestation(nil, anchorPub, ch, now); a.Verified || !strings.Contains(a.Problems[0], "no key attestation") {
		t.Fatalf("no attestation: %v", a.Problems)
	}
}

func TestAnchorAttestationChallengeVector(t *testing.T) {
	cb := make([]byte, 32)
	for i := range cb {
		cb[i] = byte(i)
	}
	h := sha256.Sum256(append([]byte("tpm2-kira/anchor-attest/v1"), cb...))
	if got := AnchorAttestationChallenge(cb); hex.EncodeToString(got) != hex.EncodeToString(h[:]) {
		t.Fatal("challenge")
	}
}
