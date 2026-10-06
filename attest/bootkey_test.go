package attest_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"

	. "github.com/matthias/tpm2-kira/attest"
	"github.com/matthias/tpm2-kira/attest/attesttest"
)

const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func bootPair(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k, k.PublicKey().Bytes()
}

// The code reaches only who holds the boot key, for this session only.
func TestBootChallenge(t *testing.T) {
	machine, pub := bootPair(t)
	ctx := bytes.Repeat([]byte{7}, 32)
	ch, secret, err := NewBootChallenge(rand.Reader, pub, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret.Code) != BootCodeLen || strings.Trim(secret.Code, codeAlphabet) != "" {
		t.Fatalf("code %q", secret.Code)
	}
	if got := FormatBootCode(secret.Code); len(got) != BootCodeLen+1 || got[4] != '-' {
		t.Fatalf("formatted %q", got)
	}
	open := func(key *ecdh.PrivateKey, pub, ctx, sealed []byte) (string, []byte, error) {
		eph, err := ecdh.P256().NewPublicKey(ch.EphemeralPub)
		if err != nil {
			t.Fatal(err)
		}
		z, err := key.ECDH(eph)
		if err != nil {
			t.Fatal(err)
		}
		return OpenBootChallenge(z, ch.EphemeralPub, pub, ctx, sealed)
	}
	code, proof, err := open(machine, pub, ctx, ch.Sealed)
	if err != nil || code != secret.Code || !secret.Check(proof) {
		t.Fatalf("the machine did not recover the code: %q vs %q, %v", code, secret.Code, err)
	}

	// Another key, another session, altered data: no code, no proof.
	other, otherPub := bootPair(t)
	if _, _, err := open(other, pub, ctx, ch.Sealed); err == nil {
		t.Fatal("another key opened the challenge")
	}
	if _, _, err := open(machine, otherPub, ctx, ch.Sealed); err == nil {
		t.Fatal("the challenge opened under another public key")
	}
	if _, _, err := open(machine, pub, bytes.Repeat([]byte{8}, 32), ch.Sealed); err == nil {
		t.Fatal("the challenge opened in another session")
	}
	bad := append([]byte(nil), ch.Sealed...)
	bad[0] ^= 1
	if _, _, err := open(machine, pub, ctx, bad); err == nil {
		t.Fatal("an altered challenge opened")
	}
	for _, p := range [][]byte{nil, proof[:31], bytes.Repeat([]byte{0}, 32), append([]byte{proof[0] ^ 1}, proof[1:]...)} {
		if secret.Check(p) {
			t.Fatalf("accepted the proof %x", p)
		}
	}
	// Each challenge has its own key and code.
	ch2, secret2, _ := NewBootChallenge(rand.Reader, pub, ctx)
	if bytes.Equal(ch2.EphemeralPub, ch.EphemeralPub) || secret2.Check(proof) {
		t.Fatal("two challenges share a key")
	}
	if _, _, err := NewBootChallenge(rand.Reader, pub[:64], ctx); err == nil {
		t.Fatal("a malformed boot key was accepted")
	}
}

// At enrolment the phone pins the boot key only if the attestation key
// certifies it and it is the kind of key the scheme needs.
func TestCheckBootKey(t *testing.T) {
	tpm, err := attesttest.NewSoftTPM()
	if err != nil {
		t.Fatal(err)
	}
	akPub, err := ParseAKPublic(tpm.AKPub, tpm.AKName)
	if err != nil {
		t.Fatal(err)
	}
	qd := bytes.Repeat([]byte{3}, 32)
	pub, info, sig, err := tpm.BootKey(qd)
	if err != nil {
		t.Fatal(err)
	}
	point, err := CheckBootKey(akPub, pub, info, sig, qd)
	if err != nil || !bytes.Equal(point, tpm.BootPriv.PublicKey().Bytes()) {
		t.Fatalf("genuine boot key: %x %v", point, err)
	}

	if _, err := CheckBootKey(akPub, pub, info, sig, bytes.Repeat([]byte{4}, 32)); err == nil {
		t.Fatal("a certification from another session was accepted")
	}
	otherTPM, _ := attesttest.NewSoftTPM()
	otherAK, _ := ParseAKPublic(otherTPM.AKPub, otherTPM.AKName)
	if _, err := CheckBootKey(otherAK, pub, info, sig, qd); err == nil {
		t.Fatal("a certification by another TPM's attestation key was accepted")
	}
	// A key the attestation key did not certify (the certificate is for the
	// genuine one).
	if _, err := CheckBootKey(akPub, otherTPM.BootPub, info, sig, qd); err == nil {
		t.Fatal("another key was accepted under the genuine key's certification")
	}

	// Keys of the wrong kind, each certified properly.
	for name, change := range map[string]func(*tpm2.TPMTPublic){
		"usable with a password":  func(p *tpm2.TPMTPublic) { p.ObjectAttributes.UserWithAuth = true },
		"exportable":              func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedTPM = false },
		"imported, not generated": func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SensitiveDataOrigin = false },
		"also a signing key":      func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SignEncrypt = true },
		"without a policy":        func(p *tpm2.TPMTPublic) { p.AuthPolicy = tpm2.TPM2BDigest{} },
	} {
		tmpl, _ := tpm2.Unmarshal[tpm2.TPMTPublic](tpm.BootPub)
		change(tmpl)
		tpm.BootPub = tpm2.Marshal(*tmpl)
		p, i, s, err := tpm.BootKey(qd)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CheckBootKey(akPub, p, i, s, qd); err == nil {
			t.Errorf("a boot key that is %s was accepted", name)
		}
		tpm.BootPub = pub
	}
}

// A whole session: the phone shows the code the machine shows, and nothing
// is signed before the person says so.
func TestBootKeyInTheSession(t *testing.T) {
	m, err := attesttest.NewMachine()
	if err != nil {
		t.Fatal(err)
	}
	p, _ := attesttest.NewPhone()
	rec := enrol(t, m, p)
	if !bytes.Equal(rec.BootKeyPub, m.TPM.BootPriv.PublicKey().Bytes()) {
		t.Fatal("the phone did not pin the machine's boot key")
	}

	res, merr, perr := attestOnce(t, m, p, rec)
	if merr != nil || perr != nil {
		t.Fatalf("session: %v %v", merr, perr)
	}
	ve := p.Last(EvVerdict)
	if ve == nil || !ve.NeedsDecision {
		t.Fatalf("a matching boot was signed without asking: %+v", ve)
	}
	vd := ve.Verdict
	if vd.State != StateMatch || vd.BootKey != BootKeyResultProved || vd.Code != FormatBootCode(m.TPM.BootCode) || m.TPM.BootCode == "" {
		t.Fatalf("verdict %+v, machine shows %q", vd, m.TPM.BootCode)
	}
	if res.Check.Verdict != VerdictOK || !res.Check.Authentic {
		t.Fatalf("receipt: %+v", res.Check)
	}
	first := m.TPM.BootCode
	if _, merr, perr = attestOnce(t, m, p, rec); merr != nil || perr != nil || m.TPM.BootCode == first {
		t.Fatalf("the next session reused the code %q (%v %v)", first, merr, perr)
	}

	// The TPM refuses the key (the boot state is not an approved one): no
	// code, and the quote still says what the registers are.
	m.TPM.BootRefuse = true
	if _, merr, perr = attestOnce(t, m, p, rec); merr != nil || perr != nil {
		t.Fatalf("session with a refused key: %v %v", merr, perr)
	}
	vd = p.Last(EvVerdict).Verdict
	if vd.BootKey != BootKeyResultRefused || vd.Code != "" || vd.State != StateMatch {
		t.Fatalf("refused key: %+v", vd)
	}
	m.TPM.BootRefuse = false

	// A machine that claims a proof it cannot have: failed, whatever the
	// registers say.
	m.TPM.BootForge = true
	p.Decision = DecisionReject
	if _, _, perr = attestOnce(t, m, p, rec); perr != nil {
		t.Fatalf("phone: %v", perr)
	}
	vd = p.Last(EvVerdict).Verdict
	if vd.BootKey != BootKeyResultInvalid || vd.State != StateFailed || vd.OK || vd.Code != "" {
		t.Fatalf("forged proof: %+v", vd)
	}
}

// "Continue" is for a matching boot only; a changed one needs an approval.
func TestContinueNeedsAMatch(t *testing.T) {
	m, _ := attesttest.NewMachine()
	p, _ := attesttest.NewPhone()
	rec := enrol(t, m, p)
	m.TPM.Extend(4, "new kernel")
	p.Decision = DecisionContinue
	_, _, perr := attestOnce(t, m, p, rec)
	if perr == nil || !strings.Contains(perr.Error(), "needs an approval") {
		t.Fatalf("a changed boot was continued: %v", perr)
	}
}
