package vaultproto

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// releaseKey is the machine's release key for its slot.
func (m *machine) releaseKey(t *testing.T) (public, name []byte) {
	t.Helper()
	public, name, err := m.tpm.ReleaseKey(m.dev.SigningPublic, m.dev.PolicyRef)
	if err != nil {
		t.Fatal(err)
	}
	return public, name
}

// The vault takes a release key only when it is the slot's: made under the
// slot's policy, fixedTPM, with a P-256 point.
func TestReleaseKeyNameChecksTheSlot(t *testing.T) {
	m := newMachine(t)
	public, name := m.releaseKey(t)
	req := &EnrolRequest{ReleaseKeyPublic: public, SigningPublic: m.dev.SigningPublic, PolicyRef: m.dev.PolicyRef}
	got, err := req.ReleaseKeyName()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, name) {
		t.Fatalf("Name %x, want %x", got, name)
	}

	other := *req
	other.PolicyRef = bytes.Repeat([]byte{0x11}, 16)
	if _, err := other.ReleaseKeyName(); err == nil {
		t.Fatal("a release key of another slot's policy was taken")
	}

	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](public)
	if err != nil {
		t.Fatal(err)
	}
	for what, change := range map[string]func(p *tpm2.TPMTPublic){
		"not fixedTPM":   func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedTPM = false },
		"userWithAuth":   func(p *tpm2.TPMTPublic) { p.ObjectAttributes.UserWithAuth = true },
		"another policy": func(p *tpm2.TPMTPublic) { p.AuthPolicy.Buffer = bytes.Repeat([]byte{3}, 32) },
		"not a point": func(p *tpm2.TPMTPublic) {
			p.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: bytes.Repeat([]byte{1}, 32)},
				Y: tpm2.TPM2BECCParameter{Buffer: bytes.Repeat([]byte{2}, 32)},
			})
		},
	} {
		p := *pub
		change(&p)
		bad := *req
		bad.ReleaseKeyPublic = tpm2.Marshal(p)
		if _, err := bad.ReleaseKeyName(); err == nil {
			t.Errorf("%s: taken", what)
		}
	}
	trailing := *req
	trailing.ReleaseKeyPublic = append(append([]byte(nil), public...), 0)
	if _, err := trailing.ReleaseKeyName(); err == nil {
		t.Error("a public area with trailing bytes was taken")
	}
}

// The pepper opens with K, which only the machine's TPM opens with its
// release key loaded - for this device, unaltered.
func TestPepperOpensOnlyWithTheReleaseKey(t *testing.T) {
	m := newMachine(t)
	_, name := m.releaseKey(t)
	pepper := []byte("from the operator")
	w, err := WrapPepper(rand.Reader, m.tpm.EKPub, name, m.dev.DeviceID, pepper)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(w.Ciphertext, pepper) {
		t.Fatal("the pepper is in the clear")
	}
	k, err := m.tpm.ActivateCredentialFor(name, w.Key.Credential, w.Key.EncryptedSecret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenPepper(k, m.dev.DeviceID, w)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pepper) {
		t.Fatalf("opened %q", got)
	}

	if _, err := m.tpm.ActivateCredentialFor(m.tpm.AKName, w.Key.Credential, w.Key.EncryptedSecret); err == nil {
		t.Error("K opened with another object than the release key")
	}
	if _, err := OpenPepper(k, bytes.Repeat([]byte{2}, DeviceIDSize), w); err == nil {
		t.Error("the pepper opened for another device")
	}
	altered := *w
	altered.Ciphertext = append([]byte(nil), w.Ciphertext...)
	altered.Ciphertext[len(altered.Ciphertext)-1] ^= 1
	if _, err := OpenPepper(k, m.dev.DeviceID, &altered); err == nil {
		t.Error("an altered pepper opened")
	}
	for _, p := range [][]byte{nil, bytes.Repeat([]byte{1}, MaxPepper+1)} {
		if _, err := WrapPepper(rand.Reader, m.tpm.EKPub, name, m.dev.DeviceID, p); err == nil || !strings.Contains(err.Error(), "pepper") {
			t.Errorf("a pepper of %d bytes was wrapped: %v", len(p), err)
		}
	}
}

// The release modes are numbers; their words are for people.
func TestReleaseModes(t *testing.T) {
	for _, m := range []ReleaseMode{ModeAuto, ModeApprove} {
		if err := m.Check(); err != nil {
			t.Errorf("%s: %v", m, err)
		}
		if back, err := ParseReleaseMode(m.String()); err != nil || back != m {
			t.Errorf("%s: %v %v", m, back, err)
		}
	}
	if ModeAuto != 0x01 || ModeApprove != 0x02 {
		t.Fatal("the release modes' numbers moved")
	}
	for _, m := range []ReleaseMode{0, 3, 0xff} {
		if m.Check() == nil {
			t.Errorf("%#02x is a release mode", uint8(m))
		}
	}
	if _, err := ParseReleaseMode("sometimes"); err == nil {
		t.Error("sometimes is a release mode")
	}
}
