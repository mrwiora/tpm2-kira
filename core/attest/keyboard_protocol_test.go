package attest_test

import (
	"bytes"
	"testing"

	. "github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/core/attest/attesttest"
)

// keyboardBackend is the soft TPM with a release key: in the hand-over it offers a phone salt and
// a keyboard to keep, and at a boot it opens the seed the phone releases as the machine's TPM does.
type keyboardBackend struct {
	*attesttest.SoftTPM
	keep     *KeyboardKeep
	factor   *FactorBlob
	name     []byte
	layout   *KeyboardLayout
	refuse   bool
	releases []*Release
	keeping  bool
}

func (b *keyboardBackend) FactorToKeep() *FactorBlob {
	if b.keeping {
		return b.factor
	}
	return nil
}
func (b *keyboardBackend) KeyboardToKeep() *KeyboardKeep { return b.keep }
func (b *keyboardBackend) TakeRelease(r *Release) (uint8, string) {
	b.releases = append(b.releases, r)
	if b.keeping {
		return ReleaseOK, "kept"
	}
	if b.refuse {
		return ReleaseTPMRefused, "the TPM refused"
	}
	if r.KeyboardCredential == nil {
		return ReleaseOK, "no keyboard"
	}
	seed, err := b.ActivateCredentialFor(b.name, r.KeyboardCredential, r.KeyboardSecret)
	if err != nil {
		return ReleaseTPMRefused, err.Error()
	}
	if b.layout, err = KeyboardLayoutOf(seed); err != nil {
		return ReleaseTPMRefused, err.Error()
	}
	return ReleaseOK, "opened"
}

func newKeyboardBackend(t *testing.T, m *attesttest.Machine) *keyboardBackend {
	t.Helper()
	public, name, err := m.TPM.ReleaseKey(m.TPM.SigningPub, m.TPM.PolicyRef)
	if err != nil {
		t.Fatal(err)
	}
	return &keyboardBackend{SoftTPM: m.TPM, name: name, keeping: true,
		factor: &FactorBlob{CredentialBlob: []byte("c"), EncryptedSecret: []byte("s"), Label: "luks"},
		keep:   &KeyboardKeep{ReleaseKeyPublic: public, SigningPublic: m.TPM.SigningPub, PolicyRef: m.TPM.PolicyRef}}
}

// handOver keeps a phone salt with a keyboard on the phone, and returns the record.
func handOver(t *testing.T, m *attesttest.Machine, p *attesttest.Phone, rec *MachineRecord, be *keyboardBackend) *MachineRecord {
	t.Helper()
	m.TPM.ResetCount++
	attestWithFactor(t, m, p, rec, be)
	if ev := p.Last(EvKeyboardLayout); ev != nil {
		t.Fatalf("a layout in the session that handed the salt over: %+v", ev)
	}
	updated := p.Last(EvRecordUpdated)
	if updated == nil || !updated.Record.HasKeyboard() || !updated.Record.HasFactor() {
		t.Fatalf("the phone keeps no keyboard: %+v", updated)
	}
	be.keep, be.keeping = nil, false
	be.releases = nil
	return updated.Record
}

// Handed over on the booted system; at every boot after it the phone releases the phone salt with
// a seed wrapped for the TPM, in one release, and shows the layout. Layout and machine agree, and
// the layout differs from boot to boot.
func TestPhoneKeyboard(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	m.TPM.SetSecureBoot(SecureBootOn)
	rec := enrol(t, m, p)
	be := newKeyboardBackend(t, m)
	rec = handOver(t, m, p, rec, be)

	var seen []string
	for boot := 0; boot < 2; boot++ {
		m.TPM.ResetCount++
		p.Events = nil
		attestWithFactor(t, m, p, rec, be)
		if len(be.releases) != boot+1 || be.releases[boot].Kind != ReleaseKindFactor || !bytes.Equal(be.releases[boot].CredentialBlob, []byte("c")) {
			t.Fatalf("released: %+v", be.releases)
		}
		ev := p.Last(EvKeyboardLayout)
		if ev == nil || ev.KeyboardKeys != KeyboardKeys || ev.Layout != be.layout.String() {
			t.Fatalf("the layout shown is not the machine's: %+v, %s", ev, be.layout)
		}
		seen = append(seen, ev.Layout)
		rec = p.Last(EvRecordUpdated).Record
	}
	if seen[0] == seen[1] {
		t.Fatalf("the same layout in two boots: %s", seen[0])
	}
}

// A TPM that refuses the seed shows no layout: it would open nothing.
func TestPhoneKeyboardNoLayoutWithoutTheSeed(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	m.TPM.SetSecureBoot(SecureBootOn)
	rec := enrol(t, m, p)
	be := newKeyboardBackend(t, m)
	rec = handOver(t, m, p, rec, be)
	be.refuse = true
	m.TPM.ResetCount++
	p.Events = nil
	attestWithFactor(t, m, p, rec, be)
	if ev := p.Last(EvKeyboardLayout); ev != nil {
		t.Fatalf("a layout for a seed the TPM refused: %+v", ev)
	}
}

// A phone salt handed over without a keyboard drops the keyboard: the release then carries no seed.
func TestPhoneKeyboardGoesWithTheFactor(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	m.TPM.SetSecureBoot(SecureBootOn)
	rec := enrol(t, m, p)
	be := newKeyboardBackend(t, m)
	rec = handOver(t, m, p, rec, be)
	f := &factorBackend{SoftTPM: m.TPM, status: ReleaseOK, keep: &FactorBlob{CredentialBlob: []byte("c2"), EncryptedSecret: []byte("s2"), Label: "luks"}}
	m.TPM.ResetCount++
	p.Events = nil
	attestWithFactor(t, m, p, rec, f)
	rec = p.Last(EvRecordUpdated).Record
	if !rec.HasFactor() || rec.HasKeyboard() {
		t.Fatalf("%+v", rec)
	}
	if f.released == nil || f.released.KeyboardCredential != nil {
		t.Fatalf("a seed without a keyboard: %+v", f.released)
	}
}

// The phone refuses a keyboard whose release key is not under the signing key it pinned, or one
// without a phone salt: a machine cannot have the seed wrapped for a key of its choosing.
func TestPhoneKeyboardRefusesAnotherKey(t *testing.T) {
	for name, spoil := range map[string]func(*keyboardBackend){
		"no phone salt": func(b *keyboardBackend) { b.factor = nil },
		"another signing key": func(b *keyboardBackend) {
			other, err := attesttest.NewSoftTPM()
			if err != nil {
				panic(err)
			}
			public, _, err := other.ReleaseKey(other.SigningPub, other.PolicyRef)
			if err != nil {
				panic(err)
			}
			b.keep.SigningPublic, b.keep.ReleaseKeyPublic, b.keep.PolicyRef = other.SigningPub, public, other.PolicyRef
		},
		"not the release key": func(b *keyboardBackend) { b.keep.ReleaseKeyPublic = bytes.Clone(b.keep.SigningPublic) },
	} {
		t.Run(name, func(t *testing.T) {
			m, p := newMachine(t), newPhone(t)
			m.TPM.SetSecureBoot(SecureBootOn)
			rec := enrol(t, m, p)
			be := newKeyboardBackend(t, m)
			spoil(be)
			m.TPM.ResetCount++
			a, b := attesttest.NewPipe()
			go func() {
				ServeAttestation(a, m.AttestIdentity(), be, nil)
				a.Close()
			}()
			v, err := NewAttestVerifier(p.Config(), rec)
			if err != nil {
				t.Fatal(err)
			}
			perr := p.Drive(v, b)
			b.Close()
			if name == "no phone salt" {
				// The machine sends no keyboard without a phone salt; the phone keeps none.
				if perr != nil || p.Last(EvRecordUpdated).Record.HasKeyboard() {
					t.Fatalf("%v", perr)
				}
				return
			}
			if perr == nil {
				t.Fatal("the phone took it")
			}
		})
	}
}

// Over the wire: the keyboard in the evidence, the seed beside the factor in the release.
func TestKeyboardOnTheWire(t *testing.T) {
	m := newMachine(t)
	keep := &KeyboardKeep{ReleaseKeyPublic: []byte("r"), SigningPublic: []byte("s"), PolicyRef: []byte("p")}
	ev := &Evidence{Schema: SchemaVersion, DeviceID: m.DeviceID, AKName: m.TPM.AKName, Quoted: []byte("q"), Signature: []byte("s"),
		PCRAlg: AlgSHA256, PCRValues: []PCRValue{{Index: 7, Digest: make([]byte, 32)}}, KeyboardKeep: keep}
	data, err := ev.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeEvidence(d)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyboardKeep == nil || !bytes.Equal(got.KeyboardKeep.ReleaseKeyPublic, keep.ReleaseKeyPublic) || !bytes.Equal(got.KeyboardKeep.PolicyRef, keep.PolicyRef) {
		t.Fatalf("%+v", got.KeyboardKeep)
	}

	r := &Release{Kind: ReleaseKindFactor, Slot: 1, CredentialBlob: []byte("c"), EncryptedSecret: []byte("e"), KeyboardCredential: []byte("kc"), KeyboardSecret: []byte("ks")}
	data, err = r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, _ = Decode(data)
	back, err := DecodeRelease(d)
	if err != nil || string(back.KeyboardCredential) != "kc" || string(back.KeyboardSecret) != "ks" {
		t.Fatalf("%+v %v", back, err)
	}
	r.KeyboardSecret = nil
	data, _ = r.Encode()
	d, _ = Decode(data)
	if _, err := DecodeRelease(d); err == nil {
		t.Fatal("a seed's credential without its secret was taken")
	}
}
