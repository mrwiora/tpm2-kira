package attest_test

import (
	"bytes"
	"testing"

	. "github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/core/attest/attesttest"
)

// keyboardBackend is the soft TPM with a release key: it offers a salt to keep when one is set, and
// opens what the phone releases as the machine's TPM does.
type keyboardBackend struct {
	*attesttest.SoftTPM
	keep    *KeyboardKeep
	name    []byte
	pad     []byte
	refuse  bool
	kinds   []uint8
	keeping bool
}

func (b *keyboardBackend) FactorToKeep() *FactorBlob     { return nil }
func (b *keyboardBackend) KeyboardToKeep() *KeyboardKeep { return b.keep }
func (b *keyboardBackend) TakeRelease(r *Release) (uint8, string) {
	b.kinds = append(b.kinds, r.Kind)
	if b.keeping {
		return ReleaseOK, "kept"
	}
	if b.refuse {
		return ReleaseTPMRefused, "the TPM refused"
	}
	secret, err := b.ActivateCredentialFor(b.name, r.CredentialBlob, r.EncryptedSecret)
	if err != nil {
		return ReleaseTPMRefused, err.Error()
	}
	if b.pad, err = KeyboardPadFrom(secret, 8); err != nil {
		return ReleaseTPMRefused, err.Error()
	}
	return ReleaseOK, "opened"
}

func newKeyboardBackend(t *testing.T, m *attesttest.Machine, salt []byte) *keyboardBackend {
	t.Helper()
	public, name, err := m.TPM.ReleaseKey(m.TPM.SigningPub, m.TPM.PolicyRef)
	if err != nil {
		t.Fatal(err)
	}
	return &keyboardBackend{SoftTPM: m.TPM, name: name, keeping: true, keep: &KeyboardKeep{
		Salt: salt, ReleaseKeyPublic: public, SigningPublic: m.TPM.SigningPub, PolicyRef: m.TPM.PolicyRef, Label: "luks",
	}}
}

// Handed over on the booted system; at every boot after it the phone releases a pad wrapped for the
// TPM, and shows the keys. Keys and pad make the salt, and they differ from boot to boot.
func TestPhoneKeyboard(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	m.TPM.SetSecureBoot(SecureBootOn)
	rec := enrol(t, m, p)
	salt := []byte("abcd2345")
	be := newKeyboardBackend(t, m, salt)
	m.TPM.ResetCount++
	attestWithFactor(t, m, p, rec, be)
	if ev := p.Last(EvKeyboardKeys); ev != nil {
		t.Fatalf("keys in the session that handed the salt over: %+v", ev)
	}
	updated := p.Last(EvRecordUpdated)
	if updated == nil || !updated.Record.HasKeyboard() || !bytes.Equal(updated.Record.Keyboard.Salt, salt) || updated.Record.HasFactor() {
		t.Fatalf("the phone keeps no salt: %+v", updated)
	}
	if len(be.kinds) != 1 || be.kinds[0] != ReleaseKindKeyboard {
		t.Fatalf("released in the hand-over: %v", be.kinds)
	}
	rec = updated.Record
	be.keep, be.keeping = nil, false

	var seen [][]byte
	for boot := 0; boot < 2; boot++ {
		m.TPM.ResetCount++
		p.Events = nil
		attestWithFactor(t, m, p, rec, be)
		ev := p.Last(EvKeyboardKeys)
		if ev == nil || len(ev.Keys) != len(salt) {
			t.Fatalf("no keys to press: %+v", ev)
		}
		got, err := KeyboardSaltOf([]byte(ev.Keys), be.pad)
		if err != nil || !bytes.Equal(got, salt) {
			t.Fatalf("keys %s and pad %v make %s, %v", ev.Keys, be.pad, got, err)
		}
		seen = append(seen, []byte(ev.Keys))
		rec = p.Last(EvRecordUpdated).Record
	}
	if bytes.Equal(seen[0], seen[1]) {
		t.Fatalf("the same keys in two boots: %s", seen[0])
	}
}

// A TPM that refuses the pad shows no keys: they would open nothing.
func TestPhoneKeyboardNoKeysWithoutThePad(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	m.TPM.SetSecureBoot(SecureBootOn)
	rec := enrol(t, m, p)
	be := newKeyboardBackend(t, m, []byte("abcd2345"))
	m.TPM.ResetCount++
	attestWithFactor(t, m, p, rec, be)
	rec = p.Last(EvRecordUpdated).Record
	be.keep, be.keeping, be.refuse = nil, false, true
	m.TPM.ResetCount++
	p.Events = nil
	attestWithFactor(t, m, p, rec, be)
	if ev := p.Last(EvKeyboardKeys); ev != nil {
		t.Fatalf("keys for a pad the TPM refused: %+v", ev)
	}
}

// A salt handed over replaces a factor kept before, and the other way round: one salt per record.
func TestPhoneKeyboardReplacesTheFactor(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	m.TPM.SetSecureBoot(SecureBootOn)
	rec := enrol(t, m, p)
	f := &factorBackend{SoftTPM: m.TPM, status: ReleaseOK, keep: &FactorBlob{CredentialBlob: []byte("c"), EncryptedSecret: []byte("s"), Label: "luks"}}
	m.TPM.ResetCount++
	attestWithFactor(t, m, p, rec, f)
	rec = p.Last(EvRecordUpdated).Record
	if !rec.HasFactor() {
		t.Fatal("no factor kept")
	}
	be := newKeyboardBackend(t, m, []byte("abcd2345"))
	m.TPM.ResetCount++
	p.Events = nil
	attestWithFactor(t, m, p, rec, be)
	rec = p.Last(EvRecordUpdated).Record
	if rec.HasFactor() || !rec.HasKeyboard() {
		t.Fatalf("%+v", rec)
	}
}

// The phone refuses a salt whose release key is not under the signing key it pinned, or that is no
// salt: a machine cannot have the pad wrapped for a key of its choosing.
func TestPhoneKeyboardRefusesAnotherKey(t *testing.T) {
	for name, spoil := range map[string]func(*KeyboardKeep){
		"no salt": func(k *KeyboardKeep) { k.Salt = []byte("ABCDEFGH") },
		"another signing key": func(k *KeyboardKeep) {
			other, err := attesttest.NewSoftTPM()
			if err != nil {
				panic(err)
			}
			public, _, err := other.ReleaseKey(other.SigningPub, other.PolicyRef)
			if err != nil {
				panic(err)
			}
			k.SigningPublic, k.ReleaseKeyPublic, k.PolicyRef = other.SigningPub, public, other.PolicyRef
		},
		"not the release key": func(k *KeyboardKeep) { k.ReleaseKeyPublic = bytes.Clone(k.SigningPublic) },
	} {
		t.Run(name, func(t *testing.T) {
			m, p := newMachine(t), newPhone(t)
			m.TPM.SetSecureBoot(SecureBootOn)
			rec := enrol(t, m, p)
			be := newKeyboardBackend(t, m, []byte("abcd2345"))
			spoil(be.keep)
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
			if perr == nil {
				t.Fatal("the phone took it")
			}
		})
	}
}

// Over the wire, the salt and the keys of the hand-over travel in the evidence alone.
func TestKeyboardKeepOnTheWire(t *testing.T) {
	m := newMachine(t)
	keep := &KeyboardKeep{Salt: []byte("abcd2345"), ReleaseKeyPublic: []byte("r"), SigningPublic: []byte("s"), PolicyRef: []byte("p"), Label: "luks"}
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
	if got.KeyboardKeep == nil || !bytes.Equal(got.KeyboardKeep.Salt, keep.Salt) || got.KeyboardKeep.Label != "luks" || !bytes.Equal(got.KeyboardKeep.ReleaseKeyPublic, keep.ReleaseKeyPublic) {
		t.Fatalf("%+v", got.KeyboardKeep)
	}
}
