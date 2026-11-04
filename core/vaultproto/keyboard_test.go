package vaultproto

import (
	"bytes"
	"testing"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/core/attest/attesttest"
)

func TestWrapKeyboard(t *testing.T) {
	s, err := attesttest.NewSoftTPM()
	if err != nil {
		t.Fatal(err)
	}
	_, name, err := s.ReleaseKey(s.SigningPub, s.PolicyRef)
	if err != nil {
		t.Fatal(err)
	}
	device := bytes.Repeat([]byte{1}, DeviceIDSize)
	pad, err := attest.NewKeyboardPad(nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	w, k, err := WrapKeyboard(nil, s.EKPub, name, device, pad)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := s.ActivateCredentialFor(name, w.Key.Credential, w.Key.EncryptedSecret)
	if err != nil || !bytes.Equal(opened, k) {
		t.Fatalf("the TPM opened %x, %v", opened, err)
	}
	got, err := OpenKeyboardPad(k, device, w)
	if err != nil || !bytes.Equal(got, pad) {
		t.Fatalf("%v, %v", got, err)
	}
	if _, err := OpenKeyboardPad(k, bytes.Repeat([]byte{2}, DeviceIDSize), w); err == nil {
		t.Error("the pad opened for another device")
	}
	wrongKey := bytes.Repeat([]byte{9}, SecretSize)
	if _, err := OpenKeyboardPad(wrongKey, device, w); err == nil {
		t.Error("the pad opened with another key")
	}
	if _, err := s.ActivateCredentialFor(s.AKName, w.Key.Credential, w.Key.EncryptedSecret); err == nil {
		t.Error("K opened for another object than the release key")
	}

	ct, err := SealKeyboardPepper(nil, k, device, []byte("pepper"))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := OpenKeyboardPepper(k, device, ct); err != nil || string(p) != "pepper" {
		t.Fatalf("%q, %v", p, err)
	}
	// Under the same key a pad is no pepper and a pepper no pad.
	if _, err := OpenKeyboardPepper(k, device, w.Ciphertext); err == nil {
		t.Error("the pad opened as a pepper")
	}
	if _, err := OpenKeyboardPad(k, device, &WrappedPepper{Ciphertext: ct}); err == nil {
		t.Error("the pepper opened as a pad")
	}
}

func TestKeyboardProof(t *testing.T) {
	k := bytes.Repeat([]byte{7}, SecretSize)
	p := KeyboardProof(k, "request", []byte("abcd2345"))
	if !CheckKeyboardProof(k, "request", []byte("abcd2345"), p) {
		t.Error("the right keys are refused")
	}
	if !CheckKeyboardProof(k, "request", []byte("ABCD2345"), p) {
		t.Error("capitals are other keys")
	}
	for name, ok := range map[string]bool{
		"other keys":    CheckKeyboardProof(k, "request", []byte("abcd2346"), p),
		"other request": CheckKeyboardProof(k, "other", []byte("abcd2345"), p),
		"other key":     CheckKeyboardProof(bytes.Repeat([]byte{8}, SecretSize), "request", []byte("abcd2345"), p),
		"no proof":      CheckKeyboardProof(k, "request", []byte("abcd2345"), nil),
	} {
		if ok {
			t.Errorf("%s pass", name)
		}
	}
}
