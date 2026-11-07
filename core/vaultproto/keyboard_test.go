package vaultproto

import (
	"testing"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/core/attest/attesttest"
)

// The seed opens in the TPM for the release key alone, and makes the layout the vault shows.
func TestWrapKeyboard(t *testing.T) {
	s, err := attesttest.NewSoftTPM()
	if err != nil {
		t.Fatal(err)
	}
	_, name, err := s.ReleaseKey(s.SigningPub, s.PolicyRef)
	if err != nil {
		t.Fatal(err)
	}
	w, layout, err := WrapKeyboard(nil, s.EKPub, name)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := s.ActivateCredentialFor(name, w.Credential, w.EncryptedSecret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := attest.KeyboardLayoutOf(seed)
	if err != nil || got.String() != layout.String() {
		t.Fatalf("the TPM's layout %v is not the one shown %v: %v", got, layout, err)
	}
	if _, err := s.ActivateCredentialFor(s.AKName, w.Credential, w.EncryptedSecret); err == nil {
		t.Error("the seed opened for another object than the release key")
	}
	w2, layout2, err := WrapKeyboard(nil, s.EKPub, name)
	if err != nil || layout2.String() == layout.String() || string(w2.Credential) == string(w.Credential) {
		t.Fatal("two releases, the same layout")
	}
}
