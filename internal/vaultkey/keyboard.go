package vaultkey

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/internal/diskkey"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/phonegate"
	"github.com/tpm2-trust/tpm2-kira/internal/wipe"
)

// KeyboardSession is the vault's one-time keyboard in this boot: the layout of the seed the vault
// released with the salt, opened in the TPM while the code screen held. It stays usable after the
// close: the pepper is mapped here, and reaches no one.
type KeyboardSession struct {
	layout *attest.KeyboardLayout
}

// From implements diskkey.KeyboardSession.
func (s *KeyboardSession) From() string { return "the vault" }

// Wipe clears the layout; the prompt that took the session calls it when done.
func (s *KeyboardSession) Wipe() { s.layout.Wipe() }

// copy is a session of its own for one prompt, which wipes it: a prompt asked again (Debian's
// tries=) takes another copy of the same layout.
func (s *KeyboardSession) copy() *KeyboardSession {
	l := *s.layout
	return &KeyboardSession{layout: &l}
}

// Pepper implements diskkey.KeyboardSession.
func (s *KeyboardSession) Pepper(typed []byte) ([]byte, error) {
	p, err := s.layout.Pepper(typed)
	if errors.Is(err, attest.ErrKeyboardPepper) {
		return nil, diskkey.ErrNotAPepper
	}
	return p, err
}

// OpenKeyboard asks the vault for the slot's salt and opens it with this boot's keyboard in the TPM,
// under the slot's approval: only this TPM, in a boot the signing key approved, before the close.
// The caller wipes the salt.
func OpenKeyboard(ctx context.Context, tpmDev transport.TPM, vs vaultSlot, say func(string)) ([]byte, *KeyboardSession, error) {
	v := &vs.Att.Vault
	c, err := NewClient(v.URL, v.Pin)
	if err != nil {
		return nil, nil, err
	}
	rsp, err := fetchRemoteRetrying(ctx, tpmDev, vs, c, say)
	if err != nil {
		return nil, nil, err
	}
	if rsp.Keyboard == nil {
		return nil, nil, errors.New("this keyslot takes a pepper typed through the vault's keyboard, and the vault released none")
	}
	seed, err := phonegate.UnwrapFactor(tpmDev, vs.Sealed, vs.Idx, vs.Att, &nvslot.WrappedFactor{Credential: rsp.Keyboard.Credential, EncryptedSecret: rsp.Keyboard.EncryptedSecret})
	if err != nil {
		return nil, nil, fmt.Errorf("the keyboard: %w", err)
	}
	layout, err := attest.KeyboardLayoutOf(seed)
	wipe.Bytes(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("the keyboard: %w", err)
	}
	salt, err := saltOf(tpmDev, vs, rsp)
	if err != nil {
		layout.Wipe()
		return nil, nil, err
	}
	return salt, &KeyboardSession{layout: layout}, nil
}
