package vaultproto

import (
	"io"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
)

// A pepper typed through the vault's one-time keyboard (attest/keyboard.go). A device enrolled
// with Keyboard gets, with every release of R, a seed drawn for this boot alone and wrapped for its
// TPM and the slot's release key, so it opens where R opens and nowhere else. The vault shows the
// layout the seed stands for to an operator (CLI, REST) and forgets it shortly after; the pepper
// itself never reaches the vault.

// WrapKeyboard draws a boot's seed and wraps it for the TPM whose EK is ekPublic and the release
// key named releaseKeyName. It returns the layout to show; the seed is wiped.
func WrapKeyboard(rng io.Reader, ekPublic, releaseKeyName []byte) (*Wrapped, *attest.KeyboardLayout, error) {
	seed, err := attest.NewKeyboardSeed(rng)
	if err != nil {
		return nil, nil, err
	}
	defer clear(seed)
	layout, err := attest.KeyboardLayoutOf(seed)
	if err != nil {
		return nil, nil, err
	}
	cred, enc, err := attest.MakeCredential(rng, ekPublic, releaseKeyName, seed)
	if err != nil {
		layout.Wipe()
		return nil, nil, err
	}
	return &Wrapped{Credential: cred, EncryptedSecret: enc}, layout, nil
}
