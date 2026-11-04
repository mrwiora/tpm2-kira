package vaultproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/mrwiora/tpm2-kira/core/attest"
)

// WrappedPepper is the operator's pepper as a release carries it, so that
// it opens where R opens and nowhere else: a fresh key K, wrapped like R
// (TPM2_MakeCredential for the machine's EK and the slot's release key),
// and the pepper encrypted under K. Only the machine's TPM recovers K, and
// only in a boot the slot's signing key approved; the pepper does not rely
// on the connection to the vault.
type WrappedPepper struct {
	Key        Wrapped `json:"key"`        // K, SecretSize bytes, wrapped for the TPM
	Ciphertext []byte  `json:"ciphertext"` // nonce ‖ AES-256-GCM(K, pepper)
}

// pepperAAD binds the ciphertext to its purpose; the device ID follows.
const pepperAAD = "tpm2-kira/vault/pepper/v1"

// WrapPepper wraps pepper for the TPM whose EK is ekPublic (TPMT_PUBLIC)
// and the release key named releaseKeyName, for the device deviceID.
func WrapPepper(rng io.Reader, ekPublic, releaseKeyName, deviceID, pepper []byte) (*WrappedPepper, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if len(pepper) == 0 || len(pepper) > MaxPepper {
		return nil, fmt.Errorf("a pepper is 1 to %d bytes, not %d", MaxPepper, len(pepper))
	}
	k := make([]byte, SecretSize)
	defer clear(k)
	if _, err := io.ReadFull(rng, k); err != nil {
		return nil, err
	}
	cred, enc, err := attest.MakeCredential(rng, ekPublic, releaseKeyName, k)
	if err != nil {
		return nil, err
	}
	aead, err := pepperAEAD(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rng, nonce); err != nil {
		return nil, err
	}
	return &WrappedPepper{
		Key:        Wrapped{Credential: cred, EncryptedSecret: enc},
		Ciphertext: aead.Seal(nonce, nonce, pepper, pepperAD(deviceID)),
	}, nil
}

// OpenPepper decrypts the pepper with K, once the TPM opened w.Key. The
// caller wipes the result.
func OpenPepper(k, deviceID []byte, w *WrappedPepper) ([]byte, error) {
	if w == nil {
		return nil, errors.New("no pepper")
	}
	if len(k) != SecretSize {
		return nil, fmt.Errorf("the pepper's key is %d bytes, not %d", len(k), SecretSize)
	}
	aead, err := pepperAEAD(k)
	if err != nil {
		return nil, err
	}
	if len(w.Ciphertext) < aead.NonceSize()+aead.Overhead()+1 {
		return nil, errors.New("the wrapped pepper is too short")
	}
	n := aead.NonceSize()
	pepper, err := aead.Open(nil, w.Ciphertext[:n], w.Ciphertext[n:], pepperAD(deviceID))
	if err != nil {
		return nil, errors.New("the pepper does not decrypt: not for this device, or altered")
	}
	return pepper, nil
}

func pepperAEAD(k []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func pepperAD(deviceID []byte) []byte {
	return append([]byte(pepperAAD), deviceID...)
}
