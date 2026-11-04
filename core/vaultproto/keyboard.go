package vaultproto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
)

// A salt typed through a one-time keyboard, at the vault (attest/keyboard.go). The vault holds the
// salt and, after a good release check, answers StatusKeyboard: this boot's pad under a fresh key K
// wrapped for the TPM, so the pad opens where R opens and nowhere else. The keys to press are the
// operator's to read (CLI, REST). The machine opens K before the boot's close and keeps it: once the
// person has typed, it proves the keys with K (PathKeyboard), and a pepper comes back under K, since
// the TPM is closed by then.

// PathKeyboard takes the proof of the keys: KeyboardRequest → KeyboardResponse.
const PathKeyboard = "/v1/keyboard"

// StatusKeyboard says the person is to type the keys the vault shows.
const StatusKeyboard = "keyboard"

// StatusWrongKeys says the keys typed are not the ones shown; the request stays, a few times.
const StatusWrongKeys = "wrong_keys"

// KeyboardRequest proves the keys typed, for a request answered with StatusKeyboard.
type KeyboardRequest struct {
	RequestID string `json:"request_id"`
	DeviceID  []byte `json:"device_id"`
	Proof     []byte `json:"proof"` // KeyboardProof
}

// KeyboardResponse answers it: StatusReleased (with a pepper under K, for a device with one),
// StatusPending (the operator's pepper is awaited: the same request again), StatusWrongKeys or
// StatusDenied.
type KeyboardResponse struct {
	Status     string `json:"status"`
	Pepper     []byte `json:"pepper,omitempty"` // nonce ‖ AES-256-GCM(K, pepper)
	RetryAfter int    `json:"retry_after,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

const (
	keyboardPadAAD    = "tpm2-kira/vault/keyboard-pad/v1"
	keyboardPepperAAD = "tpm2-kira/vault/keyboard-pepper/v1"
	keyboardProofInfo = "tpm2-kira/vault/keyboard-proof/v1"
)

func keyboardAD(label string, deviceID []byte) []byte {
	return append([]byte(label), deviceID...)
}

// WrapKeyboard wraps this boot's pad for the TPM whose EK is ekPublic and the release key named
// releaseKeyName, under a fresh K, which it returns as well: the vault checks the proof with it and
// sends a pepper under it. The caller wipes K.
func WrapKeyboard(rng io.Reader, ekPublic, releaseKeyName, deviceID, pad []byte) (*WrappedPepper, []byte, error) {
	if rng == nil {
		rng = rand.Reader
	}
	k := make([]byte, SecretSize)
	if _, err := io.ReadFull(rng, k); err != nil {
		return nil, nil, err
	}
	cred, enc, err := attest.MakeCredential(rng, ekPublic, releaseKeyName, k)
	if err != nil {
		return nil, nil, err
	}
	ct, err := SealKeyboard(rng, k, keyboardPadAAD, deviceID, pad)
	if err != nil {
		return nil, nil, err
	}
	return &WrappedPepper{Key: Wrapped{Credential: cred, EncryptedSecret: enc}, Ciphertext: ct}, k, nil
}

// OpenKeyboardPad decrypts the pad with K, once the TPM opened w.Key.
func OpenKeyboardPad(k, deviceID []byte, w *WrappedPepper) ([]byte, error) {
	if w == nil {
		return nil, errors.New("no keyboard")
	}
	return openKeyboard(k, keyboardPadAAD, deviceID, w.Ciphertext)
}

// SealKeyboardPepper is the operator's pepper under K, for a release after the keys.
func SealKeyboardPepper(rng io.Reader, k, deviceID, pepper []byte) ([]byte, error) {
	if len(pepper) == 0 || len(pepper) > MaxPepper {
		return nil, fmt.Errorf("a pepper is 1 to %d bytes, not %d", MaxPepper, len(pepper))
	}
	return SealKeyboard(rng, k, keyboardPepperAAD, deviceID, pepper)
}

// OpenKeyboardPepper is the pepper a release after the keys brought.
func OpenKeyboardPepper(k, deviceID, ciphertext []byte) ([]byte, error) {
	return openKeyboard(k, keyboardPepperAAD, deviceID, ciphertext)
}

// SealKeyboard is plain under K, for a purpose and a device.
func SealKeyboard(rng io.Reader, k []byte, label string, deviceID, plain []byte) ([]byte, error) {
	if rng == nil {
		rng = rand.Reader
	}
	aead, err := pepperAEAD(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rng, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, keyboardAD(label, deviceID)), nil
}

func openKeyboard(k []byte, label string, deviceID, ciphertext []byte) ([]byte, error) {
	if len(k) != SecretSize {
		return nil, fmt.Errorf("the keyboard's key is %d bytes, not %d", len(k), SecretSize)
	}
	aead, err := pepperAEAD(k)
	if err != nil {
		return nil, err
	}
	n := aead.NonceSize()
	if len(ciphertext) < n+aead.Overhead()+1 {
		return nil, errors.New("the keyboard's message is too short")
	}
	plain, err := aead.Open(nil, ciphertext[:n], ciphertext[n:], keyboardAD(label, deviceID))
	if err != nil {
		return nil, errors.New("the keyboard's message does not decrypt: not for this device, or altered")
	}
	return plain, nil
}

// KeyboardProof is the machine's word on what was typed: only a holder of K can make it, so the keys
// travel nowhere. HMAC-SHA256(K, label ‖ request ID ‖ 0 ‖ keys), the keys as lower case.
func KeyboardProof(k []byte, requestID string, keys []byte) []byte {
	m := hmac.New(sha256.New, k)
	m.Write([]byte(keyboardProofInfo))
	m.Write([]byte(requestID))
	m.Write([]byte{0})
	for _, c := range keys {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		m.Write([]byte{c})
	}
	return m.Sum(nil)
}

// CheckKeyboardProof compares a proof in constant time.
func CheckKeyboardProof(k []byte, requestID string, keys, proof []byte) bool {
	return hmac.Equal(KeyboardProof(k, requestID, keys), proof)
}
