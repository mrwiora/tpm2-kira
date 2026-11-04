package attest

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/go-tpm/tpm2"
)

// A salt typed through a one-time keyboard. The phone or the vault holds a short salt and acts
// only on a good attestation, but it does not hand the salt over: it draws a pad for this boot
// alone, gives the machine the pad and the person the keys to press. The machine applies the pad
// to what is typed and has the salt, so a recording of the keys is worth nothing: the next boot's
// keys differ.
//
// The mapping is one per position, the key at position i being salt[i] + pad[i] in the alphabet,
// and not one table for the whole salt: a table would show which of the salt's characters repeat,
// the same way in every recording, and could map a key to itself. So the keys are uniformly random
// and say nothing without the pad, which is wrapped for the TPM besides (docs/DISK-KEY.md).

// KeyboardAlphabet is what a salt and the keys are made of: no y and z, which layouts swap, and
// nothing that looks like something else (l, o, 0, 1).
const KeyboardAlphabet = "abcdefghijkmnpqrstuvwx23456789"

// A salt's length: 8 by default, as many characters as the pad's credential can carry at most.
const (
	KeyboardDefaultLength = 8
	KeyboardMinLength     = 8
	KeyboardMaxLength     = 32
)

// ErrKeyboardKeys says what was typed cannot be the keys: the wrong length or a character outside
// the alphabet.
var ErrKeyboardKeys = errors.New("those are not the keys shown")

func keyboardIndex(c byte) int {
	if c >= 'A' && c <= 'Z' {
		c += 'a' - 'A'
	}
	for i := 0; i < len(KeyboardAlphabet); i++ {
		if KeyboardAlphabet[i] == c {
			return i
		}
	}
	return -1
}

// keyboardDraw is n values below len(KeyboardAlphabet), uniformly.
func keyboardDraw(rng io.Reader, n int) ([]byte, error) {
	if rng == nil {
		rng = rand.Reader
	}
	size := byte(len(KeyboardAlphabet))
	limit := 256 - 256%int(size)
	out := make([]byte, 0, n)
	var b [1]byte
	for len(out) < n {
		if _, err := io.ReadFull(rng, b[:]); err != nil {
			return nil, err
		}
		if int(b[0]) < limit {
			out = append(out, b[0]%size)
		}
	}
	return out, nil
}

// NewKeyboardSalt draws a salt of n characters. The caller wipes it.
func NewKeyboardSalt(rng io.Reader, n int) ([]byte, error) {
	if n < KeyboardMinLength || n > KeyboardMaxLength {
		return nil, fmt.Errorf("a salt typed through the keyboard has %d to %d characters, not %d", KeyboardMinLength, KeyboardMaxLength, n)
	}
	v, err := keyboardDraw(rng, n)
	if err != nil {
		return nil, err
	}
	for i := range v {
		v[i] = KeyboardAlphabet[v[i]]
	}
	return v, nil
}

// CheckKeyboardSalt says why s is no such salt, or nil.
func CheckKeyboardSalt(s []byte) error {
	if len(s) < KeyboardMinLength || len(s) > KeyboardMaxLength {
		return fmt.Errorf("a salt typed through the keyboard has %d to %d characters, not %d", KeyboardMinLength, KeyboardMaxLength, len(s))
	}
	for _, c := range s {
		if c >= 'A' && c <= 'Z' || keyboardIndex(c) < 0 {
			return errors.New("a salt typed through the keyboard holds a character outside its alphabet")
		}
	}
	return nil
}

// KeyboardSecretSize is what the phone wraps for the TPM: a credential holds what a factor does.
const KeyboardSecretSize = 32

// keyboardStream is HMAC-SHA256(secret, label ‖ counter), read as a stream.
type keyboardStream struct {
	secret []byte
	ctr    uint32
	buf    []byte
}

func (k *keyboardStream) Read(p []byte) (int, error) {
	for len(k.buf) == 0 {
		m := hmac.New(sha256.New, k.secret)
		m.Write([]byte("tpm2-kira/keyboard-pad/v1"))
		m.Write(binary.BigEndian.AppendUint32(nil, k.ctr))
		k.ctr++
		k.buf = m.Sum(nil)
	}
	n := copy(p, k.buf)
	k.buf = k.buf[n:]
	return n, nil
}

// KeyboardPadFrom is the pad a secret of KeyboardSecretSize stands for, for n characters: the phone's
// way, since what the TPM opens has a fixed size, whatever the salt's.
func KeyboardPadFrom(secret []byte, n int) ([]byte, error) {
	if len(secret) != KeyboardSecretSize {
		return nil, fmt.Errorf("a keyboard's secret has %d bytes, not %d", KeyboardSecretSize, len(secret))
	}
	return keyboardDraw(&keyboardStream{secret: secret}, n)
}

// NewKeyboardPad draws a pad for one boot and a salt of n characters.
func NewKeyboardPad(rng io.Reader, n int) ([]byte, error) {
	return keyboardDraw(rng, n)
}

func checkKeyboardPad(pad []byte, n int) error {
	if len(pad) != n {
		return ErrKeyboardKeys
	}
	for _, p := range pad {
		if int(p) >= len(KeyboardAlphabet) {
			return errors.New("the keyboard's pad is malformed")
		}
	}
	return nil
}

// KeyboardKeys is the keys to press: the salt through the pad.
func KeyboardKeys(salt, pad []byte) ([]byte, error) {
	if err := CheckKeyboardSalt(salt); err != nil {
		return nil, err
	}
	if err := checkKeyboardPad(pad, len(salt)); err != nil {
		return nil, err
	}
	size := len(KeyboardAlphabet)
	out := make([]byte, len(salt))
	for i := range salt {
		out[i] = KeyboardAlphabet[(keyboardIndex(salt[i])+int(pad[i]))%size]
	}
	return out, nil
}

// KeyboardSaltOf is the salt behind what was typed: the keys through the pad. Capitals are taken
// for the letters they are; anything else outside the alphabet, or another length, is
// ErrKeyboardKeys. Wrong keys of the right form give a wrong salt: only the keyslot, or the vault's
// proof, can tell. The caller wipes the result.
func KeyboardSaltOf(keys, pad []byte) ([]byte, error) {
	if err := checkKeyboardPad(pad, len(keys)); err != nil {
		return nil, err
	}
	size := len(KeyboardAlphabet)
	out := make([]byte, len(keys))
	for i := range keys {
		k := keyboardIndex(keys[i])
		if k < 0 {
			clear(out)
			return nil, ErrKeyboardKeys
		}
		out[i] = KeyboardAlphabet[(k+size-int(pad[i]))%size]
	}
	return out, nil
}

// KeyboardKeep asks the phone to keep a salt typed through the keyboard, in the evidence of a
// session on the booted system. It travels in the Noise session alone. The release key is what the
// pad is wrapped for at every boot; the phone checks it against the signing key it pinned.
type KeyboardKeep struct {
	Salt             []byte
	ReleaseKeyPublic []byte
	SigningPublic    []byte
	PolicyRef        []byte
	Label            string
}

// KeyboardRecord is a kept salt in the phone's record, encrypted at rest with the record.
type KeyboardRecord struct {
	Salt           []byte    `json:"salt"`
	ReleaseKeyName HexStr    `json:"release_key_name"`
	Label          string    `json:"label,omitempty"`
	KeptAt         time.Time `json:"kept_at"`
}

// KeyboardBackend is an optional AttesterBackend extension: a salt for the phone to keep.
type KeyboardBackend interface {
	KeyboardToKeep() *KeyboardKeep
}

// HasKeyboard reports whether the record keeps a salt typed through the keyboard.
func (r *MachineRecord) HasKeyboard() bool {
	return r != nil && r.Keyboard != nil && len(r.Keyboard.Salt) > 0
}

// checkKeyboardKeep says whether what the evidence asks to keep is such a salt, for the slot's own
// release key under the signing key pinned at enrolment; it gives that key's Name.
func checkKeyboardKeep(k *KeyboardKeep, signingKeyName []byte) ([]byte, error) {
	if err := CheckKeyboardSalt(k.Salt); err != nil {
		return nil, err
	}
	name, err := ReleaseKeyName(k.ReleaseKeyPublic, k.SigningPublic, k.PolicyRef)
	if err != nil {
		return nil, err
	}
	signing, err := tpm2.Unmarshal[tpm2.TPMTPublic](k.SigningPublic)
	if err != nil {
		return nil, err
	}
	got, err := tpm2.ObjectName(signing)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(got.Buffer, signingKeyName) {
		return nil, errors.New("the release key is under another signing key than the one pinned at enrolment")
	}
	return name, nil
}
