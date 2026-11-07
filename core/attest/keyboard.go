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

// A pepper typed through a one-time keyboard. The pepper is the person's alone: no device stores
// it. After a good attestation the phone or the vault draws a seed for this boot alone, wraps it
// for the TPM and shows the person a layout made from it: on every key of the keyboard another
// character. The person types the pepper by pressing, for each of its characters, the key that
// shows it; the machine opens the seed in its TPM, makes the same layout and maps the keys back.
// A recording of the keys is worth nothing without the layout, and the next boot's differs.
//
// One layout holds for the whole boot: a recording shows the pepper's length and which of its
// characters repeat, not which they are (docs/DISK-KEY.md).

// KeyboardKeys are the keys a layout covers, in its order: the US keyboard's letters and digits,
// without Shift. Capitals are taken for their keys.
const KeyboardKeys = "abcdefghijklmnopqrstuvwxyz0123456789"

// KeyboardUS is how the US keyboard arranges KeyboardKeys, row by row, for a phone's screen. Other
// arrangements are added beside it; the layout itself does not change with them.
var KeyboardUS = []string{"1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"}

// A pepper's length.
const (
	KeyboardPepperMin = 8
	KeyboardPepperMax = 64
)

// KeyboardSeedSize is what is wrapped for the TPM: a credential holds what a factor does.
const KeyboardSeedSize = 32

// ErrKeyboardPepper says what was typed cannot be a pepper: the wrong length or a key outside the
// layout.
var ErrKeyboardPepper = errors.New("not a pepper: 8 to 64 keys, letters and digits alone")

// keyIndex is the place of a key in KeyboardKeys, or -1.
func keyIndex(c byte) int {
	switch {
	case c >= 'a' && c <= 'z':
		return int(c - 'a')
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= '0' && c <= '9':
		return 26 + int(c-'0')
	}
	return -1
}

// CheckKeyboardPepper says why p is no pepper for the keyboard, or nil: as it is set, lower case.
func CheckKeyboardPepper(p []byte) error {
	if len(p) < KeyboardPepperMin || len(p) > KeyboardPepperMax {
		return ErrKeyboardPepper
	}
	for _, c := range p {
		if c >= 'A' && c <= 'Z' || keyIndex(c) < 0 {
			return ErrKeyboardPepper
		}
	}
	return nil
}

// NewKeyboardSeed draws a boot's seed. The caller wipes it.
func NewKeyboardSeed(rng io.Reader) ([]byte, error) {
	if rng == nil {
		rng = rand.Reader
	}
	s := make([]byte, KeyboardSeedSize)
	if _, err := io.ReadFull(rng, s); err != nil {
		return nil, err
	}
	return s, nil
}

// keyboardStream is HMAC-SHA256(seed, label ‖ counter), read as a stream.
type keyboardStream struct {
	seed []byte
	ctr  uint32
	buf  []byte
}

func (k *keyboardStream) Read(p []byte) (int, error) {
	for len(k.buf) == 0 {
		m := hmac.New(sha256.New, k.seed)
		m.Write([]byte("tpm2-kira/keyboard-layout/v1"))
		m.Write(binary.BigEndian.AppendUint32(nil, k.ctr))
		k.ctr++
		k.buf = m.Sum(nil)
	}
	n := copy(p, k.buf)
	k.buf = k.buf[n:]
	return n, nil
}

// below is a value below n, uniformly, from the stream.
func (k *keyboardStream) below(n int) int {
	limit := 256 - 256%n
	var b [1]byte
	for {
		k.Read(b[:])
		if int(b[0]) < limit {
			return int(b[0]) % n
		}
	}
}

// KeyboardLayout is a boot's layout: Shows[i] is the character the key KeyboardKeys[i] stands for.
type KeyboardLayout struct {
	Shows [len(KeyboardKeys)]byte
}

// KeyboardLayoutOf is the layout a seed stands for: a permutation of KeyboardKeys, Fisher-Yates
// from the seed's stream, so the phone or the vault and the machine make the same.
func KeyboardLayoutOf(seed []byte) (*KeyboardLayout, error) {
	if len(seed) != KeyboardSeedSize {
		return nil, fmt.Errorf("a keyboard's seed has %d bytes, not %d", KeyboardSeedSize, len(seed))
	}
	l := &KeyboardLayout{}
	copy(l.Shows[:], KeyboardKeys)
	s := &keyboardStream{seed: seed}
	for i := len(l.Shows) - 1; i > 0; i-- {
		j := s.below(i + 1)
		l.Shows[i], l.Shows[j] = l.Shows[j], l.Shows[i]
	}
	clear(s.buf)
	return l, nil
}

// String is the characters shown, in the order of KeyboardKeys: what an event carries.
func (l *KeyboardLayout) String() string { return string(l.Shows[:]) }

// Pepper is the pepper behind the keys typed. Anything but 8 to 64 letters and digits is
// ErrKeyboardPepper; a wrong pepper of the right form is one only the keyslot can tell. The caller
// wipes the result.
func (l *KeyboardLayout) Pepper(typed []byte) ([]byte, error) {
	if len(typed) < KeyboardPepperMin || len(typed) > KeyboardPepperMax {
		return nil, ErrKeyboardPepper
	}
	out := make([]byte, len(typed))
	for i, c := range typed {
		k := keyIndex(c)
		if k < 0 {
			clear(out)
			return nil, ErrKeyboardPepper
		}
		out[i] = l.Shows[k]
	}
	return out, nil
}

// Keys are the keys to press for a pepper: the inverse of Pepper, for tests and the vault's view.
func (l *KeyboardLayout) Keys(pepper []byte) ([]byte, error) {
	if err := CheckKeyboardPepper(pepper); err != nil {
		return nil, err
	}
	out := make([]byte, len(pepper))
	for i, c := range pepper {
		out[i] = KeyboardKeys[bytes.IndexByte(l.Shows[:], c)]
	}
	return out, nil
}

// Wipe clears the layout.
func (l *KeyboardLayout) Wipe() {
	if l != nil {
		clear(l.Shows[:])
	}
}

// KeyboardKeep tells the phone, in the evidence of the session that hands a phone salt over, that
// the slot's keyslot takes a pepper typed through its keyboard: the release key the seed is wrapped
// for at every boot, which the phone checks against the signing key it pinned. It travels with the
// FactorKeep, in the Noise session alone.
type KeyboardKeep struct {
	ReleaseKeyPublic []byte
	SigningPublic    []byte
	PolicyRef        []byte
}

// KeyboardRecord in the phone's record says the phone shows a layout with every release of the
// phone salt, and for which release key.
type KeyboardRecord struct {
	ReleaseKeyName HexStr    `json:"release_key_name"`
	KeptAt         time.Time `json:"kept_at"`
}

// KeyboardBackend is an optional AttesterBackend extension: a keyboard for the phone to keep.
type KeyboardBackend interface {
	KeyboardToKeep() *KeyboardKeep
}

// HasKeyboard reports whether the record shows a layout with its phone salt.
func (r *MachineRecord) HasKeyboard() bool {
	return r != nil && r.Keyboard != nil && len(r.Keyboard.ReleaseKeyName) > 0
}

// checkKeyboardKeep says whether the release key is the slot's own, under the signing key pinned at
// enrolment; it gives that key's Name.
func checkKeyboardKeep(k *KeyboardKeep, signingKeyName []byte) ([]byte, error) {
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
