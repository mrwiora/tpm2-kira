package cmd

import (
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/argon2"
)

// The combiner: hashpwd2 (github.com/mrwiora/hashpwd2) inside tpm2-kira,
// byte for byte. A LUKS keyslot enrolled with hashpwd2 opens with what this
// file derives from the same password and salt, and the other way round;
// nothing crosses a process boundary. The salt is the factor the phone
// released (factor.go); the password is typed at tpm2-kira's prompt; the
// result is the key file systemd-cryptsetup reads from the unlock socket.

// Argon2id as hashpwd2 sets it: 1 GiB, 16 passes, 4 lanes, 64 bytes.
const (
	combineMemoryKiB   = 1 << 20
	combineIterations  = 16
	combineParallelism = 4
	combineKeyLength   = 64
)

var errCombineEmpty = errors.New("the password and the salt must both be non-empty")

// Combine derives the LUKS key hashpwd2 derives: the Argon2id output,
// base64 without padding, followed by one newline - the newline is part of
// the key, as hashpwd2's README says. Empty input is refused, not hashed.
// The caller wipes the result.
func Combine(password, salt []byte) ([]byte, error) {
	if len(password) == 0 || len(salt) == 0 {
		return nil, errCombineEmpty
	}
	hash := argon2.IDKey(password, salt, combineIterations, combineMemoryKiB, combineParallelism, combineKeyLength)
	defer wipe(hash)
	out := make([]byte, base64.RawStdEncoding.EncodedLen(len(hash))+1)
	base64.RawStdEncoding.Encode(out, hash)
	out[len(out)-1] = '\n'
	return out, nil
}
