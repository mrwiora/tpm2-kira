package diskkey

import (
	"encoding/base64"
	"errors"

	"github.com/mrwiora/tpm2-kira/internal/wipe"

	"golang.org/x/crypto/argon2"
)

// The combiner: the LUKS key derived from a password and a salt, inside
// tpm2-kira; nothing crosses a process boundary. The derivation is fixed (a
// known answer in combine_test.go): keyslots enrolled with the earlier
// separate combiner, hashpwd2, keep opening. The salt is the factor the phone
// released (internal/phonegate/factor.go); the password is typed at tpm2-kira's prompt; the
// result is the key file systemd-cryptsetup reads from the unlock socket.

// Argon2id's production cost: 1 GiB, 16 passes, 4 lanes. Constants, and nothing
// at run time reaches them: not a flag, an environment variable, a config or a
// LUKS token. What Combine uses is combineMemoryKiB and the rest (combine_cost.go,
// these numbers); only a test build, by a Go build tag, has others
// (combine_cost_fast.go, docs/TESTING.md).
const (
	productionMemoryKiB   uint32 = 1 << 20
	productionIterations  uint32 = 16
	productionParallelism uint8  = 4
)

const combineKeyLength = 64

var errCombineEmpty = errors.New("the password and the salt must both be non-empty")

// Combine derives the LUKS key: the Argon2id output, base64 without
// padding, followed by one newline - the newline is part of the key. Empty input is refused, not hashed.
// The caller wipes the result.
func Combine(password, salt []byte) ([]byte, error) {
	if len(password) == 0 || len(salt) == 0 {
		return nil, errCombineEmpty
	}
	hash := argon2.IDKey(password, salt, combineIterations, combineMemoryKiB, combineParallelism, combineKeyLength)
	defer wipe.Bytes(hash)
	out := make([]byte, base64.RawStdEncoding.EncodedLen(len(hash))+1)
	base64.RawStdEncoding.Encode(out, hash)
	out[len(out)-1] = '\n'
	return out, nil
}
