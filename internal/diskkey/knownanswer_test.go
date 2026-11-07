package diskkey

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The keyboard pepper's salt, pinned: every keyslot of 0x1302 and 0x1402 was enrolled with exactly
// these bytes. A change here is a change of every such disk's key: it needs a "what breaks" and the
// owner's word (AGENTS.md).
func TestKeyboardSaltKnownAnswer(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if got, want := hex.EncodeToString(KeyboardSalt(salt, []byte("correct9horse"))), "524e3e03ce96cb959926d1b0bf0165cfefccac74c0b4f99bc2b3b00e29737443"; got != want {
		t.Errorf("KeyboardSalt = %s, want %s", got, want)
	}
	if bytes.Equal(KeyboardSalt(salt, []byte("a")), KeyboardSalt(salt, []byte("b"))) {
		t.Error("the pepper changes nothing")
	}
}
