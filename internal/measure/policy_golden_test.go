package measure

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Values taken before PolicyCalculator replaced the hand-written hash
// (2026-11-01); TestSlotWithSignedPCR11 holds it against a real session.
func TestSignedPolicyFixed(t *testing.T) {
	if got := hex.EncodeToString(SignedPolicy(11, bytes.Repeat([]byte{12}, 32), PCRHashAlgoSHA256)); got != "64d0e3bff12fd39b41378938c5c351624926fe63e108a6cd6cbe797791ce5058" {
		t.Errorf("SHA-256: %s", got)
	}
	if got := hex.EncodeToString(SignedPolicy(11, bytes.Repeat([]byte{12}, 20), PCRHashAlgoSHA1)); got != "fad34ee53bfd6f4a58fb374482150b973e3a3287d18b24eccc9aee288a6124d9" {
		t.Errorf("SHA-1: %s", got)
	}
}
