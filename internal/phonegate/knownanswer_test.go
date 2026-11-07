package phonegate

import (
	"bytes"
	"testing"
)

// The phone salt's derivation, pinned: every keyslot of 0x1300, 0x1302 and of the TPM salt (0x1200,
// whose part T goes through it too) was enrolled with exactly these bytes. A change here is a
// change of every such disk's key: it needs a "what breaks" and the owner's word (AGENTS.md).
func TestFactorSaltKnownAnswer(t *testing.T) {
	f := bytes.Repeat([]byte{0xF0}, 32)
	for label, want := range map[string]string{
		"":     "793929a1beb7ec51782154c70f5822360b1aa659dd1284158139852cf32f9164",
		"luks": "793929a1beb7ec51782154c70f5822360b1aa659dd1284158139852cf32f9164",
		"home": "530b4b3abf454288d23d7c00edaf32bd0efce7802ebc390b24753ea65e653538",
	} {
		if got := string(FactorSalt(f, label)); got != want {
			t.Errorf("FactorSalt(F, %q) = %s, want %s", label, got, want)
		}
	}
}
