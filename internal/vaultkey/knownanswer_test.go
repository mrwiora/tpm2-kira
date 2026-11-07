package vaultkey

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The vault's derivations, pinned: every keyslot of 0x14xx and 0x24xx was enrolled with exactly
// these bytes, and PepperCheck is in every slot's blob with a pepper. A change here is a change of
// every such disk's key: it needs a "what breaks" and the owner's word (AGENTS.md).
func TestVaultDerivationsKnownAnswer(t *testing.T) {
	local, remote := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
	for name, c := range map[string]struct{ got, want string }{
		"Salt":               {string(Salt(remote, "luks", nil)), "b96ad0bf41c340e82684b19a92696876495d801d81f416fa00297a5d93ea10c8"},
		"Salt with a pepper": {string(Salt(remote, "luks", []byte("pepper"))), "1a3a4a85b8c94c54c38ca5df87fadce75afe544361605ebbe323349e9cc9d768"},
		"Salt, label home":   {string(Salt(remote, "home", nil)), "e3e3c409b60ba6a801a8f606a8b5157773108cf4ceede243003370d96a0ec590"},
		"Password":           {string(Password(local, "luks")), "45c94c8ddb84ade83d2a38e5d0d7b66ed445c1b64ef5a05cbf20e2f7603c2d11"},
		"PepperCheck":        {hex.EncodeToString(PepperCheck([]byte("a key of the combiner\n"))), "87fc968fe040f5b82bede03d89e39053"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", name, c.got, c.want)
		}
	}
}
