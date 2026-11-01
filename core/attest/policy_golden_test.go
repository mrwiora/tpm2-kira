package attest

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// Values taken from the hand-written hashes before PolicyCalculator replaced them
// (2026-11-01): the digests may not move, or every object of every slot, the
// phones' pins and the vault's checks with them. TestSlotPolicyDigestIsTheTPMs
// holds them against a real session.
func TestPolicyDigestsFixed(t *testing.T) {
	name := append([]byte{0, 0x0b}, bytes.Repeat([]byte{0xa5}, 32)...)
	ref := bytes.Repeat([]byte{0x5a}, 16)
	check := func(what string, got []byte, err error, want string) {
		t.Helper()
		if err != nil || hex.EncodeToString(got) != want {
			t.Errorf("%s: %x %v, want %s", what, got, err, want)
		}
	}
	check("PolicyAuthorize", PolicyAuthorizeDigest(name, ref), nil, "7aed7bdcb95c665973054a43f9407a63592339d3af21c9592ed67ac727dca6c5")
	check("PolicyAuthorize, no reference", PolicyAuthorizeDigest(name, nil), nil, "14757c08c9605a2460af04c1dbeee01fc523b1c38f215dad408fd6d201c506d4")
	for _, c := range []struct {
		bank                tpm2.TPMIAlgHash
		open, slot, release string
	}{
		{tpm2.TPMAlgSHA256, "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925", "c033df06707a4fe89da3638ca1c5ee9f175cfa7d0a64cc97655c67f99ba11124", "2792e4dd5e107abbfdd2085e30d06c1395a20b6ae8274bc1fc9db2e2a2adffb7"},
		{tpm2.TPMAlgSHA1, "de47c9b27eb8d300dbb5f2c353e632c393262cf06340c4fa7f1b40c4cbd36f90", "eef0438331d97bbe8d9fdc3882f01b6f503ecb33ee68686e4b1486a8dae96b9f", "11b722ba87bffad491df23c3c58931e9a4a010b790c150826a5790e0c82dcf59"},
	} {
		open, err := OpenPCRDigest(c.bank)
		check("the open PCR", open, err, c.open)
		slot, err := SlotPolicyDigest(name, ref, c.bank)
		check("the slot's policy", slot, err, c.slot)
		release, err := ReleaseKeyPolicy(name, ref, c.bank)
		check("the release key's policy", release, err, c.release)
	}
}
