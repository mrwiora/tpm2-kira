package vaultproto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Values taken before PolicyCalculator replaced the hand-written hashes
// (2026-11-01); a real session holds them in tpm2-kira's vault test.
func TestPolicyDigestsFixed(t *testing.T) {
	const pcrKey = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100a8061bd2de458a43b71ef7dc57f92f266219c8fe53fee0740b78b2d73a0d26aadc1aab14470693bd13cdaf4e655f72e462faa53fb95e322a9065480b2cea537fccc76f2b43a22920ee1d52880b4b71350543001e78d164ba1b03be6ebc7b8690cd87cb5e9675f6e493ea0f142f3bbd127198d302c76f98add055004aff050e82c432718b4899fed0036a9579f10953b1089725b1af9d26336c29cd2521d661f192d2b135c216f83a1143613e7d53d1f59556b3588918a5844ab2930d04b44567a3561157b1c1a60ab30022aef5573b8251d8d6e1818de94c06d58daba0527719898bab688bdf24b694ae364095d70c7c4bf91e74319fdddd339f955dff4ec7d50203010001"
	der, err := hex.DecodeString(pcrKey)
	if err != nil {
		t.Fatal(err)
	}
	v := func(i uint8, n int) PCRValue { return PCRValue{Index: i, Value: bytes.Repeat([]byte{i + 1}, n)} }
	check := func(what string, got []byte, want string) {
		t.Helper()
		if hex.EncodeToString(got) != want {
			t.Errorf("%s: %x, want %s", what, got, want)
		}
	}
	p256 := PolicyPCRDigest(Selection{Alg: 0x0b, Indices: []uint8{0, 2, 4, 7}}, []PCRValue{v(0, 32), v(2, 32), v(4, 32), v(7, 32)})
	check("PolicyPCR, SHA-256", p256, "632c28e540e52559536e96c40b3689967eb3662ad25b53d6ea443357bc5037b8")
	check("PolicyPCR, SHA-1", PolicyPCRDigest(Selection{Alg: 0x04, Indices: []uint8{7, 8, 9}}, []PCRValue{v(7, 20), v(8, 20), v(9, 20)}), "8fb3cca3e55729c80d2af22e5fea637295e6c0aeb4b143096d32e22323c6facd")
	check("PolicyPCR, PCR 11", PolicyPCRDigest(Selection{Alg: 0x0b, Indices: []uint8{11}}, []PCRValue{v(11, 32)}), "64d0e3bff12fd39b41378938c5c351624926fe63e108a6cd6cbe797791ce5058")
	signed, err := SignedPCRPolicy(der, Selection{Alg: 0x0b, Indices: []uint8{7}}, []PCRValue{v(7, 32)})
	if err != nil {
		t.Fatal(err)
	}
	check("signed PCRs", signed, "a77f29aa445fe8969153bb64cfe14829c896da68ded0844e17d77ff8d27eef20")
	gen := append([]byte{0, 0x0b}, bytes.Repeat([]byte{0xc3}, 32)...)
	approved := ApprovedPolicy(p256, gen, 7)
	check("the approved policy", approved, "37f259445deaa2ca77f66bd92d5458f730059f811ba360e8d4425af592af5a8d")
	check("the approved policy, signed PCRs", ApprovedPolicy(signed, gen, 0), "8d0b0aba99d6b03da030aed799905d4aef091451a5944db47ee6bc2ed627d8cf")
	check("the approval's digest", ApprovalDigest(approved, bytes.Repeat([]byte{0x5a}, 16)), "02a3bcaa2fb5d3d2e11bffc6b548e4a6d4caf0b1101f038dee4e0c97ee6afbcc")
}
