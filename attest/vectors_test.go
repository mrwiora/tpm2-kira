package attest_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	. "github.com/matthias/tpm2-kira/attest"
)

// Golden vectors for every canonical computation. docs/PROTOCOL-BLE.md §9
// publishes the same values for implementers; if this test changes, the
// protocol changed, and the document and the label versions must change too.

func seq(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func h(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestGoldenVectors(t *testing.T) {
	cb := seq(0x00, 32)
	nonceA, nonceV := seq(0x20, 32), seq(0x40, 32)
	nonceP, nonceM := seq(0x60, 32), seq(0x80, 32)
	sel, _ := NewPCRSelection(AlgSHA256, []int{0, 2, 4, 7})
	qd, _ := QualifyingData(nonceA, nonceV, cb, sel)
	receipt := &Receipt{
		Verdict: VerdictOK, DeviceID: seq(0xA0, 16), AKName: append([]byte{0x00, 0x0B}, seq(0xB0, 32)...),
		QD: qd, QuoteDigest: seq(0xC0, 32), PolicyID: "default",
		IssuedAt: 1790000000, ExpiresAt: 1790000300, VerifierID: "pixel-1",
	}
	anchor := bytes.Repeat([]byte{0x5A}, 91)

	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"qd", qd, "8233fca13c1522b8b5f715163dfc02d22617bc43fba8305290717e1976edfe8d"},
		{"enrol_qd", EnrolQualifyingData(cb), "46a8e194d0d031af05922c5866e8a5e037d0860c8f82a6451cf020e1f5da1ba1"},
		{"offline_qd", OfflineQualifyingData(seq(0xD0, 32)), "efbd3a1a95d1e8b70f06136fac569b7333839eda17a3b86452fa3f27389f16c8"},
		{"sas_commit", SASCommitment(cb, nonceM), "1e54a4dbd650ce9dc357e9eadf904cf5cbdd35c923f24bc4da85d40488af1efb"},
		{"receipt_tbs", ReceiptTBS(receipt), "74706d322d6b6972612f726563656970742f76310110000000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf22000000000bb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf200000008233fca13c1522b8b5f715163dfc02d22617bc43fba8305290717e1976edfe8d20000000c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf0700000064656661756c74803bb16a00000000ac3cb16a0000000007000000706978656c2d31"},
		{"enrol_accept_tbs", EnrolAcceptTBS(receipt.DeviceID, cb, receipt.AKName, anchor, "pixel-1", "default"), "74706d322d6b6972612f656e726f6c2d6163636570742f763110000000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf20000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f22000000000bb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf5b0000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a07000000706978656c2d310700000064656661756c74"},
		{"anchor_digest", AnchorDigest(anchor), "da0912c41cf5e85586e925cb47e7d00377338fc4cce96832f21b36808946fc27"},
		{"service_data", BuildServiceData(AdvFlagAttest, []byte{1, 2, 3, 4}, seq(0xE0, 32)), "020102030424213b87412e6e4e"},
		{"factor", FactorFromSecret(seq(0xF0, 16), "luks"), "be5af6edaaa51a5d8243045ef04287fdba640410a8364f256fa39381b0491cf8"},
	}
	for _, c := range cases {
		if !bytes.Equal(c.got, h(c.want)) {
			t.Errorf("%s:\n got  %x\n want %s", c.name, c.got, c.want)
		}
	}
	if got := ShortAuthString(cb, nonceP, nonceM); got != "394551" {
		t.Errorf("sas: got %s want 394551", got)
	}
	if !MatchServiceData(h("020102030424213b87412e6e4e"), seq(0xE0, 32)) {
		t.Error("service data does not match its own key")
	}
}
