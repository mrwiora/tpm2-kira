package attest

import (
	"bytes"
	"testing"
)

func TestEnrolOfferCarriesChainAndInitrdEvents(t *testing.T) {
	sel, _ := NewPCRSelection(AlgSHA256, []int{0, 2, 4, 7})
	offer := &EnrolOffer{
		Schema: SchemaVersion, DeviceID: make([]byte, DeviceIDSize), FriendlyName: "box",
		EKPub: []byte{1}, AKPub: []byte{2}, AKName: []byte{3}, Selection: sel,
		PCRValues: []PCRValue{{0, make([]byte, 32)}, {2, make([]byte, 32)}, {4, make([]byte, 32)}, {7, make([]byte, 32)}},
		Quoted:    []byte{4}, Signature: []byte{5}, AdvKey: make([]byte, 32),
		EKCert: []byte{0x30, 0}, EKCertChain: []byte{0x30, 1, 2},
		Initrd:             InitrdEvents{PCR8Chain: bytes.Repeat([]byte{8}, 32), PCR11Chain: bytes.Repeat([]byte{11}, 32), Command: "initrd /initrd.img"},
		MeasurePointValues: []PCRValue{{0, make([]byte, 32)}, {2, make([]byte, 32)}, {4, bytes.Repeat([]byte{4}, 32)}, {7, make([]byte, 32)}},
	}
	b, err := offer.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeEnrolOffer(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.EKCertChain, offer.EKCertChain) || !bytes.Equal(got.Initrd.PCR8Chain, offer.Initrd.PCR8Chain) ||
		!bytes.Equal(got.Initrd.PCR11Chain, offer.Initrd.PCR11Chain) || got.Initrd.Command != offer.Initrd.Command {
		t.Fatalf("round trip lost fields: %+v", got)
	}
	if len(got.MeasurePointValues) != 4 || got.MeasurePointValues[2].Index != 4 || got.MeasurePointValues[2].Digest[0] != 4 {
		t.Fatalf("round trip lost the boot-check values: %+v", got.MeasurePointValues)
	}
	if !bytes.Equal(got.BaselineValues()[2].Digest, got.MeasurePointValues[2].Digest) || got.BaselineAddedBy() != BaselineMeasurePoint {
		t.Fatal("baseline should be the boot-check values when offered")
	}

	// Without the optional fields.
	offer.EKCertChain, offer.Initrd, offer.MeasurePointValues = nil, InitrdEvents{}, nil
	b, _ = offer.Encode()
	d, _ = Decode(b)
	if got, err = DecodeEnrolOffer(d); err != nil || got.EKCertChain != nil || got.Initrd.PCR8Chain != nil || got.Initrd.Command != "" || got.MeasurePointValues != nil {
		t.Fatalf("old offer: %+v %v", got, err)
	}
	if got.BaselineAddedBy() != BaselineLive || len(got.BaselineValues()) != 4 {
		t.Fatal("baseline should fall back to the quote's values")
	}
}
