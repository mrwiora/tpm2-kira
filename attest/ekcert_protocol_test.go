package attest

import (
	"bytes"
	"testing"
)

func TestEnrolOfferCarriesChainAndInitrd(t *testing.T) {
	sel, _ := NewPCRSelection(AlgSHA256, []int{0, 2, 4, 7})
	offer := &EnrolOffer{
		Schema: SchemaVersion, DeviceID: make([]byte, DeviceIDSize), FriendlyName: "box",
		EKPub: []byte{1}, AKPub: []byte{2}, AKName: []byte{3}, Selection: sel,
		PCRValues: []PCRValue{{0, make([]byte, 32)}, {2, make([]byte, 32)}, {4, make([]byte, 32)}, {7, make([]byte, 32)}},
		Quoted:    []byte{4}, Signature: []byte{5}, AdvKey: make([]byte, 32),
		EKCert: []byte{0x30, 0}, EKCertChain: []byte{0x30, 1, 2},
		BootContext:        BootContext{InitrdState: InitrdMeasured, InitrdPCRs: []uint8{9}},
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
	if !bytes.Equal(got.EKCertChain, offer.EKCertChain) || got.BootContext.InitrdState != InitrdMeasured ||
		!bytes.Equal(got.BootContext.InitrdPCRs, []uint8{9}) {
		t.Fatalf("round trip lost fields: %+v", got)
	}
	if len(got.MeasurePointValues) != 4 || got.MeasurePointValues[2].Index != 4 || got.MeasurePointValues[2].Digest[0] != 4 {
		t.Fatalf("round trip lost the boot-check values: %+v", got.MeasurePointValues)
	}
	if !bytes.Equal(got.BaselineValues()[2].Digest, got.MeasurePointValues[2].Digest) || got.BaselineAddedBy() != BaselineMeasurePoint {
		t.Fatal("baseline should be the boot-check values when offered")
	}

	// An attester that predates the fields: absent means unknown, not "none".
	offer.EKCertChain, offer.BootContext, offer.MeasurePointValues = nil, BootContext{}, nil
	b, _ = offer.Encode()
	d, _ = Decode(b)
	if got, err = DecodeEnrolOffer(d); err != nil || got.EKCertChain != nil || got.BootContext.InitrdState != InitrdUnknown || got.MeasurePointValues != nil {
		t.Fatalf("old offer: %+v %v", got, err)
	}
	if got.BaselineAddedBy() != BaselineLive || len(got.BaselineValues()) != 4 {
		t.Fatal("baseline should fall back to the quote's values")
	}
}

func TestInitrdCoverageDecision(t *testing.T) {
	sel, _ := NewPCRSelection(AlgSHA256, []int{0, 2, 4, 7})
	cases := []struct {
		bc   BootContext
		want string
	}{
		{BootContext{}, InitrdUnknownMsg},
		{BootContext{InitrdState: InitrdMeasured, InitrdPCRs: []uint8{9}}, InitrdNotCovered},
		{BootContext{InitrdState: InitrdMeasured, InitrdPCRs: []uint8{11, 4}}, InitrdCovered},
		{BootContext{InitrdState: InitrdMeasured}, InitrdUnknownMsg},
		{BootContext{InitrdState: InitrdNone}, InitrdNoInitrd},
	}
	for _, c := range cases {
		if got, _ := initrdCoverage(&EnrolOffer{Selection: sel, BootContext: c.bc}); got != c.want {
			t.Errorf("%+v: %s, want %s", c.bc, got, c.want)
		}
	}
}
