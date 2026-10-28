package cmd

import (
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/measure"
)

func TestMeasurePointSpecs(t *testing.T) {
	got := measurePointSpecs([]uint8{0, 2, 7, 11, 14})
	want := []measure.PCRSpec{
		{Index: 0, Source: measure.PCRSourceEventlog},
		{Index: 2, Source: measure.PCRSourceEventlog},
		{Index: 7, Source: measure.PCRSourceEventlog},
		{Index: 11, Source: measure.PCRSourceEventlog}, // the stub's section measurements are in the firmware log
		{Index: 14, Source: measure.PCRSourceRegister}, // beyond what the firmware log describes
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("PCR %d: got %+v, want %+v", want[i].Index, got[i], want[i])
		}
	}
}
