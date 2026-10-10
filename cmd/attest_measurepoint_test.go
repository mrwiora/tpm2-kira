package cmd

import (
	"testing"
)

func TestMeasurePointSpecs(t *testing.T) {
	got := measurePointSpecs([]uint8{0, 2, 7, 11, 14})
	want := []PCRSpec{
		{Index: 0, Source: PCRSourceEventlog},
		{Index: 2, Source: PCRSourceEventlog},
		{Index: 7, Source: PCRSourceEventlog},
		{Index: 11, Source: PCRSourceEventlog}, // the stub's section measurements are in the firmware log
		{Index: 14, Source: PCRSourceRegister}, // beyond what the firmware log describes
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
