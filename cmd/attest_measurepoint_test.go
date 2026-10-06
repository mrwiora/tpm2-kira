package cmd

import (
	"strings"
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

func TestDescribeMeasurePoint(t *testing.T) {
	specs := measurePointSpecs([]uint8{0, 2, 4, 7, 11})
	res := &ReadPCRValuesResult{EventlogInfo: &EventlogInfo{MeasurePointExtends: "enter-initrd:11;os-separator:0,2,4,7"}}
	got := describeMeasurePoint(specs, res)
	want := "values at the boot check (event log for 0,2,4,7,11 + enter-initrd on 11, os-separator on 0,2,4,7)"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	uki := describeMeasurePoint([]PCRSpec{{Index: 11, Source: PCRSourceUKI}, {Index: 14}}, &ReadPCRValuesResult{})
	if !strings.Contains(uki, "unified kernel image for 11 + enter-initrd on 11") || !strings.Contains(uki, "registers for 14") {
		t.Fatalf("got %q", uki)
	}
}
