package attest

import (
	"bytes"
	"testing"
)

func TestCheckMeasurePointValues(t *testing.T) {
	for _, alg := range []uint16{AlgSHA1, AlgSHA256} {
		n := 32
		if alg == AlgSHA1 {
			n = 20
		}
		gate := bytes.Repeat([]byte{0x11}, n)
		live := gate
		for _, w := range []string{"leave-initrd", "sysinit", "ready"} {
			live, _ = ExtendWord(alg, live, w)
		}
		four := bytes.Repeat([]byte{4}, n)
		quote := []PCRValue{{4, four}, {11, live}}

		if err := CheckMeasurePointValues(alg, quote, []PCRValue{{4, four}, {11, gate}}); err != nil {
			t.Errorf("alg %#x: PCR 11 before the later phases should pass: %v", alg, err)
		}
		if err := CheckMeasurePointValues(alg, quote, []PCRValue{{4, four}, {11, live}}); err != nil {
			t.Errorf("alg %#x: equal values should pass: %v", alg, err)
		}
		// One phase only (no pcrphase-initrd in the image, say).
		partial, _ := ExtendWord(alg, gate, "sysinit")
		if err := CheckMeasurePointValues(alg, []PCRValue{{4, four}, {11, partial}}, []PCRValue{{4, four}, {11, gate}}); err != nil {
			t.Errorf("alg %#x: a subset of the phases should pass: %v", alg, err)
		}
		// Out of order is not a boot.
		wrongOrder, _ := ExtendWord(alg, gate, "ready")
		wrongOrder, _ = ExtendWord(alg, wrongOrder, "sysinit")
		if err := CheckMeasurePointValues(alg, []PCRValue{{4, four}, {11, wrongOrder}}, []PCRValue{{4, four}, {11, gate}}); err == nil {
			t.Errorf("alg %#x: phases out of order should fail", alg)
		}
		// A made-up PCR 11, or any other PCR differing, is rejected.
		if err := CheckMeasurePointValues(alg, quote, []PCRValue{{4, four}, {11, bytes.Repeat([]byte{0x22}, n)}}); err == nil {
			t.Errorf("alg %#x: an unrelated PCR 11 should fail", alg)
		}
		if err := CheckMeasurePointValues(alg, quote, []PCRValue{{4, bytes.Repeat([]byte{5}, n)}, {11, gate}}); err == nil {
			t.Errorf("alg %#x: a differing PCR 4 should fail", alg)
		}
		if err := CheckMeasurePointValues(alg, quote, []PCRValue{{11, gate}}); err == nil {
			t.Errorf("alg %#x: a partial selection should fail", alg)
		}
	}
}
