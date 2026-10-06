package attest

import (
	"bytes"
	"testing"
	"time"
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

// One boot, asked before and after systemd's OS separator, is one state.
func TestSameBootState(t *testing.T) {
	for _, alg := range []uint16{AlgSHA1, AlgSHA256} {
		size := 20
		if alg == AlgSHA256 {
			size = 32
		}
		before := bytes.Repeat([]byte{0x11}, size)
		after, _ := ExtendWord(alg, before, OSSeparatorWord)
		twice, _ := ExtendWord(alg, after, OSSeparatorWord)
		other := bytes.Repeat([]byte{0x22}, size)
		phase, _ := ExtendWord(alg, before, "leave-initrd")

		for _, idx := range OSSeparatorPCRs {
			if !SameBootState(idx, before, before) || !SameBootState(idx, before, after) || !SameBootState(idx, after, before) {
				t.Fatalf("alg %#x PCR %d: before/after the separator not recognised", alg, idx)
			}
			if SameBootState(idx, before, twice) || SameBootState(idx, before, other) || SameBootState(idx, before, phase) {
				t.Fatalf("alg %#x PCR %d: accepted a state that is not this boot", alg, idx)
			}
		}
		// Registers the separator is not extended into must be equal.
		for _, idx := range []uint8{8, 10, 11, 15, 23} {
			if !SameBootState(idx, before, before) {
				t.Fatalf("PCR %d: equal values differ", idx)
			}
			if SameBootState(idx, before, after) {
				t.Fatalf("PCR %d: separator accepted where systemd does not extend it", idx)
			}
		}
		if SameBootState(0, before, after[:size-1]) || SameBootState(0, nil, nil) {
			t.Fatal("malformed values accepted")
		}
	}
}

func TestProfileMatchesBeforeAndAfterTheSeparator(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	sep := func(d []byte) []byte { e, _ := ExtendWord(AlgSHA256, d, OSSeparatorWord); return e }
	// The profile as enrolment records it: after the separator; PCR 11 is
	// not touched by it.
	after := []PCRValue{{Index: 0, Digest: sep(v(1))}, {Index: 7, Digest: sep(v(7))}, {Index: 11, Digest: v(11)}}
	pol := &Policy{Selection: []uint8{0, 7, 11}, Profiles: []Profile{ProfileFromValues("enrolment", after, now, "test")}}

	quote := func(p0, p7, p11 []byte) map[uint8][]byte { return map[uint8][]byte{0: p0, 7: p7, 11: p11} }
	for name, q := range map[string]map[uint8][]byte{
		"after the separator":  quote(sep(v(1)), sep(v(7)), v(11)),
		"before the separator": quote(v(1), v(7), v(11)),
		"while it runs":        quote(sep(v(1)), v(7), v(11)),
	} {
		if _, err := pol.MatchProfile(q, now); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, q := range map[string]map[uint8][]byte{
		"another kernel (PCR 11)":     quote(v(1), v(7), v(12)),
		"another firmware (PCR 0)":    quote(v(2), v(7), v(11)),
		"Secure Boot changed (PCR 7)": quote(sep(v(1)), sep(v(8)), v(11)),
		"separator on PCR 11":         quote(v(1), v(7), sep(v(11))),
	} {
		if _, err := pol.MatchProfile(q, now); err == nil {
			t.Fatalf("%s: matched", name)
		}
	}
	// What is shown as changed is what changed, not the separator.
	changed := quote(v(1), v(8), v(11))
	if n := pol.Profiles[0].diffCount(pol.Selection, changed); n != 1 {
		t.Fatalf("%d PCRs reported as changed, want 1", n)
	}
}
