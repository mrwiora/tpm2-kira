package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestMeasurePointWordsAt(t *testing.T) {
	// Before the separator only PCR 11 has been extended (enter-initrd).
	if w := MeasurePointWordsAt(MeasurePointBeforeSeparator, 11); len(w) != 1 || w[0] != EnterInitrdWord {
		t.Fatalf("PCR 11 before: %v", w)
	}
	for _, pcr := range []int{0, 4, 7, 9, 12, 14} {
		if w := MeasurePointWordsAt(MeasurePointBeforeSeparator, pcr); len(w) != 0 {
			t.Fatalf("PCR %d before the separator should have no words, got %v", pcr, w)
		}
		if w := MeasurePointWordsAt(MeasurePointAfterSeparator, pcr); len(w) != 1 || w[0] != OSSeparatorWord {
			t.Fatalf("PCR %d after: %v", pcr, w)
		}
	}
	if w := MeasurePointWordsAt(MeasurePointAfterSeparator, 11); len(w) != 1 || w[0] != EnterInitrdWord {
		t.Fatalf("PCR 11 after: %v", w)
	}
}

func TestApplyMeasurePointExtendsAtPoint(t *testing.T) {
	for _, algo := range []PCRHashAlgo{PCRHashAlgoSHA1, PCRHashAlgoSHA256} {
		zero := make([]byte, len(DigestOf(algo, nil)))
		values := map[int][]byte{4: zero, 11: zero}
		got := ApplyMeasurePointExtends(values, []int{4, 11}, algo, MeasurePointBeforeSeparator, false)
		if got != "enter-initrd:11" {
			t.Fatalf("%s before: applied %q", algo, got)
		}
		if !bytes.Equal(values[4], zero) {
			t.Fatalf("%s: PCR 4 must stay at its end-of-firmware value before the separator", algo)
		}
		want := ExtendDigest(algo, zero, DigestOf(algo, []byte(EnterInitrdWord)))
		if !bytes.Equal(values[11], want) {
			t.Fatalf("%s: PCR 11 should carry enter-initrd", algo)
		}

		values = map[int][]byte{4: zero, 11: zero}
		got = ApplyMeasurePointExtends(values, []int{4, 11}, algo, MeasurePointAfterSeparator, false)
		if !strings.Contains(got, "os-separator:4") || !strings.Contains(got, "enter-initrd:11") {
			t.Fatalf("%s after: applied %q", algo, got)
		}
	}
}

func TestSeparatorLockedAndStatus(t *testing.T) {
	for _, algo := range []PCRHashAlgo{PCRHashAlgoSHA1, PCRHashAlgoSHA256} {
		sealed := DigestOf(algo, []byte("end of firmware"))
		live := ExtendDigest(algo, sealed, DigestOf(algo, []byte(OSSeparatorWord)))
		if !SeparatorLocked(sealed, live) {
			t.Fatalf("%s: separator-extended register should count as locked", algo)
		}
		if SeparatorLocked(sealed, sealed) || SeparatorLocked(sealed, DigestOf(algo, []byte("other"))) {
			t.Fatalf("%s: equal or unrelated values are not locked", algo)
		}
		if s := PCRStatus(sealed, live); !strings.Contains(s, "LOCKED") {
			t.Fatalf("%s: status %q", algo, s)
		}
		if s := PCRStatus(sealed, sealed); s != "✓ MATCH" {
			t.Fatalf("%s: status %q", algo, s)
		}
		if s := PCRStatus(sealed, DigestOf(algo, []byte("other"))); s != "✗ CHANGED" {
			t.Fatalf("%s: status %q", algo, s)
		}
	}
}

func TestBlobMeasurePoint(t *testing.T) {
	cases := map[string]MeasurePoint{
		"":                                   MeasurePointBeforeSeparator,
		"enter-initrd:11":                    MeasurePointBeforeSeparator,
		"enter-initrd:11;os-separator:0,2,7": MeasurePointAfterSeparator, // sealed by an older version
	}
	for ext, want := range cases {
		sb := &SealedBlob{Payload: SealedBlobPayload{EventlogInfo: &EventlogInfo{MeasurePointExtends: ext}}}
		if got := sb.MeasurePoint(); got != want {
			t.Errorf("extends %q: got %v, want %v", ext, got, want)
		}
	}
	if (&SealedBlob{}).MeasurePoint() != MeasurePointBeforeSeparator {
		t.Error("a blob without eventlog info is checked before the separator")
	}
}
