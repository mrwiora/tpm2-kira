package attest_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	. "github.com/tpm2-trust/tpm2-kira/core/attest"
)

func seedOf(b byte) []byte { return bytes.Repeat([]byte{b}, KeyboardSeedSize) }

// A layout is a permutation of the keys; the pepper goes there and back, capitals for their keys.
func TestKeyboardLayoutRoundTrip(t *testing.T) {
	for b := byte(0); b < 20; b++ {
		l, err := KeyboardLayoutOf(seedOf(b))
		if err != nil {
			t.Fatal(err)
		}
		shown := []byte(l.String())
		sorted, wantSorted := slices.Sorted(slices.Values(shown)), slices.Sorted(slices.Values([]byte(KeyboardKeys)))
		if !bytes.Equal(sorted, wantSorted) {
			t.Fatalf("not a permutation: %s", shown)
		}
		pepper := []byte("correct9horse")
		keys, err := l.Keys(pepper)
		if err != nil {
			t.Fatal(err)
		}
		got, err := l.Pepper(keys)
		if err != nil || !bytes.Equal(got, pepper) {
			t.Fatalf("%s through %s: %s, %v", keys, shown, got, err)
		}
		if got, err = l.Pepper(bytes.ToUpper(keys)); err != nil || !bytes.Equal(got, pepper) {
			t.Fatalf("in capitals: %s, %v", got, err)
		}
	}
}

// The same seed makes the same layout on the phone and the machine; another seed another one, and
// over many seeds every key shows every character.
func TestKeyboardLayoutFromTheSeed(t *testing.T) {
	a, _ := KeyboardLayoutOf(seedOf(1))
	b, _ := KeyboardLayoutOf(seedOf(1))
	c, _ := KeyboardLayoutOf(seedOf(2))
	if a.String() != b.String() || a.String() == c.String() {
		t.Fatalf("%s %s %s", a, b, c)
	}
	seen := make([]map[byte]bool, len(KeyboardKeys))
	for i := range seen {
		seen[i] = map[byte]bool{}
	}
	fixed := 0
	const rounds = 3000
	for r := 0; r < rounds; r++ {
		seed, err := NewKeyboardSeed(nil)
		if err != nil {
			t.Fatal(err)
		}
		l, err := KeyboardLayoutOf(seed)
		if err != nil {
			t.Fatal(err)
		}
		for i, c := range l.Shows {
			seen[i][c] = true
			if c == KeyboardKeys[i] {
				fixed++
			}
		}
	}
	for i, s := range seen {
		if len(s) != len(KeyboardKeys) {
			t.Errorf("key %c showed %d of %d characters", KeyboardKeys[i], len(s), len(KeyboardKeys))
		}
	}
	// A uniform permutation leaves one key in its place on average.
	if fixed > 2*rounds {
		t.Errorf("%d keys of %d layouts show themselves", fixed, rounds)
	}
}

func TestKeyboardPepperRefuses(t *testing.T) {
	l, _ := KeyboardLayoutOf(seedOf(3))
	for name, p := range map[string][]byte{
		"too short": []byte("abcdefg"), "too long": bytes.Repeat([]byte("a"), KeyboardPepperMax+1),
		"a space": []byte("abcd fgh"), "a dash": []byte("abcd-fgh"), "empty": {},
	} {
		if _, err := l.Pepper(p); !errors.Is(err, ErrKeyboardPepper) {
			t.Errorf("typed %s: %v", name, err)
		}
		if CheckKeyboardPepper(p) == nil {
			t.Errorf("%s is taken for a pepper", name)
		}
	}
	if CheckKeyboardPepper([]byte("ABCDEFGH")) == nil {
		t.Error("a pepper is set in capitals")
	}
	if CheckKeyboardPepper([]byte("abc12345")) != nil {
		t.Error("letters and digits are refused")
	}
	if _, err := KeyboardLayoutOf(seedOf(1)[:16]); err == nil {
		t.Error("a short seed was taken")
	}
}

// The US arrangement holds every key once.
func TestKeyboardUS(t *testing.T) {
	all := strings.Join(KeyboardUS, "")
	if len(all) != len(KeyboardKeys) {
		t.Fatalf("%d keys", len(all))
	}
	for _, c := range KeyboardKeys {
		if strings.Count(all, string(c)) != 1 {
			t.Errorf("%c", c)
		}
	}
}
