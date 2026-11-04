package attest_test

import (
	"bytes"
	"errors"
	"testing"

	. "github.com/tpm2-trust/tpm2-kira/core/attest"
)

func TestKeyboardRoundTrip(t *testing.T) {
	for _, n := range []int{KeyboardMinLength, 16, KeyboardMaxLength} {
		salt, err := NewKeyboardSalt(nil, n)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckKeyboardSalt(salt); err != nil {
			t.Fatal(err)
		}
		pad, err := NewKeyboardPad(nil, n)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := KeyboardKeys(salt, pad)
		if err != nil {
			t.Fatal(err)
		}
		got, err := KeyboardSaltOf(keys, pad)
		if err != nil || !bytes.Equal(got, salt) {
			t.Fatalf("%s through %v: %s, %v", keys, pad, got, err)
		}
		got, err = KeyboardSaltOf(bytes.ToUpper(keys), pad)
		if err != nil || !bytes.Equal(got, salt) {
			t.Fatalf("in capitals: %s, %v", got, err)
		}
	}
}

// The same salt gives other keys each boot, and every position takes every key: a recording says
// nothing, not even which characters of the salt repeat.
func TestKeyboardKeysSayNothing(t *testing.T) {
	salt := []byte("aaaaaaaa")
	seen := make([]map[byte]bool, len(salt))
	for i := range seen {
		seen[i] = map[byte]bool{}
	}
	sameEveryTime, equalAdjacent := true, 0
	var first []byte
	const rounds = 4000
	for r := 0; r < rounds; r++ {
		pad, err := NewKeyboardPad(nil, len(salt))
		if err != nil {
			t.Fatal(err)
		}
		keys, err := KeyboardKeys(salt, pad)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = keys
		} else if !bytes.Equal(first, keys) {
			sameEveryTime = false
		}
		for i, k := range keys {
			seen[i][k] = true
		}
		if keys[0] == keys[1] {
			equalAdjacent++
		}
	}
	if sameEveryTime {
		t.Error("the keys do not change")
	}
	for i, s := range seen {
		if len(s) != len(KeyboardAlphabet) {
			t.Errorf("position %d took %d of %d keys", i, len(s), len(KeyboardAlphabet))
		}
	}
	// A salt of one repeated character shows no repeats beyond chance (1 in 30).
	if equalAdjacent > rounds/10 {
		t.Errorf("adjacent keys equal %d of %d times", equalAdjacent, rounds)
	}
}

func TestKeyboardRefuses(t *testing.T) {
	for name, s := range map[string][]byte{
		"too short": []byte("abcdefg"), "too long": bytes.Repeat([]byte("a"), KeyboardMaxLength+1),
		"a y": []byte("abcdefgy"), "an l": []byte("abcdefgl"), "capitals": []byte("ABCDEFGH"), "a space": []byte("abcd fgh"),
	} {
		if CheckKeyboardSalt(s) == nil {
			t.Errorf("%s is taken for a salt", name)
		}
	}
	if _, err := NewKeyboardSalt(nil, KeyboardMinLength-1); err == nil {
		t.Error("a short salt was drawn")
	}
	pad := make([]byte, 8)
	for name, keys := range map[string][]byte{"too short": []byte("abc"), "outside": []byte("abcdefgy"), "empty": {}} {
		if _, err := KeyboardSaltOf(keys, pad); !errors.Is(err, ErrKeyboardKeys) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := KeyboardKeys([]byte("abcdefgh"), []byte{30, 0, 0, 0, 0, 0, 0, 0}); err == nil {
		t.Error("a pad value outside the alphabet was taken")
	}
}

// The phone's pad from its secret: the same for the same secret, another for another, and in range.
func TestKeyboardPadFrom(t *testing.T) {
	a := bytes.Repeat([]byte{1}, KeyboardSecretSize)
	p1, err := KeyboardPadFrom(a, 16)
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := KeyboardPadFrom(a, 16)
	p3, _ := KeyboardPadFrom(bytes.Repeat([]byte{2}, KeyboardSecretSize), 16)
	if !bytes.Equal(p1, p2) || bytes.Equal(p1, p3) {
		t.Fatalf("%v %v %v", p1, p2, p3)
	}
	short, _ := KeyboardPadFrom(a, 8)
	if !bytes.Equal(short, p1[:8]) {
		t.Fatalf("a shorter salt has another start: %v %v", short, p1)
	}
	for _, v := range p1 {
		if int(v) >= len(KeyboardAlphabet) {
			t.Fatalf("out of range: %v", p1)
		}
	}
	if _, err := KeyboardPadFrom(a[:8], 8); err == nil {
		t.Fatal("a short secret was taken")
	}
}
