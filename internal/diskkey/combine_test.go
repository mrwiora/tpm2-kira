package diskkey

import (
	"testing"
)

// cheapCombine makes Combine cheap for the rest of the test, for the tests
// of what happens around the derivation: the key's route, the prompts, the
// modes. The derivation itself is TestCombineKnownAnswer's.
func cheapCombine(t *testing.T) {
	t.Helper()
	mem, it := combineMemoryKiB, combineIterations
	combineMemoryKiB, combineIterations = 8*1024, 1
	t.Cleanup(func() { combineMemoryKiB, combineIterations = mem, it })
}

// TestCombineKnownAnswer pins the derivation to a key file the earlier
// separate combiner (hashpwd2) derived from the same password and salt: a
// keyslot enrolled with it keeps opening.
func TestCombineKnownAnswer(t *testing.T) {
	if testing.Short() {
		t.Skip("1 GiB of Argon2id")
	}
	if combineMemoryKiB != 1<<20 || combineIterations != 16 || combineParallelism != 4 {
		t.Fatalf("not the combiner's cost: %d KiB, %d passes, %d lanes", combineMemoryKiB, combineIterations, combineParallelism)
	}
	const (
		password = "correct horse battery staple"
		salt     = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		want     = "Lko7sdgG7YSiruQ6Mk+OqsnJUYFzMTpZ9mSDQ9f4n/6c2cmPNg0Rc6emq+TAB/wqwV8DUhj5IvjlKAs0LEbtfw\n"
	)
	key, err := Combine([]byte(password), []byte(salt))
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != want {
		t.Fatalf("Combine derives %q, want %q", key, want)
	}
}

func TestCombineRefusesEmptyInput(t *testing.T) {
	for _, in := range [][2]string{{"", "salt"}, {"pw", ""}, {"", ""}} {
		if key, err := Combine([]byte(in[0]), []byte(in[1])); err == nil || key != nil {
			t.Errorf("%q: %q %v", in, key, err)
		}
	}
}
