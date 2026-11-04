//go:build !kira_test_fast_kdf

package diskkey

import "testing"

// The default build has the real cost, whatever the package's constants are
// called: the numbers here are the security parameter, stated twice on purpose.
func TestCombineHasTheProductionCost(t *testing.T) {
	if productionMemoryKiB != 1<<20 || productionIterations != 16 || productionParallelism != 4 {
		t.Fatalf("the production cost changed: %d KiB, %d passes, %d lanes", productionMemoryKiB, productionIterations, productionParallelism)
	}
	if combineMemoryKiB != productionMemoryKiB || combineIterations != productionIterations || combineParallelism != productionParallelism {
		t.Fatalf("this build does not use the production cost: %d KiB, %d passes, %d lanes", combineMemoryKiB, combineIterations, combineParallelism)
	}
	if TestBuildNote != "" {
		t.Fatalf("the default build says it is a test build: %q", TestBuildNote)
	}
}

// TestCombineKnownAnswer pins the derivation at its cost to a key file the
// earlier separate combiner (hashpwd2) derived from the same password and salt:
// a keyslot enrolled with it keeps opening.
func TestCombineKnownAnswer(t *testing.T) {
	if testing.Short() {
		t.Skip("1 GiB of Argon2id")
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
