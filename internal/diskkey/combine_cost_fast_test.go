//go:build kira_test_fast_kdf

package diskkey

import "testing"

// A test build is cheaper than production, says so, and derives another key.
func TestFastBuildIsAnotherCost(t *testing.T) {
	if combineMemoryKiB >= productionMemoryKiB || combineIterations >= productionIterations {
		t.Fatalf("no cheaper: %d KiB, %d passes", combineMemoryKiB, combineIterations)
	}
	if TestBuildNote == "" {
		t.Fatal("a test build must say so")
	}
	const production = "Lko7sdgG7YSiruQ6Mk+OqsnJUYFzMTpZ9mSDQ9f4n/6c2cmPNg0Rc6emq+TAB/wqwV8DUhj5IvjlKAs0LEbtfw\n"
	key, err := Combine([]byte("correct horse battery staple"), []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if string(key) == production {
		t.Fatal("a test build derives the production key")
	}
}
