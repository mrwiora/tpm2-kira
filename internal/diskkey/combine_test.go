package diskkey

import (
	"testing"

	"golang.org/x/crypto/argon2"
)

// cheapCombine makes the prompts' derivation cheap for the rest of the test,
// for the tests of what happens around it: the key's route, the prompts, the
// modes. Combine itself is tested at its cost (combine_cost_test.go).
func cheapCombine(t *testing.T) {
	t.Helper()
	saved := derive
	derive = func(password, salt []byte) ([]byte, error) {
		hash := argon2.IDKey(password, salt, 1, 8*1024, 1, combineKeyLength)
		return append(hash, '\n'), nil
	}
	t.Cleanup(func() { derive = saved })
}

func TestCombineRefusesEmptyInput(t *testing.T) {
	for _, in := range [][2]string{{"", "salt"}, {"pw", ""}, {"", ""}} {
		if key, err := Combine([]byte(in[0]), []byte(in[1])); err == nil || key != nil {
			t.Errorf("%q: %q %v", in, key, err)
		}
	}
}
