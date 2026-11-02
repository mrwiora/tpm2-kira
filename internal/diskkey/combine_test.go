package diskkey

import (
	"runtime"
	"sync"
	"sync/atomic"
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

// One derivation at a time: the machine's memory floor counts one.
func TestCombinesDoNotOverlap(t *testing.T) {
	old := idKey
	t.Cleanup(func() { idKey = old })
	var running, most atomic.Int32
	idKey = func(_, _ []byte, _, _ uint32, _ uint8, n uint32) []byte {
		now := running.Add(1)
		if now > most.Load() {
			most.Store(now)
		}
		for range 1000 {
			runtime.Gosched()
		}
		running.Add(-1)
		return make([]byte, n)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Combine([]byte("p"), []byte("s")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if most.Load() != 1 {
		t.Fatalf("%d derivations ran at once", most.Load())
	}
}

func TestMemTotal(t *testing.T) {
	if got := memTotalMiB([]byte("MemFree: 1 kB\nMemTotal:       16297144 kB\nSwapTotal: 0 kB\n")); got != 15915 {
		t.Errorf("MemTotal: %d MiB", got)
	}
	if got := memTotalMiB([]byte("MemFree: 1 kB\n")); got != 0 {
		t.Errorf("no MemTotal: %d MiB", got)
	}
	if MemoryNote() == "" {
		t.Error("no note")
	}
}
