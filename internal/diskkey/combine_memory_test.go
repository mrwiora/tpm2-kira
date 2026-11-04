//go:build !kira_test_fast_kdf

package diskkey

import (
	"os"
	"runtime"
	"testing"
)

// memoryNow is the Go heap not given back and what is resident, in MiB.
func memoryNow(t *testing.T) (heap, resident uint64) {
	t.Helper()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skip(err)
	}
	return (m.HeapSys - m.HeapReleased) >> 20, statusMiB(status, "VmRSS")
}

// A boot after a wrong pepper derives twice, and the keyslot's Argon2id comes on
// top: nothing of the two may stay with the process (docs/DISK-KEY.md, "Memory").
func TestCombineGivesItsMemoryBack(t *testing.T) {
	if testing.Short() {
		t.Skip("2 GiB-passes of Argon2id")
	}
	heap, resident := memoryNow(t)
	t.Logf("before: heap %d MiB, resident %d MiB", heap, resident)
	for i := 1; i <= 2; i++ {
		key, err := Combine([]byte("a password"), []byte("a salt"))
		if err != nil {
			t.Fatal(err)
		}
		if len(key) == 0 {
			t.Fatal("no key")
		}
		h, r := memoryNow(t)
		t.Logf("after derivation %d: heap %d MiB, resident %d MiB", i, h, r)
		if h > heap+64 || r > resident+64 {
			t.Errorf("after derivation %d the process holds heap %d MiB, resident %d MiB (before: %d, %d)", i, h, r, heap, resident)
		}
	}
	status, _ := os.ReadFile("/proc/self/status")
	t.Logf("peak: %d MiB", statusMiB(status, "VmHWM"))
	if hwm := statusMiB(status, "VmHWM"); hwm > 1400 {
		t.Errorf("the peak is %d MiB: two derivations add up", hwm)
	}
}
