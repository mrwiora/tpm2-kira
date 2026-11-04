package diskkey

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
)

// MinMemoryMiB is the least RAM, as the kernel counts it (MemTotal), on which
// every step was measured to hold on both test machines with no swap touched, the
// memory lock on: Argon2id's 1 GiB, then the keyslot's own, beside the initrd
// (docs/DISK-KEY.md, "Memory").
const MinMemoryMiB uint64 = 1620

// MemTotalMiB is the machine's RAM as the kernel counts it; 0 when it cannot be read.
func MemTotalMiB() uint64 {
	data, err := os.ReadFile(MeminfoPath)
	if err != nil {
		return 0
	}
	return memTotalMiB(data)
}

// MeminfoPath is where MemTotalMiB reads; a test's file in a test.
var MeminfoPath = "/proc/meminfo"

var memTotalLine = regexp.MustCompile(`(?m)^MemTotal:\s+(\d+) kB$`)

func memTotalMiB(meminfo []byte) uint64 {
	m := memTotalLine.FindSubmatch(meminfo)
	if m == nil {
		return 0
	}
	var kib uint64
	fmt.Sscan(string(m[1]), &kib)
	return kib >> 10
}

// MemoryNote says what this process holds now, for the boot's log: the Go heap
// not given back to the kernel, what is resident, the most that was, and the
// locked address space, most of it the runtime's reservations and untouched
// (docs/DISK-KEY.md, "Memory"). Numbers alone; nothing of what they hold.
func MemoryNote() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Sprintf("memory: heap %d MiB", (m.HeapSys-m.HeapReleased)>>20)
	}
	return fmt.Sprintf("memory: heap %d MiB, resident %d MiB, peak %d MiB, locked %d MiB", (m.HeapSys-m.HeapReleased)>>20, statusMiB(status, "VmRSS"), statusMiB(status, "VmHWM"), statusMiB(status, "VmLck"))
}

var statusLine = regexp.MustCompile(`(?m)^(Vm[A-Za-z]+):\s+(\d+) kB$`)

// statusMiB is one VmXxx line of /proc/<pid>/status in MiB; 0 without it.
func statusMiB(status []byte, name string) uint64 {
	for _, m := range statusLine.FindAllSubmatch(status, -1) {
		if string(m[1]) == name {
			var kib uint64
			fmt.Sscan(string(m[2]), &kib)
			return kib >> 10
		}
	}
	return 0
}
