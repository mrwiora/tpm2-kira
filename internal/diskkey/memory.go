package diskkey

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
)

// MemoryNote says what this process holds now, for the boot's log: the Go heap
// not given back to the kernel, what is resident, and the most that was
// (docs/DISK-KEY.md, "Memory"). Numbers alone; nothing of what they hold.
func MemoryNote() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Sprintf("memory: heap %d MiB", (m.HeapSys-m.HeapReleased)>>20)
	}
	return fmt.Sprintf("memory: heap %d MiB, resident %d MiB, peak %d MiB", (m.HeapSys-m.HeapReleased)>>20, statusMiB(status, "VmRSS"), statusMiB(status, "VmHWM"))
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
