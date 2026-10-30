package admin

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Hibernation to a plain swap is named; to dm-crypt, LVM on dm-crypt, a
// swap file on an encrypted file system or zram it is not; without
// hibernation (lockdown) nothing is.
func TestPlainSwaps(t *testing.T) {
	root := t.TempDir()
	old := swapPaths
	t.Cleanup(func() { swapPaths = old })
	swapPaths.powerState = filepath.Join(root, "state")
	swapPaths.swaps = filepath.Join(root, "swaps")
	swapPaths.mountinfo = filepath.Join(root, "mountinfo")
	swapPaths.sysBlock = filepath.Join(root, "block")
	write := func(p, s string) {
		t.Helper()
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	block := func(name, uuid string, slaves ...string) {
		t.Helper()
		d := filepath.Join(swapPaths.sysBlock, name)
		os.MkdirAll(filepath.Join(d, "slaves"), 0o755)
		if uuid != "" {
			write(filepath.Join(d, "dm", "uuid"), uuid+"\n")
		}
		for _, s := range slaves {
			os.MkdirAll(filepath.Join(d, "slaves", s), 0o755)
		}
	}
	block("sda2", "")
	block("dm-0", "CRYPT-LUKS2-abc-root")
	block("dm-1", "LVM-xyz", "dm-0")
	block("dm-2", "LVM-plain", "sda3")
	block("sda3", "")
	block("zram0", "")
	write(swapPaths.mountinfo, `22 1 254:0 / / rw,relatime - ext4 /dev/dm-0 rw
30 22 8:1 / /data rw - ext4 /dev/sda4 rw
`)
	block("sda4", "")
	write(swapPaths.swaps, `Filename				Type		Size		Used		Priority
/dev/sda2                               partition	1048572		0		-2
/dev/dm-1                               partition	1048572		0		-3
/dev/dm-2                               partition	1048572		0		-4
/dev/zram0                              partition	1048572		0		100
/swapfile                               file		1048572		0		-5
/data/swapfile                          file		1048572		0		-6
`)
	write(swapPaths.powerState, "freeze mem disk\n")
	if got, want := plainSwaps(), []string{"/dev/sda2", "/dev/dm-2", "/data/swapfile"}; !slices.Equal(got, want) {
		t.Fatalf("plain swaps %v, want %v", got, want)
	}
	write(swapPaths.powerState, "freeze mem\n")
	if got := plainSwaps(); got != nil {
		t.Fatalf("without hibernation: %v", got)
	}
}
