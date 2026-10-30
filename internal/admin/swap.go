package admin

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Hibernation writes the running system's memory - the disk's key, the
// passphrase's traces, everything - into a swap device. Onto an encrypted
// one it is as safe as the disk; onto a plain one it lies on the disk in
// the clear, and the kernel may resume it before the boot image runs at
// all, so nothing of tpm2-kira's (the SSH CA's window closed before a
// resume) comes in between. control shows it as a risk; tpm2-kira does not
// cover it.

// swapPaths are where the swap check reads; a var, for the tests.
var swapPaths = struct{ powerState, swaps, mountinfo, sysBlock string }{
	"/sys/power/state", "/proc/swaps", "/proc/self/mountinfo", "/sys/class/block",
}

// plainSwaps are the active swaps a hibernation image would be written to
// in the clear: none while the kernel offers no hibernation (no "disk" in
// /sys/power/state, as under lockdown). A swap is encrypted when its
// device - a partition's, or a swap file's file system's - is dm-crypt, or
// built on dm-crypt alone (LVM on LUKS); zram is memory, not a disk.
func plainSwaps() []string {
	state, err := os.ReadFile(swapPaths.powerState)
	if err != nil || !hasWord(string(state), "disk") {
		return nil
	}
	f, err := os.Open(swapPaths.swaps)
	if err != nil {
		return nil
	}
	defer f.Close()
	var plain []string
	sc := bufio.NewScanner(f)
	sc.Scan() // the header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		name, kind := strings.ReplaceAll(fields[0], `\040`, " "), fields[1]
		dev := name
		if kind == "file" {
			dev = mountSource(name)
		}
		if !encryptedDevice(dev) {
			plain = append(plain, name)
		}
	}
	return plain
}

func hasWord(s, w string) bool {
	for _, f := range strings.Fields(s) {
		if f == w {
			return true
		}
	}
	return false
}

// mountSource is the device of the file system path is on: the source of
// the longest mount point that holds it ("" when none is a device).
func mountSource(path string) string {
	f, err := os.Open(swapPaths.mountinfo)
	if err != nil {
		return ""
	}
	defer f.Close()
	best, src := -1, ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// ID parent maj:min root mountpoint options [optional...] - fstype source superopts
		l := sc.Text()
		pre, post, ok := strings.Cut(l, " - ")
		if !ok {
			continue
		}
		pf, qf := strings.Fields(pre), strings.Fields(post)
		if len(pf) < 5 || len(qf) < 2 {
			continue
		}
		mp := strings.ReplaceAll(pf[4], `\040`, " ")
		if path != mp && !strings.HasPrefix(path, strings.TrimSuffix(mp, "/")+"/") {
			continue
		}
		if len(mp) > best {
			best, src = len(mp), qf[1]
		}
	}
	return src
}

// encryptedDevice: dev is dm-crypt, or every device it is built on is; zram
// counts as encrypted (it never reaches a disk).
func encryptedDevice(dev string) bool {
	if !strings.HasPrefix(dev, "/dev/") {
		return false
	}
	if r, err := filepath.EvalSymlinks(dev); err == nil {
		dev = r
	}
	return encryptedBlock(filepath.Base(dev), 0)
}

func encryptedBlock(name string, depth int) bool {
	if depth > 8 {
		return false
	}
	if strings.HasPrefix(name, "zram") {
		return true
	}
	dir := filepath.Join(swapPaths.sysBlock, name)
	if uuid, err := os.ReadFile(filepath.Join(dir, "dm", "uuid")); err == nil && strings.HasPrefix(string(uuid), "CRYPT-") {
		return true
	}
	slaves, err := os.ReadDir(filepath.Join(dir, "slaves"))
	if err != nil || len(slaves) == 0 {
		return false
	}
	for _, s := range slaves {
		if !encryptedBlock(s.Name(), depth+1) {
			return false
		}
	}
	return true
}
