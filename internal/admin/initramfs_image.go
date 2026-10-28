package admin

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// The image that boots next, as its listing shows it (lsinitcpio, which
// unpacks a unified kernel image too, or Debian's lsinitramfs): control
// reads the boot plan the image names from it (bootplan.go, imagePlan).

// btModulesLoadConf is mkinitcpio's list of the adapter's modules, loaded
// by systemd-modules-load in the image.
const btModulesLoadConf = "etc/modules-load.d/tpm2-kira-bluetooth.conf"

// listImage lists an image's files; a var for the tests.
var listImage = func(img string) ([]string, error) {
	tool := "lsinitcpio"
	if isDebianInitramfs() {
		tool = "lsinitramfs"
	}
	out, err := exec.Command(tool, img).Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", tool, img, err)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}

// bootImages is the image the next boot starts: the first preset's default
// image on mkinitcpio (mkinitcpioImages), the running kernel's initrd on
// Debian.
func bootImages() []string {
	if isDebianInitramfs() {
		if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			return []string{"/boot/initrd.img-" + strings.TrimSpace(string(b))}
		}
		return nil
	}
	return mkinitcpioImages()
}

var imageListCache = struct {
	sync.Mutex
	m map[string]imageListing
}{m: map[string]imageListing{}}

type imageListing struct {
	mod   time.Time
	files map[string]bool
	err   error
}

// imageFiles lists img once per modification: control asks after every step.
func imageFiles(img string) (map[string]bool, error) {
	st, err := os.Stat(img)
	if err != nil {
		return nil, err
	}
	imageListCache.Lock()
	defer imageListCache.Unlock()
	if c, ok := imageListCache.m[img]; ok && c.mod.Equal(st.ModTime()) {
		return c.files, c.err
	}
	lines, err := listImage(img)
	files := map[string]bool{}
	for _, l := range lines {
		files[strings.TrimPrefix(strings.TrimSpace(l), "./")] = true
	}
	imageListCache.m[img] = imageListing{mod: st.ModTime(), files: files, err: err}
	return files, err
}
