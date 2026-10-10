package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// What the boot image holds of the phone's gate: whether the image that
// boots next carries the Bluetooth adapter's driver and firmware, looked up
// in the image itself (lsinitcpio, which unpacks a unified kernel image
// too, or Debian's lsinitramfs). The hooks add it (attest_initramfs.go);
// this is control's check that they did.

// btModulesLoadConf is the file the hooks write next to the modules: its
// presence means the gate's part went in.
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

// imageBluetoothProblem says what the boot images lack of the adapter's
// part, given the firmware it needs: "" when every image carries the
// gate's modules and that firmware.
func imageBluetoothProblem(firmware []string) string {
	images := bootImages()
	if len(images) == 0 {
		return ""
	}
	for _, img := range images {
		files, err := imageFiles(img)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Sprintf("%s cannot be read (%v)", img, err)
		}
		if !files[btModulesLoadConf] {
			return fmt.Sprintf("%s holds no Bluetooth: the hook did not add it (see the mkinitcpio output) - rebuild", filepath.Base(img))
		}
		if !files[strings.TrimPrefix(DefaultAttestSignerPath, "/")] {
			return fmt.Sprintf("%s lacks the signing public key the phone check needs (%s): the gate does not start - rebuild", filepath.Base(img), DefaultAttestSignerPath)
		}
		for _, fw := range firmware {
			if !imageHasFirmware(files, fw) {
				return fmt.Sprintf("%s lacks the adapter's firmware %s - rebuild", filepath.Base(img), fw)
			}
		}
	}
	return ""
}

func imageHasFirmware(files map[string]bool, fw string) bool {
	for _, dir := range []string{"usr/lib/firmware/", "lib/firmware/"} {
		for _, ext := range []string{"", ".zst", ".xz", ".gz"} {
			if files[dir+fw+ext] {
				return true
			}
		}
	}
	return false
}

// imageAuthorizationProblem says whether the boot image lacks the rule
// that lets the adapter in, when its bus lets no new device in by itself:
// "" when the image carries it.
func imageAuthorizationProblem(dev *USBDevice) string {
	for _, img := range bootImages() {
		files, err := imageFiles(img)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Sprintf("%s cannot be read (%v)", img, err)
		}
		if !files[BTUdevRuleFile] {
			return fmt.Sprintf("the USB bus lets no new device in, and %s has no rule for the adapter (USB %s, %s:%s) - rebuild",
				filepath.Base(img), dev.Port, dev.Vendor, dev.Product)
		}
	}
	return ""
}
