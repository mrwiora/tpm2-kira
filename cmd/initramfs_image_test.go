package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The checks look at the first preset's default image: its unified kernel
// image when it builds one, its initramfs otherwise. Fallback and further
// profiles are not checked yet.
func TestPresetDefaultImage(t *testing.T) {
	dir := t.TempDir()
	old := mkinitcpioPresetDir
	mkinitcpioPresetDir = dir
	defer func() { mkinitcpioPresetDir = old }()
	os.WriteFile(filepath.Join(dir, "linux.preset"), []byte(`ALL_kver="/boot/vmlinuz-linux"
PRESETS=('default' 'fallback')
#default_image="/boot/initramfs-linux.img"
tmp_uki="/boot/EFI/Linux/arch-linux-tmp.efi"
default_uki="/boot/EFI/Linux/arch-linux.efi"
fallback_uki="/boot/EFI/Linux/arch-linux-fallback.efi"
`), 0o644)
	if got := strings.Join(mkinitcpioImages(), " "); got != "/boot/EFI/Linux/arch-linux.efi" {
		t.Fatalf("images %q", got)
	}
	os.WriteFile(filepath.Join(dir, "linux.preset"), []byte("default_image=\"/boot/initramfs-linux.img\"\nfallback_image=\"/boot/initramfs-linux-fallback.img\"\n"), 0o644)
	if got := strings.Join(mkinitcpioImages(), " "); got != "/boot/initramfs-linux.img" {
		t.Fatalf("images %q", got)
	}
}

// control looks into the images: the gate's part and the adapter's
// firmware must be in every one the next boot may start.
func TestImageBluetoothProblem(t *testing.T) {
	dir := t.TempDir()
	old := mkinitcpioPresetDir
	mkinitcpioPresetDir = dir
	defer func() { mkinitcpioPresetDir = old }()
	img := filepath.Join(dir, "arch-linux.efi")
	os.WriteFile(img, []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "linux.preset"), []byte(`default_uki="`+img+`"`+"\n"), 0o644)

	oldList := listImage
	defer func() { listImage = oldList }()
	contents := []string{}
	listImage = func(string) ([]string, error) { return contents, nil }
	fw := []string{"intel/ibt-0040-0041.sfi"}

	if p := imageBluetoothProblem(fw); !strings.Contains(p, "holds no Bluetooth") {
		t.Fatalf("an image without the gate: %q", p)
	}
	contents = []string{"./" + btModulesLoadConf}
	touch := func() { // a new build: the cache goes by modification time
		st, _ := os.Stat(img)
		os.Chtimes(img, st.ModTime().Add(1e9), st.ModTime().Add(1e9))
	}
	touch()
	if p := imageBluetoothProblem(fw); !strings.Contains(p, "lacks the signing public key") {
		t.Fatalf("an image without the signer: %q", p)
	}
	contents = append(contents, "etc/tpm2-kira/attest-signer.pem")
	touch()
	if p := imageBluetoothProblem(fw); !strings.Contains(p, "lacks the adapter's firmware intel/ibt-0040-0041.sfi") {
		t.Fatalf("an image without the firmware: %q", p)
	}
	contents = append(contents, "usr/lib/firmware/intel/ibt-0040-0041.sfi.zst")
	touch()
	if p := imageBluetoothProblem(fw); p != "" {
		t.Fatalf("a complete image: %q", p)
	}
	listImage = func(string) ([]string, error) { return nil, errors.New("no objcopy") }
	touch()
	if p := imageBluetoothProblem(fw); !strings.Contains(p, "cannot be read") {
		t.Fatalf("an unreadable image: %q", p)
	}
}

func TestImageAuthorizationProblem(t *testing.T) {
	dir := t.TempDir()
	old := mkinitcpioPresetDir
	mkinitcpioPresetDir = dir
	defer func() { mkinitcpioPresetDir = old }()
	img := filepath.Join(dir, "arch-linux.efi")
	os.WriteFile(img, []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "linux.preset"), []byte(`default_uki="`+img+`"`+"\n"), 0o644)
	oldList := listImage
	defer func() { listImage = oldList }()
	contents := []string{btModulesLoadConf}
	listImage = func(string) ([]string, error) { return contents, nil }
	dev := &USBDevice{Port: "3-10", Vendor: "8087", Product: "0033"}

	if p := imageAuthorizationProblem(dev); !strings.Contains(p, "no rule for the adapter (USB 3-10, 8087:0033)") {
		t.Fatalf("an image without the rule: %q", p)
	}
	contents = append(contents, BTUdevRuleFile)
	st, _ := os.Stat(img)
	os.Chtimes(img, st.ModTime().Add(1e9), st.ModTime().Add(1e9))
	if p := imageAuthorizationProblem(dev); p != "" {
		t.Fatalf("an image with the rule: %q", p)
	}
}
