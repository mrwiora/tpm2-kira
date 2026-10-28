package admin

import (
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
