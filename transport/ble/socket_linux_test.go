package ble

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeUSBAdapter lays out sysfs as for a USB Bluetooth adapter and returns
// the hciN "device" link and the USB device's power/control file.
func fakeUSBAdapter(t *testing.T, control string) (string, string) {
	root := t.TempDir()
	usb := filepath.Join(root, "devices", "usb2", "2-7")
	iface := filepath.Join(usb, "2-7:1.0")
	if err := os.MkdirAll(filepath.Join(usb, "power"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(iface, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(usb, "idVendor"), []byte("8087\n"), 0o644)
	ctl := filepath.Join(usb, "power", "control")
	_ = os.WriteFile(ctl, []byte(control+"\n"), 0o644)
	link := filepath.Join(root, "class", "bluetooth", "hci0", "device")
	_ = os.MkdirAll(filepath.Dir(link), 0o755)
	if err := os.Symlink(iface, link); err != nil {
		t.Fatal(err)
	}
	return link, ctl
}

func readControl(t *testing.T, ctl string) string {
	b, err := os.ReadFile(ctl)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestKeepUSBAwake(t *testing.T) {
	link, ctl := fakeUSBAdapter(t, "auto")
	restore := keepUSBAwake(link, t.Logf)
	if got := readControl(t, ctl); got != "on" {
		t.Fatalf("while in use: power/control = %q, want on", got)
	}
	restore()
	if got := readControl(t, ctl); got != "auto" {
		t.Fatalf("after release: power/control = %q, want auto", got)
	}
}

func TestKeepUSBAwakeLeavesOthersAlone(t *testing.T) {
	link, ctl := fakeUSBAdapter(t, "on")
	keepUSBAwake(link, t.Logf)()
	if got := readControl(t, ctl); got != "on" {
		t.Fatalf("power/control = %q, want on unchanged", got)
	}
	// Not a USB adapter (no idVendor anywhere up the tree): nothing happens.
	keepUSBAwake(filepath.Join(t.TempDir(), "missing"), t.Logf)()
}
