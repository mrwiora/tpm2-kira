package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeSysfs builds a sysfs tree for a USB Bluetooth adapter behind xhci:
//
//	/sys/devices/pci0000:00/0000:00:14.0           driver xhci_hcd, module xhci_pci
//	  /usb1/1-10                                   driver usb (built in, no module link)
//	    /1-10:1.0                                  driver btusb, module btusb
//	      /bluetooth/hci0                          <- /sys/class/bluetooth/hci0
func fakeSysfs(t *testing.T) string {
	root := t.TempDir()
	mk := func(p string) string {
		d := filepath.Join(root, p)
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
		return d
	}
	link := func(target, name string) {
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	mk("module/xhci_pci")
	mk("module/btusb")
	mk("bus/pci/drivers/xhci_hcd")
	mk("bus/usb/drivers/usb")
	mk("bus/usb/drivers/btusb")
	link(filepath.Join(root, "module/xhci_pci"), filepath.Join(root, "bus/pci/drivers/xhci_hcd/module"))
	link(filepath.Join(root, "module/btusb"), filepath.Join(root, "bus/usb/drivers/btusb/module"))

	pci := mk("devices/pci0000:00/0000:00:14.0")
	usb := mk("devices/pci0000:00/0000:00:14.0/usb1/1-10")
	iface := mk("devices/pci0000:00/0000:00:14.0/usb1/1-10/1-10:1.0")
	hci := mk("devices/pci0000:00/0000:00:14.0/usb1/1-10/1-10:1.0/bluetooth/hci0")
	link(filepath.Join(root, "bus/pci/drivers/xhci_hcd"), filepath.Join(pci, "driver"))
	link(filepath.Join(root, "bus/usb/drivers/usb"), filepath.Join(usb, "driver"))
	link(filepath.Join(root, "bus/usb/drivers/btusb"), filepath.Join(iface, "driver"))
	mk("class/bluetooth")
	link(hci, filepath.Join(root, "class/bluetooth/hci0"))
	return root
}

func fakeFirmware(t *testing.T, files ...string) string {
	dir := t.TempDir()
	for _, f := range files {
		p := filepath.Join(dir, f)
		os.MkdirAll(filepath.Dir(p), 0755)
		if err := os.WriteFile(p, []byte("fw"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const intelLog = `[    2.101] Bluetooth: Core ver 2.22
[    2.304] Bluetooth: hci0: Device revision is 0
[    2.305] Bluetooth: hci0: Found device firmware: intel/ibt-0041-0041.sfi
[    2.306] Bluetooth: hci1: Found device firmware: intel/ibt-other.sfi
[    3.112] Bluetooth: hci0: Found Intel DDC parameters: intel/ibt-0041-0041.ddc
[    3.113] Bluetooth: hci0: Waiting for firmware download to complete
[    3.114] Bluetooth: hci0: Found device firmware: intel/ibt-0041-0041.sfi
`

func TestResolveBTDepsIntelUSB(t *testing.T) {
	sys := fakeSysfs(t)
	fw := fakeFirmware(t, "intel/ibt-0041-0041.sfi.zst", "intel/ibt-0041-0041.ddc.zst", "intel/ibt-other.sfi")
	deps, err := ResolveBTDeps(sys, fw, 0, []byte(intelLog))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"btusb", "xhci_pci", "bluetooth"}; !reflect.DeepEqual(deps.Modules, want) {
		t.Fatalf("modules %v, want %v", deps.Modules, want)
	}
	// Only hci0's files, deduplicated, compressed variants recognised.
	if want := []string{"intel/ibt-0041-0041.sfi", "intel/ibt-0041-0041.ddc"}; !reflect.DeepEqual(deps.Firmware, want) {
		t.Fatalf("firmware %v, want %v", deps.Firmware, want)
	}
	if len(deps.Warnings) != 0 {
		t.Fatalf("unexpected warnings %v", deps.Warnings)
	}
}

func TestResolveBTDepsRealtekAndBroadcomLogFormats(t *testing.T) {
	sys := fakeSysfs(t)
	fw := fakeFirmware(t, "rtl_bt/rtl8761bu_fw.bin", "rtl_bt/rtl8761bu_config.bin", "brcm/BCM20702A1-0a5c-21e8.hcd")
	log := "Bluetooth: hci0: RTL: loading rtl_bt/rtl8761bu_fw.bin\n" +
		"Bluetooth: hci0: RTL: loading rtl_bt/rtl8761bu_config.bin\n" +
		"Bluetooth: hci0: BCM: 'brcm/BCM20702A1-0a5c-21e8.hcd'\n" +
		"Bluetooth: hci0: RTL: loading rtl_bt/missing_fw.bin\n"
	deps, err := ResolveBTDeps(sys, fw, 0, []byte(log))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"rtl_bt/rtl8761bu_fw.bin", "rtl_bt/rtl8761bu_config.bin", "brcm/BCM20702A1-0a5c-21e8.hcd"}
	if !reflect.DeepEqual(deps.Firmware, want) {
		t.Fatalf("firmware %v, want %v", deps.Firmware, want)
	}
}

func TestResolveBTDepsNoAdapterAndNoLog(t *testing.T) {
	sys := fakeSysfs(t)
	if _, err := ResolveBTDeps(sys, t.TempDir(), 3, nil); err == nil {
		t.Fatal("hci3 does not exist")
	}
	deps, err := ResolveBTDeps(sys, t.TempDir(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps.Firmware) != 0 || len(deps.Warnings) != 1 {
		t.Fatalf("expected a firmware warning, got %+v", deps)
	}
}

func TestResolveBTDepsRejectsPathTraversal(t *testing.T) {
	sys := fakeSysfs(t)
	fw := fakeFirmware(t, "x.bin")
	deps, _ := ResolveBTDeps(sys, filepath.Join(fw, "sub"), 0, []byte("Bluetooth: hci0: loading ../x.bin\n"))
	if len(deps.Firmware) != 0 {
		t.Fatalf("path traversal accepted: %v", deps.Firmware)
	}
}

func TestParseAttestConfig(t *testing.T) {
	cfg, err := ParseAttestConfig([]byte(`
# comment
TPM2_KIRA_ATTEST_ADAPTER="hci1"
TPM2_KIRA_ATTEST_TIMEOUT=90
TPM2_KIRA_ATTEST_ADAPTER_WAIT=1m
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Adapter != 1 || cfg.Timeout != 90*time.Second || cfg.AdapterWait != time.Minute {
		t.Fatalf("parsed %+v", cfg)
	}
	// Debug is off unless asked for, and a typo is not silently "off".
	if cfg.Debug {
		t.Fatal("debug on by default")
	}
	for val, want := range map[string]bool{"1": true, "yes": true, "0": false, "off": false} {
		c, err := ParseAttestConfig([]byte("TPM2_KIRA_ATTEST_DEBUG=" + val + "\n"))
		if err != nil || c.Debug != want {
			t.Fatalf("TPM2_KIRA_ATTEST_DEBUG=%s: %v %v", val, c.Debug, err)
		}
	}
	if _, err := ParseAttestConfig([]byte("TPM2_KIRA_ATTEST_DEBUG=maybe\n")); err == nil {
		t.Fatal("invalid debug value accepted")
	}
	if _, err := ParseAttestConfig([]byte("TPM2_KIRA_ATTEST=lazy\n")); err == nil || !strings.Contains(err.Error(), "no attestation mode") {
		t.Fatalf("a mode line must be refused: %v", err)
	}
	if _, err := ParseAttestConfig([]byte("TPM2_KIRA_SOMETHING=1\n")); err == nil {
		t.Fatal("unknown key accepted")
	}
	def, err := LoadAttestConfig(filepath.Join(t.TempDir(), "missing"))
	if err != nil || def.AdapterWait != 30*time.Second {
		t.Fatalf("missing file should mean the defaults: %+v %v", def, err)
	}
}
