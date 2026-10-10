package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
	os.WriteFile(filepath.Join(iface, "modalias"), []byte("usb:v8087p0026d0002dcE0dsc01dp01icE0isc01ip01in00\n"), 0o644)
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
	BTFirmwareStateDir = t.TempDir()
	deps, err := ResolveBTDeps(sys, t.TempDir(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	rememberedFirmware(deps, t.TempDir())
	if len(deps.Firmware) != 0 || len(deps.Warnings) != 1 || !strings.Contains(deps.Warnings[0], "Power the machine off") {
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
	cfg, err := parseAttest([]byte(`
# comment
TPM2_KIRA_ATTEST_ADAPTER="hci1"
`))
	if err != nil || cfg.Adapter != 1 {
		t.Fatalf("parsed %+v %v", cfg, err)
	}
	// What the boot image used to read from the file is gone: the gate
	// waits as long as the code screen holds, and debug is a kernel
	// command line switch. Each says what replaces it.
	for line, want := range map[string]string{
		"TPM2_KIRA_ATTEST_TIMEOUT=90\n":      "as long as the code screen holds",
		"TPM2_KIRA_ATTEST_ADAPTER_WAIT=1m\n": "as long as the code screen holds",
		"TPM2_KIRA_ATTEST_DEBUG=1\n":         "Debug at boot",
		"TPM2_KIRA_ATTEST=lazy\n":            "no attestation mode",
	} {
		if _, err := parseAttest([]byte(line)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", line, err)
		}
	}
	if _, err := parseAttest([]byte("TPM2_KIRA_SOMETHING=1\n")); err == nil {
		t.Fatal("unknown key accepted")
	}
	def, err := LoadAttestConfig(filepath.Join(t.TempDir(), "missing"))
	if err != nil || def.Adapter != 0 || def.Bluetooth != "auto" {
		t.Fatalf("missing file should mean the defaults: %+v %v", def, err)
	}
}

// parseAttest is the radio part of control.conf's content.
func parseAttest(data []byte) (AttestConfig, error) {
	cfg, err := ParseControlConfig(data)
	return cfg.Attest, err
}

// A boot whose Intel controller kept its firmware over a warm reboot names
// no file. The image built in it must still carry the firmware a cold start
// needs: the one an earlier boot loaded, remembered per adapter - with its
// DDC file, which belongs to it even where the log names only the image.
func TestResolveBTDepsRemembersFirmwareOverAWarmReboot(t *testing.T) {
	sys := fakeSysfs(t)
	fw := fakeFirmware(t, "intel/ibt-0040-0041.sfi.zst", "intel/ibt-0040-0041.ddc.zst", "intel/ibt-11-5.sfi")
	BTFirmwareStateDir = filepath.Join(t.TempDir(), "state")

	cold := "Bluetooth: hci0: Found device firmware: intel/ibt-0040-0041.sfi\n"
	deps, err := ResolveBTDeps(sys, fw, 0, []byte(cold))
	if err != nil {
		t.Fatal(err)
	}
	rememberedFirmware(deps, fw)
	want := []string{"intel/ibt-0040-0041.sfi", "intel/ibt-0040-0041.ddc"}
	if !reflect.DeepEqual(deps.Firmware, want) || len(deps.Warnings) != 0 {
		t.Fatalf("cold start: %+v", deps)
	}

	warm := "Bluetooth: hci0: Firmware already loaded\nBluetooth: hci0: Firmware revision 0.0 build 191 week 21 2021\n"
	deps, err = ResolveBTDeps(sys, fw, 0, []byte(warm))
	if err != nil {
		t.Fatal(err)
	}
	rememberedFirmware(deps, fw)
	if !reflect.DeepEqual(deps.Firmware, want) || len(deps.Warnings) != 1 || !strings.Contains(deps.Warnings[0], "an earlier boot") {
		t.Fatalf("warm reboot: %+v", deps)
	}

	// Another adapter (another modalias) does not take this one's files.
	os.WriteFile(filepath.Join(sys, "devices/pci0000:00/0000:00:14.0/usb1/1-10/1-10:1.0/modalias"), []byte("usb:v0BDAp8771\n"), 0o644)
	deps, _ = ResolveBTDeps(sys, fw, 0, []byte(warm))
	rememberedFirmware(deps, fw)
	if len(deps.Firmware) != 0 {
		t.Fatalf("another adapter got these files: %v", deps.Firmware)
	}
}

// A USB bus that lets no new device in by itself (usbcore.authorized_
// default=0, as with USBGuard) needs a rule in the image for the adapter,
// exactly it at its port; a bus that lets devices in needs none.
func TestResolveBTDepsUSBAuthorization(t *testing.T) {
	sys := fakeSysfs(t)
	usb := filepath.Join(sys, "devices/pci0000:00/0000:00:14.0/usb1/1-10")
	os.WriteFile(filepath.Join(usb, "idVendor"), []byte("8087\n"), 0o644)
	os.WriteFile(filepath.Join(usb, "idProduct"), []byte("0033\n"), 0o644)
	bus := filepath.Join(sys, "devices/pci0000:00/0000:00:14.0/usb1")
	for value, want := range map[string]string{
		"1\n": "",
		"0\n": `ACTION=="add", SUBSYSTEM=="usb", KERNEL=="1-10", ATTR{idVendor}=="8087", ATTR{idProduct}=="0033", ATTR{authorized}="1"`,
		"2\n": `ACTION=="add", SUBSYSTEM=="usb", KERNEL=="1-10", ATTR{idVendor}=="8087", ATTR{idProduct}=="0033", ATTR{authorized}="1"`,
	} {
		os.WriteFile(filepath.Join(bus, "authorized_default"), []byte(value), 0o644)
		deps, err := ResolveBTDeps(sys, t.TempDir(), 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if deps.Authorize != nil {
			got = deps.Authorize.UdevRule()
		}
		if got != want {
			t.Errorf("authorized_default %q: rule %q, want %q", strings.TrimSpace(value), got, want)
		}
	}
}
