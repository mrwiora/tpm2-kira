package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

// Bluetooth inside the initramfs (PLAN-BLE.md §3.1).
//
// The initramfs hooks ask `tpm2-kira attest initramfs-deps` what the adapter
// on the build host needs, and copy exactly that: the driver modules along the
// adapter's sysfs path and the firmware files the kernel actually loaded for
// it. One implementation serves mkinitcpio (bash) and initramfs-tools (sh).
//
// Firmware comes from the kernel log, not from `modinfo -F firmware`: the
// modules' declarations are incomplete (btintel declares four legacy files,
// while current Intel adapters load names like intel/ibt-0041-0041.sfi that
// appear nowhere in modinfo), and copying every declared file would put
// megabytes of firmware for other chips into the image.
//
// A boot does not always log its firmware: an Intel controller that kept
// its firmware over a warm reboot says "Firmware already loaded" and names
// no file, and an image built in that boot would lack the file the next
// cold start needs ("firmware missing" in the initrd). So the hooks pass
// the kernel messages of every boot the journal keeps, and what was found
// is remembered per adapter (BTFirmwareStateDir) for a boot whose journal
// names none.

// DefaultFirmwareDir is where the kernel loads firmware from.
const DefaultFirmwareDir = "/usr/lib/firmware"

// BTFirmwareStateDir keeps, per adapter, the firmware files a kernel log
// once named for it. A variable so the tests can point it elsewhere.
var BTFirmwareStateDir = "/var/lib/tpm2-kira/bt-firmware"

// firmwareSiblings are files a driver loads next to the one it names:
// Intel's DDC parameters belong to its firmware image.
var firmwareSiblings = map[string][]string{".sfi": {".ddc"}}

// BTDeps is what an initramfs needs for one adapter.
type BTDeps struct {
	Adapter  string
	Key      string // the adapter's hardware identity (its modalias): the firmware depends on it
	Modules  []string
	Firmware []string // paths relative to the firmware directory, without compression suffix
	// Authorize is the adapter's USB device when its bus lets no new
	// device in by itself (usbcore.authorized_default=0, or 2 for an
	// external one; USBGuard sets 0): the image then needs a rule that
	// lets exactly this device in, or the driver never binds at boot.
	Authorize *USBDevice
	Warnings  []string
}

// USBDevice names one USB device: its port (the kernel's name for it,
// such as 3-10) and its vendor and product.
type USBDevice struct {
	Port, Vendor, Product string
}

// BTUdevRuleFile is where the hooks put the rule in the image.
const BTUdevRuleFile = "etc/udev/rules.d/70-tpm2-kira-bluetooth.rules"

// UdevRule is the rule that authorizes the device at its port, and only
// it: in the image alone, never on the host, where the person's own
// policy (USBGuard, their rules) decides.
func (d *USBDevice) UdevRule() string {
	return fmt.Sprintf(`ACTION=="add", SUBSYSTEM=="usb", KERNEL=="%s", ATTR{idVendor}=="%s", ATTR{idProduct}=="%s", ATTR{authorized}="1"`,
		d.Port, d.Vendor, d.Product)
}

// firmwareToken matches firmware file names as Bluetooth drivers log them:
// "intel/ibt-0041-0041.sfi", "rtl_bt/rtl8761bu_fw.bin", "'brcm/BCM20702A1-0a5c-21e8.hcd'".
var firmwareToken = regexp.MustCompile(`[A-Za-z0-9_][A-Za-z0-9_./+-]*\.(?:sfi|ddc|bin|hcd|tlv|nvm|bseq|dfu|fw|img|mbn)`)

// ResolveBTDeps finds the modules and firmware for hci<adapter>.
//
// sysRoot is normally "/sys", fwDir the firmware directory, and kernelLog
// the kernel messages of the current boot (dmesg/journal text).
func ResolveBTDeps(sysRoot, fwDir string, adapter int, kernelLog []byte) (*BTDeps, error) {
	name := fmt.Sprintf("hci%d", adapter)
	link := filepath.Join(sysRoot, "class", "bluetooth", name)
	real, err := filepath.EvalSymlinks(link)
	if err != nil {
		return nil, fmt.Errorf("no Bluetooth adapter %s on this machine", name)
	}
	deps := &BTDeps{Adapter: name, Key: adapterKey(real, filepath.Join(sysRoot, "devices"))}
	seen := map[string]bool{}
	addModule := func(m string) {
		m = strings.ReplaceAll(m, "-", "_")
		if m != "" && !seen[m] {
			seen[m] = true
			deps.Modules = append(deps.Modules, m)
		}
	}

	// Every driver along the device path: the Bluetooth driver itself
	// (btusb, hci_uart), and the bus drivers above it (xhci_pci for a USB
	// adapter) that must be loaded before the adapter can appear.
	devicesRoot := filepath.Join(sysRoot, "devices")
	for dir := real; strings.HasPrefix(dir, devicesRoot) && dir != devicesRoot; dir = filepath.Dir(dir) {
		mod, err := filepath.EvalSymlinks(filepath.Join(dir, "driver", "module"))
		if err == nil {
			addModule(filepath.Base(mod))
		}
	}
	addModule("bluetooth")
	deps.Authorize = usbAuthorization(real, devicesRoot)
	if len(deps.Modules) == 1 {
		deps.Warnings = append(deps.Warnings, fmt.Sprintf("no driver module found for %s; it may be built into the kernel", name))
	}

	// Firmware the kernel loaded for this adapter in this boot.
	fwSeen := map[string]bool{}
	prefix := name + ":"
	for _, line := range strings.Split(string(kernelLog), "\n") {
		if !strings.Contains(line, prefix) {
			continue
		}
		for _, tok := range firmwareToken.FindAllString(line, -1) {
			tok = strings.TrimPrefix(tok, "/lib/firmware/")
			tok = strings.TrimPrefix(tok, "/usr/lib/firmware/")
			if fwSeen[tok] || strings.Contains(tok, "..") {
				continue
			}
			if !firmwareExists(fwDir, tok) {
				continue
			}
			for _, f := range append([]string{tok}, siblings(tok)...) {
				if !fwSeen[f] && firmwareExists(fwDir, f) {
					fwSeen[f] = true
					deps.Firmware = append(deps.Firmware, f)
				}
			}
		}
	}
	return deps, nil
}

// usbAuthorization finds the USB device above the adapter and reports it
// when its bus does not let new devices in by default. The root hub of
// the bus (usbN) carries authorized_default: 1 all, 0 none, 2 internal
// only. With 2 an internal adapter is let in anyway, but its rule costs
// nothing and does not depend on how the port is described.
func usbAuthorization(hciDir, devicesRoot string) *USBDevice {
	var dev *USBDevice
	for dir := filepath.Dir(hciDir); strings.HasPrefix(dir, devicesRoot) && dir != devicesRoot; dir = filepath.Dir(dir) {
		if dev == nil {
			vendor, verr := os.ReadFile(filepath.Join(dir, "idVendor"))
			product, perr := os.ReadFile(filepath.Join(dir, "idProduct"))
			if verr == nil && perr == nil {
				dev = &USBDevice{Port: filepath.Base(dir), Vendor: strings.TrimSpace(string(vendor)), Product: strings.TrimSpace(string(product))}
			}
			continue
		}
		if b, err := os.ReadFile(filepath.Join(dir, "authorized_default")); err == nil {
			switch strings.TrimSpace(string(b)) {
			case "0", "2":
				return dev
			}
			return nil
		}
	}
	return nil
}

func siblings(file string) []string {
	ext := filepath.Ext(file)
	var out []string
	for _, other := range firmwareSiblings[ext] {
		out = append(out, strings.TrimSuffix(file, ext)+other)
	}
	return out
}

// adapterKey names the adapter's hardware for BTFirmwareStateDir: the
// modalias of the nearest device above hciN that has one (USB vendor,
// product and revision, for example), made a file name.
func adapterKey(hciDir, devicesRoot string) string {
	for dir := filepath.Dir(hciDir); strings.HasPrefix(dir, devicesRoot) && dir != devicesRoot; dir = filepath.Dir(dir) {
		if b, err := os.ReadFile(filepath.Join(dir, "modalias")); err == nil {
			alias := strings.TrimSpace(string(b))
			if alias != "" {
				return regexp.MustCompile(`[^A-Za-z0-9._-]`).ReplaceAllString(alias, "_")
			}
		}
	}
	return ""
}

// rememberedFirmware completes deps from BTFirmwareStateDir when no log
// named the adapter's firmware, and records what a log did name. It says
// in a warning which way it went when the log was silent.
func rememberedFirmware(deps *BTDeps, fwDir string) {
	if deps.Key == "" {
		if len(deps.Firmware) == 0 {
			deps.Warnings = append(deps.Warnings, noFirmwareWarning(deps.Adapter))
		}
		return
	}
	state := filepath.Join(BTFirmwareStateDir, deps.Key)
	if len(deps.Firmware) > 0 {
		if err := os.MkdirAll(BTFirmwareStateDir, 0o755); err == nil {
			os.WriteFile(state, []byte(strings.Join(deps.Firmware, "\n")+"\n"), 0o644)
		}
		return
	}
	data, err := os.ReadFile(state)
	if err == nil {
		for _, f := range strings.Fields(string(data)) {
			if !strings.Contains(f, "..") && firmwareExists(fwDir, f) {
				deps.Firmware = append(deps.Firmware, f)
			}
		}
	}
	if len(deps.Firmware) > 0 {
		deps.Warnings = append(deps.Warnings, fmt.Sprintf(
			"no kernel log names %s's firmware; using what an earlier boot loaded (%s)", deps.Adapter, strings.Join(deps.Firmware, ", ")))
		return
	}
	deps.Warnings = append(deps.Warnings, noFirmwareWarning(deps.Adapter))
}

func noFirmwareWarning(adapter string) string {
	return fmt.Sprintf("no kernel log names the firmware %s loads, and none is remembered: the image gets only the firmware "+
		"the modules declare, which for current Intel adapters is not the right file, and the adapter may then not start "+
		"in the initrd. Power the machine off (a cold start loads the firmware and logs it), boot, and rebuild (mkinitcpio -P)", adapter)
}

func firmwareExists(fwDir, rel string) bool {
	for _, ext := range []string{"", ".zst", ".xz"} {
		if st, err := os.Stat(filepath.Join(fwDir, rel+ext)); err == nil && st.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// readKernelLog returns the kernel ring buffer (needs CAP_SYSLOG, as the
// initramfs hooks have) plus an optional extra log file, e.g. the output of
// `journalctl -k -b`, which survives ring-buffer rotation on a long uptime.
func readKernelLog(extra string) []byte {
	var out []byte
	if size, err := unix.Klogctl(10, nil); err == nil && size > 0 { // SYSLOG_ACTION_SIZE_BUFFER
		buf := make([]byte, size)
		if n, err := unix.Klogctl(3, buf); err == nil { // SYSLOG_ACTION_READ_ALL
			out = append(out, buf[:n]...)
		}
	}
	if extra != "" {
		if data, err := os.ReadFile(extra); err == nil {
			out = append(out, '\n')
			out = append(out, data...)
		}
	}
	return out
}

// AttestInitramfsDeps prints the adapter's needs for the initramfs hooks:
//
//	adapter hci0
//	module btusb
//	firmware intel/ibt-0041-0041.sfi
//	udev <rule>     only when the bus lets no new device in by itself
//	warning <text>
//
// Exit status 0 when the adapter exists, ExitUnavailable when it does not.
func AttestInitramfsDeps(adapter int, kernelLogPath, fwDir string) int {
	if fwDir == "" {
		fwDir = DefaultFirmwareDir
	}
	deps, err := ResolveBTDeps("/sys", fwDir, adapter, readKernelLog(kernelLogPath))
	if err != nil {
		fmt.Printf("warning %v\n", err)
		return ExitUnavailable
	}
	rememberedFirmware(deps, fwDir)
	fmt.Printf("adapter %s\n", deps.Adapter)
	for _, m := range deps.Modules {
		fmt.Printf("module %s\n", m)
	}
	for _, f := range deps.Firmware {
		fmt.Printf("firmware %s\n", f)
	}
	if deps.Authorize != nil {
		fmt.Printf("udev %s\n", deps.Authorize.UdevRule())
	}
	for _, w := range deps.Warnings {
		fmt.Printf("warning %s\n", w)
	}
	return ExitAttested
}

// preferResourceManager returns /dev/tpmrm0 for a /dev/tpm0 path when the
// kernel's resource manager is available. The gate runs next to the OTP
// display in the initrd; on the raw device only one process may open the TPM,
// and the display's per-cycle cleanup would flush the gate's loaded AK.
func preferResourceManager(path string) string {
	if path != "/dev/tpm0" {
		return path
	}
	if st, err := os.Stat("/dev/tpmrm0"); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		return "/dev/tpmrm0"
	}
	return path
}

// adapterDeps is what the image build would put in for the adapter, by
// the same resolution the hooks run: the firmware this boot's or an
// earlier boot's kernel log names (or remembered), and the rule that lets
// the adapter in when its bus does not. nil when there is no such adapter.
func adapterDeps(adapter string) *BTDeps {
	var n int
	if _, err := fmt.Sscanf(adapter, "hci%d", &n); err != nil {
		return nil
	}
	deps, err := ResolveBTDeps("/sys", DefaultFirmwareDir, n, append(readKernelLog(""), journalBluetoothLines()...))
	if err != nil {
		return nil
	}
	rememberedFirmware(deps, DefaultFirmwareDir)
	return deps
}

// journalBluetoothLines are the Bluetooth kernel messages of every boot
// the journal keeps, as the hooks pass them.
func journalBluetoothLines() []byte {
	out, err := exec.Command("journalctl", "-k", "-o", "cat", "--no-pager", "-g", `Bluetooth: hci[0-9]+:`).Output()
	if err == nil {
		return out
	}
	all, err := exec.Command("journalctl", "-k", "-o", "cat", "--no-pager").Output()
	if err != nil {
		return nil
	}
	var keep []byte
	for _, l := range strings.Split(string(all), "\n") {
		if strings.Contains(l, "Bluetooth: hci") {
			keep = append(keep, l+"\n"...)
		}
	}
	return keep
}
