package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

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

const (
	// DefaultAttestConfigPath holds the attestation mode for the initramfs.
	DefaultAttestConfigPath = "/etc/tpm2-kira/attest.conf"
	// DefaultFirmwareDir is where the kernel loads firmware from.
	DefaultFirmwareDir = "/usr/lib/firmware"
)

// AttestConfig is /etc/tpm2-kira/attest.conf: shell-style KEY=VALUE lines,
// so the Debian init scripts can source the same file.
type AttestConfig struct {
	Mode        string        // TPM2_KIRA_ATTEST: off | lazy (enforced is not implemented)
	Adapter     int           // TPM2_KIRA_ATTEST_ADAPTER
	Timeout     time.Duration // TPM2_KIRA_ATTEST_TIMEOUT: 0 waits until the initrd ends
	AdapterWait time.Duration // TPM2_KIRA_ATTEST_ADAPTER_WAIT: how long to wait for hciN to appear
	Debug       bool          // TPM2_KIRA_ATTEST_DEBUG: the gate logs every step it takes
}

// DefaultAttestConfig is used when the file is missing.
func DefaultAttestConfig() AttestConfig {
	return AttestConfig{Mode: "off", AdapterWait: 30 * time.Second}
}

// LoadAttestConfig reads the config file; a missing file yields the defaults.
func LoadAttestConfig(path string) (AttestConfig, error) {
	cfg := DefaultAttestConfig()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	return ParseAttestConfig(data)
}

// ParseAttestConfig parses attest.conf content.
func ParseAttestConfig(data []byte) (AttestConfig, error) {
	cfg := DefaultAttestConfig()
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return cfg, fmt.Errorf("attest.conf line %d: expected KEY=VALUE", n)
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch key {
		case "TPM2_KIRA_ATTEST":
			switch val {
			case "off", "lazy":
				cfg.Mode = val
			case "enforced":
				return cfg, fmt.Errorf("attest.conf line %d: enforced mode is not implemented; use lazy", n)
			default:
				return cfg, fmt.Errorf("attest.conf line %d: TPM2_KIRA_ATTEST must be off or lazy, not %q", n, val)
			}
		case "TPM2_KIRA_ATTEST_ADAPTER":
			v, err := strconv.Atoi(strings.TrimPrefix(val, "hci"))
			if err != nil || v < 0 || v > 255 {
				return cfg, fmt.Errorf("attest.conf line %d: invalid adapter %q", n, val)
			}
			cfg.Adapter = v
		case "TPM2_KIRA_ATTEST_TIMEOUT", "TPM2_KIRA_ATTEST_ADAPTER_WAIT":
			d, err := parseSecondsOrDuration(val)
			if err != nil {
				return cfg, fmt.Errorf("attest.conf line %d: %v", n, err)
			}
			if key == "TPM2_KIRA_ATTEST_TIMEOUT" {
				cfg.Timeout = d
			} else {
				cfg.AdapterWait = d
			}
		case "TPM2_KIRA_ATTEST_DEBUG":
			switch strings.ToLower(val) {
			case "1", "yes", "true", "on":
				cfg.Debug = true
			case "", "0", "no", "false", "off":
				cfg.Debug = false
			default:
				return cfg, fmt.Errorf("attest.conf line %d: TPM2_KIRA_ATTEST_DEBUG must be 1 or 0, not %q", n, val)
			}
		default:
			// Unknown keys are ignored so newer files work with older binaries.
		}
	}
	return cfg, sc.Err()
}

// parseSecondsOrDuration accepts "30" (seconds) or a Go duration ("2m").
func parseSecondsOrDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

// BTDeps is what an initramfs needs for one adapter.
type BTDeps struct {
	Adapter  string
	Modules  []string
	Firmware []string // paths relative to the firmware directory, without compression suffix
	Warnings []string
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
	deps := &BTDeps{Adapter: name}
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
			if firmwareExists(fwDir, tok) {
				fwSeen[tok] = true
				deps.Firmware = append(deps.Firmware, tok)
			}
		}
	}
	if len(deps.Firmware) == 0 {
		deps.Warnings = append(deps.Warnings, fmt.Sprintf(
			"the kernel log records no firmware load for %s (adapter without firmware, or log rotated); relying on the firmware the modules declare", name))
	}
	return deps, nil
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
	fmt.Printf("adapter %s\n", deps.Adapter)
	for _, m := range deps.Modules {
		fmt.Printf("module %s\n", m)
	}
	for _, f := range deps.Firmware {
		fmt.Printf("firmware %s\n", f)
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
