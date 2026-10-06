package main

import (
	"os"
	"strings"
	"testing"
)

// directives returns the non-comment lines of a unit file.
func directives(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

func has(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// The initrd units are installed on the host too (the mkinitcpio hook takes
// them from there). Enabled on the host by mistake they must do nothing.
func TestInitrdUnitsOnlyRunInTheInitrd(t *testing.T) {
	for _, unit := range []string{"tpm2-kira.service", "tpm2-kira-cap.service", "tpm2-kira-attest.service"} {
		if !has(directives(t, "initramfs/systemd/"+unit), "ConditionPathExists=/etc/initrd-release") {
			t.Errorf("%s lacks ConditionPathExists=/etc/initrd-release", unit)
		}
	}
}

// The Bluetooth gate parses radio input as root before the disk is unlocked.
// Its unit confines it to what it needs; this pins the parts that matter, so
// a later edit cannot quietly drop them.
func TestGateUnitIsConfined(t *testing.T) {
	lines := directives(t, "initramfs/systemd/tpm2-kira-attest.service")
	for _, want := range []string{
		"NoNewPrivileges=yes",
		"CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW",
		"RestrictAddressFamilies=AF_BLUETOOTH AF_UNIX",
		"IPAddressDeny=any",
		"DevicePolicy=closed",
		"ProtectSystem=strict",
		"ProtectKernelTunables=yes",
		"MemoryDenyWriteExecute=yes",
		"SystemCallFilter=@system-service",
		"SystemCallFilter=~@privileged",
		"SystemCallErrorNumber=EPERM",
	} {
		if !has(lines, want) {
			t.Errorf("gate unit lacks %q", want)
		}
	}
	// What the gate cannot work without.
	for _, want := range []string{"DeviceAllow=/dev/tpmrm0 rw", "DeviceAllow=/dev/rfkill rw", "DeviceAllow=/dev/console rw"} {
		if !has(lines, want) {
			t.Errorf("gate unit lacks %q", want)
		}
	}
	// Bluetooth sockets exist only in the initial network namespace, and
	// the TPM is a device.
	for _, bad := range []string{"PrivateNetwork=yes", "PrivateDevices=yes"} {
		if has(lines, bad) {
			t.Errorf("gate unit has %q, which breaks it", bad)
		}
	}
}
