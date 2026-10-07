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
	for _, unit := range []string{"tpm2-kira.service", "tpm2-kira-cap.service", "tpm2-kira-attest.service", "tpm2-kira-unlock.socket"} {
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
	// What the gate did must be readable after the boot, not only on a
	// screen that has since been cleared.
	if !has(lines, "StandardOutput=journal+console") || !has(lines, "StandardError=journal+console") {
		t.Error("the gate's output does not reach the journal")
	}
	// The gate runs next to the code screen, not after it: a slot enrolled
	// with a phone is verified while the code is shown.
	if has(lines, "After=systemd-pcrosseparator.service") || has(lines, "After=tpm2-kira.service") {
		t.Error("the gate waits for the code screen to end")
	}
	if !has(lines, "After=systemd-pcrphase-initrd.service") {
		t.Error("the gate may quote before enter-initrd is in PCR 11")
	}
	// The radio worker has no TPM (it would compute TOTP codes while the
	// code screen is up); the coordinator in tpm2-kira.service has it.
	for _, l := range lines {
		if strings.HasPrefix(l, "DeviceAllow=") && strings.Contains(l, "tpm") {
			t.Errorf("the radio worker is given a TPM: %s", l)
		}
		if strings.Contains(l, "dev-tpm") {
			t.Errorf("the radio worker depends on a TPM device: %s", l)
		}
		if strings.HasPrefix(l, "RuntimeDirectory") || strings.HasPrefix(l, "ReadWritePaths") {
			t.Errorf("the radio worker can write to the file system: %s", l)
		}
	}
	const socket = "/run/tpm2-kira/gate.sock"
	if !has(lines, "ExecStart=/usr/bin/tpm2-kira attest gate --coordinator "+socket) {
		t.Error("the radio worker is not pointed at its coordinator")
	}
	display := directives(t, "initramfs/systemd/tpm2-kira.service")
	// The code screen owns the terminal; what the key provider reports
	// (stderr) must be readable after the boot as well.
	if !has(display, "StandardInput=tty") || !has(display, "StandardOutput=tty") || !has(display, "StandardError=journal+console") {
		t.Error("the display's terminal and journal wiring")
	}
	if !has(display, "ExecStart=tpm2-kira run --gate "+socket) {
		t.Error("the code screen does not listen where the radio worker asks")
	}
	if !has(display, "Before=systemd-pcrosseparator.service") || !has(display, "Conflicts=initrd-switch-root.target") {
		t.Error("the coordinator must hold the separator back and end with the initramfs")
	}
	// What the gate cannot work without.
	for _, want := range []string{"DeviceAllow=/dev/rfkill rw", "DeviceAllow=/dev/console rw"} {
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

// The disk's key comes from tpm2-kira: the socket unit is the key file of
// the volumes (crypttab(5), AF_UNIX key files), exists before any
// cryptsetup unit, and is answered by the display's process.
func TestUnlockSocketIsWiredToTheDisplay(t *testing.T) {
	sock := directives(t, "initramfs/systemd/tpm2-kira-unlock.socket")
	for _, want := range []string{
		"ListenStream=/run/tpm2-kira/unlock.sock",
		"SocketMode=0600",
		"Before=cryptsetup-pre.target",
		"Service=tpm2-kira.service",
		"RemoveOnStop=yes",
	} {
		if !has(sock, want) {
			t.Errorf("socket unit lacks %q", want)
		}
	}
	svc := directives(t, "initramfs/systemd/tpm2-kira.service")
	if !has(svc, "Sockets=tpm2-kira-unlock.socket") {
		t.Error("the display's service does not take the key socket")
	}
	// The key is asked for after the separator, which the display's READY
	// precedes; the service must not end with the hold any more.
	if !has(svc, "Conflicts=initrd-switch-root.target") {
		t.Error("the service is not ended at switch-root")
	}
}
