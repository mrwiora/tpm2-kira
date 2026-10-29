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
	for _, unit := range []string{"tpm2-kira.service", "tpm2-kira-cap.service", "tpm2-kira-unlock.socket"} {
		if !has(directives(t, "initramfs/systemd/"+unit), "ConditionPathExists=/etc/initrd-release") {
			t.Errorf("%s lacks ConditionPathExists=/etc/initrd-release", unit)
		}
	}
}

// The boot is one process tree on every distribution: the unit (Arch) and
// the init-premount script (Debian) start the same run, which starts the
// phone's radio worker and the SSH server's unprivileged half itself and
// confines them in code (phonegate/gate_child.go, assh/sandbox). Neither
// starts a gate of its own, waits for the TPM itself or loads the
// adapter's modules itself.
func TestTheBootIsRunOnBothDistributions(t *testing.T) {
	if _, err := os.Stat("initramfs/systemd/tpm2-kira-attest.service"); err == nil {
		t.Error("a unit of the gate's own: run starts the radio worker")
	}
	display := directives(t, "initramfs/systemd/tpm2-kira.service")
	// The code screen owns the terminal; what the key provider reports
	// (stderr) must be readable after the boot as well.
	if !has(display, "StandardInput=tty") || !has(display, "StandardOutput=tty") || !has(display, "StandardError=journal+console") {
		t.Error("the display's terminal and journal wiring")
	}
	// $TPM2_KIRA_REMOTE: the SSH server's flags from the image's drop-in,
	// no argument at all without one. --plan: what the image carries.
	const arch = "ExecStart=tpm2-kira-boot run --plan /etc/tpm2-kira/plan $TPM2_KIRA_REMOTE"
	if !has(display, arch) {
		t.Error("the code screen does not follow the image's plan")
	}
	// run waits for the TPM itself, when the plan needs it.
	for _, l := range display {
		if strings.Contains(l, "dev-tpm") {
			t.Errorf("the code screen's unit waits for the TPM: %s", l)
		}
	}
	// The stop is run's to pass on to its children, as on Debian: a
	// SIGTERM to ssh-child at the same moment cuts the sessions before
	// they are told.
	if !has(display, "KillMode=mixed") {
		t.Error("the stop's SIGTERM reaches run's children too")
	}
	if !has(display, "Before=systemd-pcrosseparator.service") || !has(display, "Before=systemd-pcrnvdone.service") || !has(display, "Conflicts=initrd-switch-root.target") {
		t.Error("the coordinator must hold both separators back and end with the initramfs")
	}

	// Debian: the same run, with the key socket of its own (systemd's
	// socket unit hands it over instead), and nothing else of tpm2-kira's.
	script, err := os.ReadFile("initramfs/initramfs-tools/scripts/init-premount/tpm2-kira")
	if err != nil {
		t.Fatal(err)
	}
	var started []string
	for _, l := range strings.Split(string(script), "\n") {
		if l = strings.TrimSpace(l); !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "[") && strings.Contains(l, "tpm2-kira-boot ") {
			started = append(started, l)
		}
	}
	const debian = `/usr/bin/tpm2-kira-boot run --plan "$PLAN" --unlock "$UNLOCK" $TPM2_KIRA_REMOTE `
	if len(started) != 1 || !strings.Contains(started[0], debian) {
		t.Errorf("Debian starts %q, want run alone as %q", started, debian)
	}
	for _, bad := range []string{"modprobe", "/dev/tpmrm0", "gate-child", "--gate", "INITRAMFS_MODE"} {
		if strings.Contains(string(script), bad) {
			t.Errorf("Debian's script has %q: run, or the image's init, does that on both", bad)
		}
	}
	hook, err := os.ReadFile("initramfs/initramfs-tools/hooks/tpm2-kira")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hook), `force_load "$value"`) {
		t.Error("Debian's image does not load the adapter's modules by its init")
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
