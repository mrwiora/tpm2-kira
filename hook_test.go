package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The mkinitcpio hook reports which volumes are unlocked through tpm2-kira:
// those whose key file is the socket, on the kernel command line
// (rd.luks.key=<UUID>=socket, or the socket for every volume) or in an
// x-initrd.attach line of /etc/crypttab. With none, it names the command
// line parameter to add. It writes nothing.
func TestHookReportsTheVolumesUnlockedThroughTpm2Kira(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	script := `
add_systemd_unit() { echo "UNIT $1"; }
add_symlink() { echo "LINK $1"; }
plain() { echo "PLAIN $*"; }
warning() { echo "WARNING $*"; }
# 'tpm2-kira luks route' as the test wants it: its lines and its exit status.
tpm2-kira() { [[ "$1 $2" == "luks route" ]] || return 0; printf '%s' "$ROUTE_OUT"; return "${ROUTE_RC:-0}"; }
source initramfs/mkinitcpio/install/sd-tpm2-kira
_add_unlock "$@"
`
	run := func(args ...string) string {
		out, err := exec.Command("bash", append([]string{"-c", script, "-"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		return string(out)
	}

	crypttab := write("crypttab", `# a comment
cryptroot UUID=aaaa /run/tpm2-kira/unlock.sock x-initrd.attach,discard
home UUID=bbbb - x-initrd.attach
later UUID=cccc /run/tpm2-kira/unlock.sock discard
`)
	cmdline := write("cmdline", "root=/dev/mapper/cryptroot rd.luks.name=1111-2222=cryptroot rd.luks.key=1111-2222=/run/tpm2-kira/unlock.sock rw\n")
	got := run(crypttab, cmdline)
	for _, want := range []string{
		"UNIT tpm2-kira-unlock.socket",
		"LINK /usr/lib/systemd/system/sysinit.target.wants/tpm2-kira-unlock.socket",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	for _, no := range []string{"home", "later", "WARNING"} {
		if strings.Contains(got, no) {
			t.Errorf("%q should not appear:\n%s", no, got)
		}
	}
	if b, _ := os.ReadFile(crypttab); !strings.Contains(string(b), "home UUID=bbbb - x-initrd.attach") {
		t.Error("the crypttab was changed")
	}

	// The socket for every volume on the command line.
	all := write("all", "rd.luks.name=1111-2222=cryptroot rd.luks.key=/run/tpm2-kira/unlock.sock\n")
	if got := run(filepath.Join(dir, "none"), all); strings.Contains(got, "WARNING") {
		t.Errorf("socket without a UUID:\n%s", got)
	}

	// What 'luks route' says, one line each, as the hook shows it.
	cmd0 := exec.Command("bash", "-c", script, "-", crypttab, cmdline)
	cmd0.Env = append(os.Environ(), "ROUTE_OUT=/dev/sda2 (1111-2222): the key comes from tpm2-kira: rd.luks.key= in "+cmdline+"\n")
	if out, err := cmd0.CombinedOutput(); err != nil || !strings.Contains(string(out), "PLAIN tpm2-kira: /dev/sda2 (1111-2222): the key comes from tpm2-kira: rd.luks.key= in "+cmdline) || strings.Contains(string(out), "WARNING") {
		t.Errorf("the route line: %v\n%s", err, out)
	}

	// Nothing routed: the parameter to add.
	plain := write("plain", "root=/dev/mapper/cryptroot rd.luks.name=1111-2222=cryptroot\n")
	got = run(filepath.Join(dir, "none"), plain)
	if !strings.Contains(got, "WARNING tpm2-kira: no volume is unlocked through tpm2-kira yet; add rd.luks.key=<UUID>=/run/tpm2-kira/unlock.sock") {
		t.Errorf("no hint:\n%s", got)
	}

	// 'luks route' found a problem: its lines, under a warning, as the
	// person should see them.
	advice := "/dev/sda2: /etc/kernel/cmdline: rd.luks.name= for 1111-2222 appears 2 times.\n  The line should read:\n    rd.luks.name=1111-2222=cryptroot rd.luks.key=1111-2222=/run/tpm2-kira/unlock.sock rw\n"
	cmd := exec.Command("bash", "-c", script, "-", filepath.Join(dir, "none"), plain)
	cmd.Env = append(os.Environ(), "ROUTE_RC=1", "ROUTE_OUT="+advice)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, want := range []string{
		"WARNING tpm2-kira: the disk's key is not routed through tpm2-kira everywhere",
		"PLAIN     /dev/sda2: /etc/kernel/cmdline: rd.luks.name= for 1111-2222 appears 2 times.",
		"PLAIN         rd.luks.name=1111-2222=cryptroot rd.luks.key=1111-2222=/run/tpm2-kira/unlock.sock rw",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// Nothing of control.conf goes into the image - not the YubiKey's PIN,
// not a setting: the hooks only check the file, which their build reads.
// Neither hook writes a control.conf into the image, and a file that does
// not load stops the build.
func TestHookPutsNoConfigIntoTheImage(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	for _, hook := range []string{"initramfs/mkinitcpio/install/sd-tpm2-kira", "initramfs/initramfs-tools/hooks/tpm2-kira"} {
		b, err := os.ReadFile(hook)
		if err != nil {
			t.Fatal(err)
		}
		if regexp.MustCompile(`(BUILDROOT|DESTDIR)[^\n]*control\.conf|add_file[^\n]*control\.conf|copy_file[^\n]*control\.conf`).Match(b) {
			t.Errorf("%s writes a control.conf into the image", hook)
		}
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0o755)
	if out, err := exec.Command("go", "build", "-o", filepath.Join(bin, "tpm2-kira"), ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	root := filepath.Join(dir, "root")
	run := func(conf string) string {
		cmd := exec.Command("bash", "-c", "error() { echo \"ERROR $*\"; }\nwarning() { echo \"WARNING $*\"; }\nsource initramfs/mkinitcpio/install/sd-tpm2-kira\n_check_config && echo OK")
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TPM2_KIRA_CONTROL_CONF="+conf, "BUILDROOT="+root, "TPM2_KIRA_UNPRIVILEGED=1")
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	good := filepath.Join(dir, "good.conf")
	os.WriteFile(good, []byte("TPM2_KIRA_ATTEST_ADAPTER=hci1\nTPM2_KIRA_PIN='secret-1234'\n"), 0o600)
	if out := run(good); !strings.Contains(out, "OK") {
		t.Fatalf("a good file: %s", out)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/tpm2-kira")); err == nil {
		t.Fatal("the check wrote into the image")
	}
	old := filepath.Join(dir, "old.conf")
	os.WriteFile(old, []byte("TPM2_KIRA_ATTEST_DEBUG=1\n"), 0o600)
	// A file that does not load is said, but never stops the build.
	if out := run(old); !strings.Contains(out, "OK") || strings.Contains(out, "ERROR") || !strings.Contains(out, "Debug at boot") {
		t.Fatalf("a file with a gone setting: %s", out)
	}
}

// The hook's Bluetooth part, into an empty image tree: the modules, the
// firmware, the rule that lets the adapter in, and the signing public key
// the gate checks the enrolment with - which needs etc/tpm2-kira in the
// image, a directory nothing else creates any more.
func TestHookAddsBluetoothIntoAnEmptyImage(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	os.Mkdir(root, 0o755)
	conf := filepath.Join(dir, "control.conf")
	os.WriteFile(conf, []byte("TPM2_KIRA_ATTEST_ADAPTER=0\nTPM2_KIRA_PIN='secret-1234'\n"), 0o600)
	script := `
add_module() { echo "MODULE $1"; }
add_firmware() { echo "FIRMWARE $1"; }
add_systemd_unit() { echo "UNIT $1"; }
add_symlink() { :; }
plain() { echo "PLAIN $*"; }
warning() { echo "WARNING $*"; }
error() { echo "ERROR $*"; }
journalctl() { :; }
tpm2-kira() {
    case "$1 $2" in
    "attest status") echo '[{"slot_number":0}]' ;;
    "attest signer") printf -- '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n' ;;
    "attest initramfs-deps")
        printf 'policy auto\nadapter hci0\nmodule btusb\nmodule btintel\nfirmware intel/ibt-0180-0041.sfi\n'
        printf 'udev ACTION=="add", SUBSYSTEM=="usb", KERNEL=="3-10", ATTR{idVendor}=="8087", ATTR{idProduct}=="0033", ATTR{authorized}="1"\n' ;;
    esac
}
source initramfs/mkinitcpio/install/sd-tpm2-kira
_add_bluetooth
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "BUILDROOT="+root, "TPM2_KIRA_CONTROL_CONF="+conf)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), "WARNING") || strings.Contains(string(out), "ERROR") ||
		strings.Contains(string(out), "No such file") {
		t.Fatalf("%v:\n%s", err, out)
	}
	for file, want := range map[string]string{
		"etc/tpm2-kira/attest-signer.pem":               "BEGIN PUBLIC KEY",
		"etc/modules-load.d/tpm2-kira-bluetooth.conf":   "btusb\nbtintel\n",
		"etc/udev/rules.d/70-tpm2-kira-bluetooth.rules": `KERNEL=="3-10"`,
	} {
		b, err := os.ReadFile(filepath.Join(root, file))
		if err != nil || !strings.Contains(string(b), want) {
			t.Errorf("%s: %q %v", file, b, err)
		}
	}
	// Nothing of control.conf in the image: no file of it, and not the PIN
	// in any file.
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), "secret-1234") || filepath.Base(p) == "control.conf" {
				t.Errorf("%s carries control.conf or its PIN", p)
			}
		}
		return nil
	})
	for _, want := range []string{"MODULE btusb", "FIRMWARE intel/ibt-0180-0041.sfi", "UNIT tpm2-kira-attest.service", "2 modules, 1 firmware files"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the hook did not say %q:\n%s", want, out)
		}
	}
}

// The network and SSH part of the hook: what 'tpm2-kira remote initramfs'
// prints is added - systemd-networkd enabled with its user, the matched
// interface's driver - and a setting it refuses leaves both out with the
// reason. Without tinysshd on the system the SSH server is left out and
// its drop-in removed, so the image boots with the code screen at the
// console.
func TestHookAddsNetworkAndSSH(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	script := `
add_module() { echo "MODULE $1"; }
add_checked_modules() { echo "ALLMODULES $1"; }
add_binary() { echo "BINARY $*"; }
add_systemd_unit() { echo "UNIT $1"; }
add_symlink() { echo "LINK $1"; }
plain() { echo "PLAIN $*"; }
warning() { echo "WARNING $*"; }
tpm2-kira() { [[ "$1 $2" == "remote initramfs" ]] || return 0; printf '%s' "$REMOTE_OUT"; return "${REMOTE_RC:-0}"; }
source initramfs/mkinitcpio/install/sd-tpm2-kira
_add_remote
`
	run := func(out, rc string) (string, string) {
		root := t.TempDir()
		os.MkdirAll(filepath.Join(root, "etc/systemd/system/tpm2-kira.service.d"), 0o755)
		os.WriteFile(filepath.Join(root, "etc/systemd/system/tpm2-kira.service.d/remote.conf"), []byte("x"), 0o644)
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "BUILDROOT="+root, "REMOTE_OUT="+out, "REMOTE_RC="+rc)
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v:\n%s", err, b)
		}
		return string(b), root
	}

	if got, _ := run("net off\n", "0"); strings.Contains(got, "UNIT") || strings.Contains(got, "WARNING") {
		t.Fatalf("off added something:\n%s", got)
	}
	if got, _ := run("tpm2-kira: TPM2_KIRA_SSH=on needs a network in the image\n", "2"); !strings.Contains(got, "WARNING tpm2-kira: no network or SSH in the image: TPM2_KIRA_SSH=on needs a network") || strings.Contains(got, "UNIT") {
		t.Fatalf("a refused setting:\n%s", got)
	}
	got, root := run("net dhcp\nmodule e1000e\nssh 22\nhostkey SHA256:abc from /etc/ssh/ssh_host_ed25519_key, sealed to PCR 0+7\n", "0")
	for _, want := range []string{"MODULE e1000e", "UNIT systemd-networkd.service", "LINK /usr/lib/systemd/system/sysinit.target.wants/systemd-networkd.service", "PLAIN tpm2-kira: network at boot: dhcp via e1000e"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	dropIn := filepath.Join(root, "etc/systemd/system/tpm2-kira.service.d/remote.conf")
	if _, err := os.Stat("/usr/bin/tinysshd"); err == nil {
		if !strings.Contains(got, "BINARY /usr/bin/tinysshd") || !strings.Contains(got, "BINARY systemd-tty-ask-password-agent") ||
			!strings.Contains(got, "PLAIN tpm2-kira: SSH host key SHA256:abc from /etc/ssh/ssh_host_ed25519_key, sealed to PCR 0+7") {
			t.Errorf("tinysshd or the password agent not added:\n%s", got)
		}
	} else {
		if !strings.Contains(got, "tinysshd is not installed") || strings.Contains(got, "BINARY") {
			t.Errorf("without tinysshd:\n%s", got)
		}
		if _, err := os.Stat(dropIn); !os.IsNotExist(err) {
			t.Error("the drop-in that starts the SSH server stayed without tinysshd")
		}
	}
	if got, _ := run("net static\nmodules-all\nwarning no interface aa:bb:cc:dd:ee:09 on this machine\n", "0"); !strings.Contains(got, "ALLMODULES /drivers/net") || !strings.Contains(got, "WARNING tpm2-kira: no interface aa:bb") {
		t.Errorf("no interface matched:\n%s", got)
	}
}
