package main

import (
	"os"
	"os/exec"
	"path/filepath"
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

// The image gets the radio settings of control.conf and nothing else: the
// YubiKey's PIN never reaches it, however its line is spelt (the image, a
// UKI on the ESP say, is not root's alone).
func TestHookPutsNoPINIntoTheImage(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0o755)
	if out, err := exec.Command("go", "build", "-o", filepath.Join(bin, "tpm2-kira"), ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	conf := filepath.Join(dir, "control.conf")
	if err := os.WriteFile(conf, []byte(`# radio
TPM2_KIRA_ATTEST_ADAPTER=hci1
TPM2_KIRA_ATTEST_ADAPTER_WAIT=45
TPM2_KIRA_PIN = 'secret-1234'
  TPM2_KIRA_CONTROL=guided
TPM2_KIRA_ATTEST_BLUETOOTH=always
TPM2_KIRA_ATTEST_DEBUG=1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "root")
	script := `
error() { echo "ERROR $*"; }
source initramfs/mkinitcpio/install/sd-tpm2-kira
_add_config
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TPM2_KIRA_CONTROL_CONF="+conf, "BUILDROOT="+root, "TPM2_KIRA_UNPRIVILEGED=1")
	if out, err := cmd.CombinedOutput(); err != nil || strings.Contains(string(out), "ERROR") {
		t.Fatalf("%v: %s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(root, "etc/tpm2-kira/control.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, no := range []string{"secret", "PIN", "CONTROL", "BLUETOOTH"} {
		if strings.Contains(string(got), no) {
			t.Errorf("%q reached the image:\n%s", no, got)
		}
	}
	for _, want := range []string{"TPM2_KIRA_ATTEST_ADAPTER=1\n", "TPM2_KIRA_ATTEST_ADAPTER_WAIT=45\n", "TPM2_KIRA_ATTEST_DEBUG=1\n"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("the image lacks %q:\n%s", want, got)
		}
	}
}
