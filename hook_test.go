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
		cmd := exec.Command("bash", "-c", "error() { echo \"ERROR $*\"; }\nsource initramfs/mkinitcpio/install/sd-tpm2-kira\n_check_config && echo OK")
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
	if out := run(old); !strings.Contains(out, "ERROR") || !strings.Contains(out, "tpm2-kira.debug=1") {
		t.Fatalf("a file with a gone setting: %s", out)
	}
}
