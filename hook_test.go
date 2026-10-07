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
		"PLAIN tpm2-kira: the volume 1111-2222 is unlocked through tpm2-kira's prompt (" + cmdline + ")",
		"PLAIN tpm2-kira: cryptroot is unlocked through tpm2-kira's prompt (" + crypttab + ")",
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
	if got := run(filepath.Join(dir, "none"), all); !strings.Contains(got, "every volume named on the kernel command line") || strings.Contains(got, "WARNING") {
		t.Errorf("socket without a UUID:\n%s", got)
	}

	// Nothing routed: the parameter to add.
	plain := write("plain", "root=/dev/mapper/cryptroot rd.luks.name=1111-2222=cryptroot\n")
	got = run(filepath.Join(dir, "none"), plain)
	if !strings.Contains(got, "WARNING tpm2-kira: no volume is unlocked through tpm2-kira yet; add rd.luks.key=<UUID>=/run/tpm2-kira/unlock.sock") {
		t.Errorf("no hint:\n%s", got)
	}
}
