package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The mkinitcpio hook reports, per volume the initrd unlocks, where the
// key comes from: tpm2-kira's socket in the key field means tpm2-kira's
// prompt; a volume still asked for by systemd's own prompt is named with
// the line to change; a volume with its own key source is left alone.
func TestHookReportsTheKeySourceOfEachVolume(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	file := filepath.Join(t.TempDir(), "crypttab")
	in := `# a comment

cryptroot UUID=aaaa /run/tpm2-kira/unlock.sock x-initrd.attach,discard
home UUID=bbbb - x-initrd.attach
later UUID=cccc none discard
tpm UUID=dddd none tpm2-device=auto,x-initrd.attach
keyed UUID=eeee /etc/key x-initrd.attach
`
	if err := os.WriteFile(file, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `
add_systemd_unit() { echo "UNIT $1"; }
add_symlink() { echo "LINK $1"; }
plain() { echo "PLAIN $*"; }
warning() { echo "WARNING $*"; }
source initramfs/mkinitcpio/install/sd-tpm2-kira
_add_unlock "$1"
`
	out, err := exec.Command("bash", "-c", script, "-", file).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got := string(out)
	for _, want := range []string{
		"UNIT tpm2-kira-unlock.socket",
		"LINK /usr/lib/systemd/system/sysinit.target.wants/tpm2-kira-unlock.socket",
		"PLAIN tpm2-kira: cryptroot is unlocked through tpm2-kira's prompt",
		"WARNING tpm2-kira: home is asked for by systemd's own prompt",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	for _, name := range []string{"later", "tpm ", "keyed", "no x-initrd.attach"} {
		if strings.Contains(got, name) {
			t.Errorf("%q should not be reported:\n%s", name, got)
		}
	}

	// Without any x-initrd.attach line, the kernel command line hint.
	empty := filepath.Join(t.TempDir(), "crypttab")
	os.WriteFile(empty, []byte("later UUID=cccc none discard\n"), 0o600)
	out, err = exec.Command("bash", "-c", script, "-", empty).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(string(out), "rd.luks.key=<UUID>=/run/tpm2-kira/unlock.sock") {
		t.Errorf("no hint without x-initrd.attach lines:\n%s", out)
	}
}
