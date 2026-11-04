package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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
KIRA=tpm2-kira # the function above
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
		"UNIT cryptsetup-pre.target",
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
// not a setting: neither hook copies the file, and the plan, which reads
// it, writes only the files of the parts it puts in. A file that does not
// load is said, and never stops the build.
func TestHookPutsNoConfigIntoTheImage(t *testing.T) {
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
	bin := filepath.Join(dir, "tpm2-kira")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	// Secure Boot on: nothing to warn of here (that is TestHookAddsThePlan's).
	testDir := filepath.Join(dir, "testdir")
	writeSecureBootVars(t, testDir, 1, 0)
	plan := func(conf string) (string, string) {
		root := t.TempDir()
		cmd := exec.Command(bin, "initramfs", "plan", "--conf", conf, "--tpm", filepath.Join(dir, "no-tpm"), "--buildroot", root)
		cmd.Env = append(os.Environ(), "TPM2_KIRA_UNPRIVILEGED=1", "TPM2_KIRA_TEST_DIR="+testDir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		return string(out), root
	}
	good := filepath.Join(dir, "control.conf")
	os.WriteFile(good, []byte("TPM2_KIRA_ATTEST_ADAPTER=hci1\nTPM2_KIRA_ATTEST_BLUETOOTH=always\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "pin"), []byte("secret-1234\n"), 0o600)
	out, root := plan(good)
	if strings.Contains(out, "warning") || !strings.Contains(out, "say Phone (Bluetooth): out - no TPM") {
		t.Fatalf("a good file, no TPM:\n%s", out)
	}
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), "secret-1234") || filepath.Base(p) == "control.conf" {
				t.Errorf("%s carries control.conf or the PIN", p)
			}
		}
		return nil
	})
	old := filepath.Join(dir, "old.conf")
	os.WriteFile(old, []byte("TPM2_KIRA_NOSUCH=1\n"), 0o600)
	if out, _ := plan(old); !strings.Contains(out, "warning control.conf does not load") || !strings.Contains(out, "unknown key") {
		t.Fatalf("a file with an unknown setting:\n%s", out)
	}
}

// planStub is 'tpm2-kira initramfs plan' as a hook test wants it: it names
// the parts in $PLAN_PARTS in the image and prints $PLAN_OUT. The boot
// binary is there to be found, and does nothing.
const planStub = `
tpm2-kira-boot() { :; }
tpm2-kira() {
    [ "$1 $2" = "initramfs plan" ] || return 0
    root=${BUILDROOT:-$DESTDIR}
    for p in $PLAN_PARTS; do mkdir -p "$root/etc/tpm2-kira/plan/$p"; done
    case " $* " in *" --no-busybox "*) echo "say NOBUSYBOX" ;; esac
    printf '%s' "$PLAN_OUT"
    return "${PLAN_RC:-0}"
}
`

// The mkinitcpio hook adds what the plan names: the lock with the codes,
// the gate with the phone (its modules and only the firmware the adapter
// loads), systemd-networkd with the network; with the disk unlock alone,
// nothing. What the plan says is said.
func TestHookAddsThePlan(t *testing.T) {
	script := `
add_module() { echo "MODULE $1"; add_firmware "fw-of-$1"; }
add_firmware() { echo "FIRMWARE $1"; }
add_checked_modules() { echo "ALLMODULES $1"; }
add_systemd_unit() { echo "UNIT $1"; }
add_symlink() { :; }
plain() { echo "PLAIN $*"; }
warning() { echo "WARNING $*"; }
` + planStub + `
source initramfs/mkinitcpio/install/sd-tpm2-kira
KIRA=tpm2-kira # the function above
_add_plan
`
	run := func(parts, out, rc string) string {
		root := t.TempDir()
		for _, db := range []string{"passwd", "shadow", "group"} {
			os.MkdirAll(filepath.Join(root, "etc"), 0o755)
			os.WriteFile(filepath.Join(root, "etc", db), nil, 0o644)
		}
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "BUILDROOT="+root, "PLAN_PARTS="+parts, "PLAN_OUT="+out, "PLAN_RC="+rc)
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v:\n%s", err, b)
		}
		return string(b)
	}

	got := run("unlock", "say Disk unlock:       in  - the key of every volume\nsay Phone (Bluetooth): out - no TPM (none): a phone cannot attest this machine\nwarning Secure Boot is off\n", "0")
	if strings.Contains(got, "UNIT") || strings.Replace(got, "MODULE efivarfs", "", 1) != strings.ReplaceAll(got, "MODULE efivarfs", "") || !strings.Contains(got, "MODULE efivarfs") || strings.Contains(strings.ReplaceAll(got, "MODULE efivarfs", ""), "MODULE") || !strings.Contains(got, "PLAIN tpm2-kira: Phone (Bluetooth): out - no TPM") {
		t.Fatalf("the disk unlock alone: efivarfs and nothing else, for Secure Boot's state:\n%s", got)
	}
	if !strings.Contains(got, "WARNING tpm2-kira: Secure Boot is off") {
		t.Fatalf("the plan's warning is not said:\n%s", got)
	}

	got = run("unlock codes phone net ssh tpm",
		"bt-module btusb\nbt-module btintel\nbt-firmware intel/ibt-0180-0041.sfi\nnet-module e1000e\nwarning no firmware named\n", "0")
	for _, want := range []string{
		"UNIT tpm2-kira-close.service", "UNIT systemd-networkd.service", "UNIT tpm2-kira-machine-id.service",
		"MODULE btusb", "MODULE btintel", "FIRMWARE intel/ibt-0180-0041.sfi", "MODULE e1000e", "FIRMWARE fw-of-e1000e",
		"PLAIN tpm2-kira: Bluetooth: 2 modules, 1 firmware files", "WARNING tpm2-kira: no firmware named",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	// The adapter's modules bring only the firmware the kernel log named.
	if strings.Contains(got, "FIRMWARE fw-of-btusb") {
		t.Errorf("btusb's declared firmware went in:\n%s", got)
	}
	if got := run("unlock net", "net-modules-all\n", "0"); !strings.Contains(got, "ALLMODULES /drivers/net") || strings.Contains(got, "tpm2-kira-close") {
		t.Errorf("every network driver:\n%s", got)
	}
	// A sealed slot without codes (the vault, the TPM salt alone): it is
	// closed all the same, and its record is an EFI variable.
	if got := run("unlock vault tpm", "", "0"); strings.Contains(got, "tpm2-kira-cap") || !strings.Contains(got, "UNIT tpm2-kira-close.service") || !strings.Contains(got, "MODULE efivarfs") {
		t.Errorf("a slot without codes:\n%s", got)
	}
	// The SSH server reads its CA from an EFI variable: efivarfs's module.
	if got := run("unlock net ssh", "module efivarfs\n", "0"); !strings.Contains(got, "MODULE efivarfs") {
		t.Errorf("efivarfs:\n%s", got)
	}
	// An installed tpm2-kira that makes no plan: the disk unlock alone, said.
	if got := run("", "", "2"); !strings.Contains(got, "WARNING tpm2-kira: the installed tpm2-kira made no boot plan") || strings.Contains(got, "UNIT") {
		t.Errorf("no plan:\n%s", got)
	}
}

// The initramfs-tools hook adds what the plan names: the TPM's drivers
// when a part needs the TPM, the adapter's modules and firmware, the
// network's drivers; without busybox it asks for a plan without network.
func TestDebianHookAddsThePlan(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	hook, err := os.ReadFile("initramfs/initramfs-tools/hooks/tpm2-kira")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	funcs := filepath.Join(dir, "hook-functions")
	os.WriteFile(funcs, []byte(`
copy_exec() { :; }
copy_file() { :; }
manual_add_modules() { echo "MODULE $1"; }
force_load() { echo "FORCELOAD $1"; }
auto_add_modules() { echo "AUTOMODULES $1"; }
add_firmware() { echo "FIRMWARE $1"; }
busybox() { :; }
`), 0o644)
	// As commands, not planStub's functions: the hook runs under sh, and dash, Debian's,
	// takes no '-' in a function's name.
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "tpm2-kira-boot"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	os.WriteFile(filepath.Join(bin, "tpm2-kira"), []byte(`#!/bin/sh
[ "$1 $2" = "initramfs plan" ] || exit 0
root=${BUILDROOT:-$DESTDIR}
for p in $PLAN_PARTS; do mkdir -p "$root/etc/tpm2-kira/plan/$p"; done
case " $* " in *" --no-busybox "*) echo "say NOBUSYBOX" ;; esac
printf '%s' "$PLAN_OUT"
exit "${PLAN_RC:-0}"
`), 0o755)
	copyHook := filepath.Join(dir, "hook")
	os.WriteFile(copyHook, []byte(strings.Replace(string(hook), "/usr/share/initramfs-tools/hook-functions", funcs, 1)), 0o755)
	run := func(parts, out, busybox string) string {
		cmd := exec.Command("sh", copyHook)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "DESTDIR="+t.TempDir(), "PLAN_PARTS="+parts, "PLAN_OUT="+out, "BUSYBOX="+busybox)
		b, _ := cmd.CombinedOutput()
		return string(b)
	}
	if got := run("unlock", "say Disk unlock: in\nwarning Secure Boot is off\n", "auto"); strings.Contains(got, "MODULE") || !strings.Contains(got, "FORCELOAD efivarfs") || !strings.Contains(got, "tpm2-kira: Disk unlock: in") || strings.Contains(got, "NOBUSYBOX") || !strings.Contains(got, "tpm2-kira: WARNING: Secure Boot is off") {
		t.Fatalf("the disk unlock alone: efivarfs for Secure Boot's state, and the plan's warning:\n%s", got)
	}
	got := run("unlock codes phone net tpm", "bt-module btusb\nbt-firmware intel/ibt.sfi\nnet-module e1000e\n", "auto")
	for _, want := range []string{"MODULE tpm_tis", "MODULE tpm_crb", "FORCELOAD btusb", "FIRMWARE intel/ibt.sfi", "MODULE e1000e",
		"tpm2-kira: Bluetooth: 1 modules, 1 firmware files", "tpm2-kira: network drivers: e1000e"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	if got := run("unlock net", "net-modules-all\n", "auto"); !strings.Contains(got, "AUTOMODULES net") {
		t.Errorf("every network driver:\n%s", got)
	}
	if got := run("unlock net ssh", "module efivarfs\n", "auto"); !strings.Contains(got, "MODULE efivarfs") {
		t.Errorf("efivarfs:\n%s", got)
	}
	if got := run("unlock", "", "n"); !strings.Contains(got, "NOBUSYBOX") {
		t.Errorf("without busybox the plan is not told:\n%s", got)
	}
}

// The boot binary goes into the image from /usr/local/bin too (make
// install), which mkinitcpio's PATH leaves out: build adds it as
// /usr/bin/tpm2-kira-boot, and the units go in without add_systemd_unit looking for it again; every
// other binary they name is added as before, and add_binary is mkinitcpio's
// again afterwards.
func TestHookTakesTheBinaryFromUsrLocal(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	script := `
add_binary() { echo "BIN $*"; }
add_systemd_unit() { echo "UNIT $1"; add_binary tpm2-kira-boot; add_binary sh; }
source initramfs/mkinitcpio/install/sd-tpm2-kira
KIRA_BOOT=/usr/local/bin/tpm2-kira-boot
add_binary "$KIRA_BOOT" /usr/bin/tpm2-kira-boot
_add_kira_unit tpm2-kira.service
add_binary after
`
	out, err := exec.Command("bash", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := "BIN /usr/local/bin/tpm2-kira-boot /usr/bin/tpm2-kira-boot\nUNIT tpm2-kira.service\nBIN sh\nBIN after\n"
	if string(out) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
}

// writeSecureBootVars puts SecureBoot and SetupMode where TPM2_KIRA_TEST_DIR=testDir
// makes the binaries read them.
func writeSecureBootVars(t *testing.T, testDir string, secureBoot, setupMode byte) {
	t.Helper()
	dir := filepath.Join(testDir, "efivars")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]byte{"SecureBoot": secureBoot, "SetupMode": setupMode} {
		path := filepath.Join(dir, name+"-8be4df61-93ca-11d2-aa0d-00e098032b8c")
		if err := os.WriteFile(path, []byte{6, 0, 0, 0, v}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Debian's order, as initramfs-tools makes it (hook-functions' get_prereq_pairs and
// cache_run_scripts): the package's script, and cryptsetup's cryptroot, which names every
// other script of local-top, as in cryptsetup-initramfs 2:2.7.5. No loop, whose breaking is
// tsort's to choose; the close before cryptroot. The real image's ORDER: tools/vmtest.py.
func TestDebianScriptOrder(t *testing.T) {
	dir := t.TempDir()
	const cryptroot = `#!/bin/sh
PREREQ="cryptroot-prepare"
prereqs() {
    # Make sure that cryptroot is run last in local-top
    local req script="${0##*/}" dir
    dir="$DESTDIR/scripts/${CRYPTROOT_STAGE-local-top}"
    for req in "$dir"/*; do
        test -x "$req" || continue
        req="${req##*/}"
        if [ "$req" != "$script" ]; then
            printf '%s\n' "$req"
        fi
    done
}
case $1 in prereqs) prereqs; exit 0;; esac
`
	local := filepath.Join(dir, "scripts", "local-top")
	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatal(err)
	}
	close, err := os.ReadFile("initramfs/initramfs-tools/scripts/local-top/tpm2-kira-close")
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"tpm2-kira-close": close, "cryptroot": []byte(cryptroot)} {
		if err := os.WriteFile(filepath.Join(local, name), body, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pairs := `cd "$DESTDIR/scripts/local-top"
for s in *; do
    echo "$s $s"
    for p in $(./"$s" prereqs); do echo "$p $s"; done
done | tsort`
	cmd := exec.Command("sh", "-c", pairs)
	cmd.Env = append(os.Environ(), "DESTDIR="+dir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v: %s", err, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("tsort says: %s", stderr.String())
	}
	got := strings.Fields(stdout.String())
	c, k := slices.Index(got, "tpm2-kira-close"), slices.Index(got, "cryptroot")
	if c < 0 || k < 0 || c > k {
		t.Errorf("the order: %v", got)
	}
}
