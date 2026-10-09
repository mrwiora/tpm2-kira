package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Whether the boot integration is wired, for control's status: the package
// installs the mkinitcpio hook files, but it is the person who puts
// sd-tpm2-kira into HOOKS of /etc/mkinitcpio.conf - forgotten, every
// protection reads done while the next boot shows no code screen and
// serves no key. On Debian the .deb's initramfs-tools scripts are active
// in every image; there only their presence can be missing (a build from
// source without the package).

// The paths, as vars for the tests.
var (
	mkinitcpioConf = "/etc/mkinitcpio.conf"
	mkinitcpioHook = "/usr/lib/initcpio/install/sd-tpm2-kira"
	debianPremount = "/usr/share/initramfs-tools/scripts/init-premount/tpm2-kira"
)

// initramfsHookState says why the boot integration of kind would not run,
// "" when it is wired.
func initramfsHookState(kind string) string {
	switch kind {
	case "mkinitcpio":
		if !fileExists(mkinitcpioHook) {
			return "the sd-tpm2-kira hook is not installed (sudo make install-mkinitcpio, or the package)"
		}
		if !slices.Contains(mkinitcpioHooks(mkinitcpioConf), "sd-tpm2-kira") {
			return "sd-tpm2-kira is not in HOOKS of " + mkinitcpioConf + " - add it next to sd-encrypt, then rebuild"
		}
	case "initramfs-tools":
		if !fileExists(debianPremount) {
			return "the tpm2-kira boot scripts are not installed (the .deb installs them)"
		}
	}
	return ""
}

// mkinitcpioHooks is the HOOKS mkinitcpio would use: the conf and its
// conf.d drop-ins in sorted order, the last assignment winning, as
// mkinitcpio reads them.
func mkinitcpioHooks(conf string) []string {
	files := []string{conf}
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(conf), "mkinitcpio.conf.d", "*.conf")); len(m) > 0 {
		sort.Strings(m)
		files = append(files, m...)
	}
	var hooks []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if h, ok := parseHooks(string(data)); ok {
			hooks = h
		}
	}
	return hooks
}

// hooksRe matches a HOOKS assignment: an array (which may span lines), a
// quoted string, or the rest of the line.
var hooksRe = regexp.MustCompile(`(?ms)^[ \t]*HOOKS=(\([^)]*\)|"[^"]*"|'[^']*'|[^\n]*)`)

// parseHooks finds the last HOOKS assignment in one file's text, with the
// comments cut as a shell would.
func parseHooks(data string) ([]string, bool) {
	lines := strings.Split(data, "\n")
	for i, l := range lines {
		if n := strings.IndexByte(l, '#'); n >= 0 {
			lines[i] = l[:n]
		}
	}
	ms := hooksRe.FindAllStringSubmatch(strings.Join(lines, "\n"), -1)
	if len(ms) == 0 {
		return nil, false
	}
	fields := strings.Fields(strings.Trim(ms[len(ms)-1][1], `()`))
	for i, f := range fields {
		fields[i] = strings.Trim(f, `"'`)
	}
	return fields, true
}
