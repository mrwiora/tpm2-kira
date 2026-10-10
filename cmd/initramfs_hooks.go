package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
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
	_, _, hooks := winningHooks(conf)
	return hooks
}

// hooksRe matches a HOOKS assignment: an array (which may span lines), a
// quoted string, or the rest of the line.
var hooksRe = regexp.MustCompile(`(?ms)^[ \t]*HOOKS=(\([^)]*\)|"[^"]*"|'[^']*'|[^\n]*)`)

// winningHooks is the HOOKS assignment mkinitcpio would use - the last one
// over the conf and its drop-ins - as it stands in its file: the file, the
// assignment's value text, and the parsed hooks.
func winningHooks(conf string) (file, value string, hooks []string) {
	files := []string{conf}
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(conf), "mkinitcpio.conf.d", "*.conf")); len(m) > 0 {
		sort.Strings(m)
		files = append(files, m...)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if h, ok := parseHooks(string(data)); ok {
			ms := hooksRe.FindAllStringSubmatch(string(data), -1)
			file, value, hooks = f, ms[len(ms)-1][1], h
		}
	}
	return file, value, hooks
}

// AdoptHookLine is the winning HOOKS line as it should read, with
// sd-tpm2-kira in it, and the file it lives in - for control to show, and
// for AdoptHook to write when asked. An error says why it cannot be done
// by editing (no HOOKS assignment, or an initramfs without the systemd
// hook, which sd-tpm2-kira needs).
func AdoptHookLine(conf string) (file, oldLine, newLine string, err error) {
	file, value, hooks := winningHooks(conf)
	if file == "" {
		return "", "", "", fmt.Errorf("no HOOKS assignment found in %s or its drop-ins", conf)
	}
	if slices.Contains(hooks, "sd-tpm2-kira") {
		return file, "HOOKS=" + value, "HOOKS=" + value, nil
	}
	var adopted string
	switch {
	case strings.Contains(value, "sd-encrypt"):
		adopted = strings.Replace(value, "sd-encrypt", "sd-tpm2-kira sd-encrypt", 1)
	case regexp.MustCompile(`systemd([ \t\n)'"])`).MatchString(value):
		adopted = regexp.MustCompile(`systemd([ \t\n)'"])`).ReplaceAllString(value, "systemd sd-tpm2-kira${1}")
	default:
		return "", "", "", fmt.Errorf("the HOOKS of %s carry neither systemd nor sd-encrypt: sd-tpm2-kira needs a systemd-based initramfs (HOOKS with base systemd ... sd-encrypt)", file)
	}
	return file, "HOOKS=" + value, "HOOKS=" + adopted, nil
}

// AdoptHook writes sd-tpm2-kira into the winning HOOKS assignment, before
// sd-encrypt (else after systemd), and reports the file and the line as it
// reads now. Only the one assignment changes; the rest of the file is kept
// byte for byte.
func AdoptHook(conf string) (file, newLine string, err error) {
	file, oldLine, newLine, err := AdoptHookLine(conf)
	if err != nil {
		return "", "", err
	}
	if oldLine == newLine {
		return file, newLine, nil // already in
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", "", err
	}
	oldValue, newValue := oldLine[len("HOOKS="):], newLine[len("HOOKS="):]
	ms := hooksRe.FindAllStringSubmatchIndex(string(data), -1)
	if len(ms) == 0 {
		return "", "", fmt.Errorf("the HOOKS assignment of %s disappeared while editing", file)
	}
	start, end := ms[len(ms)-1][2], ms[len(ms)-1][3]
	if string(data[start:end]) != oldValue {
		return "", "", fmt.Errorf("the HOOKS assignment of %s changed while editing", file)
	}
	out := string(data[:start]) + newValue + string(data[end:])
	st, err := os.Stat(file)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(file, []byte(out), st.Mode().Perm()); err != nil {
		return "", "", err
	}
	return file, newLine, nil
}

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

// mkinitcpioPresetDir holds the presets whose images -P builds; a var for
// the tests.
var mkinitcpioPresetDir = "/etc/mkinitcpio.d"

// presetDefaultRe matches a preset's default image: default_uki="..." for
// a unified kernel image, default_image="..." for an initramfs.
var presetDefaultRe = regexp.MustCompile(`(?m)^default_(uki|image)="?([^"\n]+)"?`)

// mkinitcpioImages is the image the checks look at: the default unified
// kernel image of the first preset, else its default initramfs. The other
// images - fallback, further profiles - are not checked yet; checking each
// is planned (docs/PLAN-SUPPORT-MULTIPLE-UKI.md, step 6). One image, as a
// list, so the callers need not change when it becomes several.
func mkinitcpioImages() []string {
	files, _ := filepath.Glob(filepath.Join(mkinitcpioPresetDir, "*.preset"))
	sort.Strings(files)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var image string
		for _, m := range presetDefaultRe.FindAllStringSubmatch(string(data), -1) {
			if m[1] == "uki" {
				return []string{strings.TrimSpace(m[2])}
			}
			image = strings.TrimSpace(m[2])
		}
		if image != "" {
			return []string{image}
		}
	}
	return nil
}

// rebuildPending says, as far as the timestamps tell, whether an image
// still predates the HOOKS that name sd-tpm2-kira: built before the file
// last changed, it cannot carry the hook, and the next boot would show no
// code screen. "" when every image is newer, or when nothing can be told
// (no presets, no images yet - mkinitcpio -P is then due anyway and the
// step offers it).
func rebuildPending(conf string) string {
	file, _, _ := winningHooks(conf)
	if file == "" {
		return ""
	}
	st, err := os.Stat(file)
	if err != nil {
		return ""
	}
	for _, img := range mkinitcpioImages() {
		ist, err := os.Stat(img)
		if err != nil {
			continue
		}
		if ist.ModTime().Before(st.ModTime()) {
			return fmt.Sprintf("%s was built before %s last changed: the image cannot carry the hook yet", img, file)
		}
	}
	return ""
}

// uptimePath is /proc/uptime; a var for the tests.
var uptimePath = "/proc/uptime"

// imageNewerThanBoot says whether a preset image was rebuilt after this
// boot started. A phone enrolled now would pin this boot's values, which
// the next start - of the newer image - cannot match; the answer is a
// reboot before enrolling. "" when the images predate the boot, or when
// nothing can be told.
func imageNewerThanBoot() string {
	data, err := os.ReadFile(uptimePath)
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return ""
	}
	up, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return ""
	}
	booted := time.Now().Add(-time.Duration(up * float64(time.Second)))
	for _, img := range mkinitcpioImages() {
		st, err := os.Stat(img)
		if err != nil {
			continue
		}
		if st.ModTime().After(booted) {
			return fmt.Sprintf("%s was rebuilt after this boot started: reboot first - a phone enrolled now would pin values the next boot cannot match", img)
		}
	}
	return ""
}
