package cmd

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/google/go-attestation/attest"
)

// Predicting PCR 8 and 9 on a GRUB system (Debian). GRUB measures every
// command it runs into PCR 8 and every file it reads into PCR 9; the
// kernel's EFI stub adds its load options and the initrd to PCR 9. The
// event log of the running boot is the complete script of that, and after
// an update only the entries of what changed differ: the initrd's digest,
// the kernel's, grub.cfg's, and the version string inside the GRUB
// commands. The prediction replays this boot's log with those entries
// replaced by what is on disk now - what GRUB will read at the next boot -
// using the digest conventions the log itself shows:
//
//	PCR 9  "(hd0,gpt2)/grub/grub.cfg", "/initrd.img-…"  sha256(file contents)
//	PCR 9  tag LOADED_IMAGE::LoadOptions               sha256(UTF-16LE("BOOT_IMAGE=" ‖ kernel command line))
//	PCR 9  tag Linux initrd                            sha256(initrd contents)
//	PCR 8  "grub_cmd: <command>"                       sha256(<command>)
//	PCR 8  "kernel_cmdline: <line>"                    sha256(<line>)
//
// GRUB names files by its own device syntax, "(hd0,gpt2)/grub/grub.cfg".
// Which mount point a device is, is learnt from the log itself: a device
// is taken to be the mount point under which the file with the logged
// digest is found (a file that did not change). What the prediction cannot
// know is what a person does at the GRUB menu, or a grubenv the next boot
// rewrites (GRUB_SAVEDEFAULT, recordfail); such a boot shows no code, and
// a reseal after it puts things right, as before.

// grubPrediction says what was substituted in a replayed log.
type grubPrediction struct {
	Substituted []string // one line per changed event
	NewKernel   string   // the kernel version the prediction is for, when it differs from the booted one
}

var (
	grubFileEvent = regexp.MustCompile(`^(\([^)]*\))?(/.*)$`)
	kernelVersion = regexp.MustCompile(`(vmlinuz|initrd\.img)-([0-9][^ \t\n\x00]*)`)
)

// grubMountPoints are where GRUB's devices can be mounted on a Debian
// system, in the order they are tried.
var grubMountPoints = []string{"/boot", "/boot/efi", "/"}

// grubFiles is what the prediction reads: the digest of a file (nil, false
// when it is not there) and, for grub.cfg, its contents.
type grubFiles interface {
	Digest(path string) ([]byte, bool)
	Read(path string) ([]byte, bool)
}

// diskFiles is grubFiles on the file system.
type diskFiles struct{}

func (diskFiles) Digest(path string) ([]byte, bool) { return fileDigest(path) }
func (diskFiles) Read(path string) ([]byte, bool) {
	b, err := os.ReadFile(path)
	return b, err == nil
}

// predictGRUB rewrites the digests of the PCR 8 and 9 events in place for
// the next boot. kernels lists the installed kernel versions, newest last.
// Only events whose data is understood are touched; the rest replay as
// logged.
func predictGRUB(events []attest.Event, files grubFiles, kernels []string) *grubPrediction {
	digestOf := files.Digest
	p := &grubPrediction{}
	booted := ""
	for _, e := range events {
		if e.Index == 9 {
			if m := kernelVersion.FindStringSubmatch(eventText(e)); m != nil && m[1] == "vmlinuz" {
				booted = m[2]
			}
		}
	}
	next := booted
	if len(kernels) > 0 && kernels[len(kernels)-1] != booted && booted != "" {
		next = kernels[len(kernels)-1]
		p.NewKernel = next
	}
	swapVersion := func(s string) string {
		if next == booted || booted == "" {
			return s
		}
		return strings.ReplaceAll(s, booted, next)
	}

	// The devices: a file event whose logged digest is found under a
	// mount point names the device's mount point.
	devices := map[string]string{}
	for _, e := range events {
		if e.Index != 9 || e.Type != attest.EventType(0x0d) { // EV_IPL
			continue
		}
		m := grubFileEvent.FindStringSubmatch(eventText(e))
		if m == nil || m[1] == "" {
			continue
		}
		if _, known := devices[m[1]]; known {
			continue
		}
		for _, mp := range grubMountPoints {
			if d, ok := digestOf(filepath.Join(mp, m[2])); ok && bytes.Equal(d, e.Digest) {
				devices[m[1]] = mp
				break
			}
		}
	}

	// The menu commands are measured with their whole body, the raw text
	// of grub.cfg; a kernel update rewrites them. They are rebuilt from
	// the grub.cfg on disk, found through the device the log read it from.
	var grubCfg []byte
	for _, e := range events {
		if e.Index != 9 || e.Type != attest.EventType(0x0d) {
			continue
		}
		m := grubFileEvent.FindStringSubmatch(eventText(e))
		if m == nil || filepath.Base(m[2]) != "grub.cfg" || m[1] == "" {
			continue
		}
		if mp, ok := devices[m[1]]; ok && strings.HasPrefix(m[2], "/grub/") {
			if b, ok := files.Read(filepath.Join(mp, m[2])); ok {
				grubCfg = b
			}
		}
	}

	var cmdline string
	var initrdDigest []byte
	for i := range events {
		e := &events[i]
		text := eventText(*e)
		switch {
		case e.Index == 9 && e.Type == attest.EventType(0x0d):
			m := grubFileEvent.FindStringSubmatch(text)
			if m == nil {
				continue
			}
			rel := swapVersion(m[2])
			var path string
			if m[1] == "" {
				// A bare path is on GRUB's root device: /boot on Debian.
				path = filepath.Join("/boot", rel)
			} else if mp, ok := devices[m[1]]; ok {
				path = filepath.Join(mp, rel)
			} else {
				continue
			}
			d, ok := digestOf(path)
			if !ok {
				continue
			}
			if strings.HasPrefix(filepath.Base(path), "initrd.img-") {
				initrdDigest = d
			}
			if !bytes.Equal(d, e.Digest) {
				p.Substituted = append(p.Substituted, fmt.Sprintf("PCR9 %s: now %s", text, path))
				e.Digest = d
			}
		case e.Index == 8 && e.Type == attest.EventType(0x0d):
			prefix, cmd, ok := strings.Cut(text, ": ")
			if !ok || (prefix != "grub_cmd" && prefix != "kernel_cmdline") {
				continue
			}
			changed := swapVersion(cmd)
			if prefix == "grub_cmd" && (strings.HasPrefix(cmd, "menuentry ") || strings.HasPrefix(cmd, "submenu ")) {
				// From the file, not by substitution: the body lists
				// every kernel, and a version swap cannot know the list.
				rebuilt, ok := grubMenuCommand(grubCfg, menuID(cmd))
				if !ok {
					continue
				}
				changed = rebuilt
			}
			if prefix == "kernel_cmdline" {
				cmdline = changed
			}
			if changed != cmd {
				d := sha256.Sum256([]byte(changed))
				p.Substituted = append(p.Substituted, fmt.Sprintf("PCR8 %s: %s", prefix, changed))
				e.Digest = d[:]
			}
		case e.Index == 9 && e.Type == attest.EventType(0x06): // EV_EVENT_TAG, from the kernel's EFI stub
			switch {
			case strings.HasSuffix(text, "LOADED_IMAGE::LoadOptions") && cmdline != "":
				d := sha256.Sum256(utf16LE("BOOT_IMAGE=" + cmdline))
				if !bytes.Equal(d[:], e.Digest) {
					p.Substituted = append(p.Substituted, "PCR9 LoadOptions: BOOT_IMAGE="+cmdline)
					e.Digest = d[:]
				}
			case strings.HasSuffix(text, "Linux initrd") && initrdDigest != nil:
				if !bytes.Equal(initrdDigest, e.Digest) {
					p.Substituted = append(p.Substituted, "PCR9 Linux initrd: the initrd on disk")
					e.Digest = initrdDigest
				}
			}
		}
	}
	return p
}

// menuID is the --id of a measured menuentry or submenu command.
func menuID(cmd string) string {
	header, _, _ := strings.Cut(cmd, "\n")
	_, id, ok := strings.Cut(header, " --id ")
	if !ok {
		return ""
	}
	id, _, _ = strings.Cut(id, " ")
	return id
}

// grubMenuCommand rebuilds a menuentry or submenu command as GRUB measures
// it, from grub.cfg: the header with its arguments parsed (quotes gone,
// $menuentry_id_option expanded to --id) joined by single spaces, " {",
// then the body's lines and the closing brace exactly as in the file,
// indentation included.
func grubMenuCommand(cfg []byte, id string) (string, bool) {
	if id == "" || cfg == nil {
		return "", false
	}
	lines := strings.Split(string(cfg), "\n")
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, "\t ")
		if !(strings.HasPrefix(trimmed, "menuentry ") || strings.HasPrefix(trimmed, "submenu ")) || !strings.Contains(line, "'"+id+"'") {
			continue
		}
		indent := line[:len(line)-len(trimmed)]
		var out []string
		out = append(out, strings.Join(grubArgs(strings.TrimSuffix(trimmed, "{")), " ")+" {")
		// The body and the closing brace keep the file's indentation.
		for j := i + 1; j < len(lines); j++ {
			out = append(out, lines[j])
			if lines[j] == indent+"}" {
				return strings.Join(out, "\n"), true
			}
		}
		return "", false
	}
	return "", false
}

// grubArgs splits a GRUB command line into its words, taking single-quoted
// strings as one word without the quotes and expanding $menuentry_id_option.
func grubArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inQuote, have := false, false
	for _, r := range s {
		switch {
		case r == '\'':
			inQuote = !inQuote
			have = true
		case (r == ' ' || r == '\t') && !inQuote:
			if have {
				args = append(args, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if have {
		args = append(args, cur.String())
	}
	for i, a := range args {
		if a == "$menuentry_id_option" {
			args[i] = "--id"
		}
	}
	return args
}

func eventText(e attest.Event) string {
	return string(bytes.TrimRight(e.Data, "\x00"))
}

func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2*len(u))
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}

// fileDigest reads a file's SHA-256.
func fileDigest(path string) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, false
	}
	return h.Sum(nil), true
}

// installedKernels lists the kernel versions with an image in /boot,
// oldest first by Debian's ordering (dpkg --compare-versions would be
// exact; the version strings sort correctly as text for one series).
func installedKernels(bootDir string) []string {
	matches, _ := filepath.Glob(filepath.Join(bootDir, "vmlinuz-*"))
	var versions []string
	for _, m := range matches {
		v := strings.TrimPrefix(filepath.Base(m), "vmlinuz-")
		if _, err := os.Stat(filepath.Join(bootDir, "initrd.img-"+v)); err == nil {
			versions = append(versions, v)
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versionLess(versions[i], versions[j]) })
	return versions
}

// versionLess compares kernel versions numerically segment by segment.
func versionLess(a, b string) bool {
	as, bs := strings.FieldsFunc(a, versionSep), strings.FieldsFunc(b, versionSep)
	for i := 0; i < len(as) && i < len(bs); i++ {
		var x, y int
		_, errX := fmt.Sscanf(as[i], "%d", &x)
		_, errY := fmt.Sscanf(bs[i], "%d", &y)
		if errX == nil && errY == nil && x != y {
			return x < y
		}
		if as[i] != bs[i] && (errX != nil || errY != nil) {
			return as[i] < bs[i]
		}
	}
	return len(as) < len(bs)
}

func versionSep(r rune) bool { return r == '.' || r == '-' || r == '+' }
