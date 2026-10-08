package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The route of the disk's key: how the initrd is told to take the key
// from tpm2-kira. On a systemd initrd (Arch) that is the kernel command
// line, rd.luks.key=<UUID>=/run/tpm2-kira/unlock.sock next to
// rd.luks.name=<UUID>=<name>, or an x-initrd.attach line of /etc/crypttab
// with the socket as its key file; on Debian the crypttab line's
// keyscript=/lib/cryptsetup/scripts/tpm2-kira. tpm2-kira does not edit
// these files - they are the boot's, and a wrong line there costs a
// reboot - it reads them and prints the line as it should read, so the
// person changes exactly that. 'luks route' is the command, 'luks enrol'
// ends with it, 'status' notes it, and the mkinitcpio hook runs it.

// DebianKeyscript is the keyscript cryptsetup-initramfs runs for a volume.
const DebianKeyscript = "/lib/cryptsetup/scripts/tpm2-kira"

// RouteFinding is one file's verdict for one volume.
type RouteFinding struct {
	File    string `json:"file"`
	UUID    string `json:"uuid"`
	Device  string `json:"device,omitempty"`
	Routed  bool   `json:"routed"`            // the key comes from tpm2-kira
	Problem string `json:"problem,omitempty"` // what is wrong, if anything
	Should  string `json:"should,omitempty"`  // the line as it should read
	Note    string `json:"note,omitempty"`    // routed: how
}

// luksUUID is the LUKS UUID of a device.
var luksUUID = func(device string) (string, error) {
	out, err := cryptsetup(nil, "luksUUID", device)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// cmdlineFiles are where a systemd initrd's kernel command line comes
// from, the ones that exist: /etc/cmdline.d/*.conf when the directory has
// any (mkinitcpio then ignores /etc/kernel/cmdline), else
// /etc/kernel/cmdline; and every boot loader entry.
func cmdlineFiles() []string {
	var files []string
	if m, _ := filepath.Glob("/etc/cmdline.d/*.conf"); len(m) > 0 {
		files = append(files, m...)
	} else if _, err := os.Stat("/etc/kernel/cmdline"); err == nil {
		files = append(files, "/etc/kernel/cmdline")
	}
	for _, dir := range []string{"/boot/loader/entries", "/efi/loader/entries", "/boot/efi/loader/entries"} {
		if m, _ := filepath.Glob(filepath.Join(dir, "*.conf")); len(m) > 0 {
			files = append(files, m...)
		}
	}
	return files
}

// cmdlineOf is the command line in a file: the whole file, or, in a boot
// loader entry, its options line.
func cmdlineOf(file string, data []byte) string {
	if strings.Contains(file, "/loader/entries/") {
		for _, l := range strings.Split(string(data), "\n") {
			if f := strings.Fields(l); len(f) > 1 && f[0] == "options" {
				return strings.Join(f[1:], " ")
			}
		}
		return ""
	}
	return strings.Join(strings.Fields(string(data)), " ")
}

// AdviseCmdline judges one command line for one volume and says what it
// should read. A volume not named on it is not this line's business.
func AdviseCmdline(file, cmdline, uuid string) (RouteFinding, bool) {
	f := RouteFinding{File: file, UUID: uuid}
	words := strings.Fields(cmdline)
	var names, keys []int // indices of the words
	defaultKey := ""
	for i, w := range words {
		k, v, ok := strings.Cut(w, "=")
		if !ok {
			continue
		}
		k = strings.TrimPrefix(k, "rd.")
		switch k {
		case "luks.name":
			if strings.HasPrefix(v, uuid+"=") {
				names = append(names, i)
			}
		case "luks.key":
			if strings.HasPrefix(v, uuid+"=") {
				keys = append(keys, i)
			} else if !strings.Contains(v, "=") {
				defaultKey = v
			}
		}
	}
	if len(names) == 0 {
		return f, false
	}
	fixed := append([]string{}, words...)
	switch {
	case len(names) > 1:
		// The second rd.luks.name= is meant as the key: it carries a path.
		for _, i := range names[1:] {
			v := strings.TrimPrefix(words[i], "rd.")
			fixed[i] = "rd.luks.key=" + strings.TrimPrefix(v, "luks.name=")
		}
		f.Problem = fmt.Sprintf("rd.luks.name= for %s appears %d times; the key file is given with rd.luks.key=, not a second rd.luks.name=", uuid, len(names))
	case strings.HasPrefix(words[names[0]][strings.LastIndex(words[names[0]], "=")+1:], "/"):
		f.Problem = fmt.Sprintf("rd.luks.name= for %s names the volume %q, a path: the socket belongs into rd.luks.key=, the volume keeps its name", uuid, words[names[0]][strings.LastIndex(words[names[0]], "=")+1:])
		fixed[names[0]] = "rd.luks.name=" + uuid + "=cryptroot"
		fixed = append(fixed[:names[0]+1], append([]string{"rd.luks.key=" + uuid + "=" + DefaultUnlockSocket}, fixed[names[0]+1:]...)...)
	case len(keys) == 0 && defaultKey == DefaultUnlockSocket:
		f.Routed, f.Note = true, "rd.luks.key= without a UUID in "+file+", for every volume named there"
		return f, true
	case len(keys) == 0:
		f.Problem = fmt.Sprintf("rd.luks.key= for %s is missing: the initrd asks at systemd's own prompt", uuid)
		fixed = append(fixed[:names[0]+1], append([]string{"rd.luks.key=" + uuid + "=" + DefaultUnlockSocket}, fixed[names[0]+1:]...)...)
	default:
		path := words[keys[0]][strings.LastIndex(words[keys[0]], "=")+1:]
		if path == DefaultUnlockSocket {
			f.Routed, f.Note = true, "rd.luks.key= in "+file
			return f, true
		}
		f.Problem = fmt.Sprintf("rd.luks.key= for %s is %s, not tpm2-kira's socket", uuid, path)
		fixed[keys[0]] = "rd.luks.key=" + uuid + "=" + DefaultUnlockSocket
	}
	f.Should = strings.Join(fixed, " ")
	return f, true
}

// AdviseCrypttab judges /etc/crypttab for one volume, in the systemd form
// (the socket as the key file of an x-initrd.attach line; Arch) or the
// Debian form (the keyscript in the options).
func AdviseCrypttab(file string, data []byte, uuid, device string, debian bool) (RouteFinding, bool) {
	f := RouteFinding{File: file, UUID: uuid, Device: device}
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) < 2 {
			continue
		}
		dev := fields[1]
		if !strings.EqualFold(dev, "UUID="+uuid) && dev != device && dev != "/dev/disk/by-uuid/"+uuid {
			continue
		}
		key, opts := "none", ""
		if len(fields) > 2 {
			key = fields[2]
		}
		if len(fields) > 3 {
			opts = fields[3]
		}
		if debian {
			if strings.Contains(","+opts+",", ",keyscript="+DebianKeyscript+",") {
				f.Routed, f.Note = true, "keyscript= in "+file
				return f, true
			}
			f.Problem = fmt.Sprintf("the line for %s has no keyscript=%s: the initrd asks at cryptsetup's own prompt", fields[0], DebianKeyscript)
			o := strings.Split(opts, ",")
			var kept []string
			for _, x := range o {
				if x != "" && !strings.HasPrefix(x, "keyscript=") {
					kept = append(kept, x)
				}
			}
			kept = append(kept, "keyscript="+DebianKeyscript)
			f.Should = fields[0] + " " + dev + " " + key + " " + strings.Join(kept, ",")
			return f, true
		}
		if key == DefaultUnlockSocket && strings.Contains(","+opts+",", ",x-initrd.attach,") {
			f.Routed, f.Note = true, "the key file of "+fields[0]+" in "+file
			return f, true
		}
		if key == DefaultUnlockSocket {
			f.Problem = fmt.Sprintf("the line for %s has the socket as its key file but no x-initrd.attach: the initrd does not read it", fields[0])
		} else {
			f.Problem = fmt.Sprintf("the line for %s has %s as its key file, not tpm2-kira's socket", fields[0], key)
		}
		o := strings.Split(opts, ",")
		var kept []string
		for _, x := range o {
			if x != "" && x != "none" {
				kept = append(kept, x)
			}
		}
		if !strings.Contains(","+opts+",", ",x-initrd.attach,") {
			kept = append(kept, "x-initrd.attach")
		}
		f.Should = fields[0] + " " + dev + " " + DefaultUnlockSocket + " " + strings.Join(kept, ",")
		return f, true
	}
	return f, false
}

// isDebianInitramfs says whether this is an initramfs-tools system.
func isDebianInitramfs() bool {
	_, err := os.Stat("/etc/initramfs-tools")
	return err == nil
}

// RouteFindings gathers the findings for the devices (every LUKS device
// with a keyslot of tpm2-kira's when none is named), from the command
// line files and /etc/crypttab. A device routed nowhere gets a finding
// with the line to add.
func RouteFindings(devices []string, cmdlines []string, crypttab string) ([]RouteFinding, error) {
	if len(devices) == 0 {
		all, err := luksDevices()
		if err != nil {
			return nil, err
		}
		for _, d := range all {
			st := readLuksStatus(d)
			for _, ks := range st.Keyslots {
				if ks.Token != nil {
					devices = append(devices, d)
					break
				}
			}
		}
	}
	if cmdlines == nil {
		cmdlines = cmdlineFiles()
	}
	if crypttab == "" {
		crypttab = "/etc/crypttab"
	}
	debian := isDebianInitramfs()
	var out []RouteFinding
	for _, dev := range devices {
		uuid, err := luksUUID(dev)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", dev, err)
		}
		found := false
		if !debian {
			for _, file := range cmdlines {
				data, err := os.ReadFile(file)
				if err != nil {
					continue
				}
				if f, ok := AdviseCmdline(file, cmdlineOf(file, data), uuid); ok {
					f.Device = dev
					out = append(out, f)
					found = true
				}
			}
		}
		if data, err := os.ReadFile(crypttab); err == nil {
			if f, ok := AdviseCrypttab(crypttab, data, uuid, dev, debian); ok {
				out = append(out, f)
				found = true
			}
		}
		if !found {
			f := RouteFinding{UUID: uuid, Device: dev}
			if debian {
				f.File = crypttab
				f.Problem = "no line names this volume"
				f.Should = "cryptroot UUID=" + uuid + " none luks,discard,keyscript=" + DebianKeyscript
			} else {
				f.File = "the kernel command line"
				if len(cmdlines) > 0 {
					f.File = cmdlines[0]
				}
				f.Problem = "the volume is not named on the kernel command line, nor in " + crypttab
				f.Should = "rd.luks.name=" + uuid + "=cryptroot rd.luks.key=" + uuid + "=" + DefaultUnlockSocket + " root=/dev/mapper/cryptroot ..."
			}
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Device < out[j].Device })
	return out, nil
}

// errRouteProblem: at least one finding has a problem.
var errRouteProblem = errors.New("the disk's key is not routed through tpm2-kira everywhere")

// LuksRoute prints the findings; exit status 1 when a problem remains.
func LuksRoute(devices []string, cmdlines []string, crypttab string, jsonOut bool) error {
	findings, err := RouteFindings(devices, cmdlines, crypttab)
	if err != nil {
		return err
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if findings == nil {
			findings = []RouteFinding{}
		}
		return enc.Encode(findings)
	}
	if len(findings) == 0 {
		fmt.Println("No LUKS device has a keyslot of tpm2-kira's; nothing to route (tpm2-kira luks enrol).")
		return nil
	}
	problem := false
	for _, f := range findings {
		problem = problem || !f.Routed
		fmt.Print(routeText(f))
	}
	if problem {
		return errRouteProblem
	}
	return nil
}

// routeText is one finding, as printed.
func routeText(f RouteFinding) string {
	var b bytes.Buffer
	dev := f.Device
	if dev == "" {
		dev = f.UUID
	}
	if f.Routed {
		fmt.Fprintf(&b, "%s (%s): the key comes from tpm2-kira: %s\n", dev, f.UUID, f.Note)
		return b.String()
	}
	fmt.Fprintf(&b, "%s (%s): %s: %s.\n", dev, f.UUID, f.File, f.Problem)
	fmt.Fprintf(&b, "  The line should read:\n    %s\n", f.Should)
	return b.String()
}

// RouteAdvice is the advice as a block for 'luks enrol' and the hook: the
// findings for one device, with the rebuild line.
func RouteAdvice(device string) string {
	findings, err := RouteFindings([]string{device}, nil, "")
	if err != nil {
		return ""
	}
	var b bytes.Buffer
	for _, f := range findings {
		b.WriteString(routeText(f))
	}
	return b.String()
}
