package admin

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tpm2-trust/tpm2-kira/internal/imageplan"
)

// rebuildCommand is the build of the image the next boot starts.
func rebuildCommand(initramfs string) string {
	if initramfs == "initramfs-tools" {
		return "update-initramfs -u"
	}
	return "mkinitcpio -P"
}

// offerRebuild says why the image is out of date and what a build puts
// in, and runs mkinitcpio -P (update-initramfs -u) when asked. It is
// control's one rebuild, when control is left: what changes the image in
// the steps only marks it out of date.
func (c *controller) offerRebuild() error {
	f := &c.facts
	name := rebuildCommand(f.Initramfs)
	fmt.Fprintf(c.out, "\033[1mThe boot image is out of date\033[0m\n")
	for _, p := range f.Pending {
		fmt.Fprintf(c.out, "  - %s\n", p)
	}
	fmt.Fprintf(c.out, "\n\033[1mWhat %s puts in\033[0m\n%s", name, planText(f.Plan))
	if f.planHas(imageplan.PartPhone) {
		fmt.Fprintln(c.out, "\n"+btImagePlan(f.Adapter))
	}
	fmt.Fprintln(c.out)
	ok, err := c.confirmYes("Run "+name+" now?", "Builds the image the next boot starts; the output follows here.")
	if err != nil || !ok {
		fmt.Fprintf(c.out, "Not rebuilt: run %s yourself before the next boot.\n", name)
		return nil
	}
	argv := strings.Fields(name)
	rebuild := exec.Command(argv[0], argv[1:]...)
	rebuild.Stdout, rebuild.Stderr = c.out, c.out
	if err := rebuild.Run(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	fmt.Fprintln(c.out)
	fmt.Fprintln(c.out, "Reboot before enrolling a phone or a phone salt: the phone pins what the")
	fmt.Fprintln(c.out, "next boot shows, and the boot key answers only in a boot through this image.")
	return nil
}

// planText is the plan, a part per line: in, or out and why.
func planText(p *BootPlan) string {
	if p == nil {
		return ""
	}
	var b strings.Builder
	for _, pt := range p.Parts {
		if pt.On {
			fmt.Fprintf(&b, "  %s %-18s %s\n", good("✓"), pt.Title(), pt.Why)
		} else {
			fmt.Fprintf(&b, "  %s %-18s %s\n", "\033[0;90m-\033[0m", pt.Title(), "\033[0;90mout: "+pt.Why+"\033[0m")
		}
	}
	return b.String()
}

// planHas says whether the plan has the part in; false without a plan.
func (f *machineFacts) planHas(name string) bool {
	return f.Plan != nil && f.Plan.Has(name)
}

// imageLine is the status' line on the boot image: what it carries, or
// why it is rebuilt when control is left.
func (f *machineFacts) imageLine() string {
	if f.Plan == nil || f.Initramfs == "" || f.HookState != "" {
		return ""
	}
	var in []string
	for _, pt := range f.Plan.Parts {
		if pt.On {
			in = append(in, pt.Title())
		}
	}
	line := "carries " + strings.Join(in, ", ")
	if len(f.Unused) > 0 {
		line += "; the next build leaves out " + strings.Join(f.Unused, ", ") + ", which nothing uses any more"
	}
	switch {
	case len(f.Pending) > 0:
		return warn("rebuilt when you quit control: " + strings.Join(f.Pending, "; "))
	case f.ImageErr != "":
		return bad("its plan cannot be read (" + f.ImageErr + ")")
	}
	return good(line)
}

// btImagePlan says what the sd-tpm2-kira hook puts into the image for the
// adapter - the same resolution it runs (attest_initramfs.go) - so it can
// be seen before the rebuild, and checked after it.
func btImagePlan(adapter string) string {
	var n int
	if _, err := fmt.Sscanf(adapter, "hci%d", &n); err != nil {
		return ""
	}
	deps, err := ResolveBTDeps("/sys", DefaultFirmwareDir, n, append(readKernelLog(""), journalBluetoothLines()...))
	if err != nil {
		return "The sd-tpm2-kira hook adds Bluetooth for " + adapter + ": " + err.Error()
	}
	rememberedFirmware(deps, DefaultFirmwareDir)
	var b strings.Builder
	fmt.Fprintf(&b, "The sd-tpm2-kira hook adds for %s (no edit of mkinitcpio.conf):\n", adapter)
	fmt.Fprintf(&b, "  modules:   %s (with their dependencies)\n", strings.Join(deps.Modules, " "))
	if len(deps.Firmware) > 0 {
		fmt.Fprintf(&b, "  firmware:  %s\n", strings.Join(deps.Firmware, " "))
	} else {
		fmt.Fprintf(&b, "  firmware:  none known - only what the modules declare\n")
	}
	fmt.Fprintf(&b, "  and:       /%s, the signing public key", btModulesLoadConf)
	if deps.Authorize != nil {
		fmt.Fprintf(&b, "\n  and:       /%s, as the adapter's USB bus lets no new device in by itself:\n             %s", BTUdevRuleFile, deps.Authorize.UdevRule())
	}
	for _, w := range deps.Warnings {
		fmt.Fprintf(&b, "\n  NOTE: %s", w)
	}
	return b.String()
}

// imageHints is step 2's hint about the boot image: when it is current
// and this boot did not go through it, reboot - picking it does. An image
// out of date is rebuilt when control is left.
func (c *controller) imageHints() []controlStep {
	f := &c.facts
	if f.Initramfs == "" || !chainDone(f) || len(f.Pending) > 0 {
		return nil
	}
	if len(f.Status.Slots) == 0 || (f.Closed && f.NewImage == "") {
		return nil
	}
	why := "the boot image is ready, and this boot did not go through it"
	if f.NewImage != "" {
		why = f.NewImage
	}
	explain := "The device is ready to be rebooted: " + why + ". At the boot, compare the code on the screen with your authenticator, press Enter and type your passphrase."
	if f.Remote.SSH.On {
		explain += " With SSH at boot, the console says where to log in to do that remotely."
	}
	if !f.Phone {
		explain += " The phone and the disk keys that need it are enrolled afterwards, in a boot through the image."
	}
	return []controlStep{{Key: "reboot", Title: "Ready to reboot", Optional: true, SelfConfirm: true,
		Explain: explain + " Picking this reboots now, after a confirmation.",
		Run: func(c *controller) error {
			ok, err := c.confirm("Reboot now?", "Unsaved work in other programs is lost.")
			if err != nil || !ok {
				return errors.New("not rebooted")
			}
			return rebootNow()
		}}}
}

// pendingRebuild lists the files of the boot chain a boot image is built
// from that changed after the image the next boot starts was built: the
// HOOKS, the command line, crypttab. What the image carries for the
// protections is told by its plan (imageState).
func pendingRebuild(initramfs string) []string {
	var inputs []string
	switch initramfs {
	case "mkinitcpio":
		inputs = append([]string{mkinitcpioConf, "/etc/kernel/cmdline", "/etc/crypttab.initramfs"}, globs("/etc/mkinitcpio.conf.d/*.conf", "/etc/cmdline.d/*.conf")...)
	case "initramfs-tools":
		inputs = append([]string{"/etc/crypttab", "/etc/initramfs-tools/initramfs.conf", "/etc/initramfs-tools/modules"}, globs("/etc/initramfs-tools/conf.d/*")...)
	default:
		return nil
	}
	var out []string
	for _, img := range bootImages() {
		ist, err := os.Stat(img)
		if err != nil {
			continue
		}
		for _, in := range inputs {
			if st, err := os.Stat(in); err == nil && st.ModTime().After(ist.ModTime()) {
				out = append(out, fmt.Sprintf("%s changed after %s was built", in, filepath.Base(img)))
			}
		}
	}
	return out
}

// imageState compares the image the next boot starts with the plan: the
// reasons to rebuild (the boot chain's files, the parts in use and not in
// it), the parts it carries for nothing, and why its plan cannot be read.
func imageState(initramfs string, plan *BootPlan) (pending, unused []string, problem string) {
	if initramfs == "" {
		return nil, nil, ""
	}
	pending = pendingRebuild(initramfs)
	for _, img := range bootImages() {
		parts, err := imagePlan(img)
		switch {
		case os.IsNotExist(err):
			pending = append(pending, filepath.Base(img)+" is not built yet")
			continue
		case err != nil:
			problem = err.Error()
			continue
		}
		pending = append(pending, planPending(plan, parts, img)...)
		unused = append(unused, planUnused(plan, parts)...)
	}
	return pending, unused, problem
}

func globs(patterns ...string) []string {
	var out []string
	for _, p := range patterns {
		m, _ := filepath.Glob(p)
		out = append(out, m...)
	}
	return out
}
