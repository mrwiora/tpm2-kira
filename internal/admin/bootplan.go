package admin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/mrwiora/tpm2-kira/internal/imageplan"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/internal/sshscreen"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"

	"github.com/tpm2-trust/assh/config"
)

// The boot plan: what the boot image carries and starts, decided once, when
// it is built, from what this machine uses - the slots in the TPM and what
// each is enrolled with, the signing key, the Bluetooth adapter, the
// network and SSH settings of control.conf. The disk unlock is always in
// it: how a volume's key is made is read from its LUKS2 header at boot,
// and no recipe needs anything else of the image. Every other part goes
// in only when something uses it, and it says why it is out otherwise: no
// TPM, then no codes, no phone and no SSH server; no phone, then
// no Bluetooth.
//
// The hooks ask 'tpm2-kira initramfs plan', which writes the image's files
// for the parts that are in and says what the hook adds (WriteImage). The
// image names its parts in ImagePlanDir, one directory per part with an
// empty file named by the digest of the settings the part was built with:
// the boot reads which parts are there ('run --plan', the boot scripts),
// and control reads the image's listing to see whether a rebuild is due -
// a part that is in use now but not in the image, or whose settings
// changed. A part the image carries but nothing uses any more is no
// reason to rebuild: the next build leaves it out.

var planOrder = []string{imageplan.PartUnlock, imageplan.PartCodes, imageplan.PartPhone, imageplan.PartVault, imageplan.PartTPMSalt, imageplan.PartNet, imageplan.PartSSH}

var partTitles = map[string]string{
	imageplan.PartUnlock:  "Disk unlock",
	imageplan.PartCodes:   "TOTP codes",
	imageplan.PartPhone:   "Phone (Bluetooth)",
	imageplan.PartVault:   "Vault",
	imageplan.PartTPMSalt: "TPM salt",
	imageplan.PartNet:     "Network",
	imageplan.PartSSH:     "SSH server",
}

// PlanPart is one part of the plan: in or out, and why.
type PlanPart struct {
	Name   string
	On     bool
	Why    string // in: what uses it; out: why not
	Digest string // the settings it is built with; set when On
}

// Title is the part's name for the screen.
func (p PlanPart) Title() string { return partTitles[p.Name] }

// BootPlan is the decided plan, with what its files are made of.
type BootPlan struct {
	Parts    []PlanPart
	TPM      bool     // a part needs the TPM at boot
	Warnings []string // said at the build; not a reason for a part to be out
	in       planInputs
}

// Part is the named part; a part that is not in the plan is out.
func (p *BootPlan) Part(name string) PlanPart {
	if p == nil {
		return PlanPart{Name: name}
	}
	for _, pt := range p.Parts {
		if pt.Name == name {
			return pt
		}
	}
	return PlanPart{Name: name}
}

// Has says whether the named part is in.
func (p *BootPlan) Has(name string) bool { return p.Part(name).On }

// planInputs is what the plan is decided from; read by readPlanInputs on
// this machine, set by hand in the tests.
type planInputs struct {
	Config    ControlConfig
	ConfigErr string

	TPMErr   string
	Slots    int // populated slots: their codes are shown at boot
	Phones   int // phones enrolled, over all slots
	Vaults   int // slots enrolled with a vault
	TPMSalts int // slots holding a TPM salt (recipe 0x1200)

	Signer    []byte // the signing public key the gate checks the enrolments with (PEM)
	SignerErr string
	BT        *BTDeps // the adapter's driver and firmware
	BTErr     string

	Keys        []string // the keys that may log in over SSH
	KeysSkipped int      // lines of the file that let nobody in
	KeysErr     string
	SSHCA       sshCAState // the CA, whether it loads

	NoBusybox bool // initramfs-tools: no busybox in the image, so no ip

	DHCP dhcpIdentity // the identity the image's DHCP asks with
}

// PlanOptions is what reading the machine for the plan takes.
type PlanOptions struct {
	TPMPath    string
	ConfigPath string
	// KernelLog is extra kernel log text naming the adapter's firmware;
	// the journal's Bluetooth lines are read in any case.
	KernelLog string
	FwDir     string
	NoBusybox bool
	Debug     bool
}

// ReadBootPlan decides the plan for this machine as it is now.
func ReadBootPlan(o PlanOptions) *BootPlan {
	return decidePlan(readPlanInputs(o))
}

// readPlanInputs reads what the plan is decided from. Nothing in here
// fails the build: what cannot be read keeps its part out, and says why.
func readPlanInputs(o PlanOptions) planInputs {
	in := planInputs{NoBusybox: o.NoBusybox}
	cfg, err := LoadControlConfig(o.ConfigPath)
	if err != nil {
		in.ConfigErr = err.Error()
		cfg = DefaultControlConfig()
		cfg.Remote.SSH.Assh = sshConfDefaults(config.Default(), o.ConfigPath)
	}
	in.Config = cfg
	in.DHCP = cfg.Remote.Net.DHCPIdentity()

	tpmDev, err := tpmdev.Open(o.TPMPath)
	if err != nil {
		in.TPMErr = err.Error()
	} else {
		for _, idx := range nvslot.FindPopulatedSlots(tpmDev, o.Debug) {
			_, sb, err := phonegate.ReadSlot(tpmDev, idx)
			if err != nil {
				continue
			}
			in.Slots++
			if att := sb.Payload.Attestation; att != nil {
				if att.Phone.Enabled() {
					in.Phones += len(att.Phone.Verifiers)
				}
				if att.Vault.Enabled() {
					in.Vaults++
				}
				if len(att.TPMSalt.Credential) != 0 {
					in.TPMSalts++
				}
			}
		}
		// The gate checks an enrolment with the signing public key before
		// it advertises. With a phone the records are checked here first:
		// one written by somebody else, or an older one put back, keeps the
		// gate out. Packed ahead of any enrolment, the key is setup's.
		switch {
		case in.Phones > 0:
			var why bytes.Buffer
			pem, code := phonegate.SignerForImage(tpmDev, "", &why, o.Debug)
			if code != 0 {
				in.SignerErr = strings.Join(strings.Fields(strings.ReplaceAll(why.String(), "tpm2-kira: ", "")), " ")
			}
			in.Signer = pem
		case cfg.Attest.Bluetooth == "always":
			if pub, path, err := phonegate.AttestPublicKey(""); err != nil {
				in.SignerErr = fmt.Sprintf("no signing public key at %s (tpm2-kira setup)", path)
			} else if in.Signer, err = signing.PublicKeyToPEM(pub); err != nil {
				in.SignerErr = err.Error()
			}
		}
		tpmDev.Close()
	}

	if in.TPMErr == "" && (in.Phones > 0 || cfg.Attest.Bluetooth == "always") {
		fw := o.FwDir
		if fw == "" {
			fw = DefaultFirmwareDir
		}
		log := append(readKernelLog(o.KernelLog), journalBluetoothLines()...)
		if deps, err := ResolveBTDeps("/sys", fw, cfg.Attest.Adapter, log); err != nil {
			in.BTErr = err.Error()
		} else {
			rememberedFirmware(deps, fw)
			in.BT = deps
		}
	}

	if cfg.Remote.SSH.On {
		keys, skipped, err := sshscreen.AuthorizedKeys(cfg.Remote.SSH.Assh.AuthorizedKeys)
		switch {
		case err != nil:
			in.KeysErr = err.Error()
		case len(keys) == 0:
			in.KeysErr = cfg.Remote.SSH.Assh.AuthorizedKeys + " holds no key without options: nobody could log in"
		default:
			in.Keys = keys
		}
		in.KeysSkipped = skipped
		in.SSHCA = loadSSHCA(cfg.Remote.SSH.Assh)
	}
	return in
}

// decidePlan is the rules: each part in or out, and why.
func decidePlan(in planInputs) *BootPlan {
	p := &BootPlan{in: in}
	cfg := in.Config
	if in.ConfigErr != "" {
		p.Warnings = append(p.Warnings, fmt.Sprintf("control.conf does not load (%s): the image is built with the defaults - no network, no SSH, Bluetooth only with an enrolled phone", in.ConfigErr))
	}
	noTPM := "no TPM (" + in.TPMErr + ")"
	add := func(name string, on bool, why string, digest ...string) {
		pt := PlanPart{Name: name, On: on, Why: why}
		if on {
			pt.Digest = planDigest(append([]string{name}, digest...)...)
		}
		p.Parts = append(p.Parts, pt)
	}

	add(imageplan.PartUnlock, true, "the key of every volume routed through tpm2-kira, made as its LUKS2 header says")

	switch {
	case in.TPMErr != "":
		add(imageplan.PartCodes, false, noTPM)
	case in.Slots == 0:
		add(imageplan.PartCodes, false, "nothing is sealed (tpm2-kira slot add)")
	default:
		add(imageplan.PartCodes, true, plural(in.Slots, "slot")+" sealed")
	}

	always := cfg.Attest.Bluetooth == "always"
	switch {
	case in.TPMErr != "":
		add(imageplan.PartPhone, false, noTPM+": a phone cannot attest this machine")
	case in.Phones == 0 && !always:
		add(imageplan.PartPhone, false, "no phone is enrolled")
	case in.SignerErr != "":
		add(imageplan.PartPhone, false, "the enrolment is not accepted: "+in.SignerErr)
	case in.BT == nil:
		add(imageplan.PartPhone, false, in.BTErr)
	default:
		why := plural(in.Phones, "phone") + " enrolled, via " + in.BT.Adapter
		if in.Phones == 0 {
			why = "packed into every image (TPM2_KIRA_ATTEST_BLUETOOTH=always), via " + in.BT.Adapter
		}
		rule := ""
		if in.BT.Authorize != nil {
			rule = in.BT.Authorize.UdevRule()
		}
		add(imageplan.PartPhone, true, why, strings.Join(in.BT.Modules, " "), strings.Join(in.BT.Firmware, " "), rule, string(in.Signer))
	}
	if in.BT != nil && p.Has(imageplan.PartPhone) {
		p.Warnings = append(p.Warnings, in.BT.Warnings...)
	}

	net := cfg.Remote.Net
	switch {
	case net.Mode == "off":
		add(imageplan.PartNet, false, "off (Network and SSH at boot)")
	case net.problem() != "":
		add(imageplan.PartNet, false, net.problem())
	case in.NoBusybox:
		add(imageplan.PartNet, false, "it needs busybox in the image (apt install busybox, BUSYBOX not n in initramfs.conf)")
	default:
		why := net.Mode
		if net.Mode == "dhcp" && in.DHCP.From != "" {
			why += ", asking as " + in.DHCP.From
			if in.DHCP.ID != nil {
				why += " (" + colonHex(in.DHCP.ID) + ")"
			}
			if in.DHCP.ID == nil && strings.HasPrefix(in.DHCP.From, "unknown") {
				p.Warnings = append(p.Warnings, "the running system's DHCP identity is "+in.DHCP.From+": the image asks with its MAC and may get another address than the running system (TPM2_KIRA_NET_DHCP_ID sets it)")
			}
		}
		add(imageplan.PartNet, true, why, net.Mode, net.Match, strings.Join(net.Addresses, " "), strings.Join(net.Gateways, " "), strings.Join(net.DNS, " "), hex.EncodeToString(in.DHCP.ID))
	}

	switch {
	case in.Vaults == 0:
		add(imageplan.PartVault, false, "no slot is enrolled with a vault")
	case in.TPMErr != "":
		add(imageplan.PartVault, false, noTPM)
	case !p.Has(imageplan.PartNet):
		add(imageplan.PartVault, false, "the vault is asked over the network, and the image has none")
	default:
		add(imageplan.PartVault, true, plural(in.Vaults, "slot")+" enrolled with a vault")
	}

	switch {
	case in.TPMSalts == 0:
		add(imageplan.PartTPMSalt, false, "no slot holds a TPM salt")
	case in.TPMErr != "":
		add(imageplan.PartTPMSalt, false, noTPM)
	default:
		add(imageplan.PartTPMSalt, true, plural(in.TPMSalts, "slot")+" holding a TPM salt")
	}

	ssh := cfg.Remote.SSH
	switch {
	case !ssh.On:
		add(imageplan.PartSSH, false, "off (Network and SSH at boot)")
	case !p.Has(imageplan.PartNet):
		add(imageplan.PartSSH, false, "it needs the image's network")
	case in.TPMErr != "":
		add(imageplan.PartSSH, false, noTPM+": the host key is made and certified in it")
	case in.KeysErr != "":
		add(imageplan.PartSSH, false, in.KeysErr)
	case in.SSHCA.Err != "":
		add(imageplan.PartSSH, false, in.SSHCA.Err)
	default:
		fp := in.SSHCA.CA.Fingerprint()
		add(imageplan.PartSSH, true, fmt.Sprintf("port %d, host keys certified by the SSH CA %s", ssh.Port(), fp),
			fmt.Sprint(ssh.Hold), fp, keysSum(imageKeys(in.Keys)), keysSum(imageSSHConf(ssh.Assh)))
	}
	if p.Has(imageplan.PartSSH) && in.KeysSkipped > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("%d line(s) of %s left out: options in front of the key are not honoured, and what does not parse is no key", in.KeysSkipped, ssh.Assh.AuthorizedKeys))
	}

	sort.SliceStable(p.Parts, func(i, j int) bool { return planIndex(p.Parts[i].Name) < planIndex(p.Parts[j].Name) })
	p.TPM = p.Has(imageplan.PartCodes) || p.Has(imageplan.PartPhone) || p.Has(imageplan.PartVault) || p.Has(imageplan.PartTPMSalt) || p.Has(imageplan.PartSSH)
	return p
}

func planIndex(name string) int {
	for i, n := range planOrder {
		if n == name {
			return i
		}
	}
	return len(planOrder)
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

// planDigest names the settings a part is built with: short, as it is
// part of a file name in the image.
func planDigest(fields ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	return hex.EncodeToString(sum[:8])
}

// The image's files for the parts. 'initramfs plan --buildroot' writes them
// and prints, one per line, what the hook itself adds:
//
//	say TEXT              a line of the build output: a part, in or out
//	warning TEXT          said as a warning; the build goes on
//	module NAME           a module the image needs (efivarfs, for the SSH CA)
//	bt-module NAME        the adapter's driver (with its dependencies)
//	bt-firmware PATH      the firmware the adapter loads
//	net-module NAME       the driver of an interface the network matches
//	net-modules-all       no interface matched here: every network driver
//
// The units are the hook's: it adds them by the parts ImagePlanDir names.

// WriteImage writes the plan's files into the image under construction
// and says what the hook adds.
func (p *BootPlan) WriteImage(buildroot, format string, out io.Writer) error {
	if buildroot == "" {
		return fmt.Errorf("--buildroot is required")
	}
	if format != FormatMkinitcpio && format != FormatInitramfsTools {
		return fmt.Errorf("--format must be %s or %s, not %q", FormatMkinitcpio, FormatInitramfsTools, format)
	}
	in := p.in

	dir := filepath.Join(buildroot, imageplan.Dir)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	markers := append([]PlanPart{}, p.Parts...)
	if p.TPM {
		markers = append(markers, PlanPart{Name: imageplan.PartTPM, On: true, Digest: planDigest(imageplan.PartTPM)})
	}
	for _, pt := range markers {
		if pt.On {
			if err := writeImageFile(buildroot, filepath.Join(imageplan.Dir, pt.Name, pt.Digest), nil, 0o644); err != nil {
				return err
			}
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, pt := range p.Parts {
		state := "in  - "
		if !pt.On {
			state = "out - "
		}
		fmt.Fprintf(out, "say %-18s %s%s\n", pt.Title()+":", state, pt.Why)
	}
	for _, w := range p.Warnings {
		fmt.Fprintf(out, "warning %s\n", w)
	}

	if p.Has(imageplan.PartPhone) {
		bt := in.BT
		// The adapter's modules are loaded by the image's init, before
		// run: mkinitcpio's systemd-modules-load reads this list,
		// initramfs-tools' init the hook's (bt-module, force_load).
		if format == FormatMkinitcpio {
			modules := []byte(strings.Join(bt.Modules, "\n") + "\n")
			if err := writeImageFile(buildroot, "/"+btModulesLoadConf, modules, 0o644); err != nil {
				return err
			}
		}
		// The signing key's public half, which the gate checks the
		// enrolment with: in the image alone, never on the running system.
		if err := writeImageFile(buildroot, phonegate.DefaultAttestSignerPath, in.Signer, 0o644); err != nil {
			return err
		}
		// The adapter's USB bus lets no new device in by itself: the rule
		// lets exactly this adapter in, at its port, in the image alone.
		if bt.Authorize != nil {
			if err := writeImageFile(buildroot, "/"+BTUdevRuleFile, []byte(bt.Authorize.UdevRule()+"\n"), 0o644); err != nil {
				return err
			}
		}
		for _, m := range bt.Modules {
			fmt.Fprintf(out, "bt-module %s\n", m)
		}
		for _, f := range bt.Firmware {
			fmt.Fprintf(out, "bt-firmware %s\n", f)
		}
	}

	if p.Has(imageplan.PartNet) {
		r := in.Config.Remote
		if !p.Has(imageplan.PartSSH) {
			r.SSH.On = false
		}
		if format == FormatInitramfsTools {
			if err := writeImageFile(buildroot, imageRemoteConf, []byte(remoteConf(r, in.DHCP)), 0o644); err != nil {
				return err
			}
			if in.DHCP.ID != nil {
				if err := writeImageFile(buildroot, imageUdhcpcScript, []byte(udhcpcScript), 0o755); err != nil {
					return err
				}
			}
		} else {
			mac := r.Net.Match
			if m := r.Net.matchedInterfaces(); len(m) == 1 {
				mac = m[0].MAC
			}
			if _, ok := networkdDHCP(in.DHCP.ID, mac); !ok {
				fmt.Fprintf(out, "warning the DHCP client identifier %s is none systemd-networkd sends: the image asks with its MAC\n", colonHex(in.DHCP.ID))
			}
			if err := writeImageFile(buildroot, imageNetworkFile, []byte(r.Net.NetworkdFile(in.DHCP)), 0o644); err != nil {
				return err
			}
		}
		matched := r.Net.matchedInterfaces()
		if len(matched) == 0 {
			what := "no wired interface"
			if r.Net.Match != "" {
				what = "no interface " + r.Net.Match
			}
			fmt.Fprintln(out, "net-modules-all")
			fmt.Fprintf(out, "warning %s on this machine: every network driver goes into the image\n", what)
		}
		for _, it := range matched {
			if it.Module != "" {
				fmt.Fprintf(out, "net-module %s\n", it.Module)
			}
		}
	}

	if p.Has(imageplan.PartSSH) {
		// The CA is read from its EFI variable at boot; initramfs-tools
		// mounts no efivarfs, run does, with the module where it is one.
		fmt.Fprintln(out, "module efivarfs")
		// assh.conf, and the keys where it says: the paths of the image
		// are the running system's.
		assh := in.Config.Remote.SSH.Assh
		if err := writeImageFile(buildroot, sshscreen.DefaultConf, imageSSHConf(assh), 0o644); err != nil {
			return err
		}
		if err := writeImageFile(buildroot, assh.AuthorizedKeys, imageKeys(in.Keys), 0o600); err != nil {
			return err
		}
		if format == FormatMkinitcpio {
			if err := writeImageFile(buildroot, imageRunDropIn, []byte(runDropIn(in.Config.Remote.SSH)), 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// drop takes a part out after the decision, with the reason, and what
// needed it with it.
func (p *BootPlan) drop(name, why string) {
	for i := range p.Parts {
		if p.Parts[i].Name == name {
			p.Parts[i] = PlanPart{Name: name, Why: why}
		}
	}
	p.TPM = p.Has(imageplan.PartCodes) || p.Has(imageplan.PartPhone) || p.Has(imageplan.PartVault) || p.Has(imageplan.PartTPMSalt) || p.Has(imageplan.PartSSH)
}

// InitramfsPlanCommand implements 'initramfs plan': with a build root the
// image's files and the hook's lines, without one the plan alone.
func InitramfsPlanCommand(o PlanOptions, buildroot, format string, out io.Writer) error {
	p := ReadBootPlan(o)
	if buildroot != "" {
		return p.WriteImage(buildroot, format, out)
	}
	for _, pt := range p.Parts {
		state := "in "
		if !pt.On {
			state = "out"
		}
		fmt.Fprintf(out, "%s %-18s %s\n", state, pt.Title(), pt.Why)
	}
	for _, w := range p.Warnings {
		fmt.Fprintf(out, "warning: %s\n", w)
	}
	return nil
}

// imagePlan is the parts an image names, each with the digest of the
// settings it was built with, from the image's listing. An image that
// names none was built without a plan: nothing of it is known.
func imagePlan(img string) (map[string]string, error) {
	files, err := imageFiles(img)
	if err != nil {
		return nil, err
	}
	parts := map[string]string{}
	prefix := strings.TrimPrefix(imageplan.Dir, "/") + "/"
	for f := range files {
		rest, ok := strings.CutPrefix(strings.TrimSuffix(f, "/"), prefix)
		if !ok || rest == "" {
			continue
		}
		name, digest, _ := strings.Cut(rest, "/")
		if parts[name] == "" {
			parts[name] = digest
		}
	}
	return parts, nil
}

// switchedOffRebuilds are the parts that, switched off, are a reason to
// rebuild at once: they open the machine to the network at boot, and
// switching them off means the next boot without them - not one that still
// listens until some later build.
var switchedOffRebuilds = []string{imageplan.PartSSH, imageplan.PartNet}

// planPending compares the plan with an image's parts: what is in use now
// and not in the image, or in it with other settings, is a reason to
// rebuild, and so is the SSH server or the network switched off while the
// image still carries it. Another part the image carries and nothing uses
// is not: the next build leaves it out.
func planPending(p *BootPlan, image map[string]string, img string) []string {
	var out []string
	name := filepath.Base(img)
	for _, part := range switchedOffRebuilds {
		if _, ok := image[part]; ok && !p.Has(part) {
			out = append(out, fmt.Sprintf("%s: switched off, still in %s - the next boot would start it", partTitles[part], name))
		}
	}
	for _, pt := range p.Parts {
		if !pt.On {
			continue
		}
		switch digest, ok := image[pt.Name]; {
		case !ok:
			out = append(out, fmt.Sprintf("%s: in use now, not in %s yet (%s)", pt.Title(), name, pt.Why))
		case digest != pt.Digest:
			out = append(out, fmt.Sprintf("%s: its settings changed after %s was built", pt.Title(), name))
		}
	}
	return out
}

// planUnused are the parts an image carries that nothing uses any more,
// other than those switched off that planPending names: the next build
// leaves them out.
func planUnused(p *BootPlan, image map[string]string) []string {
	var out []string
	for _, name := range planOrder {
		if _, ok := image[name]; ok && !p.Has(name) && !slices.Contains(switchedOffRebuilds, name) {
			out = append(out, partTitles[name])
		}
	}
	return out
}
