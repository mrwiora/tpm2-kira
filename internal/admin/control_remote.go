package admin

import (
	"crypto"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/internal/sshscreen"

	"charm.land/huh/v2"
	"github.com/tpm2-trust/assh/config"
	"github.com/tpm2-trust/assh/hostkey"
)

// control's options for the boot image's network and SSH server
// (remote_config.go, docs/SSH.md), under "Network and SSH at boot": the
// settings are asked one by one, proposed from what is set or, the first
// time, from the running system's network configuration (systemd-networkd
// or ifupdown), and written into control.conf; the image takes them at
// the rebuild when control is left. Nothing of it is on until it is
// picked here. SSH needs the network: picked without one, it sets the
// network up first.

// netStep is the network's line.
func (c *controller) netStep() controlStep {
	f := &c.facts
	st := controlStep{Key: "net", Title: "Network in the boot image", Optional: true, SelfConfirm: true,
		Explain: "The boot image brings up its own network, DHCP or a static address, set here and nowhere else - what the vault and the SSH server at boot reach the machine by. Picking it changes the settings; Off switches the network and SSH off.",
		Run:     (*controller).runNetwork}
	switch {
	case f.Initramfs != "mkinitcpio" && f.Initramfs != "initramfs-tools":
		st.Blocked = "the boot image is built with mkinitcpio or initramfs-tools only"
	case f.AttestConf != "":
		st.Blocked = "control.conf does not load"
	case f.Remote.Net.Mode != "off":
		st.Done = f.Remote.Net.Describe()
		if p := f.Remote.Problem(); p != "" && !f.Remote.SSH.On {
			st.Done, st.Dirty = "", p
		}
	case f.Wired == 0:
		st.Blocked = "no wired network interface (wireless is not supported in the boot image)"
	}
	return st
}

// sshStep is the SSH server's line.
func (c *controller) sshStep() controlStep {
	f := &c.facts
	st := controlStep{Key: "ssh", Title: "SSH server at boot", Optional: true, SelfConfirm: true,
		Explain: "tpm2-kira starts its own, unprivileged SSH server with the code screen: the codes are confirmed and the passwords typed in an SSH session, and the console says where to log in - Enter there continues at the console instead. It needs the image's network, and sets it up first when there is none. Picking it changes the settings.",
		Run:     (*controller).runSSH}
	switch {
	case f.Initramfs != "mkinitcpio" && f.Initramfs != "initramfs-tools":
		st.Blocked = "the boot image is built with mkinitcpio or initramfs-tools only"
	case f.AttestConf != "":
		st.Blocked = "control.conf does not load"
	case !f.Remote.SSH.On && f.Remote.Net.Mode == "off" && f.Wired == 0:
		st.Blocked = "needs the image's network, and this machine has no wired interface"
	case !f.Remote.SSH.On:
	case f.Remote.Problem() != "":
		st.Dirty = f.Remote.Problem()
	case f.SSHKeys < 0:
		st.Dirty = f.Remote.SSH.Assh.AuthorizedKeys + " cannot be read: nobody can log in"
	case f.SSHKeys == 0:
		st.Dirty = f.Remote.SSH.Assh.AuthorizedKeys + " holds no key without options: nobody can log in"
	case f.TPMErr != "":
		st.Dirty = "no TPM: the host keys are made and certified in it, and the image is built without SSH"
	case f.SSHCA.CA == nil:
		st.Dirty = f.SSHCA.Err + ": the image is built without SSH"
	case f.SSHCAOtherKey:
		st.Dirty = "the SSH CA " + f.SSHCA.CA.Fingerprint() + " was made for another signing key: slot approve cannot approve it, the next boots serve a temporary host key - pick this to create it again"
	default:
		lines := RemoteStatusLines(f.Remote)
		st.Done = strings.TrimPrefix(lines[len(lines)-1], "SSH at boot: ") + fmt.Sprintf("; %d key(s) may log in; SSH CA %s", f.SSHKeys, f.SSHCA.CA.Fingerprint())
		if !f.SSHCA.Approved() {
			st.Done += "; " + sshCAUnapproved
		} else if n := f.SSHCA.Unapproved(); len(n) > 0 {
			st.Done += fmt.Sprintf("; the SSH CA's slot %s has no approval of the next boot: approved when you quit control", strings.Trim(fmt.Sprint(n), "[]"))
		}
	}
	return st
}

// runNetwork asks the network's settings and writes them.
func (c *controller) runNetwork() error {
	r := c.facts.Remote
	if r.Net.Mode == "off" {
		// The first time: what the running system does, as the proposal.
		sug, from := SuggestNetwork()
		fmt.Fprintf(c.out, "Proposed from the running system (%s): %s\n", from, sug.Describe())
		r.Net = sug
	}
	mode := r.Net.Mode
	if err := c.form(huh.NewSelect[string]().Title("Network in the boot image").
		Description("Set for the image alone; the running system's network configuration stays as it is.").
		Options(huh.NewOption("DHCP", "dhcp"), huh.NewOption("Static address", "static"),
			huh.NewOption("Off: no network, no SSH", "off")).
		Value(&mode)).Run(); err != nil {
		return err
	}
	if mode == "off" {
		for _, s := range c.facts.Status.Slots {
			if s.Vault == "" {
				continue
			}
			ok, err := c.confirm("Switch the network off?", "Slot "+fmt.Sprint(s.Slot)+"'s keyslot opens with the vault at "+s.Vault+", which the boot then cannot reach: the recovery passphrase is the way in.")
			if err != nil || !ok {
				return errors.New("not switched off")
			}
		}
		wasOn := r.SSH.On
		r.Net.Mode, r.SSH.On = "off", false
		if err := c.writeRemote(r); err != nil {
			return err
		}
		if wasOn {
			return c.offerRemoveSSHCA(r.SSH.Assh.CA)
		}
		return nil
	}
	r.Net.Mode = mode

	var ifaces []string
	for _, it := range physicalInterfaces() {
		kind := "wired"
		if it.Wireless {
			kind = "wireless: not supported in the image"
		}
		ifaces = append(ifaces, fmt.Sprintf("%s %s (%s)", it.Name, it.MAC, kind))
	}
	match := r.Net.Match
	if err := c.form(huh.NewInput().Title("Interface: its MAC address, or its name").
		Description("The MAC is safer: the image may name the interface differently. Empty: every wired interface (DHCP only).\nThis machine: " + strings.Join(ifaces, "; ")).
		Value(&match).Validate(func(s string) error {
		s = strings.TrimSpace(s)
		switch {
		case s == "" && mode == "static":
			return errors.New("a static address needs one interface")
		case s != "" && !isMAC(s) && !ifaceRe.MatchString(s):
			return errors.New("a MAC address (aa:bb:cc:dd:ee:ff) or an interface name")
		}
		return nil
	})).Run(); err != nil {
		return err
	}
	r.Net.Match = strings.TrimSpace(match)
	if isMAC(r.Net.Match) {
		r.Net.Match = strings.ToLower(r.Net.Match)
	}

	if mode == "static" {
		addr, gw, dns := strings.Join(r.Net.Addresses, " "), strings.Join(r.Net.Gateways, " "), strings.Join(r.Net.DNS, " ")
		if err := c.form(
			huh.NewInput().Title("Address with prefix (several: separated by spaces)").Value(&addr).Validate(validList(true, true)),
			huh.NewInput().Title("Gateway (empty: none)").Value(&gw).Validate(validList(false, false)),
			huh.NewInput().Title("DNS servers (empty: none)").Value(&dns).Validate(validList(false, false)),
		).Run(); err != nil {
			return err
		}
		r.Net.Addresses, r.Net.Gateways, r.Net.DNS = strings.Fields(addr), strings.Fields(gw), strings.Fields(dns)
	} else {
		r.Net.Addresses, r.Net.Gateways = nil, nil
	}
	return c.writeRemote(r)
}

// runSSH asks the SSH server's settings - the network first, when the
// image has none - and writes them.
func (c *controller) runSSH() error {
	if c.facts.Remote.Net.Mode == "off" {
		ok, err := c.confirmYes("SSH needs the boot image's network. Set it up now?", "The same as \"Network in the boot image\"; the SSH settings follow.")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("no network in the boot image: no SSH there")
		}
		if err := c.runNetwork(); err != nil {
			return err
		}
		if c.facts.Remote.Net.Mode == "off" {
			return errors.New("no network in the boot image: no SSH there")
		}
	}
	r := c.facts.Remote
	on := r.SSH.On // off until somebody says yes
	if err := c.form(huh.NewConfirm().Title("Start the SSH server with the code screen?").
		Description("tpm2-kira's own, unprivileged SSH server at boot: log in as root with a key of " + r.SSH.Assh.AuthorizedKeys + ", confirm the code, type the password there.").
		Affirmative("Yes").Negative("No: the network alone").Value(&on)).Run(); err != nil {
		return err
	}
	wasOn := r.SSH.On
	r.SSH.On = on
	if !on && wasOn {
		if err := c.writeRemote(r); err != nil {
			return err
		}
		return c.offerRemoveSSHCA(r.SSH.Assh.CA)
	}
	if on {
		port, hold := strconv.Itoa(r.SSH.Port()), strconv.Itoa(r.SSH.Hold)
		if err := c.form(
			huh.NewInput().Title("SSH port").Value(&port).Validate(func(s string) error {
				if p, err := strconv.Atoi(s); err != nil || p < 1 || p > 65535 {
					return errors.New("a port number")
				}
				return nil
			}),
			huh.NewInput().Title("Seconds the boot waits for the confirmation (0: until it comes)").
				Description("Enter at the console always continues there at once.").
				Value(&hold).Validate(func(s string) error {
				if h, err := strconv.Atoi(s); err != nil || h < 0 {
					return errors.New("seconds, or 0")
				}
				return nil
			}),
		).Run(); err != nil {
			return err
		}
		r.SSH.Assh.Listen = ":" + port
		r.SSH.Hold, _ = strconv.Atoi(hold)
		if err := c.ensureSSHKeys(&r.SSH); err != nil {
			return err
		}
	}
	return c.writeRemote(r)
}

// offerRemoveSSHCA asks, once the SSH server is switched off, whether the
// SSH CA goes too - No unless said. Kept, it serves again when SSH is
// switched on, and the clients' known_hosts line stays good; removed, the
// CA made then is a new one, which every client must trust again.
func (c *controller) offerRemoveSSHCA(path string) error {
	if !sshCAThere(path) {
		return nil
	}
	ok, err := c.confirm("Remove the SSH CA too?",
		"The SSH server is off. Kept, the CA "+path+" serves again when SSH is switched on, and the clients' known_hosts line stays good. Removed (the EFI variable and "+sshCAPub(path)+"), a CA made later is a new one that every client must trust again.")
	if err != nil || !ok {
		return err
	}
	removed, err := removeSSHCA(c.o.TPMPath, path)
	for _, r := range removed {
		fmt.Fprintf(c.out, "Removed %s\n", r)
	}
	return err
}

// ensureSSHKeys checks what the image's SSH server needs on this system:
// the SSH CA in the TPM, created when asked (its slots go into s's
// assh.conf), and a key that may log in.
func (c *controller) ensureSSHKeys(s *SSHConfig) error {
	if err := c.ensureSSHCA(&s.Assh); err != nil {
		return err
	}
	if authorizedKeyCount(s.Assh.AuthorizedKeys) <= 0 {
		if err := c.offerRootKeys(s.Assh.AuthorizedKeys); err != nil {
			return err
		}
	}
	switch n := authorizedKeyCount(s.Assh.AuthorizedKeys); {
	case n < 0:
		fmt.Fprintln(c.out, warn(s.Assh.AuthorizedKeys+" cannot be read: nobody could log in. Put a key there before the rebuild."))
	case n == 0:
		fmt.Fprintln(c.out, warn(s.Assh.AuthorizedKeys+" holds no key without options: nobody could log in."))
	default:
		fmt.Fprintf(c.out, "%s: %d key(s) may log in at boot.\n", s.Assh.AuthorizedKeys, n)
	}
	return nil
}

// ensureSSHCA creates the SSH CA in the TPM when there is none, or when the
// one there was made for another signing key and the person says so - with
// the slots of conf, or when it has none those worked out for this
// machine, which go into conf - approved for the next boot with the
// signing key, and says how clients trust it. A CA that stays gives conf
// its slots when conf has none, so that assh.conf shows them.
func (c *controller) ensureSSHCA(conf *config.Config) error {
	path := conf.CA
	if st := readSSHCA(*conf, c.o.TPMPath); st.CA != nil {
		pub, err := signing.LoadCheckedSigningPublicKey(signing.DefaultPublicKeyPath)
		if err != nil || samePublicKey(st.CA.AuthorityKey(), pub) {
			if len(conf.Slots) == 0 {
				conf.Slots = map[int][]int{}
				for _, sl := range st.CA.Slots {
					conf.Slots[sl.Number] = sl.PCRs
				}
			}
			fmt.Fprintf(c.out, "SSH CA %s: %s", path, st.CA.Describe())
			return c.sayKnownHosts(st.CA)
		}
		fmt.Fprintln(c.out, warn(fmt.Sprintf("The SSH CA %s (%s) was made for another signing key than %s: it cannot be approved for the next boot, which would serve a temporary host key.", path, st.CA.Fingerprint(), signing.DefaultPublicKeyPath)))
		ok, err := c.confirmYes("Create the SSH CA again, for this signing key?", "A new CA in the TPM in place of the old one: clients need its new known_hosts line.")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("the SSH CA stays the other signing key's")
		}
	}
	if c.facts.TPMErr != "" {
		fmt.Fprintln(c.out, warn("No TPM: the SSH CA lives in it, and without one the image is built without SSH."))
		return nil
	}
	if c.facts.Keys == "" {
		fmt.Fprintln(c.out, warn("No signing key (step 1, Set up): it approves the PCR states the SSH CA signs in."))
		return nil
	}
	typ := conf.CAType
	if err := c.form(huh.NewSelect[hostkey.Type]().Title("Create the SSH CA in the TPM").
		Description("The boot image's host key is made in the TPM at every boot and certified by this CA, which never leaves the TPM and signs only while the PCRs hold values the signing key approved: PCR 0 (firmware), 2 (option ROMs), 7 (Secure Boot) and the image's, or PCR 7 alone. It is kept in the EFI variable KIRAasshCA; slot approve approves each rebuilt image. Clients trust the CA, once.").
		Options(huh.NewOption("ECDSA P-256 (recommended)", hostkey.P256), huh.NewOption("RSA-2048", hostkey.RSA2048)).
		Value(&typ)).Run(); err != nil {
		return err
	}
	signer, err := c.signingKey()
	if err != nil {
		return err
	}
	conf.CAType = typ
	ca, err := createSSHCA(conf, c.o.TPMPath, signer)
	if err != nil {
		return err
	}
	if err := writeSSHConf(controlConfigPath(), *conf); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Created %s: %s", path, ca.Describe())
	fmt.Fprintf(c.out, "Its slots are written in %s: an edit there takes effect at the next approval.\n", sshConfPath(controlConfigPath()))
	return c.sayKnownHosts(ca)
}

// sayKnownHosts is how a client trusts the CA.
func (c *controller) sayKnownHosts(ca *hostkey.CA) error {
	line, err := ca.KnownHosts("*")
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Clients trust it with this line in ~/.ssh/known_hosts (put the machine's names and addresses for the *):\n  %s\n", line)
	return nil
}

// approveSSHCA has the signing key approve the PCRs as the next boot meets
// them, in every slot of the SSH CA.
func (c *controller) approveSSHCA() error {
	ok, err := c.confirmYes("Approve the SSH CA for the next boot?",
		"The PCRs as the next boot meets them have no approval yet in every slot (a new image, or a firmware, option ROM or Secure Boot update). The signing key approves them; without an approval the next boot serves a temporary host key.")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("not approved")
	}
	signer, err := c.signingKey()
	if err != nil {
		return err
	}
	if _, err := approveSSHCA(c.facts.Remote.SSH.Assh, c.o.TPMPath, signer); err != nil {
		return err
	}
	fmt.Fprintln(c.out, "The SSH CA is approved for the next boot.")
	return nil
}

// signingKey is the signing key, ready to sign (a token found, its PIN
// checked).
func (c *controller) signingKey() (crypto.Signer, error) {
	signer, err := signing.LoadCheckedSigningPrivateKey(signing.DefaultPrivateKeyPath)
	if err != nil {
		return nil, err
	}
	if err := signing.PrepareSigningKey(signer); err != nil {
		return nil, err
	}
	return signer, nil
}

// rootSSHKeys is where offerRootKeys takes keys from; a var for the tests.
var rootSSHKeys = "/root/.ssh/authorized_keys"

// offerRootKeys fills the image's own authorized_keys, empty or missing,
// with root's keys, when asked: who may log in at boot is then tracked
// apart from who may log in to the running system, and later changes to
// root's file do not reach the image.
func (c *controller) offerRootKeys(path string) error {
	keys, _, err := sshscreen.AuthorizedKeys(rootSSHKeys)
	if err != nil || len(keys) == 0 {
		fmt.Fprintln(c.out, warn(path+" holds no key, and "+rootSSHKeys+" none to take: put the keys that may log in at boot into "+path+" (one per line, as in authorized_keys)."))
		return nil
	}
	ok, err := c.confirmYes(fmt.Sprintf("Copy root's %d SSH key(s) to %s?", len(keys), path),
		"The keys that may log in at boot are tpm2-kira's own file; root's stays as it is, and what changes in it later does not reach the image. Edit "+path+" for other keys; control sees a change and rebuilds the image when you quit it.")
	if err != nil || !ok {
		return err
	}
	if err := os.WriteFile(path, imageKeys(keys), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "%s: %d key(s) copied from %s\n", path, len(keys), rootSSHKeys)
	return nil
}

// writeRemote writes the settings; the image takes them at the rebuild
// when control is left.
func (c *controller) writeRemote(r RemoteConfig) error {
	if err := setRemoteConfig(controlConfigPath(), r); err != nil {
		return err
	}
	c.facts.Remote = r
	for _, l := range RemoteStatusLines(r) {
		fmt.Fprintf(c.out, "%s: %s\n", controlConfigPath(), l)
	}
	if p := r.Problem(); p != "" {
		fmt.Fprintln(c.out, bad(p))
	}
	fmt.Fprintln(c.out, "The image takes it at its next build, when you quit control.")
	return nil
}

// validList checks a field of space-separated addresses: with prefix
// (cidr) or plain IPs, and whether one is required.
func validList(cidr, required bool) func(string) error {
	return func(s string) error {
		f := strings.Fields(s)
		if required && len(f) == 0 {
			return errors.New("at least one")
		}
		for _, a := range f {
			if cidr {
				if _, _, err := net.ParseCIDR(a); err != nil {
					return fmt.Errorf("%q: an address with its prefix, 192.0.2.10/24", a)
				}
			} else if net.ParseIP(a) == nil {
				return fmt.Errorf("%q is not an IP address", a)
			}
		}
		return nil
	}
}

// RemoteStatusLines is control's view of the image's network and SSH
// settings: one line each, and what is missing for them.
func RemoteStatusLines(r RemoteConfig) []string {
	var out []string
	if r.Net.Mode == "off" {
		return []string{"Network at boot: off"}
	}
	out = append(out, "Network at boot: "+r.Net.Describe())
	if r.SSH.On {
		s := fmt.Sprintf("SSH at boot: port %d", r.SSH.Port())
		if r.SSH.Hold > 0 {
			s += fmt.Sprintf(", the boot waits %d s for a confirmation", r.SSH.Hold)
		} else {
			s += ", the boot waits until it is confirmed (or Enter at the console)"
		}
		out = append(out, s)
	}
	return out
}

// authorizedKeyCount is the number of keys that may log in from the file,
// -1 when it cannot be read.
func authorizedKeyCount(path string) int {
	keys, _, err := sshscreen.AuthorizedKeys(path)
	if err != nil {
		return -1
	}
	return len(keys)
}
