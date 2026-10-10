package cmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"charm.land/huh/v2"
)

// control's step for the boot image's network and SSH server
// (remote_config.go, docs/REMOTE-SSH.md): the settings are asked one by
// one, proposed from what is set or, the first time, from the running
// system's systemd-networkd configuration, then written into control.conf
// and the image rebuilt.

// remoteStep is the overview's line.
func (c *controller) remoteStep() controlStep {
	f := &c.facts
	st := controlStep{Key: "remote", Title: "Network and SSH at boot", Optional: true, SelfConfirm: true,
		Explain: "The boot image brings up its own network (DHCP or a static address, set here and nowhere else) and tpm2-kira starts an SSH server (tinysshd) with the code screen: the codes are confirmed and the password typed in an SSH session, and the console says where to log in - Enter there continues at the console instead. Picking it changes the settings.",
		Run:     (*controller).runRemote}
	switch {
	case f.Initramfs != "mkinitcpio":
		st.Blocked = "the boot image is built with mkinitcpio only, for now"
	case f.AttestConf != "":
		st.Blocked = "control.conf does not load"
	case f.Remote.Net.Mode != "off":
		st.Done = strings.Join(RemoteStatusLines(f.Remote), "; ")
		if p := f.Remote.Problem(); p != "" {
			st.Done, st.Dirty = "", p
		}
	}
	return st
}

// runRemote asks the settings, writes them and offers the rebuild.
func (c *controller) runRemote() error {
	r := c.facts.Remote
	if r.Net.Mode == "off" {
		// The first time: what the running system does, as the proposal.
		sug, from := SuggestNetwork()
		fmt.Fprintf(c.out, "Proposed from the running system (%s): %s\n", from, sug.Describe())
		r.Net = sug
	}
	mode := r.Net.Mode
	if err := c.form(huh.NewSelect[string]().Title("Network in the boot image").
		Description("Set for the image alone; /etc/systemd/network stays the running system's.").
		Options(huh.NewOption("DHCP", "dhcp"), huh.NewOption("Static address", "static"),
			huh.NewOption("Off: no network, no SSH", "off")).
		Value(&mode)).Run(); err != nil {
		return err
	}
	if mode == "off" {
		r.Net.Mode, r.SSH.On = "off", false
		return c.writeRemote(r)
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

	on := r.SSH.On || c.facts.Remote.Net.Mode == "off"
	if err := c.form(huh.NewConfirm().Title("Start the SSH server with the code screen?").
		Description("tinysshd, started by tpm2-kira at boot: log in as root with a key of " + r.SSH.AuthorizedKeys + " (ssh-ed25519 only), confirm the code, type the password there.").
		Affirmative("Yes").Negative("No: the network alone").Value(&on)).Run(); err != nil {
		return err
	}
	r.SSH.On = on
	if on {
		port, hold := strconv.Itoa(r.SSH.Port), strconv.Itoa(r.SSH.Hold)
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
		r.SSH.Port, _ = strconv.Atoi(port)
		r.SSH.Hold, _ = strconv.Atoi(hold)
		if err := c.ensureSSHKeys(r.SSH); err != nil {
			return err
		}
	}
	return c.writeRemote(r)
}

// ensureSSHKeys checks what the image's SSH server needs on this system,
// and creates the host key when asked: tinysshd itself, a host key of its
// own (never the running system's OpenSSH key), and a key that may log in.
func (c *controller) ensureSSHKeys(s SSHConfig) error {
	if _, err := exec.LookPath("tinysshd"); err != nil {
		fmt.Fprintln(c.out, warn("tinysshd is not installed: pacman -S tinyssh, before the rebuild."))
	}
	if _, err := os.Stat(s.HostKeys + "/.ed25519.sk"); err != nil {
		ok, err := c.confirmYes("Create the SSH host key of the boot image?",
			"tinysshd-makekey "+s.HostKeys+": a key of the image's own, not the running system's. It sits unencrypted in the boot image, like every host key of an initramfs SSH server; note its fingerprint at the first login.")
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(c.out, warn("No host key: the image is built without SSH until "+s.HostKeys+" holds one."))
		} else {
			mk := exec.Command("tinysshd-makekey", s.HostKeys)
			mk.Stdout, mk.Stderr = c.out, c.out
			if err := mk.Run(); err != nil {
				return fmt.Errorf("tinysshd-makekey %s: %w", s.HostKeys, err)
			}
		}
	}
	switch n := authorizedKeyCount(s.AuthorizedKeys); {
	case n < 0:
		fmt.Fprintln(c.out, warn(s.AuthorizedKeys+" cannot be read: nobody could log in. Put an ssh-ed25519 key there before the rebuild."))
	case n == 0:
		fmt.Fprintln(c.out, warn(s.AuthorizedKeys+" holds no ssh-ed25519 key, the only kind tinysshd accepts: nobody could log in."))
	default:
		fmt.Fprintf(c.out, "%s: %d ssh-ed25519 key(s) may log in at boot.\n", s.AuthorizedKeys, n)
	}
	return nil
}

// writeRemote writes the settings and offers the rebuild that puts them
// into the image.
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
	return c.offerRebuild()
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
