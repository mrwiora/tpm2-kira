package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/tpm2-trust/assh/config"
)

// The network and the SSH server of the boot image (docs/SSH.md):
// the TPM2_KIRA_NET_* and TPM2_KIRA_SSH_* lines of control.conf. They are
// set for the image alone and do not depend on /etc/systemd/network or
// /etc/network/interfaces, which configure the running system ('tpm2-kira
// control' only reads them for a suggestion). The image build ('tpm2-kira
// initramfs plan', called by the hooks) turns them into a systemd-networkd
// file and a drop-in of tpm2-kira.service (mkinitcpio), or into
// /etc/tpm2-kira/remote.conf for the boot scripts (initramfs-tools);
// control.conf itself stays out of the image. The
// network is its own setting because more than the SSH server will use it
// (an outgoing request for the phone salt, PLAN-REMOTEUNLOCKING.md).

// NetConfig is the image's network.
type NetConfig struct {
	Mode      string   // TPM2_KIRA_NET: "off", "dhcp" or "static"
	Match     string   // TPM2_KIRA_NET_MATCH: a MAC address or an interface name; "" every wired interface
	Addresses []string // TPM2_KIRA_NET_ADDRESS: static only, CIDR, IPv4 and/or IPv6
	Gateways  []string // TPM2_KIRA_NET_GATEWAY: static only
	DNS       []string // TPM2_KIRA_NET_DNS
	// DHCPID is TPM2_KIRA_NET_DHCP_ID: the client identifier the image
	// asks the DHCP server with - "auto" (the running system's, read at
	// the build), "mac", or one in hex (remote_dhcpid.go).
	DHCPID string
}

// SSHConfig is the image's SSH server, started by 'tpm2-kira run' while
// the code screen holds.
type SSHConfig struct {
	On   bool // TPM2_KIRA_SSH: on or off
	Hold int  // TPM2_KIRA_SSH_HOLD: seconds the boot waits for a confirmation; 0 until one comes
	// Assh is assh.conf beside control.conf (remote_assh.go): the SSH CA
	// and its slots, the port, the keys that may log in.
	Assh config.Config
}

// Port is the port the server listens on.
func (s SSHConfig) Port() int { return listenPort(s.Assh.Listen) }

// RemoteConfig is both.
type RemoteConfig struct {
	Net NetConfig
	SSH SSHConfig
}

// Who may log in to the SSH server at boot.
const (
	// DefaultSSHAuthorizedKeys is tpm2-kira's own file, not root's: what
	// may log in at boot is tracked apart from who may log in to the
	// running system, and control writes it.
	DefaultSSHAuthorizedKeys = "/etc/tpm2-kira/authorized_keys"
)

// DefaultRemoteConfig is a file without these lines: no network, no SSH.
func DefaultRemoteConfig() RemoteConfig {
	return RemoteConfig{
		Net: NetConfig{Mode: "off", DHCPID: "auto"},
		SSH: SSHConfig{Assh: sshConfDefaults(config.Default(), DefaultControlConfigPath)},
	}
}

var (
	macRe   = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)
	ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,15}$`)
)

// isMAC says whether a match is a MAC address rather than an interface name.
func isMAC(s string) bool { return macRe.MatchString(s) }

// parseRemoteLine takes one network or SSH line into cfg; handled is false
// for a key that is not one of them.
func parseRemoteLine(cfg *RemoteConfig, n int, key, val string) (handled bool, err error) {
	fields := strings.Fields(val)
	switch key {
	case "TPM2_KIRA_NET":
		switch val {
		case "", "off":
			cfg.Net.Mode = "off"
		case "dhcp", "static":
			cfg.Net.Mode = val
		default:
			return true, fmt.Errorf("control.conf line %d: TPM2_KIRA_NET must be off, dhcp or static, not %q", n, val)
		}
	case "TPM2_KIRA_NET_MATCH":
		if val != "" && !isMAC(val) && !ifaceRe.MatchString(val) {
			return true, fmt.Errorf("control.conf line %d: TPM2_KIRA_NET_MATCH must be a MAC address (aa:bb:cc:dd:ee:ff) or an interface name, not %q", n, val)
		}
		cfg.Net.Match = strings.ToLower(val)
		if !isMAC(val) {
			cfg.Net.Match = val
		}
	case "TPM2_KIRA_NET_ADDRESS":
		for _, a := range fields {
			if _, _, err := net.ParseCIDR(a); err != nil {
				return true, fmt.Errorf("control.conf line %d: TPM2_KIRA_NET_ADDRESS takes addresses with their prefix (192.0.2.10/24), not %q", n, a)
			}
		}
		cfg.Net.Addresses = fields
	case "TPM2_KIRA_NET_GATEWAY", "TPM2_KIRA_NET_DNS":
		for _, a := range fields {
			if net.ParseIP(a) == nil {
				return true, fmt.Errorf("control.conf line %d: %s takes IP addresses, not %q", n, key, a)
			}
		}
		if key == "TPM2_KIRA_NET_GATEWAY" {
			cfg.Net.Gateways = fields
		} else {
			cfg.Net.DNS = fields
		}
	case "TPM2_KIRA_NET_DHCP_ID":
		switch val {
		case "", "auto":
			cfg.Net.DHCPID = "auto"
		case "mac":
			cfg.Net.DHCPID = val
		default:
			if _, err := parseClientID(val); err != nil {
				return true, fmt.Errorf("control.conf line %d: TPM2_KIRA_NET_DHCP_ID must be %v", n, err)
			}
			cfg.Net.DHCPID = strings.ToLower(val)
		}
	case "TPM2_KIRA_SSH":
		switch val {
		case "", "off":
			cfg.SSH.On = false
		case "on":
			cfg.SSH.On = true
		default:
			return true, fmt.Errorf("control.conf line %d: TPM2_KIRA_SSH must be on or off, not %q", n, val)
		}
	case "TPM2_KIRA_SSH_HOLD":
		h, err := strconv.Atoi(val)
		if err != nil || h < 0 {
			return true, fmt.Errorf("control.conf line %d: TPM2_KIRA_SSH_HOLD must be seconds (0: until a confirmation comes), not %q", n, val)
		}
		cfg.SSH.Hold = h
	default:
		return false, nil
	}
	return true, nil
}

// Problem says what keeps the settings from making a working image, ""
// when nothing does: what one line cannot tell (static without an address,
// SSH without a network).
func (r RemoteConfig) Problem() string {
	if p := r.Net.problem(); p != "" {
		return p
	}
	if r.SSH.On && r.Net.Mode == "off" {
		return "TPM2_KIRA_SSH=on needs a network in the image (TPM2_KIRA_NET=dhcp or static)"
	}
	return ""
}

// problem is what keeps the network's settings from working.
func (n NetConfig) problem() string {
	switch {
	case n.Mode == "static" && len(n.Addresses) == 0:
		return "TPM2_KIRA_NET=static needs TPM2_KIRA_NET_ADDRESS"
	case n.Mode == "static" && n.Match == "":
		return "TPM2_KIRA_NET=static needs TPM2_KIRA_NET_MATCH (a MAC address or an interface name): one static address on every interface would collide"
	}
	return ""
}

// NetworkdFile is the systemd-networkd configuration of the image's
// network (systemd.network(5)), asking DHCP with id; "" when it has none.
func (n NetConfig) NetworkdFile(id dhcpIdentity) string {
	if n.Mode != "dhcp" && n.Mode != "static" {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Written by 'tpm2-kira initramfs plan' from /etc/tpm2-kira/control.conf\n")
	b.WriteString("# (TPM2_KIRA_NET_*), for the boot image alone.\n\n[Match]\n")
	switch {
	case isMAC(n.Match):
		fmt.Fprintf(&b, "MACAddress=%s\n", n.Match)
	case n.Match != "":
		fmt.Fprintf(&b, "Name=%s\n", n.Match)
	default:
		b.WriteString("Type=ether\n")
	}
	b.WriteString("\n[Network]\n")
	if n.Mode == "dhcp" {
		b.WriteString("DHCP=yes\n")
	}
	for _, a := range n.Addresses {
		if n.Mode == "static" {
			fmt.Fprintf(&b, "Address=%s\n", a)
		}
	}
	for _, g := range n.Gateways {
		if n.Mode == "static" {
			fmt.Fprintf(&b, "Gateway=%s\n", g)
		}
	}
	for _, d := range n.DNS {
		fmt.Fprintf(&b, "DNS=%s\n", d)
	}
	if n.Mode == "dhcp" {
		// The image has no machine-id, from which networkd would make a
		// DUID of its own: it asks as the running system does.
		mac := n.Match
		if m := n.matchedInterfaces(); len(m) == 1 {
			mac = m[0].MAC
		}
		section, _ := networkdDHCP(id.ID, mac)
		b.WriteString("\n" + section)
	}
	return b.String()
}

// Lines are the control.conf lines of r's network and SSH settings, in
// the file's order, for control to write.
func (r RemoteConfig) Lines() [][2]string {
	onOff := map[bool]string{true: "on", false: "off"}
	return [][2]string{
		{"TPM2_KIRA_NET", r.Net.Mode},
		{"TPM2_KIRA_NET_MATCH", r.Net.Match},
		{"TPM2_KIRA_NET_ADDRESS", quoteList(r.Net.Addresses)},
		{"TPM2_KIRA_NET_GATEWAY", quoteList(r.Net.Gateways)},
		{"TPM2_KIRA_NET_DNS", quoteList(r.Net.DNS)},
		{"TPM2_KIRA_NET_DHCP_ID", r.Net.DHCPID},
		{"TPM2_KIRA_SSH", onOff[r.SSH.On]},
		{"TPM2_KIRA_SSH_HOLD", strconv.Itoa(r.SSH.Hold)},
	}
}

func quoteList(l []string) string {
	if len(l) < 2 {
		return strings.Join(l, "")
	}
	return `"` + strings.Join(l, " ") + `"`
}

// setRemoteConfig writes r's lines into control.conf, and with the SSH
// server its aSSH settings into assh.conf beside it; the rest of each file
// stays as it is.
func setRemoteConfig(path string, r RemoteConfig) error {
	for _, kv := range r.Lines() {
		if err := setControlValue(path, kv[0], kv[1]); err != nil {
			return err
		}
	}
	if !r.SSH.On {
		return nil
	}
	return writeSSHConf(path, r.SSH.Assh)
}

// Where the running system's interfaces are; vars for the tests.
var (
	sysClassNet       = "/sys/class/net"
	systemdNetworkDir = "/etc/systemd/network"
	ifupdownFile      = "/etc/network/interfaces"
)

// netInterface is a physical network interface of this machine.
type netInterface struct {
	Name     string
	MAC      string
	Wireless bool
	Module   string // its driver's module, "" when built in
}

// physicalInterfaces lists the interfaces that sit on a device (not lo,
// bridges, tunnels), sorted by name.
func physicalInterfaces() []netInterface {
	ents, _ := os.ReadDir(sysClassNet)
	var out []netInterface
	for _, e := range ents {
		dir := filepath.Join(sysClassNet, e.Name())
		if _, err := os.Stat(filepath.Join(dir, "device")); err != nil {
			continue
		}
		mac, _ := os.ReadFile(filepath.Join(dir, "address"))
		it := netInterface{Name: e.Name(), MAC: strings.ToLower(strings.TrimSpace(string(mac)))}
		if _, err := os.Stat(filepath.Join(dir, "wireless")); err == nil {
			it.Wireless = true
		}
		if _, err := os.Stat(filepath.Join(dir, "phy80211")); err == nil {
			it.Wireless = true
		}
		if mod, err := os.Readlink(filepath.Join(dir, "device", "driver", "module")); err == nil {
			it.Module = filepath.Base(mod)
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// matchedInterfaces are the interfaces of this machine the image's network
// would configure.
func (n NetConfig) matchedInterfaces() []netInterface {
	var out []netInterface
	for _, it := range physicalInterfaces() {
		switch {
		case isMAC(n.Match):
			if it.MAC == n.Match {
				out = append(out, it)
			}
		case n.Match != "":
			if it.Name == n.Match {
				out = append(out, it)
			}
		default:
			if !it.Wireless {
				out = append(out, it)
			}
		}
	}
	return out
}

// SuggestNetwork proposes the image's network from the running system's
// systemd-networkd configuration: the first .network file that sets DHCP
// or an address, matched by the MAC of the interface it names (the image
// may name the interface differently). Without one, from ifupdown's
// /etc/network/interfaces (Debian); without that either, DHCP on the
// first wired interface. The second value says where it comes from.
func SuggestNetwork() (NetConfig, string) {
	files, _ := filepath.Glob(filepath.Join(systemdNetworkDir, "*.network"))
	sort.Strings(files)
	ifaces := physicalInterfaces()
	for _, f := range files {
		nf := parseNetworkFile(f)
		if !nf.dhcp && len(nf.addresses) == 0 {
			continue
		}
		var it *netInterface
		for i := range ifaces {
			if ifaces[i].Wireless {
				continue
			}
			if (nf.mac != "" && ifaces[i].MAC == nf.mac) || (nf.name != "" && globMatch(nf.name, ifaces[i].Name)) {
				it = &ifaces[i]
				break
			}
		}
		if it == nil && (nf.mac != "" || nf.name != "") {
			continue // a file for an interface this machine does not have, or a wireless one
		}
		s := NetConfig{Mode: "dhcp", DNS: nf.dns}
		if it != nil {
			s.Match = it.MAC
		} else if nf.mac != "" {
			s.Match = nf.mac
		}
		if !nf.dhcp {
			s.Mode, s.Addresses, s.Gateways = "static", nf.addresses, nf.gateways
		}
		return s, filepath.Base(f)
	}
	if s, ok := suggestFromIfupdown(ifaces); ok {
		return s, ifupdownFile
	}
	for _, it := range ifaces {
		if !it.Wireless {
			return NetConfig{Mode: "dhcp", Match: it.MAC}, "no network configuration found; DHCP on " + it.Name
		}
	}
	return NetConfig{Mode: "dhcp"}, "no wired interface found"
}

// globMatch is networkd's Name= match: space-separated globs.
func globMatch(patterns, name string) bool {
	for _, p := range strings.Fields(patterns) {
		if ok, _ := filepath.Match(p, name); ok {
			return true
		}
	}
	return false
}

// networkFile is what SuggestNetwork reads of a .network file.
type networkFile struct {
	name, mac                string
	dhcp                     bool
	addresses, gateways, dns []string
}

// parseNetworkFile reads the few keys of systemd.network(5) a suggestion
// is made from: [Match] Name, MACAddress; [Network] DHCP, Address, Gateway,
// DNS; [Address] Address; [Route] Gateway.
func parseNetworkFile(path string) networkFile {
	var nf networkFile
	f, err := os.Open(path)
	if err != nil {
		return nf
	}
	defer f.Close()
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch section + "." + k {
		case "Match.Name":
			nf.name = v
		case "Match.MACAddress":
			if f := strings.Fields(v); len(f) > 0 && isMAC(f[0]) {
				nf.mac = strings.ToLower(f[0])
			}
		case "Network.DHCP":
			switch v {
			case "yes", "true", "ipv4", "both", "1":
				nf.dhcp = true
			}
		case "Network.Address", "Address.Address":
			if _, _, err := net.ParseCIDR(v); err == nil {
				nf.addresses = append(nf.addresses, v)
			}
		case "Network.Gateway", "Route.Gateway":
			if net.ParseIP(v) != nil {
				nf.gateways = append(nf.gateways, v)
			}
		case "Network.DNS":
			for _, d := range strings.Fields(v) {
				if net.ParseIP(d) != nil {
					nf.dns = append(nf.dns, d)
				}
			}
		}
	}
	return nf
}

// Describe is the network in one line, for control's status.
func (n NetConfig) Describe() string {
	where := "every wired interface"
	if n.Match != "" {
		where = n.Match
	}
	switch n.Mode {
	case "dhcp":
		return "DHCP on " + where
	case "static":
		s := strings.Join(n.Addresses, " ") + " on " + where
		if len(n.Gateways) > 0 {
			s += ", gateway " + strings.Join(n.Gateways, " ")
		}
		return s
	}
	return "off"
}

// suggestFromIfupdown proposes from the first wired interface of this
// machine that /etc/network/interfaces (and the files it sources) brings
// up by DHCP or with a static address (interfaces(5)): "iface NAME inet
// dhcp|static" with address, netmask, gateway, dns-nameservers, plus
// "iface NAME inet6 static" addresses.
func suggestFromIfupdown(ifaces []netInterface) (NetConfig, bool) {
	stanzas := map[string]*NetConfig{}
	var order []string
	var cur *NetConfig
	var netmask string // for the address of the current inet stanza
	finish := func() {
		if cur != nil && netmask != "" && len(cur.Addresses) > 0 && !strings.Contains(cur.Addresses[len(cur.Addresses)-1], "/") {
			if ones, _ := net.IPMask(net.ParseIP(netmask).To4()).Size(); ones > 0 {
				cur.Addresses[len(cur.Addresses)-1] += "/" + strconv.Itoa(ones)
			}
		}
		netmask = ""
	}
	var read func(path string, depth int)
	read = func(path string, depth int) {
		f, err := os.Open(path)
		if err != nil || depth > 3 {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			w := strings.Fields(sc.Text())
			if len(w) == 0 || strings.HasPrefix(w[0], "#") {
				continue
			}
			switch {
			case w[0] == "source" && len(w) > 1:
				finish()
				cur = nil
				files, _ := filepath.Glob(w[1])
				sort.Strings(files)
				for _, f := range files {
					read(f, depth+1)
				}
			case w[0] == "iface" && len(w) >= 4:
				finish()
				cur = nil
				name, family, method := w[1], w[2], w[3]
				if family != "inet" && family != "inet6" {
					continue
				}
				n := stanzas[name]
				if n == nil {
					n = &NetConfig{}
					stanzas[name] = n
					order = append(order, name)
				}
				switch {
				case family == "inet" && method == "dhcp":
					n.Mode = "dhcp"
				case method == "static" && n.Mode != "dhcp":
					n.Mode = "static"
				}
				if method == "static" {
					cur = n
				}
			case w[0] == "auto" || w[0] == "allow-hotplug" || strings.HasPrefix(w[0], "allow-") || w[0] == "mapping":
				finish()
				cur = nil
			case cur != nil && len(w) > 1:
				switch w[0] {
				case "address":
					finish()
					if ip := net.ParseIP(w[1]); ip != nil {
						cur.Addresses = append(cur.Addresses, w[1]) // the prefix from netmask, or none
					} else if _, _, err := net.ParseCIDR(w[1]); err == nil {
						cur.Addresses = append(cur.Addresses, w[1])
					}
				case "netmask":
					if strings.Contains(w[1], ".") {
						netmask = w[1]
					} else if len(cur.Addresses) > 0 && !strings.Contains(cur.Addresses[len(cur.Addresses)-1], "/") {
						cur.Addresses[len(cur.Addresses)-1] += "/" + w[1]
					}
				case "gateway":
					if net.ParseIP(w[1]) != nil {
						cur.Gateways = append(cur.Gateways, w[1])
					}
				case "dns-nameservers":
					for _, d := range w[1:] {
						if net.ParseIP(d) != nil {
							cur.DNS = append(cur.DNS, d)
						}
					}
				}
			}
		}
		finish()
	}
	read(ifupdownFile, 0)
	for _, name := range order {
		n := stanzas[name]
		if n.Mode == "" {
			continue
		}
		for _, it := range ifaces {
			if it.Wireless || !globMatch(name, it.Name) {
				continue
			}
			s := NetConfig{Mode: n.Mode, Match: it.MAC, DNS: n.DNS}
			if n.Mode == "static" {
				for _, a := range n.Addresses {
					if _, _, err := net.ParseCIDR(a); err == nil {
						s.Addresses = append(s.Addresses, a)
					}
				}
				if len(s.Addresses) == 0 {
					continue // an address without its prefix: no proposal
				}
				s.Gateways = n.Gateways
			}
			return s, true
		}
	}
	return NetConfig{}, false
}
