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
)

// The network and the SSH server of the boot image (docs/REMOTE-SSH.md):
// the TPM2_KIRA_NET_* and TPM2_KIRA_SSH_* lines of control.conf. They are
// set for the image alone and do not depend on /etc/systemd/network, which
// configures the running system ('tpm2-kira control' only reads it for a
// suggestion). The image build turns them into a systemd-networkd file and
// a drop-in of tpm2-kira.service ('tpm2-kira remote initramfs', called by
// the mkinitcpio hook); control.conf itself stays out of the image. The
// network is its own setting because more than the SSH server will use it
// (an outgoing request for the remote salt, PLAN-REMOTEUNLOCKING.md).

// NetConfig is the image's network.
type NetConfig struct {
	Mode      string   // TPM2_KIRA_NET: "off", "dhcp" or "static"
	Match     string   // TPM2_KIRA_NET_MATCH: a MAC address or an interface name; "" every wired interface
	Addresses []string // TPM2_KIRA_NET_ADDRESS: static only, CIDR, IPv4 and/or IPv6
	Gateways  []string // TPM2_KIRA_NET_GATEWAY: static only
	DNS       []string // TPM2_KIRA_NET_DNS
}

// SSHConfig is the image's SSH server (tinysshd), started by 'tpm2-kira
// run' while the code screen holds.
type SSHConfig struct {
	On             bool   // TPM2_KIRA_SSH: on or off
	Port           int    // TPM2_KIRA_SSH_PORT
	AuthorizedKeys string // TPM2_KIRA_SSH_AUTHORIZED_KEYS: whose ssh-ed25519 keys may log in
	HostKeys       string // TPM2_KIRA_SSH_HOSTKEYS: tinysshd's key directory (tinysshd-makekey)
	Hold           int    // TPM2_KIRA_SSH_HOLD: seconds the boot waits for a confirmation; 0 until one comes
}

// RemoteConfig is both.
type RemoteConfig struct {
	Net NetConfig
	SSH SSHConfig
}

// Default paths of the SSH server's keys.
const (
	DefaultSSHAuthorizedKeys = "/root/.ssh/authorized_keys"
	DefaultSSHHostKeys       = "/etc/tinyssh/sshkeydir"
)

// DefaultRemoteConfig is a file without these lines: no network, no SSH.
func DefaultRemoteConfig() RemoteConfig {
	return RemoteConfig{
		Net: NetConfig{Mode: "off"},
		SSH: SSHConfig{Port: 22, AuthorizedKeys: DefaultSSHAuthorizedKeys, HostKeys: DefaultSSHHostKeys},
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
	case "TPM2_KIRA_SSH":
		switch val {
		case "", "off":
			cfg.SSH.On = false
		case "on":
			cfg.SSH.On = true
		default:
			return true, fmt.Errorf("control.conf line %d: TPM2_KIRA_SSH must be on or off, not %q", n, val)
		}
	case "TPM2_KIRA_SSH_PORT":
		p, err := strconv.Atoi(val)
		if err != nil || p < 1 || p > 65535 {
			return true, fmt.Errorf("control.conf line %d: TPM2_KIRA_SSH_PORT must be a port number, not %q", n, val)
		}
		cfg.SSH.Port = p
	case "TPM2_KIRA_SSH_HOLD":
		h, err := strconv.Atoi(val)
		if err != nil || h < 0 {
			return true, fmt.Errorf("control.conf line %d: TPM2_KIRA_SSH_HOLD must be seconds (0: until a confirmation comes), not %q", n, val)
		}
		cfg.SSH.Hold = h
	case "TPM2_KIRA_SSH_AUTHORIZED_KEYS", "TPM2_KIRA_SSH_HOSTKEYS":
		if !filepath.IsAbs(val) {
			return true, fmt.Errorf("control.conf line %d: %s must be an absolute path, not %q", n, key, val)
		}
		if key == "TPM2_KIRA_SSH_HOSTKEYS" {
			cfg.SSH.HostKeys = val
		} else {
			cfg.SSH.AuthorizedKeys = val
		}
	default:
		return false, nil
	}
	return true, nil
}

// Problem says what keeps the settings from making a working image, ""
// when nothing does: what one line cannot tell (static without an address,
// SSH without a network).
func (r RemoteConfig) Problem() string {
	switch {
	case r.Net.Mode == "static" && len(r.Net.Addresses) == 0:
		return "TPM2_KIRA_NET=static needs TPM2_KIRA_NET_ADDRESS"
	case r.Net.Mode == "static" && r.Net.Match == "":
		return "TPM2_KIRA_NET=static needs TPM2_KIRA_NET_MATCH (a MAC address or an interface name): one static address on every interface would collide"
	case r.SSH.On && r.Net.Mode == "off":
		return "TPM2_KIRA_SSH=on needs a network in the image (TPM2_KIRA_NET=dhcp or static)"
	}
	return ""
}

// NetworkdFile is the systemd-networkd configuration of the image's
// network (systemd.network(5)), "" when it has none.
func (n NetConfig) NetworkdFile() string {
	if n.Mode != "dhcp" && n.Mode != "static" {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Written by 'tpm2-kira remote initramfs' from /etc/tpm2-kira/control.conf\n")
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
		// The image has no machine-id, so the DUID networkd would identify
		// itself with differs from the running system's at every build:
		// the MAC is what a DHCP server can keep a reservation for.
		b.WriteString("\n[DHCPv4]\nClientIdentifier=mac\n")
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
		{"TPM2_KIRA_SSH", onOff[r.SSH.On]},
		{"TPM2_KIRA_SSH_PORT", strconv.Itoa(r.SSH.Port)},
		{"TPM2_KIRA_SSH_HOLD", strconv.Itoa(r.SSH.Hold)},
	}
}

func quoteList(l []string) string {
	if len(l) < 2 {
		return strings.Join(l, "")
	}
	return `"` + strings.Join(l, " ") + `"`
}

// setRemoteConfig writes r's lines into control.conf; the rest of the
// file stays as it is.
func setRemoteConfig(path string, r RemoteConfig) error {
	for _, kv := range r.Lines() {
		if err := setControlValue(path, kv[0], kv[1]); err != nil {
			return err
		}
	}
	return nil
}

// Where the running system's interfaces are; vars for the tests.
var (
	sysClassNet       = "/sys/class/net"
	systemdNetworkDir = "/etc/systemd/network"
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
// may name the interface differently). Without such a file, DHCP on the
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
	for _, it := range ifaces {
		if !it.Wireless {
			return NetConfig{Mode: "dhcp", Match: it.MAC}, "no systemd-networkd configuration; DHCP on " + it.Name
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
