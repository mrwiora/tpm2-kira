package admin

// The image's DHCP identity: the client identifier (RFC 2132 option 61) the
// boot image asks the DHCP server with. A server hands out its addresses
// by it, so an image that asks as someone else gets another address than
// the running system - the code screen is somewhere the person does not
// look. The image releases the running system's machine-id, sealed under
// slot 0's policy (internal/machineid), before networkd starts, which
// derives its default DUID from it; this copied identity is what the image
// asks with where the running system's client has an identifier of its own
// (and on Debian, whose image has no networkd): the running system's, read
// when the image is built
// (TPM2_KIRA_NET_DHCP_ID=auto, the default), or set in control.conf (mac,
// or the identifier in hex).
//
// What the running system asks with is read from its DHCP client, for the
// interface the image's network is for: systemd-networkd (networkctl's
// JSON), NetworkManager (its lease file), dhcpcd (its configuration and
// DUID file). A client that sends no identifier (ISC dhclient by default)
// is known by its MAC alone; so is the image then: networkd sends the MAC
// as the identifier, initramfs-tools' ipconfig none.

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Where the running system's DHCP clients keep what tells their identity;
// vars for the tests.
var (
	networkctlStatus = func(iface string) ([]byte, error) {
		return exec.Command("networkctl", "status", "--json=short", iface).Output()
	}
	networkManagerLeases = "/var/lib/NetworkManager"
	dhcpcdConf           = "/etc/dhcpcd.conf"
	dhcpcdDB             = "/var/lib/dhcpcd"
)

// dhcpIdentity is the client identifier the image asks with.
type dhcpIdentity struct {
	ID   []byte // nil: none known
	From string // where it comes from, for the build's output
}

// parseClientID reads TPM2_KIRA_NET_DHCP_ID's identifier: hex bytes,
// with or without colons.
func parseClientID(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(s, ":", ""))
	if err != nil || len(b) < 2 || len(b) > 255 {
		return nil, fmt.Errorf("auto, mac or a client identifier in hex (ff:56:50:4d:98:00:02:...), not %q", s)
	}
	return b, nil
}

// macClientID is the identifier of a MAC: type 1 (Ethernet), the address.
func macClientID(mac string) []byte {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return nil
	}
	return append([]byte{1}, hw...)
}

// DHCPIdentity is the identity of n's DHCP: the setting's, or with auto
// the running system's on the interface n is for.
func (n NetConfig) DHCPIdentity() dhcpIdentity {
	if n.Mode != "dhcp" {
		return dhcpIdentity{}
	}
	matched := n.matchedInterfaces()
	switch n.DHCPID {
	case "mac":
		if len(matched) == 1 {
			return dhcpIdentity{ID: macClientID(matched[0].MAC), From: "the MAC (TPM2_KIRA_NET_DHCP_ID=mac)"}
		}
		return dhcpIdentity{From: "the MAC (TPM2_KIRA_NET_DHCP_ID=mac)"}
	case "", "auto":
	default:
		id, _ := parseClientID(n.DHCPID)
		return dhcpIdentity{ID: id, From: "TPM2_KIRA_NET_DHCP_ID"}
	}
	if len(matched) != 1 {
		return dhcpIdentity{From: "unknown: the network is for more than one interface (TPM2_KIRA_NET_MATCH)"}
	}
	it := matched[0]
	if id := networkdClientID(it.Name); id != nil {
		return dhcpIdentity{ID: id, From: "the running system's, systemd-networkd on " + it.Name}
	}
	if id := networkManagerClientID(it.Name); id != nil {
		return dhcpIdentity{ID: id, From: "the running system's, NetworkManager on " + it.Name}
	}
	if id := dhcpcdClientID(it); id != nil {
		return dhcpIdentity{ID: id, From: "the running system's, dhcpcd on " + it.Name}
	}
	return dhcpIdentity{From: "unknown: no DHCP client of the running system tells it on " + it.Name}
}

// networkdClientID is what systemd-networkd asks with on iface.
func networkdClientID(iface string) []byte {
	out, err := networkctlStatus(iface)
	if err != nil {
		return nil
	}
	var st struct {
		DHCPv4Client struct {
			ClientIdentifier []int
		}
	}
	if json.Unmarshal(out, &st) != nil {
		return nil
	}
	var id []byte
	for _, v := range st.DHCPv4Client.ClientIdentifier {
		if v < 0 || v > 255 {
			return nil
		}
		id = append(id, byte(v))
	}
	return id
}

// networkManagerClientID is what NetworkManager's own DHCP client asked
// with on iface, as its lease file has it (CLIENTID=, hex).
func networkManagerClientID(iface string) []byte {
	files, _ := filepath.Glob(filepath.Join(networkManagerLeases, "internal-*-"+iface+".lease"))
	for _, f := range files {
		for k, v := range keyValues(f, "=") {
			if k == "CLIENTID" {
				if id, err := hex.DecodeString(v); err == nil && len(id) >= 2 {
					return id
				}
			}
		}
	}
	return nil
}

// dhcpcdClientID is what dhcpcd asks with on it, when dhcpcd keeps a
// lease for it (dhcpcd.conf(5)): with "duid", 0xff, the IAID (the "iaid"
// option, else the last four bytes of the MAC) and the DUID of its DUID
// file (RFC 4361); with "clientid VALUE", that; else the MAC.
func dhcpcdClientID(it netInterface) []byte {
	if _, err := os.Stat(filepath.Join(dhcpcdDB, it.Name+".lease")); err != nil {
		return nil
	}
	duid, clientid, iaid := false, "", ""
	f, err := os.Open(dhcpcdConf)
	if err == nil {
		defer f.Close()
		mine := true // the global part, or this interface's block
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			w := strings.Fields(sc.Text())
			if len(w) == 0 || strings.HasPrefix(w[0], "#") {
				continue
			}
			switch w[0] {
			case "interface":
				mine = len(w) > 1 && w[1] == it.Name
			case "duid":
				if mine {
					duid, clientid = true, ""
				}
			case "clientid":
				if mine {
					duid, clientid = false, strings.Join(w[1:], " ")
				}
			case "iaid":
				if mine && len(w) > 1 {
					iaid = w[1]
				}
			}
		}
	}
	mac := macClientID(it.MAC)
	switch {
	case duid:
		data, err := os.ReadFile(filepath.Join(dhcpcdDB, "duid"))
		if err != nil {
			return nil
		}
		d, err := parseClientID(strings.TrimSpace(string(data)))
		if err != nil {
			return nil
		}
		ia := make([]byte, 4)
		if iaid != "" {
			var v uint32
			if _, err := fmt.Sscan(iaid, &v); err != nil {
				return nil
			}
			ia = []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
		} else if len(mac) == 7 {
			copy(ia, mac[3:])
		}
		return append(append([]byte{0xff}, ia...), d...)
	case clientid != "":
		if id, err := parseClientID(clientid); err == nil {
			return id
		}
		return append([]byte{0}, clientid...)
	}
	return mac
}

// keyValues reads KEY<sep>VALUE lines.
func keyValues(path, sep string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), sep); ok {
			out[k] = v
		}
	}
	return out
}

// networkdDHCP is the [DHCPv4] section that makes systemd-networkd ask
// with id; the MAC when id is none or one networkd cannot send, which ok
// says.
func networkdDHCP(id []byte, mac string) (section string, ok bool) {
	switch {
	case len(id) >= 7 && id[0] == 0xff:
		// RFC 4361: the IAID, then the DUID - its type, then the rest.
		// DHCPv6 asks with the same DUID and IAID, as the running system's
		// networkd does: the same lease for IPv6 as for IPv4.
		iaid, duidType, raw := hex.EncodeToString(id[1:5]), int(id[5])<<8|int(id[6]), colonHex(id[7:])
		return fmt.Sprintf("[DHCPv4]\nClientIdentifier=duid\nIAID=0x%s\nDUIDType=%d\nDUIDRawData=%s\n\n"+
			"[DHCPv6]\nIAID=0x%s\nDUIDType=%d\nDUIDRawData=%s\n", iaid, duidType, raw, iaid, duidType, raw), true
	case id == nil:
		return "[DHCPv4]\nClientIdentifier=mac\n", true
	}
	if m := macClientID(mac); m != nil && string(m) == string(id) {
		return "[DHCPv4]\nClientIdentifier=mac\n", true
	}
	return "[DHCPv4]\nClientIdentifier=mac\n", false
}

func colonHex(b []byte) string {
	s := make([]string, len(b))
	for i, v := range b {
		s[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(s, ":")
}
