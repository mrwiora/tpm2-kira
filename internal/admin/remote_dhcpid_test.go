package admin

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDHCPClients points the running system's DHCP clients at dir: no
// networkd unless status answers.
func fakeDHCPClients(t *testing.T, status func(string) ([]byte, error)) string {
	t.Helper()
	dir := t.TempDir()
	oldStatus, oldNM, oldConf, oldDB := networkctlStatus, networkManagerLeases, dhcpcdConf, dhcpcdDB
	t.Cleanup(func() {
		networkctlStatus, networkManagerLeases, dhcpcdConf, dhcpcdDB = oldStatus, oldNM, oldConf, oldDB
	})
	if status == nil {
		status = func(string) ([]byte, error) { return nil, errors.New("no networkd") }
	}
	networkctlStatus = status
	networkManagerLeases, dhcpcdConf, dhcpcdDB = filepath.Join(dir, "nm"), filepath.Join(dir, "dhcpcd.conf"), filepath.Join(dir, "dhcpcd")
	os.MkdirAll(networkManagerLeases, 0o755)
	os.MkdirAll(dhcpcdDB, 0o755)
	return dir
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, ":", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// The identity the image asks with is the running system's: systemd-
// networkd's (IAID and DUID, as an Arch machine sent it), dhcpcd's (its
// DUID file and the MAC's last four bytes, as a Debian machine sent it),
// NetworkManager's lease; none known for a client that tells none, or a
// network for several interfaces. mac and an identifier in hex are taken
// as they are.
func TestDHCPIdentity(t *testing.T) {
	fakeNet(t, map[string]string{"enp1s0": "52:54:00:33:53:61", "enp2s0": "52:54:00:b7:72:34"})
	arch := "ff:56:50:4d:98:00:02:00:00:ab:11:4d:86:53:19:b5:6f:f3:00"
	fakeDHCPClients(t, func(iface string) ([]byte, error) {
		if iface != "enp2s0" {
			return []byte(`{"Name":"` + iface + `"}`), nil
		}
		return []byte(`{"DHCPv4Client":{"ClientIdentifier":[255,86,80,77,152,0,2,0,0,171,17,77,134,83,25,181,111,243,0]}}`), nil
	})
	n := NetConfig{Mode: "dhcp", Match: "52:54:00:b7:72:34", DHCPID: "auto"}
	id := n.DHCPIdentity()
	if colonHex(id.ID) != arch || !strings.Contains(id.From, "systemd-networkd on enp2s0") {
		t.Fatalf("networkd: %s %s", colonHex(id.ID), id.From)
	}
	f := n.NetworkdFile(id)
	if !strings.Contains(f, "[DHCPv4]\nClientIdentifier=duid\nIAID=0x56504d98\nDUIDType=2\nDUIDRawData=00:00:ab:11:4d:86:53:19:b5:6f:f3:00\n") ||
		!strings.Contains(f, "[DHCPv6]\nIAID=0x56504d98\nDUIDType=2\nDUIDRawData=00:00:ab:11:4d:86:53:19:b5:6f:f3:00\n") {
		t.Fatalf("the networkd file:\n%s", f)
	}

	n.Match = "52:54:00:33:53:61"
	if id := n.DHCPIdentity(); id.ID != nil || !strings.Contains(id.From, "unknown") {
		t.Fatalf("no client tells it: %+v", id)
	}
	os.WriteFile(filepath.Join(dhcpcdDB, "enp1s0.lease"), []byte("lease"), 0o644)
	os.WriteFile(filepath.Join(dhcpcdDB, "duid"), []byte("00:01:00:01:32:58:f2:c0:52:54:00:33:53:61\n"), 0o644)
	os.WriteFile(dhcpcdConf, []byte("hostname\nduid\npersistent\n"), 0o644)
	debian := "ff:00:33:53:61:00:01:00:01:32:58:f2:c0:52:54:00:33:53:61"
	if id := n.DHCPIdentity(); colonHex(id.ID) != debian || !strings.Contains(id.From, "dhcpcd on enp1s0") {
		t.Fatalf("dhcpcd: %s %s", colonHex(id.ID), id.From)
	}
	os.WriteFile(dhcpcdConf, []byte("duid\ninterface enp1s0\niaid 7\ninterface other\niaid 9\n"), 0o644)
	if id := n.DHCPIdentity(); colonHex(id.ID[:5]) != "ff:00:00:00:07" {
		t.Fatalf("dhcpcd's iaid: %s", colonHex(id.ID))
	}
	os.WriteFile(dhcpcdConf, []byte("clientid\n"), 0o644)
	if id := n.DHCPIdentity(); colonHex(id.ID) != "01:52:54:00:33:53:61" {
		t.Fatalf("dhcpcd's clientid: %s", colonHex(id.ID))
	}
	if f := n.NetworkdFile(n.DHCPIdentity()); !strings.Contains(f, "ClientIdentifier=mac\n") || strings.Contains(f, "IAID") {
		t.Fatalf("the MAC as identifier:\n%s", f)
	}
	os.Remove(filepath.Join(dhcpcdDB, "enp1s0.lease"))
	os.WriteFile(filepath.Join(networkManagerLeases, "internal-1234-enp1s0.lease"), []byte("ADDRESS=192.0.2.5\nCLIENTID=ff00335361000100\n"), 0o644)
	if id := n.DHCPIdentity(); colonHex(id.ID) != "ff:00:33:53:61:00:01:00" || !strings.Contains(id.From, "NetworkManager") {
		t.Fatalf("NetworkManager: %s %s", colonHex(id.ID), id.From)
	}

	if id := (NetConfig{Mode: "dhcp", DHCPID: "auto"}).DHCPIdentity(); id.ID != nil || !strings.Contains(id.From, "more than one interface") {
		t.Fatalf("every wired interface: %+v", id)
	}
	if id := (NetConfig{Mode: "dhcp", Match: "enp1s0", DHCPID: "mac"}).DHCPIdentity(); colonHex(id.ID) != "01:52:54:00:33:53:61" {
		t.Fatalf("mac: %+v", id)
	}
	if id := (NetConfig{Mode: "dhcp", Match: "enp1s0", DHCPID: "00:6d:79:69:64"}).DHCPIdentity(); colonHex(id.ID) != "00:6d:79:69:64" {
		t.Fatalf("set: %+v", id)
	}
	if _, ok := networkdDHCP(mustHex("006d796964"), "52:54:00:33:53:61"); ok {
		t.Fatal("an identifier networkd cannot send, taken")
	}
	for _, bad := range []string{"x", "ff", "zz:zz"} {
		if _, err := ParseControlConfig([]byte("TPM2_KIRA_NET_DHCP_ID=" + bad)); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
}

// Debian's image gets the identifier for udhcpc, and its script; without
// one ipconfig asks, and no script is needed.
func TestRemoteConfClientID(t *testing.T) {
	r := RemoteConfig{Net: NetConfig{Mode: "dhcp"}}
	if c := remoteConf(r, dhcpIdentity{ID: mustHex("ff0033")}); !strings.Contains(c, `TPM2_KIRA_NET_CLIENTID="ff0033"`) {
		t.Fatalf("%s", c)
	}
	if c := remoteConf(r, dhcpIdentity{}); !strings.Contains(c, `TPM2_KIRA_NET_CLIENTID=""`) {
		t.Fatalf("%s", c)
	}
}
