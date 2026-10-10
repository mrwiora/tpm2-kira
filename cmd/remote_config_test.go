package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The network and SSH lines load, each refused with its line number, and
// what one line cannot tell is Problem's.
func TestRemoteConfigLines(t *testing.T) {
	cfg, err := ParseControlConfig([]byte(`TPM2_KIRA_NET=static
TPM2_KIRA_NET_MATCH=AA:BB:CC:DD:EE:FF
TPM2_KIRA_NET_ADDRESS="192.0.2.10/24 2001:db8::10/64"
TPM2_KIRA_NET_GATEWAY=192.0.2.1
TPM2_KIRA_NET_DNS="192.0.2.53 9.9.9.9"
TPM2_KIRA_SSH=on
TPM2_KIRA_SSH_PORT=2222
TPM2_KIRA_SSH_HOLD=300
`))
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Remote
	if r.Net.Mode != "static" || r.Net.Match != "aa:bb:cc:dd:ee:ff" || len(r.Net.Addresses) != 2 ||
		r.Net.Gateways[0] != "192.0.2.1" || len(r.Net.DNS) != 2 || !r.SSH.On || r.SSH.Port != 2222 || r.SSH.Hold != 300 ||
		r.SSH.AuthorizedKeys != DefaultSSHAuthorizedKeys || r.SSH.HostKeys != DefaultSSHHostKeys || r.Problem() != "" {
		t.Fatalf("%+v %q", r, r.Problem())
	}
	if d := DefaultControlConfig().Remote; d.Net.Mode != "off" || d.SSH.On || d.SSH.Port != 22 {
		t.Fatalf("defaults: %+v", d)
	}
	for _, bad := range []string{
		"TPM2_KIRA_NET=wifi", "TPM2_KIRA_NET_MATCH=eth 0", "TPM2_KIRA_NET_ADDRESS=192.0.2.10",
		"TPM2_KIRA_NET_GATEWAY=gw", "TPM2_KIRA_NET_DNS=1.1.1.1 dns", "TPM2_KIRA_SSH=yes",
		"TPM2_KIRA_SSH_PORT=70000", "TPM2_KIRA_SSH_HOLD=-1", "TPM2_KIRA_SSH_HOSTKEYS=keys",
	} {
		if _, err := ParseControlConfig([]byte("# x\n" + bad + "\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
			t.Errorf("%s: %v", bad, err)
		}
	}
	for content, want := range map[string]string{
		"TPM2_KIRA_NET=static\nTPM2_KIRA_NET_MATCH=eth0\n":            "needs TPM2_KIRA_NET_ADDRESS",
		"TPM2_KIRA_NET=static\nTPM2_KIRA_NET_ADDRESS=192.0.2.10/24\n": "needs TPM2_KIRA_NET_MATCH",
		"TPM2_KIRA_SSH=on\n":                                                                   "needs a network",
		"TPM2_KIRA_NET=dhcp\nTPM2_KIRA_SSH=on\n":                                               "",
		"TPM2_KIRA_NET=dhcp\nTPM2_KIRA_NET_ADDRESS=192.0.2.10/24\n":                            "",
		"TPM2_KIRA_NET=off\nTPM2_KIRA_NET_ADDRESS=192.0.2.10/24\n":                             "",
		"TPM2_KIRA_NET=static\nTPM2_KIRA_NET_MATCH=enp1s0\nTPM2_KIRA_NET_ADDRESS=10.0.0.2/8\n": "",
	} {
		cfg, err := ParseControlConfig([]byte(content))
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.Remote.Problem(); (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%q: %q, want %q", content, got, want)
		}
	}
}

// The networkd file: matched by MAC, by name or every wired interface;
// DHCP with the MAC as the client identifier, or the static addresses.
func TestNetworkdFile(t *testing.T) {
	dhcp := NetConfig{Mode: "dhcp", Match: "aa:bb:cc:dd:ee:ff", DNS: []string{"9.9.9.9"}}.NetworkdFile()
	for _, want := range []string{"[Match]\nMACAddress=aa:bb:cc:dd:ee:ff\n", "DHCP=yes\n", "DNS=9.9.9.9\n", "ClientIdentifier=mac\n"} {
		if !strings.Contains(dhcp, want) {
			t.Errorf("dhcp lacks %q:\n%s", want, dhcp)
		}
	}
	static := NetConfig{Mode: "static", Match: "enp1s0", Addresses: []string{"192.0.2.10/24", "2001:db8::10/64"}, Gateways: []string{"192.0.2.1"}}.NetworkdFile()
	for _, want := range []string{"Name=enp1s0\n", "Address=192.0.2.10/24\nAddress=2001:db8::10/64\n", "Gateway=192.0.2.1\n"} {
		if !strings.Contains(static, want) {
			t.Errorf("static lacks %q:\n%s", want, static)
		}
	}
	if strings.Contains(static, "DHCP") {
		t.Errorf("static asks DHCP:\n%s", static)
	}
	if any := (NetConfig{Mode: "dhcp"}).NetworkdFile(); !strings.Contains(any, "Type=ether\n") {
		t.Errorf("no match: %s", any)
	}
	if (NetConfig{Mode: "off"}).NetworkdFile() != "" {
		t.Error("off has a file")
	}
}

// control writes the lines and they read back; the rest of the file stays.
func TestSetRemoteConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.conf")
	os.WriteFile(path, []byte("TPM2_KIRA_CONTROL=guided\n"), 0o644)
	r := DefaultRemoteConfig()
	r.Net = NetConfig{Mode: "static", Match: "aa:bb:cc:dd:ee:ff", Addresses: []string{"192.0.2.10/24", "2001:db8::10/64"}, DNS: []string{"9.9.9.9"}}
	r.SSH.On, r.SSH.Port = true, 2222
	if err := setRemoteConfig(path, r); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadControlConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Control != "guided" || cfg.Remote.Net.Mode != "static" || len(cfg.Remote.Net.Addresses) != 2 ||
		cfg.Remote.Net.Match != r.Net.Match || !cfg.Remote.SSH.On || cfg.Remote.SSH.Port != 2222 || len(cfg.Remote.Net.Gateways) != 0 {
		t.Fatalf("read back: %+v", cfg)
	}
}

// fakeNet is a /sys/class/net and an /etc/systemd/network for the tests.
func fakeNet(t *testing.T, ifaces map[string]string, wireless ...string) (sys, conf string) {
	t.Helper()
	dir := t.TempDir()
	sys, conf = filepath.Join(dir, "sys"), filepath.Join(dir, "network")
	os.MkdirAll(conf, 0o755)
	os.MkdirAll(filepath.Join(sys, "lo"), 0o755)
	os.WriteFile(filepath.Join(sys, "lo", "address"), []byte("00:00:00:00:00:00\n"), 0o644)
	for name, mac := range ifaces {
		d := filepath.Join(sys, name)
		os.MkdirAll(filepath.Join(d, "device", "driver"), 0o755)
		os.Symlink("/sys/module/drv_"+name, filepath.Join(d, "device", "driver", "module"))
		os.WriteFile(filepath.Join(d, "address"), []byte(mac+"\n"), 0o644)
	}
	for _, w := range wireless {
		os.MkdirAll(filepath.Join(sys, w, "wireless"), 0o755)
	}
	oldSys, oldConf := sysClassNet, systemdNetworkDir
	sysClassNet, systemdNetworkDir = sys, conf
	t.Cleanup(func() { sysClassNet, systemdNetworkDir = oldSys, oldConf })
	return sys, conf
}

// The suggestion follows the running system's networkd file, matched by
// the MAC of the interface it names; without one, DHCP on the first wired
// interface. Wireless interfaces are never proposed.
func TestSuggestNetwork(t *testing.T) {
	_, conf := fakeNet(t, map[string]string{"enp1s0": "AA:BB:CC:DD:EE:01", "wlan0": "aa:bb:cc:dd:ee:02"}, "wlan0")
	if s, _ := SuggestNetwork(); s.Mode != "dhcp" || s.Match != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("without networkd: %+v", s)
	}
	os.WriteFile(filepath.Join(conf, "10-wlan.network"), []byte("[Match]\nName=wl*\n[Network]\nDHCP=yes\n"), 0o644)
	os.WriteFile(filepath.Join(conf, "20-wired.network"), []byte(`[Match]
Name=en*

[Network]
Address=192.0.2.10/24
Gateway=192.0.2.1
DNS=192.0.2.53 9.9.9.9

[Address]
Address=2001:db8::10/64
`), 0o644)
	s, from := SuggestNetwork()
	if s.Mode != "static" || s.Match != "aa:bb:cc:dd:ee:01" || strings.Join(s.Addresses, " ") != "192.0.2.10/24 2001:db8::10/64" ||
		strings.Join(s.Gateways, " ") != "192.0.2.1" || len(s.DNS) != 2 || from != "20-wired.network" {
		t.Fatalf("static: %+v from %s", s, from)
	}
	os.WriteFile(filepath.Join(conf, "15-wired.network"), []byte("[Match]\nMACAddress=aa:bb:cc:dd:ee:01\n[Network]\nDHCP=ipv4\n"), 0o644)
	if s, from := SuggestNetwork(); s.Mode != "dhcp" || s.Match != "aa:bb:cc:dd:ee:01" || from != "15-wired.network" {
		t.Fatalf("dhcp by MAC: %+v from %s", s, from)
	}
	// What the image would configure, and the drivers it needs.
	if m := (NetConfig{Mode: "dhcp"}).matchedInterfaces(); len(m) != 1 || m[0].Name != "enp1s0" || m[0].Module != "drv_enp1s0" {
		t.Fatalf("every wired interface: %+v", m)
	}
	if m := (NetConfig{Mode: "dhcp", Match: "aa:bb:cc:dd:ee:09"}).matchedInterfaces(); len(m) != 0 {
		t.Fatalf("an unknown MAC matched: %+v", m)
	}
}
