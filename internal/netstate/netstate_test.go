package netstate

import (
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseConfig(t *testing.T) {
	c, ok := ParseConfig([]byte("# x\nTPM2_KIRA_NET=\"dhcp\"\nTPM2_KIRA_NET_MATCH=\"AA:BB:CC:DD:EE:FF\"\n"))
	if !ok || c.Mode != "dhcp" || c.Match != "aa:bb:cc:dd:ee:ff" || !c.Announce {
		t.Fatalf("%+v %v", c, ok)
	}
	c, ok = ParseConfig([]byte("TPM2_KIRA_NET=\"static\"\nTPM2_KIRA_NET_MATCH=\"enp1s0\"\nTPM2_KIRA_NET_ANNOUNCE=\"off\"\n"))
	if !ok || c.Match != "enp1s0" || c.Announce {
		t.Fatalf("%+v %v", c, ok)
	}
	if _, ok := ParseConfig([]byte("TPM2_KIRA_NET=\"off\"\n")); ok {
		t.Fatal("off is no network")
	}
}

// sysNet makes /sys/class/net with the interfaces given: name, MAC,
// carrier ("" none), wireless, a device.
func sysNet(t *testing.T, ifs ...[5]string) string {
	dir := t.TempDir()
	for i, f := range ifs {
		d := filepath.Join(dir, f[0])
		must(t, os.MkdirAll(d, 0o755))
		must(t, os.WriteFile(filepath.Join(d, "address"), []byte(f[1]+"\n"), 0o644))
		must(t, os.WriteFile(filepath.Join(d, "ifindex"), []byte(string(rune('2'+i))+"\n"), 0o644))
		if f[2] != "" {
			must(t, os.WriteFile(filepath.Join(d, "carrier"), []byte(f[2]+"\n"), 0o644))
		}
		if f[3] == "wireless" {
			must(t, os.MkdirAll(filepath.Join(d, "wireless"), 0o755))
		}
		if f[4] == "device" {
			must(t, os.MkdirAll(filepath.Join(d, "device"), 0o755))
		}
	}
	return dir
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func proc(t *testing.T, route, route6 string) string {
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "net"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "net/route"), []byte(route), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "net/ipv6_route"), []byte(route6), 0o644))
	return dir
}

const route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"enp1s0\t00000000\t0102000A\t0003\t0\t0\t1024\t00000000\t0\t0\t0\n" +
	"enp1s0\t0002000A\t00000000\t0001\t0\t0\t1024\t00FFFFFF\t0\t0\t0\n"

const route6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 enp1s0\n" +
	"20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 enp1s0\n"

func TestReadChoosesTheInterfacesAndTheirState(t *testing.T) {
	sys := sysNet(t,
		[5]string{"enp1s0", "52:54:00:12:34:56", "1", "", "device"},
		[5]string{"wlan0", "52:54:00:aa:aa:aa", "1", "wireless", "device"},
		[5]string{"veth0", "52:54:00:bb:bb:bb", "1", "", ""},
		[5]string{"enp2s0", "52:54:00:cc:cc:cc", "", "", "device"},
	)
	addrs := map[string][]netip.Prefix{
		"enp1s0": {netip.MustParsePrefix("10.0.2.15/24"), netip.MustParsePrefix("fe80::1/64"), netip.MustParsePrefix("2001:db8::15/64")},
	}
	r := &Reader{Config: Config{Mode: "dhcp"}, SysNet: sys, Proc: proc(t, route, route6), AddrsOf: func(n string) []netip.Prefix { return addrs[n] }}
	st := r.Read(0)
	if len(st.Ifaces) != 2 || st.Ifaces[0].Name != "enp1s0" || st.Ifaces[1].Name != "enp2s0" {
		t.Fatalf("every wired device, no wireless, no virtual one: %+v", st.Ifaces)
	}
	e := st.Ifaces[0]
	if !e.Carrier || e.Index != 2 || e.MAC.String() != "52:54:00:12:34:56" || len(e.Addrs) != 2 {
		t.Fatalf("%+v", e)
	}
	if len(e.Gateways) != 2 || e.Gateways[0].String() != "10.0.2.1" || e.Gateways[1].String() != "fe80::1" {
		t.Fatalf("gateways: %v", e.Gateways)
	}
	if st.Ifaces[1].Carrier {
		t.Fatal("no carrier file: no link")
	}
	if st.Kind() != Up {
		t.Fatal(st.Kind())
	}
	if l := st.Key(); l != "Network (DHCP): 10.0.2.15/24 2001:db8::15/64 on enp1s0, gateway 10.0.2.1 fe80::1" {
		t.Fatal(l)
	}

	r.Match = "52:54:00:CC:CC:CC"
	r.Config, _ = ParseConfig([]byte("TPM2_KIRA_NET=dhcp\nTPM2_KIRA_NET_MATCH=52:54:00:CC:CC:CC\n"))
	if st := r.Read(0); len(st.Ifaces) != 1 || st.Ifaces[0].Name != "enp2s0" {
		t.Fatalf("by MAC: %+v", st.Ifaces)
	}
	r.Match = "wlan0"
	if st := r.Read(0); len(st.Ifaces) != 1 {
		t.Fatalf("by name, whatever it is: %+v", st.Ifaces)
	}
}

func TestLines(t *testing.T) {
	up := Iface{Name: "enp1s0", Carrier: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")}}
	link := Iface{Name: "enp1s0", Carrier: true}
	down := Iface{Name: "enp1s0"}
	for _, c := range []struct {
		st     Status
		kind   Kind
		want   string
		colour string
	}{
		{Status{Mode: "dhcp", Elapsed: 3 * time.Second}, NoInterface, "Network (DHCP): no wired interface yet - waiting for its driver (3 s)", "0;33"},
		{Status{Mode: "static", Match: "enp9s0"}, NoInterface, "Network (static): no interface enp9s0 yet", "0;33"},
		{Status{Mode: "dhcp", Ifaces: []Iface{down}, Elapsed: 12 * time.Second}, NoLink, "Network (DHCP) on enp1s0: NO LINK - is the cable plugged in? (12 s)", "1;31"},
		{Status{Mode: "dhcp", Ifaces: []Iface{link}, Elapsed: 12 * time.Second}, Waiting, "Network (DHCP) on enp1s0: WAITING FOR AN ADDRESS ... (12 s)", "0;33"},
		{Status{Mode: "static", Ifaces: []Iface{link}}, Waiting, "Network (static) on enp1s0: setting the address ...", "0;33"},
		{Status{Mode: "dhcp", Ifaces: []Iface{down, up}, Elapsed: 4 * time.Second}, Up, "Network (DHCP): 192.0.2.10/24 on enp1s0", "0;32"},
	} {
		if c.st.Kind() != c.kind {
			t.Errorf("%+v: kind %v", c.st, c.st.Kind())
		}
		l := c.st.Line()
		if !strings.HasPrefix(l, "\033["+c.colour+"m") || !strings.Contains(l, c.want) {
			t.Errorf("%q, want %q in %s", l, c.want, c.colour)
		}
		if strings.Contains(c.st.Key(), " s)") {
			t.Errorf("the key has no seconds: %q", c.st.Key())
		}
	}
}

// The frames, against fixed bytes.
func TestFramesKnownAnswers(t *testing.T) {
	mac, _ := net.ParseMAC("52:54:00:12:34:56")
	ip := netip.MustParseAddr("192.0.2.10")
	for _, c := range []struct {
		name string
		got  []byte
		want string
	}{
		{"ARP request", ARPAnnouncement(arpRequest, mac, ip), "0001080006040001525400123456c000020a000000000000c000020a"},
		{"ARP reply", ARPAnnouncement(arpReply, mac, ip), "0001080006040002525400123456c000020affffffffffffc000020a"},
		{"NA", NeighbourAdvertisement(netip.MustParseAddr("2001:db8::10"), mac), "880000002000000020010db80000000000000000000000100201525400123456"},
		{"echo v4", EchoRequest(false, 0x1234, 1), "0800e5ca12340001"},
		{"echo v6", EchoRequest(true, 0x1234, 1), "8000000012340001"},
	} {
		if g := hex.EncodeToString(c.got); g != c.want {
			t.Errorf("%s: %s, want %s", c.name, g, c.want)
		}
	}
}

func TestAnnouncerOncePerAddress(t *testing.T) {
	var mu sync.Mutex
	sent := map[string]int{}
	var wg sync.WaitGroup
	wg.Add(2 * AnnounceRounds)
	var logs []string
	a := &Announcer{
		Send: func(it Iface, p netip.Prefix) error {
			mu.Lock()
			sent[p.Addr().String()]++
			mu.Unlock()
			wg.Done()
			return nil
		},
		Log:   func(s string) { mu.Lock(); logs = append(logs, s); mu.Unlock() },
		Sleep: func(time.Duration) {},
	}
	it := Iface{Name: "enp1s0", Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")}}
	a.Seen(Status{Ifaces: []Iface{it}})
	a.Seen(Status{Ifaces: []Iface{it}})
	it.Addrs = append(it.Addrs, netip.MustParsePrefix("2001:db8::10/64"))
	a.Seen(Status{Ifaces: []Iface{it}})
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if sent["192.0.2.10"] != AnnounceRounds || sent["2001:db8::10"] != AnnounceRounds {
		t.Fatalf("%v", sent)
	}
}
