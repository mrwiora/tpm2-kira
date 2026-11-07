// Package netstate is the boot image's network as the person at the boot
// sees it: whether the interface is there, has a link, waits for an
// address or has one - one line, the same on the console and in the SSH
// session - and the announcement of a new address to the neighbours
// (announce.go). It reads /sys and /proc and the interfaces' addresses;
// it configures nothing: networkd or the image's scripts bring the
// network up.
package netstate

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ImageConf is the image's network settings, written by the boot plan
// from control.conf; the image's scripts (initramfs-tools) read it too.
const ImageConf = "/etc/tpm2-kira/remote.conf"

// Config is what run needs of the image's network settings.
type Config struct {
	Mode     string // "dhcp" or "static"
	Match    string // a MAC address, an interface name, or "" for every wired interface
	Announce bool   // tell the neighbours a new address (TPM2_KIRA_NET_ANNOUNCE)
}

// ReadConfig reads the image's settings at path; ok is false without a
// network in them.
func ReadConfig(path string) (Config, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, false
	}
	return ParseConfig(data)
}

// ParseConfig reads KEY="value" lines.
func ParseConfig(data []byte) (Config, bool) {
	c := Config{Announce: true}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "TPM2_KIRA_NET":
			c.Mode = v
		case "TPM2_KIRA_NET_MATCH":
			c.Match = strings.ToLower(v)
			if !isMAC(v) {
				c.Match = v
			}
		case "TPM2_KIRA_NET_ANNOUNCE":
			c.Announce = v != "off"
		}
	}
	return c, c.Mode == "dhcp" || c.Mode == "static"
}

func isMAC(s string) bool {
	hw, err := net.ParseMAC(s)
	return err == nil && len(hw) == 6
}

// Iface is one interface the network is for, as it is now.
type Iface struct {
	Name     string
	Index    int
	MAC      net.HardwareAddr
	Carrier  bool
	Addrs    []netip.Prefix // without link-local ones
	Gateways []netip.Addr   // its default routes' next hops
}

// Kind is where the network has got to.
type Kind int

const (
	NoInterface Kind = iota // no interface the settings name (yet)
	NoLink                  // the interface is there, without a link
	Waiting                 // a link, no address yet
	Up                      // an address
)

// Status is the network at one moment.
type Status struct {
	Mode    string
	Match   string
	Ifaces  []Iface
	Elapsed time.Duration // since run began to watch it
}

// Kind is the furthest any interface has got.
func (s Status) Kind() Kind {
	k := NoInterface
	for _, it := range s.Ifaces {
		switch {
		case len(it.Addrs) > 0:
			return Up
		case it.Carrier:
			k = max(k, Waiting)
		default:
			k = max(k, NoLink)
		}
	}
	return k
}

// Key is the line without its seconds: it changes when the state does.
func (s Status) Key() string {
	s.Elapsed = 0
	return s.text()
}

// Line is the network's line for the screen, coloured: green with an
// address, yellow while it waits, red without a link.
func (s Status) Line() string {
	colour := "0;33"
	switch s.Kind() {
	case Up:
		colour = "0;32"
	case NoLink:
		colour = "1;31"
	}
	return "\033[" + colour + "m" + s.text() + "\033[0m"
}

func (s Status) text() string {
	mode := "DHCP"
	if s.Mode == "static" {
		mode = "static"
	}
	secs := ""
	if s.Elapsed > 0 {
		secs = fmt.Sprintf(" (%d s)", int(s.Elapsed.Round(time.Second)/time.Second))
	}
	var names []string
	for _, it := range s.Ifaces {
		names = append(names, it.Name)
	}
	on := strings.Join(names, ", ")
	switch s.Kind() {
	case NoInterface:
		what := "no wired interface"
		if s.Match != "" {
			what = "no interface " + s.Match
		}
		return fmt.Sprintf("Network (%s): %s yet - waiting for its driver%s", mode, what, secs)
	case NoLink:
		return fmt.Sprintf("Network (%s) on %s: NO LINK - is the cable plugged in?%s", mode, on, secs)
	case Waiting:
		if s.Mode == "static" {
			return fmt.Sprintf("Network (static) on %s: setting the address ...%s", on, secs)
		}
		return fmt.Sprintf("Network (DHCP) on %s: WAITING FOR AN ADDRESS ...%s", on, secs)
	}
	var parts []string
	for _, it := range s.Ifaces {
		if len(it.Addrs) == 0 {
			continue
		}
		var as []string
		for _, a := range it.Addrs {
			as = append(as, a.String())
		}
		p := strings.Join(as, " ") + " on " + it.Name
		if len(it.Gateways) > 0 {
			var gs []string
			for _, g := range it.Gateways {
				gs = append(gs, g.String())
			}
			p += ", gateway " + strings.Join(gs, " ")
		}
		parts = append(parts, p)
	}
	return fmt.Sprintf("Network (%s): %s", mode, strings.Join(parts, "; "))
}

// Reader reads the state of the interfaces c names. Its roots are the
// system's; tests point them at fixtures.
type Reader struct {
	Config
	SysNet  string                           // /sys/class/net
	Proc    string                           // /proc
	AddrsOf func(name string) []netip.Prefix // the interface's addresses
}

// NewReader is a Reader of this system.
func NewReader(c Config) *Reader {
	return &Reader{Config: c, SysNet: "/sys/class/net", Proc: "/proc", AddrsOf: systemAddrs}
}

// Read is the state now; elapsed goes into the line.
func (r *Reader) Read(elapsed time.Duration) Status {
	st := Status{Mode: r.Mode, Match: r.Match, Elapsed: elapsed}
	gw4, gw6 := r.gateways()
	ents, _ := os.ReadDir(r.SysNet)
	for _, e := range ents {
		name := e.Name()
		dir := filepath.Join(r.SysNet, name)
		if !r.wanted(dir, name) {
			continue
		}
		it := Iface{Name: name}
		it.Index, _ = strconv.Atoi(readTrim(filepath.Join(dir, "ifindex")))
		it.MAC, _ = net.ParseMAC(readTrim(filepath.Join(dir, "address")))
		// carrier is unreadable (EINVAL) while the interface is down.
		it.Carrier = readTrim(filepath.Join(dir, "carrier")) == "1"
		for _, a := range r.AddrsOf(name) {
			if !a.Addr().IsLinkLocalUnicast() {
				it.Addrs = append(it.Addrs, a)
			}
		}
		it.Gateways = append(gw4[name], gw6[name]...)
		st.Ifaces = append(st.Ifaces, it)
	}
	return st
}

// wanted is the image's scripts' choice (tpm2_kira_netdev): a device, by
// its MAC or its name, or every wired one.
func (r *Reader) wanted(dir, name string) bool {
	if _, err := os.Stat(filepath.Join(dir, "device")); err != nil {
		return false
	}
	switch {
	case isMAC(r.Match):
		return strings.EqualFold(readTrim(filepath.Join(dir, "address")), r.Match)
	case r.Match != "":
		return name == r.Match
	}
	for _, w := range []string{"wireless", "phy80211"} {
		if _, err := os.Stat(filepath.Join(dir, w)); err == nil {
			return false
		}
	}
	return true
}

// gateways are the default routes' next hops per interface, from
// /proc/net/route and /proc/net/ipv6_route.
func (r *Reader) gateways() (v4, v6 map[string][]netip.Addr) {
	v4, v6 = map[string][]netip.Addr{}, map[string][]netip.Addr{}
	if data, err := os.ReadFile(filepath.Join(r.Proc, "net/route")); err == nil {
		for i, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if i == 0 || len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
				continue
			}
			b, err := hex.DecodeString(f[2])
			if err != nil || len(b) != 4 {
				continue
			}
			// In the host's byte order: little-endian here.
			a := netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]})
			if !a.IsUnspecified() && !slices.Contains(v4[f[0]], a) {
				v4[f[0]] = append(v4[f[0]], a)
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(r.Proc, "net/ipv6_route")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 || f[0] != strings.Repeat("0", 32) || f[1] != "00" {
				continue
			}
			b, err := hex.DecodeString(f[4])
			if err != nil || len(b) != 16 {
				continue
			}
			a := netip.AddrFrom16([16]byte(b))
			if !a.IsUnspecified() && !slices.Contains(v6[f[9]], a) {
				v6[f[9]] = append(v6[f[9]], a)
			}
		}
	}
	return v4, v6
}

func systemAddrs(name string) []netip.Prefix {
	it, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	as, _ := it.Addrs()
	var out []netip.Prefix
	for _, a := range as {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ones, _ := ipn.Mask.Size()
		out = append(out, netip.PrefixFrom(ip.Unmap(), ones))
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		// IPv4 first, as the console names them.
		if a.Addr().Is4() != b.Addr().Is4() {
			if a.Addr().Is4() {
				return -1
			}
			return 1
		}
		return a.Addr().Compare(b.Addr())
	})
	return out
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
