package netstate

// The announcement of a new address. A machine that comes back with the
// address it had - or with one another machine had - can stay unreachable
// while the switch, the gateway and the hosts beside it hold an old
// neighbour entry. So each new address is said to the link, a few times:
//
//   - IPv4: a gratuitous ARP, as a request and as a reply (RFC 5227's
//     announcement; some hosts update their caches only on one of them).
//   - IPv6: an unsolicited neighbour advertisement with the override flag
//     (RFC 4861 7.2.6) to all nodes.
//   - Each gateway of the interface gets an echo request, so that it
//     resolves the machine itself and holds the new entry.
//
// Only sent: no answer is read, so nothing from the network is parsed here.

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// AnnounceRounds is how often an address is announced, AnnounceEvery apart.
const (
	AnnounceRounds = 3
	AnnounceEvery  = time.Second
)

// Announcer announces each address once it appears; what it has
// announced it does not announce again.
type Announcer struct {
	Send  func(Iface, netip.Prefix) error // one round for an address; announceOnce
	Log   func(string)
	Sleep func(time.Duration)
	done  map[string]bool
}

// NewAnnouncer is an Announcer that sends.
func NewAnnouncer(log func(string)) *Announcer {
	return &Announcer{Send: announceOnce, Log: log, Sleep: time.Sleep}
}

// Seen takes the state; for each address not announced yet it starts the
// rounds, beside the caller.
func (a *Announcer) Seen(st Status) {
	if a.done == nil {
		a.done = map[string]bool{}
	}
	for _, it := range st.Ifaces {
		for _, p := range it.Addrs {
			key := it.Name + " " + p.Addr().String()
			if a.done[key] {
				continue
			}
			a.done[key] = true
			go a.rounds(it, p)
		}
	}
}

func (a *Announcer) rounds(it Iface, p netip.Prefix) {
	var err error
	for i := range AnnounceRounds {
		if i > 0 {
			a.Sleep(AnnounceEvery)
		}
		if e := a.Send(it, p); e != nil {
			err = e
		}
	}
	if err != nil {
		a.Log(fmt.Sprintf("network: announcing %s on %s: %v", p.Addr(), it.Name, err))
		return
	}
	a.Log(fmt.Sprintf("network: announced %s on %s to the neighbours and %d gateway(s)", p.Addr(), it.Name, len(it.Gateways)))
}

// announceOnce is one round for the address: the neighbour announcement,
// and an echo to every gateway of its family.
func announceOnce(it Iface, p netip.Prefix) error {
	if len(it.MAC) != 6 || it.Index == 0 {
		return fmt.Errorf("the interface has no Ethernet address")
	}
	var firstErr error
	keep := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	ip := p.Addr()
	if ip.Is4() {
		keep(sendARP(it, ip, arpRequest))
		keep(sendARP(it, ip, arpReply))
	} else {
		keep(sendNA(it, ip))
	}
	for _, g := range it.Gateways {
		if g.Is4() == ip.Is4() {
			keep(sendEcho(it, g))
		}
	}
	return firstErr
}

const (
	arpRequest = 1
	arpReply   = 2
)

var broadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// ARPAnnouncement is the ARP payload of a gratuitous ARP for ip from mac:
// sender and target address both ip; the target hardware address zero in
// the request, broadcast in the reply.
func ARPAnnouncement(op uint16, mac net.HardwareAddr, ip netip.Addr) []byte {
	b := make([]byte, 28)
	binary.BigEndian.PutUint16(b[0:], 1)      // Ethernet
	binary.BigEndian.PutUint16(b[2:], 0x0800) // IPv4
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:], op)
	a := ip.As4()
	copy(b[8:], mac)
	copy(b[14:], a[:])
	if op == arpReply {
		copy(b[18:], broadcast)
	}
	copy(b[24:], a[:])
	return b
}

// NeighbourAdvertisement is the ICMPv6 message of an unsolicited
// advertisement of target from mac: override set, solicited not, the
// target's link-layer address as its option. The kernel fills the checksum.
func NeighbourAdvertisement(target netip.Addr, mac net.HardwareAddr) []byte {
	b := make([]byte, 32)
	b[0] = 136                               // neighbour advertisement
	binary.BigEndian.PutUint32(b[4:], 1<<29) // O: override
	t := target.As16()
	copy(b[8:], t[:])
	b[24], b[25] = 2, 1 // target link-layer address, 8 octets
	copy(b[26:], mac)
	return b
}

// EchoRequest is an ICMP (v4) or ICMPv6 echo request with an empty body;
// the v4 one carries its checksum, the kernel fills the v6 one's.
func EchoRequest(v6 bool, id, seq uint16) []byte {
	b := make([]byte, 8)
	b[0] = 8
	if v6 {
		b[0] = 128
	}
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], seq)
	if !v6 {
		binary.BigEndian.PutUint16(b[2:], checksum(b))
	}
	return b
}

// checksum is the Internet checksum (RFC 1071).
func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func sendARP(it Iface, ip netip.Addr, op uint16) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return fmt.Errorf("ARP: %w", err)
	}
	defer unix.Close(fd)
	to := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: it.Index, Halen: 6}
	copy(to.Addr[:], broadcast)
	if err := unix.Sendto(fd, ARPAnnouncement(op, it.MAC, ip), 0, to); err != nil {
		return fmt.Errorf("ARP: %w", err)
	}
	return nil
}

func sendNA(it Iface, ip netip.Addr) error {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMPV6)
	if err != nil {
		return fmt.Errorf("neighbour advertisement: %w", err)
	}
	defer unix.Close(fd)
	// A receiver takes a neighbour discovery message only with hop limit 255.
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_IF, it.Index)
	to := &unix.SockaddrInet6{ZoneId: uint32(it.Index), Addr: netip.MustParseAddr("ff02::1").As16()}
	if err := unix.Sendto(fd, NeighbourAdvertisement(ip, it.MAC), 0, to); err != nil {
		return fmt.Errorf("neighbour advertisement: %w", err)
	}
	return nil
}

func sendEcho(it Iface, gw netip.Addr) error {
	var fd int
	var err error
	var to unix.Sockaddr
	if gw.Is4() {
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
		to = &unix.SockaddrInet4{Addr: gw.As4()}
	} else {
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMPV6)
		zone := uint32(0)
		if gw.IsLinkLocalUnicast() {
			zone = uint32(it.Index)
		}
		to = &unix.SockaddrInet6{Addr: gw.As16(), ZoneId: zone}
	}
	if err != nil {
		return fmt.Errorf("echo to %s: %w", gw, err)
	}
	defer unix.Close(fd)
	if err := unix.BindToDevice(fd, it.Name); err != nil {
		return fmt.Errorf("echo to %s: %w", gw, err)
	}
	if err := unix.Sendto(fd, EchoRequest(!gw.Is4(), uint16(unix.Getpid()), 1), 0, to); err != nil {
		return fmt.Errorf("echo to %s: %w", gw, err)
	}
	return nil
}
