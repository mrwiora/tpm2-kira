//go:build pcsc

// Tests for the pcscd wire protocol, run against a real pcscd.
//
// The message layout in pcsc.go mirrors C structs from pcsc-lite's internal
// winscard_msg.h, which is not part of the installed headers. Nothing in a unit
// test can tell whether that layout is right — only a live daemon can. These
// tests therefore drive a real pcscd through the vsmartcard virtual reader
// (vpcd), with a virtual card implemented below, so the whole exchange happens
// without any hardware.
//
// Run them with:
//
//	pcscd && go test -tags=pcsc ./internal/pcsc/
//
// See test/docker/ for a container that has pcscd and vpcd set up.
package pcsc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/matthias/tpm2-kira/internal/virtualpiv"
)

// vpcd's control bytes, from the vsmartcard protocol. A one-byte message is a
// control command; anything longer is an APDU to answer.
const (
	vpcdPowerOff byte = 0x00
	vpcdPowerOn  byte = 0x01
	vpcdReset    byte = 0x02
	vpcdGetATR   byte = 0x04
)

// vpcdAddr is where the Debian vsmartcard-vpcd reader configuration tells vpcd
// to listen: CHANNELID 0x8C7B.
const vpcdAddr = "127.0.0.1:35963"

// atr is a plausible T=1 ATR. pcscd only needs it to be well formed.
var atr = []byte{0x3B, 0x8C, 0x80, 0x01, 0x50, 0x49, 0x56, 0x5F, 0x49, 0x49, 0x49, 0x00, 0x00, 0x00, 0x00, 0x0D}

// virtualCard is a card that answers APDUs with a scripted handler.
type virtualCard struct {
	conn    net.Conn
	handler func(apdu []byte) []byte

	received chan []byte
	done     chan struct{}
}

// connectVirtualCard attaches a virtual card to vpcd and serves it until the
// returned card is closed.
func connectVirtualCard(t *testing.T, handler func(apdu []byte) []byte) *virtualCard {
	t.Helper()

	// The virtual reader is machine-wide, and `go test ./...` runs packages
	// concurrently, so two test processes would otherwise attach cards to the
	// same reader and pick up each other's.
	unlock, err := virtualpiv.LockReader(2 * time.Minute)
	if err != nil {
		t.Fatalf("cannot lock the virtual reader: %v", err)
	}
	t.Cleanup(unlock)

	conn, err := net.DialTimeout("tcp", vpcdAddr, 5*time.Second)
	if err != nil {
		t.Skipf("cannot reach vpcd at %s (%v); is pcscd running with vsmartcard-vpcd configured?", vpcdAddr, err)
	}

	card := &virtualCard{
		conn:     conn,
		handler:  handler,
		received: make(chan []byte, 16),
		done:     make(chan struct{}),
	}

	go card.serve()

	t.Cleanup(func() { card.Close() })

	// pcscd polls reader state; give it a moment to notice the card.
	time.Sleep(1500 * time.Millisecond)

	return card
}

func (c *virtualCard) serve() {
	defer close(c.done)

	for {
		var length uint16
		if err := binary.Read(c.conn, binary.BigEndian, &length); err != nil {
			return
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(c.conn, payload); err != nil {
			return
		}

		if length == 1 {
			switch payload[0] {
			case vpcdGetATR:
				if err := c.send(atr); err != nil {
					return
				}
			case vpcdPowerOn, vpcdPowerOff, vpcdReset:
				// Acknowledged by doing nothing, as the protocol expects.
			}
			continue
		}

		select {
		case c.received <- append([]byte{}, payload...):
		default:
		}

		if err := c.send(c.handler(payload)); err != nil {
			return
		}
	}
}

func (c *virtualCard) send(data []byte) error {
	buf := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(buf, uint16(len(data)))
	copy(buf[2:], data)

	_, err := c.conn.Write(buf)
	return err
}

func (c *virtualCard) Close() {
	_ = c.conn.Close()
	<-c.done
}

// lastAPDU returns the most recent APDU the card was asked to process.
func (c *virtualCard) lastAPDU(t *testing.T) []byte {
	t.Helper()

	select {
	case apdu := <-c.received:
		return apdu
	case <-time.After(2 * time.Second):
		t.Fatal("the virtual card received no APDU")
		return nil
	}
}

func requireDaemon(t *testing.T) {
	t.Helper()

	for _, path := range socketPaths {
		if _, err := os.Stat(path); err == nil {
			return
		}
	}
	t.Skipf("no pcscd socket found (tried %v); start pcscd to run these tests", socketPaths)
}

// TestConnectNegotiatesWithRealDaemon is the test that actually matters: if the
// rxHeader, version_struct or establish_struct layouts are wrong, this fails.
func TestConnectNegotiatesWithRealDaemon(t *testing.T) {
	requireDaemon(t)

	client, err := Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	if client.context == 0 {
		t.Error("the daemon returned a zero context handle, which suggests establish_struct is misread")
	}
}

// TestReadersReportsTheVirtualReader checks the READER_STATE array layout. A
// wrong stride would return names sliced out of the middle of a struct, so
// asserting that a plausible name comes back is a real check.
func TestReadersReportsTheVirtualReader(t *testing.T) {
	requireDaemon(t)

	client, err := Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	all, err := client.Readers(false)
	if err != nil {
		t.Fatalf("Readers failed: %v", err)
	}
	if len(all) == 0 {
		t.Skip("pcscd reports no readers at all; vsmartcard-vpcd is probably not configured")
	}

	t.Logf("readers: %v", all)

	for _, name := range all {
		if len(name) < 2 {
			t.Errorf("reader name %q is implausibly short — READER_STATE stride is likely wrong", name)
		}
		for _, c := range name {
			if c < 0x20 || c > 0x7E {
				t.Errorf("reader name %q contains non-printable bytes — READER_STATE stride is likely wrong", name)
				break
			}
		}
	}

	// Without a card attached, the present-only filter must return fewer.
	present, err := client.Readers(true)
	if err != nil {
		t.Fatalf("Readers(true) failed: %v", err)
	}
	if len(present) > len(all) {
		t.Errorf("Readers(true) returned %d readers, more than the %d total", len(present), len(all))
	}
}

// TestTransmitAgainstVirtualCard exercises the full path: connect_struct,
// transmit_struct, and the separate APDU body write.
func TestTransmitAgainstVirtualCard(t *testing.T) {
	requireDaemon(t)

	want := []byte{0xA5, 0x5A, 0x90, 0x00}

	card := connectVirtualCard(t, func(apdu []byte) []byte {
		return want
	})

	client, err := Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	readers, err := client.Readers(true)
	if err != nil {
		t.Fatalf("Readers failed: %v", err)
	}
	if len(readers) == 0 {
		t.Skip("no reader reports a card present; vpcd may not be wired up")
	}

	t.Logf("connecting to %s", readers[0])

	connected, err := client.ConnectCard(readers[0])
	if err != nil {
		t.Fatalf("ConnectCard failed: %v", err)
	}
	defer connected.Disconnect()

	if connected.handle == 0 {
		t.Error("the daemon returned a zero card handle, which suggests connect_struct is misread")
	}

	sent := []byte{0x00, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00}

	got, err := connected.Transmit(sent)
	if err != nil {
		t.Fatalf("Transmit failed: %v", err)
	}

	if string(got) != string(want) {
		t.Errorf("Transmit returned %x, want %x", got, want)
	}

	// The card must have seen exactly what we sent. A misplaced field in
	// transmit_struct would corrupt the APDU on the way out, and a response
	// that happened to look right would hide it.
	if arrived := card.lastAPDU(t); string(arrived) != string(sent) {
		t.Errorf("the card received %x, want %x", arrived, sent)
	}
}

// TestTransmitLongResponseAgainstVirtualCard covers a response larger than a
// single short-APDU buffer, which is what reading a certificate looks like.
func TestTransmitLongResponseAgainstVirtualCard(t *testing.T) {
	requireDaemon(t)

	body := make([]byte, 700)
	for i := range body {
		body[i] = byte(i % 251)
	}
	want := append(append([]byte{}, body...), 0x90, 0x00)

	connectVirtualCard(t, func(apdu []byte) []byte { return want })

	client, err := Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	readers, err := client.Readers(true)
	if err != nil || len(readers) == 0 {
		t.Skip("no reader reports a card present")
	}

	connected, err := client.ConnectCard(readers[0])
	if err != nil {
		t.Fatalf("ConnectCard failed: %v", err)
	}
	defer connected.Disconnect()

	got, err := connected.Transmit([]byte{0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x00})
	if err != nil {
		t.Fatalf("Transmit failed: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("Transmit returned %d bytes, want %d", len(got), len(want))
	}
	if string(got) != string(want) {
		t.Error("the long response came back altered")
	}
}

// TestSharedModeAllowsASecondClient checks that connecting in shared mode does
// not lock out other PC/SC users, which is the reason for going through pcscd
// rather than claiming the USB device.
func TestSharedModeAllowsASecondClient(t *testing.T) {
	requireDaemon(t)

	connectVirtualCard(t, func(apdu []byte) []byte { return []byte{0x90, 0x00} })

	first, err := Connect()
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer first.Close()

	readers, err := first.Readers(true)
	if err != nil || len(readers) == 0 {
		t.Skip("no reader reports a card present")
	}

	a, err := first.ConnectCard(readers[0])
	if err != nil {
		t.Fatalf("first ConnectCard failed: %v", err)
	}
	defer a.Disconnect()

	second, err := Connect()
	if err != nil {
		t.Fatalf("second Connect failed: %v", err)
	}
	defer second.Close()

	b, err := second.ConnectCard(readers[0])
	if err != nil {
		t.Fatalf("second ConnectCard failed while the first is open: %v", err)
	}
	defer b.Disconnect()

	if _, err := b.Transmit([]byte{0x00, 0xA4, 0x04, 0x00, 0x00}); err != nil {
		t.Errorf("the second client could not transmit: %v", err)
	}
}

// TestErrDaemonUnavailableWhenSocketMissing checks the degradation path that
// reseal depends on, by pointing the client at a socket that is not there.
func TestErrDaemonUnavailableWhenSocketMissing(t *testing.T) {
	original := socketPaths
	socketPaths = []string{"/nonexistent/pcscd.comm"}
	defer func() { socketPaths = original }()

	_, err := Connect()
	if !errors.Is(err, ErrDaemonUnavailable) {
		t.Errorf("got %v, want it to wrap ErrDaemonUnavailable", err)
	}
}

func TestStatusStringNamesCommonErrors(t *testing.T) {
	cases := map[uint32]string{
		0x8010000C: "no smart card",
		0x80100017: "in use by another application",
		0x80100069: "removed",
	}

	for code, fragment := range cases {
		got := statusString(code)
		if !contains(got, fragment) {
			t.Errorf("statusString(%#x) = %q, want it to mention %q", code, got, fragment)
		}
	}

	if got := statusString(0x12345678); !contains(got, "0x12345678") {
		t.Errorf("an unknown code should report its value, got %q", got)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

var _ = fmt.Sprintf
