package pcsc

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// Golden encodings. These are the bytes libpcsclite 2.5.2 puts on the socket
// for the same values on a little-endian host; a layout change in pcsc-lite
// must show up here first.
func TestWireGolden(t *testing.T) {
	if ne.Uint16([]byte{1, 0}) != 1 {
		t.Skip("golden vectors are little-endian")
	}
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"header", header{Size: 12, Command: cmdVersion}.encode(), "0c00000011000000"},
		{"version", versionMsg{Major: 4, Minor: 6}.encode(), "040000000600000000000000"},
		{"establish", establishMsg{Scope: scopeSystem}.encode(), "020000000000000000000000"},
		{"release", releaseMsg{Context: 0x01020304}.encode(), "0403020100000000"},
		{"begin", beginMsg{Card: 7}.encode(), "0700000000000000"},
		{"disconnect", disconnectMsg{Card: 7}.encode(), "070000000000000000000000"},
		{"transmit", transmitMsg{Card: 7, SendPCIProtocol: 2, SendPCILength: 16, SendLength: 5,
			RecvPCIProtocol: 3, RecvPCILength: 16, RecvLength: 258}.encode(),
			"0700000002000000100000000500000003000000100000000201000000000000"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(c.got); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}

	conn, err := connectMsg{Context: 9, Reader: "Yubico YubiKey", ShareMode: shareShared, PreferredProtocols: protocolAny}.encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(conn) != 152 {
		t.Fatalf("connect_struct is %d bytes, want 152", len(conn))
	}
	if !bytes.Equal(conn[:4], []byte{9, 0, 0, 0}) || string(conn[4:18]) != "Yubico YubiKey" || conn[18] != 0 {
		t.Errorf("connect_struct head: %x", conn[:20])
	}
	if hex.EncodeToString(conn[132:]) != "0200000003000000000000000000000000000000" {
		t.Errorf("connect_struct tail: %x", conn[132:])
	}
}

func TestSizes(t *testing.T) {
	for name, got := range map[string]int{
		"header": headerSize, "version": versionMsgSize, "establish": establishMsgSize,
		"release": releaseMsgSize, "connect": connectMsgSize, "disconnect": disconnectMsgSize,
		"begin": beginMsgSize, "transmit": transmitMsgSize, "readerState": readerStateSize,
	} {
		want := map[string]int{"header": 8, "version": 12, "establish": 12, "release": 8,
			"connect": 152, "disconnect": 12, "begin": 8, "transmit": 32, "readerState": 184}[name]
		if got != want {
			t.Errorf("%s: %d bytes, want %d", name, got, want)
		}
	}
}

func TestDecodeReaderState(t *testing.T) {
	b := make([]byte, readerStateSize)
	copy(b, "Yubico YubiKey OTP+FIDO+CCID 00 00")
	ne.PutUint32(b[132:], statePresent|0x20)
	copy(b[140:], []byte{0x3b, 0xfd, 0x13})
	ne.PutUint32(b[176:], 3)
	ne.PutUint32(b[180:], ProtocolT1)
	s := decodeReaderState(b)
	if s.Name != "Yubico YubiKey OTP+FIDO+CCID 00 00" || s.State&statePresent == 0 ||
		!bytes.Equal(s.ATR, []byte{0x3b, 0xfd, 0x13}) || s.Protocol != ProtocolT1 {
		t.Errorf("decoded %+v", s)
	}
	ne.PutUint32(b[176:], 200) // corrupt length must not index past the ATR
	if s := decodeReaderState(b); len(s.ATR) != 0 {
		t.Errorf("oversized ATR length accepted: %x", s.ATR)
	}
}

// fakeDaemon is a scripted pcscd. serverMinor is the protocol it speaks.
type fakeDaemon struct {
	t           *testing.T
	serverMinor int32
	readers     []string
	transmit    func(apdu []byte) []byte
	seen        []uint32
}

func (f *fakeDaemon) serve(conn net.Conn) {
	defer conn.Close()
	read := func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil
		}
		return b
	}
	for {
		h := read(headerSize)
		if h == nil {
			return
		}
		size, cmd := ne.Uint32(h[0:]), ne.Uint32(h[4:])
		body := read(int(size))
		f.seen = append(f.seen, cmd)
		switch cmd {
		case cmdVersion:
			v := decodeVersionMsg(body)
			v.RV = scardSuccess
			if v.Major != protocolMajor || v.Minor != f.serverMinor {
				if v.Minor < protocolMinorMin || v.Minor > f.serverMinor {
					v.RV = scardEServiceStopped
				}
			}
			if v.RV != scardSuccess {
				v.Major, v.Minor = protocolMajor, f.serverMinor
			}
			conn.Write(v.encode())
		case cmdEstablishContext:
			conn.Write(establishMsg{Scope: scopeSystem, Context: 0xabcd}.encode())
		case cmdReleaseContext:
			conn.Write(releaseMsg{Context: 0xabcd}.encode())
		case cmdGetReadersStateSize:
			b := make([]byte, 4)
			ne.PutUint32(b, uint32(len(f.readers)))
			conn.Write(b)
		case cmdGetReadersState, cmdGetReadersStateArray:
			n := len(f.readers)
			if cmd == cmdGetReadersState {
				n = maxReadersContexts
			}
			out := make([]byte, n*readerStateSize)
			for i, r := range f.readers {
				copy(out[i*readerStateSize:], r)
				ne.PutUint32(out[i*readerStateSize+132:], statePresent)
			}
			conn.Write(out)
		case cmdConnect:
			m := decodeConnectMsg(body)
			m.Card, m.ActiveProtocol = 42, ProtocolT1
			b, _ := m.encode()
			conn.Write(b)
		case cmdTransmit:
			m := decodeTransmitMsg(body)
			apdu := read(int(m.SendLength))
			resp := f.transmit(apdu)
			m.RecvLength = uint32(len(resp))
			conn.Write(m.encode())
			conn.Write(resp)
		case cmdDisconnect, cmdEndTransaction:
			conn.Write(decodeDisconnectMsg(body).encode())
		case cmdBeginTransaction:
			conn.Write(decodeBeginMsg(body).encode())
		default:
			f.t.Errorf("fake pcscd: unexpected command 0x%x", cmd)
			return
		}
	}
}

func startFake(t *testing.T, f *fakeDaemon) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pcscd.comm")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	t.Setenv("PCSCLITE_CSOCK_NAME", path)
}

func TestClientCurrentProtocol(t *testing.T) {
	f := &fakeDaemon{t: t, serverMinor: 6, readers: []string{"Yubico YubiKey OTP+FIDO+CCID 00 00"},
		transmit: func(apdu []byte) []byte {
			if hex.EncodeToString(apdu) != "00fd0000" {
				t.Errorf("apdu %x", apdu)
			}
			return []byte{5, 7, 1, 0x90, 0x00}
		}}
	startFake(t, f)

	c, err := Dial(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	readers, err := c.Readers()
	if err != nil || len(readers) != 1 || !readers[0].CardPresent {
		t.Fatalf("Readers: %v %+v", err, readers)
	}
	card, err := c.Connect(readers[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := card.BeginTransaction(); err != nil {
		t.Fatal(err)
	}
	resp, err := card.Transmit([]byte{0x00, 0xfd, 0x00, 0x00})
	if err != nil || !bytes.Equal(resp, []byte{5, 7, 1, 0x90, 0x00}) {
		t.Fatalf("Transmit: %v %x", err, resp)
	}
	if err := card.EndTransaction(); err != nil {
		t.Fatal(err)
	}
	if err := card.Disconnect(); err != nil {
		t.Fatal(err)
	}
}

// A 4:4 daemon rejects 4:6, the client retries with 4:4 and must then use the
// fixed-size CMD_GET_READERS_STATE array.
func TestClientBackwardProtocol(t *testing.T) {
	f := &fakeDaemon{t: t, serverMinor: 4, readers: []string{"reader A", "reader B"}}
	startFake(t, f)

	c, err := Dial(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.ProtocolVersion() != "4:4" {
		t.Fatalf("negotiated %s, want 4:4", c.ProtocolVersion())
	}
	readers, err := c.Readers()
	if err != nil || len(readers) != 2 {
		t.Fatalf("Readers: %v %+v", err, readers)
	}
	for _, cmd := range f.seen {
		if cmd == cmdGetReadersStateSize || cmd == cmdGetReadersStateArray {
			t.Errorf("4:4 daemon was sent command 0x%x", cmd)
		}
	}
}

func TestClientRefusesUnknownProtocol(t *testing.T) {
	f := &fakeDaemon{t: t, serverMinor: 3}
	startFake(t, f)
	if _, err := Dial(time.Second); err == nil {
		t.Fatal("Dial accepted protocol 4:3")
	}
}

func TestNoDaemon(t *testing.T) {
	t.Setenv("PCSCLITE_CSOCK_NAME", filepath.Join(t.TempDir(), "absent"))
	if _, err := Dial(time.Second); err == nil {
		t.Fatal("Dial succeeded without a daemon")
	}
}

// A daemon that accepts but never answers must not hang the caller.
func TestDialTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pcscd.comm")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err == nil {
			time.Sleep(2 * time.Second)
			conn.Close()
		}
	}()
	t.Setenv("PCSCLITE_CSOCK_NAME", path)
	start := time.Now()
	if _, err := Dial(200 * time.Millisecond); err == nil {
		t.Fatal("Dial succeeded against a silent daemon")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Dial took %v", d)
	}
}
