package ble

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/matthias/tpm2-kira/transport/frame"
)

// fakeController plays the controller and a central at the HCI level.
type fakeController struct {
	t      *testing.T
	toHost chan []byte
	closed chan struct{}
	once   sync.Once

	mu       sync.Mutex
	cmds     []uint16
	advOn    bool
	handle   uint16
	aclMax   int
	l2rx     []byte // reassembly of host -> central L2CAP
	l2len    int
	fromHost chan []byte // complete L2CAP payloads with CID prefix
	scanRsp  []byte
}

func newFakeController(t *testing.T) *fakeController {
	return &fakeController{
		t:        t,
		toHost:   make(chan []byte, 256),
		closed:   make(chan struct{}),
		handle:   0x0040,
		aclMax:   27,
		fromHost: make(chan []byte, 256),
	}
}

func (f *fakeController) Read(b []byte) (int, error) {
	select {
	case p := <-f.toHost:
		return copy(b, p), nil
	case <-f.closed:
		return 0, errors.New("closed")
	}
}

func (f *fakeController) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeController) event(code byte, params ...byte) {
	f.toHost <- append([]byte{pktEvent, code, byte(len(params))}, params...)
}

func (f *fakeController) cmdComplete(op uint16, ret ...byte) {
	f.event(evCmdComplete, append([]byte{1, byte(op), byte(op >> 8)}, ret...)...)
}

func (f *fakeController) Write(p []byte) (int, error) {
	switch p[0] {
	case pktCommand:
		op := binary.LittleEndian.Uint16(p[1:])
		params := p[4:]
		f.mu.Lock()
		f.cmds = append(f.cmds, op)
		f.mu.Unlock()
		switch op {
		case opLEReadBufferSize:
			f.cmdComplete(op, 0, byte(f.aclMax), 0, 3) // 3 buffers: exercises flow control
		case opLESetAdvEnable:
			f.mu.Lock()
			f.advOn = params[0] == 1
			f.mu.Unlock()
			f.cmdComplete(op, 0)
		case opLESetScanRspData:
			f.mu.Lock()
			f.scanRsp = append([]byte(nil), params[1:1+params[0]]...)
			f.mu.Unlock()
			f.cmdComplete(op, 0)
		case opDisconnect:
			f.event(evCmdStatus, 0, 1, byte(op), byte(op>>8))
			h := binary.LittleEndian.Uint16(params)
			f.event(evDisconnComplete, 0, byte(h), byte(h>>8), params[2])
		default:
			f.cmdComplete(op, 0)
		}
	case pktACL:
		hdr := binary.LittleEndian.Uint16(p[1:])
		pb := (hdr >> 12) & 3
		n := int(binary.LittleEndian.Uint16(p[3:]))
		data := p[5 : 5+n]
		if n > f.aclMax {
			f.t.Errorf("host sent %d-byte ACL packet, controller max %d", n, f.aclMax)
		}
		f.mu.Lock()
		if pb == 0 {
			f.l2len = int(binary.LittleEndian.Uint16(data)) + 4
			f.l2rx = append([]byte(nil), data...)
		} else {
			f.l2rx = append(f.l2rx, data...)
		}
		var done []byte
		if len(f.l2rx) == f.l2len {
			done = f.l2rx
			f.l2rx = nil
		}
		h := f.handle
		f.mu.Unlock()
		// Return the buffer credit, as a controller does after transmitting.
		go f.event(evNumCompletedPkts, 1, byte(h), byte(h>>8), 1, 0)
		if done != nil {
			f.fromHost <- done[2:] // CID ‖ payload
		}
	}
	return len(p), nil
}

// connect simulates a central connecting. Like a real controller, it stops
// advertising when the connection is made.
func (f *fakeController) connect() {
	f.mu.Lock()
	f.advOn = false
	f.mu.Unlock()
	h := f.handle
	f.event(evLEMeta, leConnComplete, 0, byte(h), byte(h>>8), 1, 1, 1, 2, 3, 4, 5, 6, 0x18, 0, 0, 0, 0x48, 0, 0)
}

// l2cap sends an L2CAP frame from the central, fragmented to 27-byte ACL packets.
func (f *fakeController) l2cap(cid uint16, payload []byte) {
	pdu := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint16(pdu, uint16(len(payload)))
	binary.LittleEndian.PutUint16(pdu[2:], cid)
	copy(pdu[4:], payload)
	for off := 0; off < len(pdu); off += 27 {
		end := off + 27
		if end > len(pdu) {
			end = len(pdu)
		}
		pb := uint16(0x2)
		if off > 0 {
			pb = 0x1
		}
		hdr := f.handle | pb<<12
		pkt := []byte{pktACL, byte(hdr), byte(hdr >> 8), byte(end - off), 0}
		f.toHost <- append(pkt, pdu[off:end]...)
	}
}

// recv returns the next L2CAP payload on cid from the host.
func (f *fakeController) recv(t *testing.T, cid uint16) []byte {
	t.Helper()
	for {
		select {
		case p := <-f.fromHost:
			if binary.LittleEndian.Uint16(p) == cid {
				return p[2:]
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for CID 0x%04x", cid)
		}
	}
}

func (f *fakeController) att(t *testing.T, req ...byte) []byte {
	t.Helper()
	f.l2cap(cidATT, req)
	return f.recv(t, cidATT)
}

func (f *fakeController) disconnect() {
	h := f.handle
	f.event(evDisconnComplete, 0, byte(h), byte(h>>8), 0x13)
}

func startPeripheral(t *testing.T) (*Peripheral, *fakeController) {
	fc := newFakeController(t)
	p, err := newPeripheral(fc, Config{DeviceName: "tpm2-kira", Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	return p, fc
}

var testAdv = Advertisement{ServiceData: bytes.Repeat([]byte{0xAB}, 13), Info: []byte{1, 2, 1, 0, 0, 0, 0, 0}}

func acceptAsync(p *Peripheral, budget frame.Budget) chan *frame.Conn {
	ch := make(chan *frame.Conn, 1)
	go func() {
		c, err := p.Accept(testAdv, budget, 5*time.Second)
		if err != nil {
			ch <- nil
			return
		}
		ch <- c
	}()
	return ch
}

func waitAdvertising(t *testing.T, fc *fakeController) {
	t.Helper()
	for i := 0; i < 200; i++ {
		fc.mu.Lock()
		on := fc.advOn
		fc.mu.Unlock()
		if on {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("peripheral never started advertising")
}

func TestAdvertisingCarriesNoIdentity(t *testing.T) {
	ad := advertisingData()
	if len(ad) > 31 {
		t.Fatalf("advertising data is %d bytes", len(ad))
	}
	if !bytes.Contains(ad, ServiceUUID.LE()) {
		t.Fatal("service UUID missing")
	}
	sr := scanResponseData(testAdv.ServiceData)
	if len(sr) != 31 || sr[1] != 0x21 {
		t.Fatalf("scan response malformed: %x", sr)
	}
}

func TestDiscoveryAndEcho(t *testing.T) {
	p, fc := startPeripheral(t)
	defer p.Close()
	connCh := acceptAsync(p, frame.Budget{MaxRecord: frame.MaxRecord, MaxBytes: 1 << 20, Deadline: 10 * time.Second})
	waitAdvertising(t, fc)
	fc.mu.Lock()
	if !bytes.Equal(fc.scanRsp, scanResponseData(testAdv.ServiceData)) {
		t.Fatal("scan response not programmed")
	}
	fc.mu.Unlock()
	fc.connect()
	conn := <-connCh
	if conn == nil {
		t.Fatal("accept failed")
	}

	// MTU exchange: phone asks 185 (iOS-like).
	rsp := fc.att(t, attExchangeMTUReq, 185, 0)
	if rsp[0] != attExchangeMTURsp {
		t.Fatalf("MTU rsp %x", rsp)
	}

	// Primary service discovery finds GAP and the tpm2-kira service.
	rsp = fc.att(t, attReadByGroupReq, 1, 0, 0xFF, 0xFF, 0x00, 0x28)
	if rsp[0] != attReadByGroupRsp || rsp[1] != 6 {
		t.Fatalf("first group rsp %x", rsp)
	}
	last := binary.LittleEndian.Uint16(rsp[4:])
	rsp = fc.att(t, attReadByGroupReq, byte(last+1), 0, 0xFF, 0xFF, 0x00, 0x28)
	if rsp[0] != attReadByGroupRsp || rsp[1] != 20 || !bytes.Equal(rsp[6:22], ServiceUUID.LE()) {
		t.Fatalf("service group rsp %x", rsp)
	}
	svcStart, svcEnd := binary.LittleEndian.Uint16(rsp[2:]), binary.LittleEndian.Uint16(rsp[4:])

	// Characteristic discovery inside the service, as iOS does it.
	chars := map[UUID]uint16{}
	props := map[UUID]byte{}
	start := svcStart
	for start <= svcEnd {
		rsp = fc.att(t, attReadByTypeReq, byte(start), byte(start>>8), byte(svcEnd), byte(svcEnd>>8), 0x03, 0x28)
		if rsp[0] == attErrorRsp {
			break
		}
		size := int(rsp[1])
		for off := 2; off+size <= len(rsp); off += size {
			e := rsp[off : off+size]
			var u UUID
			le := e[5:21]
			for i := range u {
				u[i] = le[15-i]
			}
			chars[u] = binary.LittleEndian.Uint16(e[3:])
			props[u] = e[2]
			start = binary.LittleEndian.Uint16(e) + 1
		}
	}
	rx, tx, info := chars[RXCharUUID], chars[TXCharUUID], chars[InfoUUID]
	if rx == 0 || tx == 0 || info == 0 {
		t.Fatalf("characteristics missing: %v", chars)
	}
	if props[RXCharUUID]&propWriteNoResp == 0 || props[TXCharUUID]&propNotify == 0 || props[InfoUUID]&propRead == 0 {
		t.Fatalf("wrong properties: %v", props)
	}

	// Descriptor discovery finds the CCCD after TX.
	rsp = fc.att(t, attFindInfoReq, byte(tx+1), byte((tx+1)>>8), byte(tx+1), byte((tx+1)>>8))
	if rsp[0] != attFindInfoRsp || rsp[1] != 1 || binary.LittleEndian.Uint16(rsp[4:]) != uuidCCCD {
		t.Fatalf("CCCD not found: %x", rsp)
	}
	cccd := binary.LittleEndian.Uint16(rsp[2:])

	// INFO is readable, TX is not.
	rsp = fc.att(t, attReadReq, byte(info), byte(info>>8))
	if rsp[0] != attReadRsp || !bytes.Equal(rsp[1:], testAdv.Info) {
		t.Fatalf("INFO read %x", rsp)
	}
	rsp = fc.att(t, attReadReq, byte(tx), byte(tx>>8))
	if rsp[0] != attErrorRsp || rsp[4] != attErrReadNotPermitted {
		t.Fatalf("TX should not be readable: %x", rsp)
	}

	// Pairing is refused; signalling requests are rejected.
	fc.l2cap(cidSMP, []byte{smpPairingReq, 3, 0, 1, 16, 7, 7})
	if r := fc.recv(t, cidSMP); !bytes.Equal(r, []byte{smpPairingFailed, smpNotSupported}) {
		t.Fatalf("SMP rsp %x", r)
	}
	fc.l2cap(cidLESignal, []byte{0x14, 9, 10, 0, 0x80, 0, 0x40, 0, 0x17, 0, 0x01, 0, 0x01, 0})
	if r := fc.recv(t, cidLESignal); r[0] != sigCommandReject || r[1] != 9 {
		t.Fatalf("signalling rsp %x", r)
	}

	// Subscribe, then exchange records in both directions.
	if rsp = fc.att(t, attWriteReq, byte(cccd), byte(cccd>>8), 1, 0); rsp[0] != attWriteRsp {
		t.Fatalf("CCCD write %x", rsp)
	}

	record := bytes.Repeat([]byte("tpm2-kira record "), 40) // 680 bytes
	frag, _ := frame.NewFragmenter(185 - 3)
	frags, _ := frag.Split(record)
	for _, fr := range frags {
		fc.l2cap(cidATT, append([]byte{attWriteCmd, byte(rx), byte(rx >> 8)}, fr...))
	}
	got, err := conn.Recv()
	if err != nil || !bytes.Equal(got, record) {
		t.Fatalf("record not reassembled: %v", err)
	}

	reply := bytes.Repeat([]byte{0x5A}, 1000)
	go func() { _ = conn.Send(reply) }()
	reas := frame.NewReassembler(frame.MaxRecord, 0)
	var back []byte
	for back == nil {
		n := fc.recv(t, cidATT)
		if n[0] != attNotify || binary.LittleEndian.Uint16(n[1:]) != tx {
			t.Fatalf("expected a TX notification, got %x", n[:3])
		}
		if len(n)-3 > 185-3 {
			t.Fatalf("notification of %d bytes exceeds MTU", len(n)-3)
		}
		if back, err = reas.Feed(n[3:]); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(back, reply) {
		t.Fatal("reply mismatch")
	}

	// Disconnect: Recv fails, and the peripheral can accept again.
	fc.disconnect()
	if _, err := conn.Recv(); err == nil {
		t.Fatal("Recv should fail after disconnect")
	}
	connCh = acceptAsync(p, frame.DefaultBudget)
	waitAdvertising(t, fc)
	fc.connect()
	if c := <-connCh; c == nil {
		t.Fatal("second accept failed")
	}
}

func TestBrokenFragmentStreamDropsConnection(t *testing.T) {
	p, fc := startPeripheral(t)
	defer p.Close()
	connCh := acceptAsync(p, frame.DefaultBudget)
	waitAdvertising(t, fc)
	fc.connect()
	conn := <-connCh
	rx := newGATTDB("x", nil).rxHandle
	// A continuation fragment with no start.
	fc.l2cap(cidATT, []byte{attWriteCmd, byte(rx), byte(rx >> 8), 10, 0, 0, 0, 0, 1, 2, 3})
	if _, err := conn.Recv(); err == nil {
		t.Fatal("broken stream must fail the connection")
	}
	// The host disconnects the central.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		fc.mu.Lock()
		n := 0
		for _, c := range fc.cmds {
			if c == opDisconnect {
				n++
			}
		}
		fc.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("host did not disconnect after a framing error")
}

func TestDeadlineDropsIdleCentral(t *testing.T) {
	p, fc := startPeripheral(t)
	defer p.Close()
	connCh := acceptAsync(p, frame.Budget{MaxRecord: 1024, MaxBytes: 1 << 16, Deadline: 100 * time.Millisecond})
	waitAdvertising(t, fc)
	fc.connect()
	conn := <-connCh
	if _, err := conn.Recv(); !errors.Is(err, frame.ErrDeadline) {
		t.Fatalf("expected deadline, got %v", err)
	}
}
