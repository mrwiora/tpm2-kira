package ble

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/matthias/tpm2-kira/transport/frame"
)

// H4 packet types.
const (
	pktCommand = 0x01
	pktACL     = 0x02
	pktEvent   = 0x04
)

// HCI opcodes (OGF << 10 | OCF).
const (
	opDisconnect        = 0x0406
	opReadRSSI          = 0x1405
	opSetEventMask      = 0x0C01
	opReset             = 0x0C03
	opWriteLEHostSupp   = 0x0C6D
	opReadBufferSize    = 0x1005
	opLESetEventMask    = 0x2001
	opLEReadBufferSize  = 0x2002
	opLESetRandomAddr   = 0x2005
	opLESetAdvParams    = 0x2006
	opLESetAdvData      = 0x2008
	opLESetScanRspData  = 0x2009
	opLESetAdvEnable    = 0x200A
	opLELTKNegReply     = 0x201B
	opLESetDataLength   = 0x2022
	evDisconnComplete   = 0x05
	evCmdComplete       = 0x0E
	evCmdStatus         = 0x0F
	evNumCompletedPkts  = 0x13
	evLEMeta            = 0x3E
	leConnComplete      = 0x01
	leConnUpdate        = 0x03
	leDataLenChange     = 0x07
	leLTKRequest        = 0x05
	leEnhConnComplete   = 0x0A
	cidATT              = 0x0004
	cidLESignal         = 0x0005
	cidSMP              = 0x0006
	reasonRemoteUser    = 0x13
	smpPairingReq       = 0x01
	smpSecurityReq      = 0x0B
	smpPairingFailed    = 0x05
	smpNotSupported     = 0x05
	sigCommandReject    = 0x01
	sigDisconnectionRsp = 0x07
	sigConnParamRsp     = 0x13
	sigLECreditConnRsp  = 0x15
	sigCreditConnRsp    = 0x18
	commandTimeout      = 5 * time.Second
	maxL2CAPPDU         = maxATTMTU + 4
	maxLEACL            = 251 // largest LE data channel payload (Data Length Extension)
)

var (
	// keepAliveInterval paces a Read RSSI command to the controller while a
	// central is connected. Some controllers (seen with an Intel 7265) lose
	// an idle LE link after ~15 s without host traffic; the command keeps
	// the controller and its USB link busy without touching the protocol.
	keepAliveInterval = 2 * time.Second
	rssiLogInterval   = 10 * time.Second
)

// hciTransport is an open controller: each Read returns exactly one H4
// packet and each Write sends one, as an HCI user channel socket does.
type hciTransport interface {
	io.ReadWriteCloser
}

// Advertisement is what the peripheral advertises.
type Advertisement struct {
	// ServiceData is the 13-byte payload placed in the scan response as
	// service data for ServiceUUID (attest.BuildServiceData).
	ServiceData []byte
	// Info is the value of the INFO characteristic.
	Info []byte
}

type cmdResult struct {
	opcode uint16
	status byte
	params []byte
}

// host drives one controller as a peripheral with at most one connection.
type host struct {
	tr   hciTransport
	logf func(string, ...any)
	wmu  sync.Mutex

	cmdMu   sync.Mutex
	cmdWait chan cmdResult

	mu       sync.Mutex
	cond     *sync.Cond
	aclMax   int
	credits  int
	link     *Link
	readErr  error
	newLinks chan *Link
	adv      Advertisement
	db       *gattDB
	budget   frame.Budget
	devName  string
	closed   bool
	done     chan struct{}
}

func newHost(tr hciTransport, devName string, logf func(string, ...any)) *host {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	h := &host{
		tr:       tr,
		logf:     logf,
		cmdWait:  make(chan cmdResult, 1),
		newLinks: make(chan *Link, 1),
		devName:  devName,
		done:     make(chan struct{}),
	}
	h.cond = sync.NewCond(&h.mu)
	go h.readLoop()
	return h
}

func (h *host) write(pkt []byte) error {
	h.wmu.Lock()
	defer h.wmu.Unlock()
	_, err := h.tr.Write(pkt)
	return err
}

// command sends an HCI command and waits for its Command Complete or Command
// Status. It must never be called from the read loop.
func (h *host) command(op uint16, params []byte) ([]byte, error) {
	h.cmdMu.Lock()
	defer h.cmdMu.Unlock()
	pkt := []byte{pktCommand, byte(op), byte(op >> 8), byte(len(params))}
	pkt = append(pkt, params...)
	// Drop a stale result from a timed-out earlier command.
	select {
	case <-h.cmdWait:
	default:
	}
	sent := time.Now()
	if err := h.write(pkt); err != nil {
		h.logf("command 0x%04x: write failed: %v", op, err)
		return nil, fmt.Errorf("ble: write command 0x%04x: %w", op, err)
	}
	timer := time.NewTimer(commandTimeout)
	defer timer.Stop()
	for {
		select {
		case r := <-h.cmdWait:
			if r.opcode != op {
				continue
			}
			if r.status != 0 {
				h.logf("command 0x%04x: status 0x%02x after %d ms", op, r.status, time.Since(sent).Milliseconds())
				return nil, fmt.Errorf("ble: command 0x%04x failed with status 0x%02x", op, r.status)
			}
			if op != opReadRSSI { // the keepalive logs its own line every 2 s
				h.logf("command 0x%04x: ok after %d ms", op, time.Since(sent).Milliseconds())
			}
			return r.params, nil
		case <-timer.C:
			h.logf("command 0x%04x: no answer from the controller within %s", op, commandTimeout)
			return nil, fmt.Errorf("ble: command 0x%04x timed out", op)
		case <-h.done:
			h.logf("command 0x%04x: the adapter went away: %v", op, h.err())
			return nil, h.err()
		}
	}
}

func (h *host) err() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.readErr != nil {
		return h.readErr
	}
	return errors.New("ble: adapter closed")
}

// init resets the controller and prepares it for advertising.
func (h *host) init() error {
	if _, err := h.command(opReset, nil); err != nil {
		return err
	}
	if _, err := h.command(opSetEventMask, le64(0x3DBFF807FFFBFFFF)); err != nil {
		return err
	}
	// Dual-mode controllers want LE host support declared; LE-only ones
	// reject the command, which is harmless.
	_, _ = h.command(opWriteLEHostSupp, []byte{1, 0})
	// LE connection complete, advertising report, connection update,
	// remote features, LTK request, data length change, enhanced connection complete.
	if _, err := h.command(opLESetEventMask, le64(0x25F)); err != nil {
		return err
	}
	p, err := h.command(opLEReadBufferSize, nil)
	if err != nil {
		return err
	}
	aclLen, aclNum := 0, 0
	if len(p) >= 3 {
		aclLen, aclNum = int(binary.LittleEndian.Uint16(p)), int(p[2])
	}
	if aclLen == 0 || aclNum == 0 {
		// Shared buffers: fall back to the BR/EDR buffer size.
		p, err := h.command(opReadBufferSize, nil)
		if err != nil {
			return err
		}
		if len(p) < 7 {
			return errors.New("ble: short Read Buffer Size response")
		}
		aclLen, aclNum = int(binary.LittleEndian.Uint16(p)), int(binary.LittleEndian.Uint16(p[3:]))
	}
	if aclLen < 27 || aclNum == 0 {
		return fmt.Errorf("ble: controller reports unusable ACL buffers (%d x %d)", aclNum, aclLen)
	}
	if aclLen > maxLEACL {
		// A controller may report a larger buffer, notably the BR/EDR one
		// when LE shares it; some old controllers then mishandle LE packets
		// above the largest LE data payload.
		aclLen = maxLEACL
	}
	h.mu.Lock()
	h.aclMax, h.credits = aclLen, aclNum
	h.mu.Unlock()
	h.logf("controller ready: %d ACL buffers of %d bytes", aclNum, aclLen)

	// Non-resolvable private address, new every boot (PLAN-BLE.md §4.2).
	addr := make([]byte, 6)
	for {
		if _, err := rand.Read(addr); err != nil {
			return err
		}
		addr[5] &= 0x3F
		if !allBytes(addr, 0) && !(allBytes(addr[:5], 0xFF) && addr[5] == 0x3F) {
			break
		}
	}
	if _, err := h.command(opLESetRandomAddr, addr); err != nil {
		return err
	}
	return nil
}

func allBytes(b []byte, v byte) bool {
	for _, x := range b {
		if x != v {
			return false
		}
	}
	return true
}

func le64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// advertisingData: flags + complete list of 128-bit service UUIDs, and
// nothing else — no name, no device id (PLAN-BLE.md §4.2).
func advertisingData() []byte {
	d := []byte{0x02, 0x01, 0x06, 0x11, 0x07}
	return append(d, ServiceUUID.LE()...)
}

// scanResponseData: service data (AD type 0x21) for the 128-bit service UUID.
func scanResponseData(sd []byte) []byte {
	if len(sd) == 0 {
		return nil
	}
	d := []byte{byte(1 + 16 + len(sd)), 0x21}
	d = append(d, ServiceUUID.LE()...)
	return append(d, sd...)
}

func padAD(d []byte) []byte {
	out := make([]byte, 32)
	out[0] = byte(len(d))
	copy(out[1:], d)
	return out
}

func (h *host) startAdvertising() error {
	h.mu.Lock()
	adv := h.adv
	h.mu.Unlock()
	sr := scanResponseData(adv.ServiceData)
	if len(sr) > 31 {
		return fmt.Errorf("ble: scan response of %d bytes exceeds 31", len(sr))
	}
	// 100 ms interval: fast enough to connect promptly at a prompt.
	params := []byte{0xA0, 0x00, 0xA0, 0x00, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0x07, 0x00}
	if _, err := h.command(opLESetAdvParams, params); err != nil {
		return err
	}
	if _, err := h.command(opLESetAdvData, padAD(advertisingData())); err != nil {
		return err
	}
	if _, err := h.command(opLESetScanRspData, padAD(sr)); err != nil {
		return err
	}
	if _, err := h.command(opLESetAdvEnable, []byte{1}); err != nil {
		return err
	}
	h.logf("advertising (100 ms interval, %d bytes of service data)", len(adv.ServiceData))
	return nil
}

func (h *host) stopAdvertising() {
	_, _ = h.command(opLESetAdvEnable, []byte{0})
	h.logf("advertising stopped")
}

// readLoop dispatches everything the controller sends.
func (h *host) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, err := h.tr.Read(buf)
		if err != nil {
			h.mu.Lock()
			if h.readErr == nil {
				h.readErr = fmt.Errorf("ble: adapter read: %w", err)
			}
			l := h.link
			h.closed = true
			h.cond.Broadcast()
			h.mu.Unlock()
			if l != nil {
				l.lost(h.readErr)
			}
			close(h.done)
			return
		}
		if n == 0 {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		switch pkt[0] {
		case pktEvent:
			h.handleEvent(pkt[1:])
		case pktACL:
			h.handleACL(pkt[1:])
		}
	}
}

func (h *host) handleEvent(ev []byte) {
	if len(ev) < 2 || len(ev)-2 < int(ev[1]) {
		return
	}
	code, p := ev[0], ev[2:2+int(ev[1])]
	switch code {
	case evCmdComplete:
		if len(p) >= 3 {
			r := cmdResult{opcode: binary.LittleEndian.Uint16(p[1:])}
			if len(p) >= 4 {
				r.status, r.params = p[3], append([]byte(nil), p[4:]...)
			}
			h.deliverCmd(r)
		}
	case evCmdStatus:
		if len(p) >= 4 {
			h.deliverCmd(cmdResult{opcode: binary.LittleEndian.Uint16(p[2:]), status: p[0]})
		}
	case evNumCompletedPkts:
		if len(p) < 1 {
			return
		}
		n := int(p[0])
		h.mu.Lock()
		for i := 0; i < n && 1+4*i+4 <= len(p); i++ {
			handle := binary.LittleEndian.Uint16(p[1+4*i:]) & 0x0FFF
			count := int(binary.LittleEndian.Uint16(p[3+4*i:]))
			h.credits += count
			if h.link != nil && h.link.handle == handle {
				h.link.inFlight -= count
				if h.link.inFlight < 0 {
					h.link.inFlight = 0
				}
			}
		}
		h.cond.Broadcast()
		h.mu.Unlock()
	case evDisconnComplete:
		if len(p) < 4 || p[0] != 0 {
			return
		}
		handle := binary.LittleEndian.Uint16(p[1:]) & 0x0FFF
		h.mu.Lock()
		l := h.link
		if l != nil && l.handle == handle {
			// The controller frees buffers of a dropped connection.
			h.credits += l.inFlight
			l.inFlight = 0
			h.link = nil
		} else {
			l = nil
		}
		h.cond.Broadcast()
		h.mu.Unlock()
		if l != nil {
			h.logf("disconnected (reason 0x%02x)", p[3])
			l.lost(fmt.Errorf("ble: peer disconnected (reason 0x%02x)", p[3]))
		}
	case evLEMeta:
		if len(p) < 1 {
			return
		}
		switch p[0] {
		case leConnComplete, leEnhConnComplete:
			if len(p) < 4 || p[1] != 0 {
				return
			}
			handle := binary.LittleEndian.Uint16(p[2:]) & 0x0FFF
			// Interval, latency and supervision timeout follow the peer
			// address, and in the enhanced event two private addresses.
			at := 12
			if p[0] == leEnhConnComplete {
				at = 24
			}
			if len(p) >= at+6 {
				h.logf("connection parameters: %s", connParams(p[at:]))
			}
			h.onConnect(handle)
		case leConnUpdate:
			if len(p) >= 10 {
				h.logf("connection update (status 0x%02x): %s", p[1], connParams(p[4:]))
			}
		case leDataLenChange:
			if len(p) >= 11 {
				h.logf("data length: tx %d bytes, rx %d bytes",
					binary.LittleEndian.Uint16(p[3:]), binary.LittleEndian.Uint16(p[7:]))
			}
		case leLTKRequest:
			// The central asks to encrypt with a key we never agreed:
			// there is no bonding, so decline (PLAN-BLE.md §5.1).
			if len(p) >= 3 {
				handle := []byte{p[1], p[2]}
				go func() { _, _ = h.command(opLELTKNegReply, handle) }()
			}
		}
	}
}

func (h *host) deliverCmd(r cmdResult) {
	select {
	case h.cmdWait <- r:
	default:
		// Nobody waiting (e.g. an unsolicited No-Op); replace the stale entry.
		select {
		case <-h.cmdWait:
		default:
		}
		select {
		case h.cmdWait <- r:
		default:
		}
	}
}

func (h *host) onConnect(handle uint16) {
	h.mu.Lock()
	if h.link != nil {
		// Only one connection at a time; refuse extras.
		h.mu.Unlock()
		go func() { _, _ = h.command(opDisconnect, []byte{byte(handle), byte(handle >> 8), reasonRemoteUser}) }()
		return
	}
	l := &Link{h: h, handle: handle}
	l.att = newATTServer(h.db, l)
	conn, err := frame.NewConn(l, h.budget)
	if err != nil {
		h.mu.Unlock()
		return
	}
	l.conn = conn
	h.link = l
	h.mu.Unlock()
	h.logf("central connected (handle 0x%03x)", handle)
	// Ask for longer link-layer packets; best effort, off the read loop.
	go func() {
		_, _ = h.command(opLESetDataLength, []byte{byte(handle), byte(handle >> 8), 0xFB, 0x00, 0x48, 0x08})
	}()
	go h.keepAlive(l)
	select {
	case h.newLinks <- l:
	default:
	}
}

// keepAlive reads the link's RSSI every keepAliveInterval until it is gone,
// and logs it every rssiLogInterval.
func (h *host) keepAlive(l *Link) {
	gone := l.goneC()
	t := time.NewTicker(keepAliveInterval)
	defer t.Stop()
	var logged time.Time
	for {
		select {
		case <-gone:
			return
		case <-h.done:
			return
		case <-t.C:
		}
		p, err := h.command(opReadRSSI, []byte{byte(l.handle), byte(l.handle >> 8)})
		switch {
		case err != nil:
			if !l.isGone() {
				h.logf("keepalive: %v", err)
			}
		case len(p) >= 3 && time.Since(logged) >= rssiLogInterval:
			h.logf("signal: RSSI %d dBm", int8(p[2]))
			logged = time.Now()
		}
	}
}

func (h *host) handleACL(p []byte) {
	if len(p) < 4 {
		return
	}
	hdr := binary.LittleEndian.Uint16(p)
	handle, pb := hdr&0x0FFF, (hdr>>12)&0x3
	n := int(binary.LittleEndian.Uint16(p[2:]))
	if len(p)-4 < n {
		return
	}
	data := p[4 : 4+n]
	h.mu.Lock()
	l := h.link
	h.mu.Unlock()
	if l == nil || l.handle != handle {
		return
	}
	l.aclIn(pb, data)
}

// sendL2CAP sends one L2CAP basic frame, fragmented to the controller's ACL
// buffer size and paced by its buffer credits.
func (h *host) sendL2CAP(l *Link, cid uint16, payload []byte) error {
	pdu := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint16(pdu, uint16(len(payload)))
	binary.LittleEndian.PutUint16(pdu[2:], cid)
	copy(pdu[4:], payload)

	// Fragments of one PDU must not interleave with another PDU's on the
	// same connection, so the whole PDU is sent under the link's TX lock.
	l.txMu.Lock()
	defer l.txMu.Unlock()

	h.mu.Lock()
	max := h.aclMax
	h.mu.Unlock()
	for off := 0; off < len(pdu); off += max {
		end := off + max
		if end > len(pdu) {
			end = len(pdu)
		}
		h.mu.Lock()
		if h.credits == 0 {
			// A controller that stops returning buffers stalls the session
			// without an error; say so in the debug log.
			stalled := time.AfterFunc(2*time.Second, func() {
				h.logf("controller has returned no ACL buffer for 2 s (%d in flight)", l.inflight())
			})
			for h.credits == 0 && !h.closed && !l.isGone() {
				h.cond.Wait()
			}
			stalled.Stop()
		}
		if h.closed || l.isGone() {
			h.mu.Unlock()
			return frame.ErrClosed
		}
		h.credits--
		l.inFlight++
		h.mu.Unlock()

		pb := uint16(0x0) // first, non-flushable
		if off > 0 {
			pb = 0x1 // continuing fragment
		}
		hdr := l.handle | pb<<12
		pkt := []byte{pktACL, byte(hdr), byte(hdr >> 8), byte(end - off), byte((end - off) >> 8)}
		pkt = append(pkt, pdu[off:end]...)
		if err := h.write(pkt); err != nil {
			return err
		}
	}
	return nil
}

// Link is one connected central. It implements frame.Link.
type Link struct {
	h        *host
	handle   uint16
	att      *attServer
	conn     *frame.Conn
	inFlight int  // guarded by h.mu
	accepted bool // guarded by h.mu: handed out by Accept
	txMu     sync.Mutex

	mu     sync.Mutex
	rx     []byte // L2CAP reassembly
	rxLen  int
	sub    bool
	gone   bool
	gonech chan struct{}
}

func (l *Link) inflight() int {
	l.h.mu.Lock()
	defer l.h.mu.Unlock()
	return l.inFlight
}

// goneC is closed when the link is lost or closed.
func (l *Link) goneC() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.gonech == nil {
		l.gonech = make(chan struct{})
	}
	return l.gonech
}

func (l *Link) isGone() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.gone
}

func (l *Link) aclIn(pb uint16, data []byte) {
	l.mu.Lock()
	if pb == 0x2 || pb == 0x0 {
		if len(data) < 4 {
			l.mu.Unlock()
			return
		}
		l.rxLen = int(binary.LittleEndian.Uint16(data)) + 4
		if l.rxLen > maxL2CAPPDU {
			l.mu.Unlock()
			l.drop("oversized L2CAP PDU")
			return
		}
		l.rx = append(make([]byte, 0, l.rxLen), data...)
	} else if pb == 0x1 && l.rx != nil {
		l.rx = append(l.rx, data...)
	} else {
		l.mu.Unlock()
		return
	}
	if len(l.rx) > l.rxLen {
		l.mu.Unlock()
		l.drop("L2CAP PDU overrun")
		return
	}
	if len(l.rx) < l.rxLen {
		l.mu.Unlock()
		return
	}
	pdu := l.rx
	l.rx = nil
	l.mu.Unlock()

	cid := binary.LittleEndian.Uint16(pdu[2:])
	payload := pdu[4:]
	switch cid {
	case cidATT:
		if rsp := l.att.handle(payload); rsp != nil {
			go func() { _ = l.h.sendL2CAP(l, cidATT, rsp) }()
		}
	case cidLESignal:
		l.signal(payload)
	case cidSMP:
		if len(payload) > 0 && (payload[0] == smpPairingReq || payload[0] == smpSecurityReq) {
			go func() { _ = l.h.sendL2CAP(l, cidSMP, []byte{smpPairingFailed, smpNotSupported}) }()
		}
	}
}

// connParams formats the interval, latency and supervision timeout fields
// that LE connection events carry, in their units (1.25 ms, events, 10 ms).
func connParams(b []byte) string {
	interval := float64(binary.LittleEndian.Uint16(b)) * 1.25
	latency := binary.LittleEndian.Uint16(b[2:])
	timeout := int(binary.LittleEndian.Uint16(b[4:])) * 10
	return fmt.Sprintf("interval %.2f ms, latency %d, supervision timeout %d ms", interval, latency, timeout)
}

// signal rejects every LE signalling request: no connection-oriented
// channels, and connection parameter updates are the central's business.
func (l *Link) signal(p []byte) {
	if len(p) < 4 {
		return
	}
	code, id := p[0], p[1]
	switch code {
	case sigCommandReject, sigDisconnectionRsp, sigConnParamRsp, sigLECreditConnRsp, sigCreditConnRsp:
		return
	}
	l.h.logf("rejecting L2CAP signalling request 0x%02x", code)
	rej := []byte{sigCommandReject, id, 2, 0, 0, 0}
	go func() { _ = l.h.sendL2CAP(l, cidLESignal, rej) }()
}

func (l *Link) drop(why string) {
	l.h.logf("dropping connection: %s", why)
	_ = l.Close()
}

// attHandler implementation.

func (l *Link) rxWrite(v []byte) {
	l.h.logf("rx fragment %s", fragInfo(v))
	l.conn.Deliver(v)
}

// fragInfo describes a frame fragment for the debug log: its sequence
// number, the record length, whether it starts a record, and its size.
func fragInfo(f []byte) string {
	if len(f) < frame.HeaderSize {
		return fmt.Sprintf("of %d bytes (short)", len(f))
	}
	start := ""
	if f[2]&frame.FlagStart != 0 {
		start = " start"
	}
	return fmt.Sprintf("seq %d%s, record %d bytes, %d bytes",
		binary.LittleEndian.Uint16(f[3:]), start, binary.LittleEndian.Uint16(f), len(f))
}

func (l *Link) subscribe(on bool) {
	l.mu.Lock()
	l.sub = on
	l.mu.Unlock()
	l.h.mu.Lock()
	l.h.cond.Broadcast()
	l.h.mu.Unlock()
}

func (l *Link) subscribed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sub
}

// SendFragment notifies one fragment on TX, waiting until the central has
// subscribed.
func (l *Link) SendFragment(frag []byte) error {
	l.h.mu.Lock()
	for !l.subscribed() && !l.h.closed && !l.isGone() {
		l.h.cond.Wait()
	}
	closed := l.h.closed || l.isGone()
	l.h.mu.Unlock()
	if closed {
		return frame.ErrClosed
	}
	if len(frag) > l.att.maxNotify() {
		return fmt.Errorf("ble: fragment of %d bytes exceeds notification size %d", len(frag), l.att.maxNotify())
	}
	l.h.logf("tx fragment %s", fragInfo(frag))
	return l.h.sendL2CAP(l, cidATT, l.att.notification(frag))
}

// MaxFragment is ATT_MTU - 3.
func (l *Link) MaxFragment() int { return l.att.maxNotify() }

// Close disconnects the central. It waits briefly for the controller to
// confirm, so advertising can resume cleanly.
func (l *Link) Close() error {
	l.mu.Lock()
	if l.gone {
		l.mu.Unlock()
		return nil
	}
	if l.gonech == nil {
		l.gonech = make(chan struct{})
	}
	ch := l.gonech
	l.mu.Unlock()
	go func() {
		_, _ = l.h.command(opDisconnect, []byte{byte(l.handle), byte(l.handle >> 8), reasonRemoteUser})
	}()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
	case <-l.h.done:
	}
	return nil
}

func (l *Link) lost(err error) {
	l.mu.Lock()
	if l.gone {
		l.mu.Unlock()
		return
	}
	l.gone = true
	if l.gonech == nil {
		l.gonech = make(chan struct{})
	}
	close(l.gonech)
	l.mu.Unlock()
	l.h.mu.Lock()
	l.h.cond.Broadcast()
	l.h.mu.Unlock()
	if l.conn != nil {
		l.conn.LinkLost(err)
	}
}
