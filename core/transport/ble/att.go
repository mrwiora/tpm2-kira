package ble

import (
	"bytes"
	"encoding/binary"
)

// ATT opcodes (Core spec Vol 3 Part F §3.4).
const (
	attErrorRsp          = 0x01
	attExchangeMTUReq    = 0x02
	attExchangeMTURsp    = 0x03
	attFindInfoReq       = 0x04
	attFindInfoRsp       = 0x05
	attFindByTypeReq     = 0x06
	attFindByTypeRsp     = 0x07
	attReadByTypeReq     = 0x08
	attReadByTypeRsp     = 0x09
	attReadReq           = 0x0A
	attReadRsp           = 0x0B
	attReadBlobReq       = 0x0C
	attReadBlobRsp       = 0x0D
	attReadByGroupReq    = 0x10
	attReadByGroupRsp    = 0x11
	attWriteReq          = 0x12
	attWriteRsp          = 0x13
	attNotify            = 0x1B
	attHandleValueConfrm = 0x1E
	attWriteCmd          = 0x52
	attCommandFlag       = 0x40
)

// ATT error codes.
const (
	attErrInvalidHandle    = 0x01
	attErrReadNotPermitted = 0x02
	attErrWriteNotPermit   = 0x03
	attErrInvalidPDU       = 0x04
	attErrReqNotSupported  = 0x06
	attErrInvalidOffset    = 0x07
	attErrAttrNotFound     = 0x0A
	attErrInvalidLength    = 0x0D
	attErrUnsupportedGroup = 0x10
)

// Characteristic properties.
const (
	propRead        = 0x02
	propWriteNoResp = 0x04
	propWrite       = 0x08
	propNotify      = 0x10
	defaultATTMTU   = 23
	// maxATTMTU is the largest ATT_MTU this server agrees to. 247 makes one
	// ATT PDU plus its 4-byte L2CAP header exactly one 251-byte LE data
	// packet, so no notification relies on the controller or the phone
	// reassembling L2CAP fragments; controllers in the field differ in how
	// well they do that. Larger records go out as more fragments instead.
	maxATTMTU        = 247
	maxAttrValueSize = 512
)

// attribute is one row of the GATT database.
type attribute struct {
	handle   uint16
	typ      []byte // 2 or 16 bytes, little-endian
	value    []byte // static value; nil for dynamic attributes
	readable bool
	writable bool
	groupEnd uint16 // for service declarations
}

func uuid16(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }

// gattDB is the fixed database for the tpm2-kira service.
type gattDB struct {
	attrs                         []*attribute
	rxHandle, txHandle, cccHandle uint16
	infoHandle                    uint16
}

func newGATTDB(deviceName string, info []byte) *gattDB {
	db := &gattDB{}
	add := func(a *attribute) *attribute {
		a.handle = uint16(len(db.attrs) + 1)
		db.attrs = append(db.attrs, a)
		return a
	}
	charDecl := func(props byte, valueHandle uint16, uuid []byte) {
		v := []byte{props, byte(valueHandle), byte(valueHandle >> 8)}
		add(&attribute{typ: uuid16(uuidCharacteristic), value: append(v, uuid...), readable: true})
	}

	// Generic Access service (mandatory).
	gap := add(&attribute{typ: uuid16(uuidPrimaryService), value: uuid16(uuidGAPService), readable: true})
	charDecl(propRead, 3, uuid16(uuidDeviceName))
	add(&attribute{typ: uuid16(uuidDeviceName), value: []byte(deviceName), readable: true})
	charDecl(propRead, 5, uuid16(uuidAppearance))
	add(&attribute{typ: uuid16(uuidAppearance), value: []byte{0, 0}, readable: true})
	gap.groupEnd = uint16(len(db.attrs))

	// tpm2-kira service.
	svc := add(&attribute{typ: uuid16(uuidPrimaryService), value: ServiceUUID.LE(), readable: true})
	next := uint16(len(db.attrs) + 2)
	charDecl(propWriteNoResp|propWrite, next, RXCharUUID.LE())
	db.rxHandle = add(&attribute{typ: RXCharUUID.LE(), writable: true}).handle
	next = uint16(len(db.attrs) + 2)
	charDecl(propNotify, next, TXCharUUID.LE())
	db.txHandle = add(&attribute{typ: TXCharUUID.LE()}).handle
	db.cccHandle = add(&attribute{typ: uuid16(uuidCCCD), readable: true, writable: true}).handle
	next = uint16(len(db.attrs) + 2)
	charDecl(propRead, next, InfoUUID.LE())
	db.infoHandle = add(&attribute{typ: InfoUUID.LE(), value: info, readable: true}).handle
	svc.groupEnd = uint16(len(db.attrs))
	return db
}

func (db *gattDB) get(h uint16) *attribute {
	if h == 0 || int(h) > len(db.attrs) {
		return nil
	}
	return db.attrs[h-1]
}

// attHandler receives what the ATT server cannot answer from the database.
type attHandler interface {
	rxWrite(value []byte)
	subscribe(on bool)
	subscribed() bool
}

// attServer is the per-connection ATT state.
type attServer struct {
	db  *gattDB
	h   attHandler
	mtu int
}

func newATTServer(db *gattDB, h attHandler) *attServer {
	return &attServer{db: db, h: h, mtu: defaultATTMTU}
}

func attError(req byte, handle uint16, code byte) []byte {
	return []byte{attErrorRsp, req, byte(handle), byte(handle >> 8), code}
}

// handle processes one ATT PDU and returns the response, or nil.
func (s *attServer) handle(pdu []byte) []byte {
	if len(pdu) == 0 {
		return nil
	}
	op := pdu[0]
	switch op {
	case attExchangeMTUReq:
		if len(pdu) != 3 {
			return attError(op, 0, attErrInvalidPDU)
		}
		client := int(binary.LittleEndian.Uint16(pdu[1:]))
		m := client
		if m > maxATTMTU {
			m = maxATTMTU
		}
		if m < defaultATTMTU {
			m = defaultATTMTU
		}
		s.mtu = m
		return []byte{attExchangeMTURsp, byte(maxATTMTU & 0xff), byte(maxATTMTU >> 8)}

	case attFindInfoReq:
		start, end, ok := rangeOf(pdu, 5)
		if !ok {
			return attError(op, 0, attErrInvalidHandle)
		}
		return s.findInfo(start, end)

	case attFindByTypeReq:
		if len(pdu) < 7 {
			return attError(op, 0, attErrInvalidPDU)
		}
		start, end, ok := rangeOf(pdu, 7)
		if !ok {
			return attError(op, start, attErrInvalidHandle)
		}
		typ := pdu[5:7]
		val := pdu[7:]
		out := []byte{attFindByTypeRsp}
		for _, a := range s.db.attrs {
			if a.handle < start || a.handle > end {
				continue
			}
			if bytes.Equal(a.typ, typ) && bytes.Equal(typ, uuid16(uuidPrimaryService)) && bytes.Equal(a.value, val) {
				if len(out)+4 > s.mtu {
					break
				}
				out = append(out, byte(a.handle), byte(a.handle>>8), byte(a.groupEnd), byte(a.groupEnd>>8))
			}
		}
		if len(out) == 1 {
			return attError(op, start, attErrAttrNotFound)
		}
		return out

	case attReadByTypeReq:
		start, end, ok := rangeOf(pdu, 7)
		if !ok || (len(pdu) != 7 && len(pdu) != 21) {
			return attError(op, start, attErrInvalidHandle)
		}
		return s.readByType(start, end, pdu[5:])

	case attReadByGroupReq:
		start, end, ok := rangeOf(pdu, 7)
		if !ok || (len(pdu) != 7 && len(pdu) != 21) {
			return attError(op, start, attErrInvalidHandle)
		}
		if !bytes.Equal(pdu[5:], uuid16(uuidPrimaryService)) {
			return attError(op, start, attErrUnsupportedGroup)
		}
		return s.readByGroup(start, end)

	case attReadReq, attReadBlobReq:
		if (op == attReadReq && len(pdu) != 3) || (op == attReadBlobReq && len(pdu) != 5) {
			return attError(op, 0, attErrInvalidPDU)
		}
		h := binary.LittleEndian.Uint16(pdu[1:])
		a := s.db.get(h)
		if a == nil {
			return attError(op, h, attErrInvalidHandle)
		}
		if !a.readable {
			return attError(op, h, attErrReadNotPermitted)
		}
		v := s.value(a)
		off := 0
		if op == attReadBlobReq {
			off = int(binary.LittleEndian.Uint16(pdu[3:]))
			if off > len(v) {
				return attError(op, h, attErrInvalidOffset)
			}
		}
		v = v[off:]
		if len(v) > s.mtu-1 {
			v = v[:s.mtu-1]
		}
		rsp := attReadRsp
		if op == attReadBlobReq {
			rsp = attReadBlobRsp
		}
		return append([]byte{byte(rsp)}, v...)

	case attWriteReq, attWriteCmd:
		if len(pdu) < 3 {
			if op == attWriteCmd {
				return nil
			}
			return attError(op, 0, attErrInvalidPDU)
		}
		h := binary.LittleEndian.Uint16(pdu[1:])
		val := pdu[3:]
		code := s.write(h, val)
		if op == attWriteCmd {
			return nil // commands are never answered, not even with errors
		}
		if code != 0 {
			return attError(op, h, code)
		}
		return []byte{attWriteRsp}

	case attHandleValueConfrm:
		return nil
	}
	if op&attCommandFlag != 0 {
		return nil
	}
	return attError(op, 0, attErrReqNotSupported)
}

func rangeOf(pdu []byte, minLen int) (uint16, uint16, bool) {
	if len(pdu) < minLen || len(pdu) < 5 {
		return 0, 0, false
	}
	start := binary.LittleEndian.Uint16(pdu[1:])
	end := binary.LittleEndian.Uint16(pdu[3:])
	return start, end, start != 0 && start <= end
}

func (s *attServer) value(a *attribute) []byte {
	if a.handle == s.db.cccHandle {
		if s.h.subscribed() {
			return []byte{1, 0}
		}
		return []byte{0, 0}
	}
	return a.value
}

func (s *attServer) write(h uint16, val []byte) byte {
	a := s.db.get(h)
	if a == nil {
		return attErrInvalidHandle
	}
	if !a.writable {
		return attErrWriteNotPermit
	}
	switch h {
	case s.db.cccHandle:
		if len(val) != 2 {
			return attErrInvalidLength
		}
		s.h.subscribe(val[0]&0x01 != 0)
	case s.db.rxHandle:
		if len(val) == 0 || len(val) > maxAttrValueSize {
			return attErrInvalidLength
		}
		s.h.rxWrite(append([]byte(nil), val...))
	}
	return 0
}

func (s *attServer) findInfo(start, end uint16) []byte {
	var out []byte
	format := byte(0)
	for _, a := range s.db.attrs {
		if a.handle < start || a.handle > end {
			continue
		}
		f := byte(1)
		if len(a.typ) == 16 {
			f = 2
		}
		if format == 0 {
			format = f
			out = []byte{attFindInfoRsp, format}
		} else if f != format {
			break
		}
		if len(out)+2+len(a.typ) > s.mtu {
			break
		}
		out = append(out, byte(a.handle), byte(a.handle>>8))
		out = append(out, a.typ...)
	}
	if out == nil {
		return attError(attFindInfoReq, start, attErrAttrNotFound)
	}
	return out
}

func (s *attServer) readByType(start, end uint16, typ []byte) []byte {
	var out []byte
	size := 0
	for _, a := range s.db.attrs {
		if a.handle < start || a.handle > end || !bytes.Equal(a.typ, typ) {
			continue
		}
		if !a.readable {
			if out == nil {
				return attError(attReadByTypeReq, a.handle, attErrReadNotPermitted)
			}
			break
		}
		v := s.value(a)
		if max := s.mtu - 4; len(v) > max {
			v = v[:max]
		}
		if max := 253; len(v) > max {
			v = v[:max]
		}
		entry := 2 + len(v)
		if out == nil {
			size = entry
			out = []byte{attReadByTypeRsp, byte(size)}
		} else if entry != size {
			break
		}
		if len(out)+entry > s.mtu {
			break
		}
		out = append(out, byte(a.handle), byte(a.handle>>8))
		out = append(out, v...)
	}
	if out == nil {
		return attError(attReadByTypeReq, start, attErrAttrNotFound)
	}
	return out
}

func (s *attServer) readByGroup(start, end uint16) []byte {
	var out []byte
	size := 0
	for _, a := range s.db.attrs {
		if a.handle < start || a.handle > end || !bytes.Equal(a.typ, uuid16(uuidPrimaryService)) {
			continue
		}
		entry := 4 + len(a.value)
		if out == nil {
			size = entry
			out = []byte{attReadByGroupRsp, byte(size)}
		} else if entry != size {
			break
		}
		if len(out)+entry > s.mtu {
			break
		}
		out = append(out, byte(a.handle), byte(a.handle>>8), byte(a.groupEnd), byte(a.groupEnd>>8))
		out = append(out, a.value...)
	}
	if out == nil {
		return attError(attReadByGroupReq, start, attErrAttrNotFound)
	}
	return out
}

// notification builds a Handle Value Notification for the TX characteristic.
func (s *attServer) notification(value []byte) []byte {
	out := []byte{attNotify, byte(s.db.txHandle), byte(s.db.txHandle >> 8)}
	return append(out, value...)
}

// maxNotify is the largest notification value at the current MTU.
func (s *attServer) maxNotify() int { return s.mtu - 3 }
