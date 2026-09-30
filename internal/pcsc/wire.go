// Package pcsc is a pure-Go client for the pcsc-lite daemon (pcscd).
//
// It speaks pcscd's Unix-socket protocol directly, the protocol libpcsclite
// implements, so tpm2-kira can talk to smart cards without cgo.
//
// Every wire structure lives in this file. Each one mirrors a C struct from
// pcsc-lite 2.5.2 (src/winscard_msg.h and src/readers.h), cited per type.
// All of them consist of 4-byte integers and byte arrays whose sizes are
// multiples of 4, apart from the ATR in readerState, so their layout is the
// same on 32- and 64-bit builds. Integers are in host byte order (see ne).
package pcsc

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

// Protocol versions, from winscard_msg.h. pcscd accepts clients from
// protocolMinorMin up to its own minor; the only difference that matters
// here is how the reader state array is fetched (see Client.readerStates).
const (
	protocolMajor    = 4
	protocolMinor    = 6
	protocolMinorMin = 4
)

// Commands, from enum pcsc_msg_commands in winscard_msg.h.
const (
	cmdEstablishContext     uint32 = 0x01
	cmdReleaseContext       uint32 = 0x02
	cmdConnect              uint32 = 0x04
	cmdDisconnect           uint32 = 0x06
	cmdBeginTransaction     uint32 = 0x07
	cmdEndTransaction       uint32 = 0x08
	cmdTransmit             uint32 = 0x09
	cmdVersion              uint32 = 0x11
	cmdGetReadersState      uint32 = 0x12
	cmdGetReadersStateSize  uint32 = 0x16
	cmdGetReadersStateArray uint32 = 0x17
)

// Constants from PCSC/pcsclite.h.
const (
	maxReaderName = 128
	maxATRSize    = 33

	// maxReadersContexts is the fixed reader array length used by protocol
	// 4:5 and earlier (PCSCLITE_MAX_READERS_CONTEXTS).
	maxReadersContexts = 16

	// maxBufferSizeExtended bounds one APDU in either direction
	// (MAX_BUFFER_SIZE_EXTENDED).
	maxBufferSizeExtended = 4 + 3 + (1 << 16) + 3 + 2

	scopeSystem = 0x0002

	ProtocolT0  = 0x0001
	ProtocolT1  = 0x0002
	protocolAny = ProtocolT0 | ProtocolT1

	shareShared = 0x0002
	leaveCard   = 0x0000
	resetCard   = 0x0001

	statePresent = 0x0004
)

// Return codes worth naming, from PCSC/pcsclite.h.
const (
	scardSuccess           uint32 = 0x00000000
	scardEServiceStopped   uint32 = 0x8010001E
	scardENoSmartcard      uint32 = 0x8010000C
	scardESharingViolation uint32 = 0x8010000B
	scardERemovedCard      uint32 = 0x80100069
	scardEResetCard        uint32 = 0x80100068
)

// ioRequestSize is sizeof(SCARD_IO_REQUEST): two C unsigned longs.
const ioRequestSize = 2 * bits.UintSize / 8

// Error is a non-success return code from pcscd.
type Error uint32

func (e Error) Error() string {
	if name, ok := errorNames[uint32(e)]; ok {
		return fmt.Sprintf("pcscd: %s (0x%08X)", name, uint32(e))
	}
	return fmt.Sprintf("pcscd: error 0x%08X", uint32(e))
}

var errorNames = map[uint32]string{
	0x80100001: "internal error",
	0x80100003: "invalid handle",
	0x80100004: "invalid parameter",
	0x80100008: "insufficient buffer",
	0x80100009: "unknown reader",
	0x8010000A: "timeout",
	0x8010000B: "sharing violation",
	0x8010000C: "no smart card",
	0x8010000F: "protocol mismatch",
	0x80100016: "not transacted",
	0x80100017: "reader unavailable",
	0x8010001D: "no service",
	0x8010001E: "service stopped",
	0x8010002E: "no readers available",
	0x80100066: "card unresponsive",
	0x80100067: "card unpowered",
	0x80100068: "card was reset",
	0x80100069: "card was removed",
}

func rvError(rv uint32) error {
	if rv == scardSuccess {
		return nil
	}
	return Error(rv)
}

// header mirrors struct rxHeader. Sent before every client request; pcscd's
// replies carry no header.
type header struct {
	Size    uint32
	Command uint32
}

const headerSize = 8

func (h header) encode() []byte {
	b := make([]byte, headerSize)
	ne.PutUint32(b[0:], h.Size)
	ne.PutUint32(b[4:], h.Command)
	return b
}

// ne is host byte order: pcscd writes its C structs to the socket as they
// are laid out in memory.
var ne = binary.NativeEndian

// versionMsg mirrors struct version_struct.
type versionMsg struct {
	Major int32
	Minor int32
	RV    uint32
}

const versionMsgSize = 12

func (m versionMsg) encode() []byte {
	b := make([]byte, versionMsgSize)
	ne.PutUint32(b[0:], uint32(m.Major))
	ne.PutUint32(b[4:], uint32(m.Minor))
	ne.PutUint32(b[8:], m.RV)
	return b
}

func decodeVersionMsg(b []byte) versionMsg {
	return versionMsg{
		Major: int32(ne.Uint32(b[0:])),
		Minor: int32(ne.Uint32(b[4:])),
		RV:    ne.Uint32(b[8:]),
	}
}

// establishMsg mirrors struct establish_struct.
type establishMsg struct {
	Scope   uint32
	Context uint32
	RV      uint32
}

const establishMsgSize = 12

func (m establishMsg) encode() []byte {
	b := make([]byte, establishMsgSize)
	ne.PutUint32(b[0:], m.Scope)
	ne.PutUint32(b[4:], m.Context)
	ne.PutUint32(b[8:], m.RV)
	return b
}

func decodeEstablishMsg(b []byte) establishMsg {
	return establishMsg{Scope: ne.Uint32(b[0:]), Context: ne.Uint32(b[4:]), RV: ne.Uint32(b[8:])}
}

// releaseMsg mirrors struct release_struct.
type releaseMsg struct {
	Context uint32
	RV      uint32
}

const releaseMsgSize = 8

func (m releaseMsg) encode() []byte {
	b := make([]byte, releaseMsgSize)
	ne.PutUint32(b[0:], m.Context)
	ne.PutUint32(b[4:], m.RV)
	return b
}

func decodeReleaseMsg(b []byte) releaseMsg {
	return releaseMsg{Context: ne.Uint32(b[0:]), RV: ne.Uint32(b[4:])}
}

// connectMsg mirrors struct connect_struct.
type connectMsg struct {
	Context            uint32
	Reader             string // NUL-padded to maxReaderName
	ShareMode          uint32
	PreferredProtocols uint32
	Card               int32
	ActiveProtocol     uint32
	RV                 uint32
}

const connectMsgSize = 4 + maxReaderName + 5*4

func (m connectMsg) encode() ([]byte, error) {
	if len(m.Reader) >= maxReaderName {
		return nil, fmt.Errorf("reader name %q is too long", m.Reader)
	}
	b := make([]byte, connectMsgSize)
	ne.PutUint32(b[0:], m.Context)
	copy(b[4:4+maxReaderName], m.Reader)
	o := 4 + maxReaderName
	ne.PutUint32(b[o:], m.ShareMode)
	ne.PutUint32(b[o+4:], m.PreferredProtocols)
	ne.PutUint32(b[o+8:], uint32(m.Card))
	ne.PutUint32(b[o+12:], m.ActiveProtocol)
	ne.PutUint32(b[o+16:], m.RV)
	return b, nil
}

func decodeConnectMsg(b []byte) connectMsg {
	o := 4 + maxReaderName
	return connectMsg{
		Context:            ne.Uint32(b[0:]),
		Reader:             cString(b[4 : 4+maxReaderName]),
		ShareMode:          ne.Uint32(b[o:]),
		PreferredProtocols: ne.Uint32(b[o+4:]),
		Card:               int32(ne.Uint32(b[o+8:])),
		ActiveProtocol:     ne.Uint32(b[o+12:]),
		RV:                 ne.Uint32(b[o+16:]),
	}
}

// disconnectMsg mirrors struct disconnect_struct, and endMsg mirrors
// struct end_struct, which has the same layout.
type disconnectMsg struct {
	Card        int32
	Disposition uint32
	RV          uint32
}

const disconnectMsgSize = 12

func (m disconnectMsg) encode() []byte {
	b := make([]byte, disconnectMsgSize)
	ne.PutUint32(b[0:], uint32(m.Card))
	ne.PutUint32(b[4:], m.Disposition)
	ne.PutUint32(b[8:], m.RV)
	return b
}

func decodeDisconnectMsg(b []byte) disconnectMsg {
	return disconnectMsg{Card: int32(ne.Uint32(b[0:])), Disposition: ne.Uint32(b[4:]), RV: ne.Uint32(b[8:])}
}

// beginMsg mirrors struct begin_struct.
type beginMsg struct {
	Card int32
	RV   uint32
}

const beginMsgSize = 8

func (m beginMsg) encode() []byte {
	b := make([]byte, beginMsgSize)
	ne.PutUint32(b[0:], uint32(m.Card))
	ne.PutUint32(b[4:], m.RV)
	return b
}

func decodeBeginMsg(b []byte) beginMsg {
	return beginMsg{Card: int32(ne.Uint32(b[0:])), RV: ne.Uint32(b[4:])}
}

// transmitMsg mirrors struct transmit_struct. The APDU follows it on the
// socket as a separate write; the response APDU follows pcscd's reply.
type transmitMsg struct {
	Card            int32
	SendPCIProtocol uint32
	SendPCILength   uint32
	SendLength      uint32
	RecvPCIProtocol uint32
	RecvPCILength   uint32
	RecvLength      uint32
	RV              uint32
}

const transmitMsgSize = 32

func (m transmitMsg) encode() []byte {
	b := make([]byte, transmitMsgSize)
	ne.PutUint32(b[0:], uint32(m.Card))
	ne.PutUint32(b[4:], m.SendPCIProtocol)
	ne.PutUint32(b[8:], m.SendPCILength)
	ne.PutUint32(b[12:], m.SendLength)
	ne.PutUint32(b[16:], m.RecvPCIProtocol)
	ne.PutUint32(b[20:], m.RecvPCILength)
	ne.PutUint32(b[24:], m.RecvLength)
	ne.PutUint32(b[28:], m.RV)
	return b
}

func decodeTransmitMsg(b []byte) transmitMsg {
	return transmitMsg{
		Card:            int32(ne.Uint32(b[0:])),
		SendPCIProtocol: ne.Uint32(b[4:]),
		SendPCILength:   ne.Uint32(b[8:]),
		SendLength:      ne.Uint32(b[12:]),
		RecvPCIProtocol: ne.Uint32(b[16:]),
		RecvPCILength:   ne.Uint32(b[20:]),
		RecvLength:      ne.Uint32(b[24:]),
		RV:              ne.Uint32(b[28:]),
	}
}

// readerState mirrors struct pubReaderState (READER_STATE) in src/readers.h.
//
//	offset  size  field
//	     0   128  readerName
//	   128     4  eventCounter
//	   132     4  readerState
//	   136     4  readerSharing
//	   140    33  cardAtr
//	   173     3  (padding to align cardAtrLength)
//	   176     4  cardAtrLength
//	   180     4  cardProtocol
type readerState struct {
	Name         string
	EventCounter uint32
	State        uint32
	Sharing      int32
	ATR          []byte
	Protocol     uint32
}

const readerStateSize = 184

func decodeReaderState(b []byte) readerState {
	atrLen := ne.Uint32(b[176:])
	if atrLen > maxATRSize {
		atrLen = 0
	}
	return readerState{
		Name:         cString(b[0:maxReaderName]),
		EventCounter: ne.Uint32(b[128:]),
		State:        ne.Uint32(b[132:]),
		Sharing:      int32(ne.Uint32(b[136:])),
		ATR:          append([]byte(nil), b[140:140+atrLen]...),
		Protocol:     ne.Uint32(b[180:]),
	}
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
