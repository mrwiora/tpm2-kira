package attest

import (
	"encoding/binary"
	"fmt"
)

// Canonical TLV encoding shared by every peer (attester, phone, server).
//
//	Message := u8 type ‖ u8 version(=1) ‖ Field*
//	Field   := u16le tag ‖ u32le len ‖ value[len]
//
// Encoding rules, each enforced by the decoder:
//
//   - tags appear in strictly ascending order, so there is exactly one
//     encoding of a given message and no duplicate fields;
//   - integers inside a value are little-endian and fixed width, as in
//     cmd/blob.go;
//   - unknown tags are skipped, so a newer peer may add optional fields
//     without a version bump; a field the reader requires is never unknown;
//   - every variable-length field has an explicit maximum, checked before
//     anything is allocated.
//
// Nothing is ever signed via this encoding: signatures cover the separate,
// domain-separated byte strings in canon.go.

// WireVersion is the value of the second byte of every message.
const WireVersion = 1

// MaxMessageSize bounds a single decoded protocol message. A Noise transport
// message carries at most 65535 bytes of ciphertext including a 16-byte tag,
// and the record layer adds one byte, so this leaves comfortable headroom.
const MaxMessageSize = 65000

// MsgType identifies a protocol message.
type MsgType uint8

// Message types. Attestation: 0x01-0x1F. Enrolment: 0x20-0x3F. Control: 0x7E-0x7F.
const (
	MsgHello           MsgType = 0x01 // attester -> verifier
	MsgRequest         MsgType = 0x02 // verifier -> attester
	MsgEvidence        MsgType = 0x03 // attester -> verifier
	MsgEventlogRequest MsgType = 0x04 // verifier -> attester
	MsgEventlogChunk   MsgType = 0x05 // attester -> verifier
	MsgReceipt         MsgType = 0x06 // verifier -> attester
	MsgRelease         MsgType = 0x07 // verifier -> attester
	MsgReceiptAck      MsgType = 0x08 // attester -> verifier
	MsgReleaseAck      MsgType = 0x09 // attester -> verifier

	MsgSASCommit         MsgType = 0x20 // attester -> verifier
	MsgSASNonce          MsgType = 0x21 // verifier -> attester
	MsgSASReveal         MsgType = 0x22 // attester -> verifier
	MsgSASConfirm        MsgType = 0x23 // verifier -> attester
	MsgEnrolOffer        MsgType = 0x24 // attester -> verifier
	MsgChallenge         MsgType = 0x25 // verifier -> attester
	MsgChallengeResponse MsgType = 0x26 // attester -> verifier
	MsgEnrolAccept       MsgType = 0x27 // verifier -> attester
	MsgEnrolConfirm      MsgType = 0x28 // attester -> verifier

	MsgBye   MsgType = 0x7E // either direction: orderly end of session
	MsgError MsgType = 0x7F // either direction: abort with a reason
)

func (t MsgType) String() string {
	switch t {
	case MsgHello:
		return "Hello"
	case MsgRequest:
		return "Request"
	case MsgEvidence:
		return "Evidence"
	case MsgEventlogRequest:
		return "EventlogRequest"
	case MsgEventlogChunk:
		return "EventlogChunk"
	case MsgReceipt:
		return "Receipt"
	case MsgRelease:
		return "Release"
	case MsgReceiptAck:
		return "ReceiptAck"
	case MsgReleaseAck:
		return "ReleaseAck"
	case MsgSASCommit:
		return "SASCommit"
	case MsgSASNonce:
		return "SASNonce"
	case MsgSASReveal:
		return "SASReveal"
	case MsgSASConfirm:
		return "SASConfirm"
	case MsgEnrolOffer:
		return "EnrolOffer"
	case MsgChallenge:
		return "Challenge"
	case MsgChallengeResponse:
		return "ChallengeResponse"
	case MsgEnrolAccept:
		return "EnrolAccept"
	case MsgEnrolConfirm:
		return "EnrolConfirm"
	case MsgBye:
		return "Bye"
	case MsgError:
		return "Error"
	default:
		return fmt.Sprintf("MsgType(0x%02x)", uint8(t))
	}
}

// Encoder builds one message. Fields must be added in ascending tag order;
// adding them out of order is a programming error and panics, because the
// result would be rejected by every decoder.
type Encoder struct {
	buf     []byte
	lastTag int
}

// NewEncoder starts a message of the given type.
func NewEncoder(t MsgType) *Encoder {
	return &Encoder{buf: []byte{byte(t), WireVersion}, lastTag: -1}
}

func (e *Encoder) field(tag uint16, value []byte) {
	if int(tag) <= e.lastTag {
		panic(fmt.Sprintf("attest: field tag %d added after tag %d", tag, e.lastTag))
	}
	e.lastTag = int(tag)
	var hdr [6]byte
	binary.LittleEndian.PutUint16(hdr[0:], tag)
	binary.LittleEndian.PutUint32(hdr[2:], uint32(len(value)))
	e.buf = append(e.buf, hdr[:]...)
	e.buf = append(e.buf, value...)
}

// Bytes adds a byte-string field. A nil or empty value is still encoded, as
// a zero-length field; use OptBytes to omit it.
func (e *Encoder) Bytes(tag uint16, v []byte) { e.field(tag, v) }

// OptBytes adds a byte-string field only when it is non-empty.
func (e *Encoder) OptBytes(tag uint16, v []byte) {
	if len(v) > 0 {
		e.field(tag, v)
	}
}

// String adds a UTF-8 string field.
func (e *Encoder) String(tag uint16, v string) { e.field(tag, []byte(v)) }

// U8 adds a one-byte integer field.
func (e *Encoder) U8(tag uint16, v uint8) { e.field(tag, []byte{v}) }

// Bool adds a boolean field encoded as one byte, 0 or 1.
func (e *Encoder) Bool(tag uint16, v bool) {
	if v {
		e.U8(tag, 1)
	} else {
		e.U8(tag, 0)
	}
}

// U16 adds a two-byte little-endian integer field.
func (e *Encoder) U16(tag uint16, v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	e.field(tag, b[:])
}

// U32 adds a four-byte little-endian integer field.
func (e *Encoder) U32(tag uint16, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	e.field(tag, b[:])
}

// U64 adds an eight-byte little-endian integer field.
func (e *Encoder) U64(tag uint16, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	e.field(tag, b[:])
}

// Finish returns the encoded message.
func (e *Encoder) Finish() ([]byte, error) {
	if len(e.buf) > MaxMessageSize {
		return nil, fmt.Errorf("attest: encoded message is %d bytes, exceeds %d", len(e.buf), MaxMessageSize)
	}
	return e.buf, nil
}

// Decoder reads the fields of one message. Getters record the first error
// and return zero values afterwards, so a message is decoded field by field
// and checked once with Err.
type Decoder struct {
	Type   MsgType
	fields map[uint16][]byte
	err    error
}

// Decode parses the message envelope and validates the field layout. The
// returned decoder borrows from data; callers must copy anything they keep
// (the typed getters already do).
func Decode(data []byte) (*Decoder, error) {
	if len(data) > MaxMessageSize {
		return nil, fmt.Errorf("attest: message is %d bytes, exceeds %d", len(data), MaxMessageSize)
	}
	if len(data) < 2 {
		return nil, fmt.Errorf("attest: message too short")
	}
	if data[1] != WireVersion {
		return nil, fmt.Errorf("attest: unsupported wire version %d", data[1])
	}
	d := &Decoder{Type: MsgType(data[0]), fields: make(map[uint16][]byte)}
	off := 2
	last := -1
	for off < len(data) {
		if len(data)-off < 6 {
			return nil, fmt.Errorf("attest: truncated field header at offset %d", off)
		}
		tag := binary.LittleEndian.Uint16(data[off:])
		n := binary.LittleEndian.Uint32(data[off+2:])
		off += 6
		if int(tag) <= last {
			return nil, fmt.Errorf("attest: field tag %d out of order or duplicated", tag)
		}
		last = int(tag)
		if uint64(n) > uint64(len(data)-off) {
			return nil, fmt.Errorf("attest: field %d declares %d bytes, only %d remain", tag, n, len(data)-off)
		}
		d.fields[tag] = data[off : off+int(n)]
		off += int(n)
	}
	return d, nil
}

// Expect checks the message type.
func (d *Decoder) Expect(t MsgType) error {
	if d.Type != t {
		return fmt.Errorf("attest: expected %s, got %s", t, d.Type)
	}
	return nil
}

// Err returns the first error recorded by a getter.
func (d *Decoder) Err() error { return d.err }

func (d *Decoder) fail(format string, args ...any) {
	if d.err == nil {
		d.err = fmt.Errorf("attest: %s: "+format, append([]any{d.Type}, args...)...)
	}
}

func (d *Decoder) raw(tag uint16, required bool) ([]byte, bool) {
	if d.err != nil {
		return nil, false
	}
	v, ok := d.fields[tag]
	if !ok && required {
		d.fail("missing required field %d", tag)
	}
	return v, ok
}

// Bytes returns a copy of a byte-string field. A required field that is
// absent, or any field longer than max, records an error.
func (d *Decoder) Bytes(tag uint16, max int, required bool) []byte {
	v, ok := d.raw(tag, required)
	if !ok {
		return nil
	}
	if len(v) > max {
		d.fail("field %d is %d bytes, maximum is %d", tag, len(v), max)
		return nil
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out
}

// Fixed returns a copy of a byte-string field that must be exactly n bytes.
func (d *Decoder) Fixed(tag uint16, n int, required bool) []byte {
	v, ok := d.raw(tag, required)
	if !ok {
		return nil
	}
	if len(v) != n {
		d.fail("field %d is %d bytes, must be %d", tag, len(v), n)
		return nil
	}
	out := make([]byte, n)
	copy(out, v)
	return out
}

// String returns a string field.
func (d *Decoder) String(tag uint16, max int, required bool) string {
	return string(d.Bytes(tag, max, required))
}

func (d *Decoder) intField(tag uint16, size int, required bool) ([]byte, bool) {
	v, ok := d.raw(tag, required)
	if !ok {
		return nil, false
	}
	if len(v) != size {
		d.fail("integer field %d is %d bytes, must be %d", tag, len(v), size)
		return nil, false
	}
	return v, true
}

// U8 returns a one-byte integer field.
func (d *Decoder) U8(tag uint16, required bool) uint8 {
	v, ok := d.intField(tag, 1, required)
	if !ok {
		return 0
	}
	return v[0]
}

// Bool returns a boolean field. Values other than 0 and 1 are rejected so
// the encoding stays canonical.
func (d *Decoder) Bool(tag uint16, required bool) bool {
	v := d.U8(tag, required)
	if v > 1 {
		d.fail("boolean field %d has value %d", tag, v)
		return false
	}
	return v == 1
}

// U16 returns a two-byte integer field.
func (d *Decoder) U16(tag uint16, required bool) uint16 {
	v, ok := d.intField(tag, 2, required)
	if !ok {
		return 0
	}
	return binary.LittleEndian.Uint16(v)
}

// U32 returns a four-byte integer field.
func (d *Decoder) U32(tag uint16, required bool) uint32 {
	v, ok := d.intField(tag, 4, required)
	if !ok {
		return 0
	}
	return binary.LittleEndian.Uint32(v)
}

// U64 returns an eight-byte integer field.
func (d *Decoder) U64(tag uint16, required bool) uint64 {
	v, ok := d.intField(tag, 8, required)
	if !ok {
		return 0
	}
	return binary.LittleEndian.Uint64(v)
}

// Sub decodes a nested structure carried as a byte-string field. Nested
// structures use the same field layout without the two-byte message header.
func (d *Decoder) Sub(tag uint16, max int, required bool) *Decoder {
	v, ok := d.raw(tag, required)
	if !ok {
		return nil
	}
	if len(v) > max {
		d.fail("field %d is %d bytes, maximum is %d", tag, len(v), max)
		return nil
	}
	sub, err := Decode(append([]byte{byte(d.Type), WireVersion}, v...))
	if err != nil {
		d.fail("field %d: %v", tag, err)
		return nil
	}
	return sub
}

// SubEncoder builds a nested structure for Encoder.Sub.
func SubEncoder() *Encoder { return &Encoder{lastTag: -1} }

// Sub adds a nested structure built with SubEncoder.
func (e *Encoder) Sub(tag uint16, sub *Encoder) { e.field(tag, sub.buf) }

// List helpers: a list is a byte-string field holding u16le count followed
// by count entries of u32le length ‖ entry. They are used for repeated
// nested structures (PCR values, profiles).

// EncodeList packs entries into a list value.
func EncodeList(entries [][]byte) []byte {
	out := make([]byte, 2, 2+len(entries)*8)
	binary.LittleEndian.PutUint16(out, uint16(len(entries)))
	for _, e := range entries {
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(e)))
		out = append(out, l[:]...)
		out = append(out, e...)
	}
	return out
}

// DecodeList unpacks a list value, enforcing a maximum entry count and entry size.
func DecodeList(v []byte, maxEntries, maxEntry int) ([][]byte, error) {
	if len(v) < 2 {
		return nil, fmt.Errorf("attest: list too short")
	}
	n := int(binary.LittleEndian.Uint16(v))
	if n > maxEntries {
		return nil, fmt.Errorf("attest: list has %d entries, maximum is %d", n, maxEntries)
	}
	off := 2
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		if len(v)-off < 4 {
			return nil, fmt.Errorf("attest: list entry %d truncated", i)
		}
		l := binary.LittleEndian.Uint32(v[off:])
		off += 4
		if uint64(l) > uint64(maxEntry) || uint64(l) > uint64(len(v)-off) {
			return nil, fmt.Errorf("attest: list entry %d has invalid length %d", i, l)
		}
		e := make([]byte, l)
		copy(e, v[off:off+int(l)])
		out = append(out, e)
		off += int(l)
	}
	if off != len(v) {
		return nil, fmt.Errorf("attest: %d trailing bytes after list", len(v)-off)
	}
	return out, nil
}
