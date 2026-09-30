package piv

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Slot is a PIV key reference.
type Slot byte

// The four standard slots. The retired key management slots are 0x82–0x95.
const (
	SlotAuthentication Slot = 0x9A
	SlotSignature      Slot = 0x9C
	SlotKeyManagement  Slot = 0x9D
	SlotCardAuth       Slot = 0x9E
)

// KeySlots lists every slot that can hold a signing key, in the order they
// are probed and presented: the four standard slots, then the retired ones.
func KeySlots() []Slot {
	slots := []Slot{SlotAuthentication, SlotSignature, SlotKeyManagement, SlotCardAuth}
	for s := Slot(0x82); s <= 0x95; s++ {
		slots = append(slots, s)
	}
	return slots
}

func (s Slot) String() string { return fmt.Sprintf("%02x", byte(s)) }

// Name is the slot's role, for display.
func (s Slot) Name() string {
	switch s {
	case SlotAuthentication:
		return "Authentication"
	case SlotSignature:
		return "Digital Signature"
	case SlotKeyManagement:
		return "Key Management"
	case SlotCardAuth:
		return "Card Authentication"
	}
	if s >= 0x82 && s <= 0x95 {
		return fmt.Sprintf("Retired %d", int(s)-0x81)
	}
	return "unknown"
}

// ParseSlot accepts "9a", "0x9a" or "9A".
func ParseSlot(str string) (Slot, error) {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(str), "0x"), 16, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid PIV slot %q", str)
	}
	s := Slot(v)
	if _, ok := s.certObject(); !ok {
		return 0, fmt.Errorf("invalid PIV slot %q (want 9a, 9c, 9d, 9e or 82-95)", str)
	}
	return s, nil
}

// certObject is the data object holding the slot's certificate
// (NIST SP 800-73-4, part 1, table 3; retired slots 5FC10D–5FC120).
func (s Slot) certObject() ([]byte, bool) {
	switch s {
	case SlotAuthentication:
		return []byte{0x5F, 0xC1, 0x05}, true
	case SlotSignature:
		return []byte{0x5F, 0xC1, 0x0A}, true
	case SlotKeyManagement:
		return []byte{0x5F, 0xC1, 0x0B}, true
	case SlotCardAuth:
		return []byte{0x5F, 0xC1, 0x01}, true
	}
	if s >= 0x82 && s <= 0x95 {
		return []byte{0x5F, 0xC1, 0x0D + byte(s-0x82)}, true
	}
	return nil, false
}

// Algorithm is a PIV algorithm identifier.
type Algorithm byte

const (
	AlgRSA1024 Algorithm = 0x06
	AlgRSA2048 Algorithm = 0x07
	AlgRSA3072 Algorithm = 0x05
	AlgRSA4096 Algorithm = 0x16
	AlgECCP256 Algorithm = 0x11
	AlgECCP384 Algorithm = 0x14
	AlgEd25519 Algorithm = 0xE0
	AlgX25519  Algorithm = 0xE1
)

func (a Algorithm) String() string {
	switch a {
	case AlgRSA1024:
		return "RSA1024"
	case AlgRSA2048:
		return "RSA2048"
	case AlgRSA3072:
		return "RSA3072"
	case AlgRSA4096:
		return "RSA4096"
	case AlgECCP256:
		return "ECCP256"
	case AlgECCP384:
		return "ECCP384"
	case AlgEd25519:
		return "ED25519"
	case AlgX25519:
		return "X25519"
	}
	return fmt.Sprintf("alg-0x%02x", byte(a))
}

// PINPolicy is when the card demands the PIN for a key.
type PINPolicy byte

const (
	PINPolicyDefault     PINPolicy = 0
	PINPolicyNever       PINPolicy = 1
	PINPolicyOnce        PINPolicy = 2
	PINPolicyAlways      PINPolicy = 3
	PINPolicyMatchOnce   PINPolicy = 4
	PINPolicyMatchAlways PINPolicy = 5
)

func (p PINPolicy) String() string {
	return [...]string{"default", "never", "once", "always", "match-once", "match-always", "unknown"}[min(int(p), 6)]
}

// TouchPolicy is when the card demands a touch for a key.
type TouchPolicy byte

const (
	TouchPolicyDefault TouchPolicy = 0
	TouchPolicyNever   TouchPolicy = 1
	TouchPolicyAlways  TouchPolicy = 2
	TouchPolicyCached  TouchPolicy = 3
)

func (p TouchPolicy) String() string {
	return [...]string{"default", "never", "always", "cached", "unknown"}[min(int(p), 4)]
}

// berLen encodes a BER-TLV length.
func berLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n <= 0xFF:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

// parseTLV reads one TLV with a single-byte tag that must equal want, and
// returns its value and whatever follows it.
func parseTLV(b []byte, want byte) (value, rest []byte, err error) {
	tag, value, rest, err := nextTLV(b)
	if err != nil {
		return nil, nil, err
	}
	if tag != want {
		return nil, nil, fmt.Errorf("expected tag %02X, found %02X", want, tag)
	}
	return value, rest, nil
}

// parseTLVs reads a flat sequence of single-byte-tag TLVs.
func parseTLVs(b []byte) (map[byte][]byte, error) {
	out := map[byte][]byte{}
	for len(b) > 0 {
		tag, value, rest, err := nextTLV(b)
		if err != nil {
			return nil, err
		}
		out[tag] = value
		b = rest
	}
	return out, nil
}

var errTruncated = errors.New("truncated TLV")

func nextTLV(b []byte) (tag byte, value, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errTruncated
	}
	tag = b[0]
	n, hdr := int(b[1]), 2
	switch {
	case n < 0x80:
	case n == 0x81 && len(b) >= 3:
		n, hdr = int(b[2]), 3
	case n == 0x82 && len(b) >= 4:
		n, hdr = int(b[2])<<8|int(b[3]), 4
	default:
		return 0, nil, nil, fmt.Errorf("unsupported TLV length encoding %02X", b[1])
	}
	if len(b) < hdr+n {
		return 0, nil, nil, errTruncated
	}
	return tag, b[hdr : hdr+n], b[hdr+n:], nil
}
