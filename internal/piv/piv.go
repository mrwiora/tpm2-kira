// Package piv implements the small part of the PIV card application that
// tpm2-kira needs: read a slot's public key, verify a PIN, and sign a digest.
//
// It deliberately contains no way to write to the card. There is no key
// generation, no certificate import and no management-key authentication, so
// tpm2-kira cannot alter or lock a token — which matters when the slot it
// borrows may also hold a Secure Boot signing key. Populating a slot is
// ykman's job; see docs/YUBIKEY.md.
//
// References: NIST SP 800-73-4 for the card application, and the YubiKey PIV
// extensions for the serial-number instruction.
package piv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// Transport sends a command APDU and returns the response, including the
// two-byte status word.
type Transport interface {
	Transmit(apdu []byte) ([]byte, error)
}

// Card is an opened PIV application.
type Card struct {
	transport Transport
}

// Algorithm identifiers from SP 800-73-4 and the YubiKey extensions.
const (
	algRSA1024 byte = 0x06
	algRSA2048 byte = 0x07
	algECCP256 byte = 0x11
	algECCP384 byte = 0x14
	algRSA3072 byte = 0x16
	algRSA4096 byte = 0x17
)

// Instruction bytes.
const (
	insSelect              byte = 0xA4
	insVerify              byte = 0x20
	insGetData             byte = 0xCB
	insGeneralAuthenticate byte = 0x87
	insGetResponse         byte = 0xC0
	insGetSerial           byte = 0xF8 // YubiKey extension
)

// pivAID is the PIV card application identifier.
var pivAID = []byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00}

// Errors callers distinguish.
var (
	// ErrSlotEmpty means the slot holds no key, so there is nothing to adopt.
	ErrSlotEmpty = errors.New("the PIV slot holds no key")
	// ErrPINBlocked means the retry counter is exhausted and only the PUK
	// can recover the slot.
	ErrPINBlocked = errors.New("the PIN is blocked")
)

// PINError reports a rejected PIN together with how many tries remain.
type PINError struct {
	Retries int
}

func (e *PINError) Error() string {
	if e.Retries <= 0 {
		return "PIN rejected and the retry counter is exhausted"
	}
	return fmt.Sprintf("PIN rejected, %d attempt(s) remaining before the slot is blocked", e.Retries)
}

// Open selects the PIV application on the card behind t.
func Open(t Transport) (*Card, error) {
	c := &Card{transport: t}

	if _, err := c.send(0x00, insSelect, 0x04, 0x00, pivAID, 256); err != nil {
		return nil, fmt.Errorf("failed to select the PIV application: %w", err)
	}

	return c, nil
}

// Serial returns the YubiKey serial number. Cards that are not YubiKeys do not
// implement this instruction and report zero rather than failing, since the
// serial is only used to tell several tokens apart.
func (c *Card) Serial() (uint32, error) {
	rsp, err := c.send(0x00, insGetSerial, 0x00, 0x00, nil, 256)
	if err != nil {
		return 0, nil
	}
	if len(rsp) < 4 {
		return 0, nil
	}
	return binary.BigEndian.Uint32(rsp[:4]), nil
}

// PINRetries returns the number of PIN attempts remaining.
//
// It is read by sending VERIFY with no data, which the card answers with
// 63 Cx without consuming an attempt. Checking this before verifying is what
// keeps a wrong PIN in a loop from blocking the slot.
func (c *Card) PINRetries() (int, error) {
	rsp, err := c.transport.Transmit([]byte{0x00, insVerify, 0x00, 0x80})
	if err != nil {
		return 0, err
	}
	if len(rsp) < 2 {
		return 0, fmt.Errorf("short response to the PIN retry query")
	}

	sw := binary.BigEndian.Uint16(rsp[len(rsp)-2:])
	switch {
	case sw == 0x9000:
		// Already verified in this session.
		return -1, nil
	case sw == 0x6983:
		return 0, nil
	case sw&0xFFF0 == 0x63C0:
		return int(sw & 0x000F), nil
	default:
		return 0, fmt.Errorf("unexpected status %04X from the PIN retry query", sw)
	}
}

// VerifyPIN presents the PIN. A PIV PIN is 6 to 8 characters, padded to eight
// bytes with 0xFF.
func (c *Card) VerifyPIN(pin string) error {
	if len(pin) < 6 || len(pin) > 8 {
		return fmt.Errorf("a PIV PIN must be 6 to 8 characters, got %d", len(pin))
	}

	padded := make([]byte, 8)
	for i := range padded {
		padded[i] = 0xFF
	}
	copy(padded, pin)

	rsp, err := c.transport.Transmit(append([]byte{0x00, insVerify, 0x00, 0x80, 0x08}, padded...))
	if err != nil {
		return err
	}
	if len(rsp) < 2 {
		return fmt.Errorf("short response to VERIFY")
	}

	sw := binary.BigEndian.Uint16(rsp[len(rsp)-2:])
	switch {
	case sw == 0x9000:
		return nil
	case sw == 0x6983:
		return ErrPINBlocked
	case sw&0xFFF0 == 0x63C0:
		return &PINError{Retries: int(sw & 0x000F)}
	default:
		return fmt.Errorf("VERIFY failed with status %04X", sw)
	}
}

// Certificate reads the X.509 certificate stored alongside a slot's key.
func (c *Card) Certificate(slot byte) (*x509.Certificate, error) {
	objectID, err := slotObjectID(slot)
	if err != nil {
		return nil, err
	}

	// The data field is a single tag 0x5C carrying the object identifier.
	request := append([]byte{0x5C, byte(len(objectID))}, objectID...)

	rsp, err := c.send(0x00, insGetData, 0x3F, 0xFF, request, 256)
	if err != nil {
		if errors.Is(err, errFileNotFound) {
			return nil, fmt.Errorf("%w: slot %02x has no certificate", ErrSlotEmpty, slot)
		}
		return nil, err
	}

	// Response is 53 { 70 <cert> 71 <info> FE 00 }.
	outer, err := tlvValue(rsp, 0x53)
	if err != nil {
		return nil, fmt.Errorf("unexpected GET DATA response for slot %02x: %w", slot, err)
	}

	certDER, err := tlvValue(outer, 0x70)
	if err != nil {
		return nil, fmt.Errorf("no certificate in slot %02x: %w", slot, err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the certificate in slot %02x: %w", slot, err)
	}

	return cert, nil
}

// PublicKey returns the public key of the key in a slot.
//
// It is read from the slot's certificate, which is how a PIV card exposes it;
// a slot holding a key but no certificate cannot be used, and says so.
func (c *Card) PublicKey(slot byte) (crypto.PublicKey, error) {
	cert, err := c.Certificate(slot)
	if err != nil {
		return nil, err
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("slot %02x holds an unsupported key type %T", slot, cert.PublicKey)
	}
}

// Sign signs a SHA-256 digest with the key in a slot.
//
// The return value matches the crypto.Signer contract for the key type: an
// ASN.1 DER SEQUENCE for ECDSA, and a PKCS#1 v1.5 signature for RSA. The card
// performs a raw private-key operation for RSA, so the padded block is built
// here.
func (c *Card) Sign(slot byte, pub crypto.PublicKey, digest []byte) ([]byte, error) {
	alg, err := algorithmFor(pub)
	if err != nil {
		return nil, err
	}

	payload := digest

	switch key := pub.(type) {
	case *rsa.PublicKey:
		payload, err = pkcs1v15SHA256(digest, key.Size())
		if err != nil {
			return nil, err
		}
	case *ecdsa.PublicKey:
		// A digest longer than the curve is truncated on the left, per
		// the ECDSA definition. SHA-256 with P-256 is the exact-fit case.
		byteLen := (key.Curve.Params().BitSize + 7) / 8
		if len(payload) > byteLen {
			payload = payload[:byteLen]
		}
	}

	// Dynamic authentication template: 7C { 82 (empty, response wanted)
	// 81 <payload> }.
	inner := append([]byte{0x82, 0x00}, encodeTLV(0x81, payload)...)
	request := encodeTLV(0x7C, inner)

	// An ECDSA response fits in a short APDU, and any card that is short of
	// bytes says so with 61xx, which send() chains. An RSA response is as
	// wide as the modulus, and its request already exceeds the one-byte Lc,
	// so that exchange is extended in both directions.
	le := 256
	if _, isRSA := pub.(*rsa.PublicKey); isRSA {
		le = 65536
	}

	rsp, err := c.send(0x00, insGeneralAuthenticate, alg, slot, request, le)
	if err != nil {
		return nil, fmt.Errorf("signing with slot %02x failed: %w", slot, err)
	}

	outer, err := tlvValue(rsp, 0x7C)
	if err != nil {
		return nil, fmt.Errorf("unexpected signing response from slot %02x: %w", slot, err)
	}

	signature, err := tlvValue(outer, 0x82)
	if err != nil {
		return nil, fmt.Errorf("no signature in the response from slot %02x: %w", slot, err)
	}

	return signature, nil
}

// errFileNotFound is the card's "no such object" status, reported when a slot
// has never been populated.
var errFileNotFound = errors.New("file or application not found")

// send builds a command APDU, handles response chaining and checks the status
// word.
//
// Short APDUs are used when the data fits, and extended-length APDUs otherwise
// — an RSA-2048 signature request carries a 256-byte block, which does not fit
// the one-byte Lc.
func (c *Card) send(cla, ins, p1, p2 byte, data []byte, le int) ([]byte, error) {
	apdu := []byte{cla, ins, p1, p2}

	switch {
	case len(data) == 0:
		if le > 0 {
			apdu = append(apdu, 0x00)
		}
	case len(data) <= 255 && le <= 256:
		apdu = append(apdu, byte(len(data)))
		apdu = append(apdu, data...)
		if le > 0 {
			apdu = append(apdu, byte(le%256))
		}
	default:
		if len(data) > 65535 {
			return nil, fmt.Errorf("command data is %d bytes, which exceeds the extended APDU limit", len(data))
		}
		apdu = append(apdu, 0x00, byte(len(data)>>8), byte(len(data)))
		apdu = append(apdu, data...)
		if le > 0 {
			apdu = append(apdu, 0x00, 0x00)
		}
	}

	rsp, err := c.transport.Transmit(apdu)
	if err != nil {
		return nil, err
	}

	var out []byte
	for {
		if len(rsp) < 2 {
			return nil, fmt.Errorf("short APDU response (%d bytes)", len(rsp))
		}

		out = append(out, rsp[:len(rsp)-2]...)
		sw := binary.BigEndian.Uint16(rsp[len(rsp)-2:])

		switch {
		case sw == 0x9000:
			return out, nil
		case sw>>8 == 0x61:
			// More data waiting: GET RESPONSE for the remaining bytes.
			rsp, err = c.transport.Transmit([]byte{cla, insGetResponse, 0x00, 0x00, byte(sw & 0xFF)})
			if err != nil {
				return nil, err
			}
		case sw == 0x6A82:
			return nil, errFileNotFound
		case sw == 0x6982:
			return nil, fmt.Errorf("security status not satisfied — the PIN has not been verified")
		case sw == 0x6983:
			return nil, ErrPINBlocked
		default:
			return nil, fmt.Errorf("card returned status %04X", sw)
		}
	}
}

// slotObjectID maps a key slot to the object holding its certificate.
func slotObjectID(slot byte) ([]byte, error) {
	switch {
	case slot == 0x9A:
		return []byte{0x5F, 0xC1, 0x05}, nil
	case slot == 0x9C:
		return []byte{0x5F, 0xC1, 0x0A}, nil
	case slot == 0x9D:
		return []byte{0x5F, 0xC1, 0x0B}, nil
	case slot == 0x9E:
		return []byte{0x5F, 0xC1, 0x01}, nil
	case slot >= 0x82 && slot <= 0x95:
		// Retired key management slots 82-95 map to 5FC10D-5FC120.
		return []byte{0x5F, 0xC1, 0x0D + (slot - 0x82)}, nil
	default:
		return nil, fmt.Errorf("slot %02x is not a PIV key slot", slot)
	}
}

// algorithmFor maps a public key to the card's algorithm identifier.
func algorithmFor(pub crypto.PublicKey) (byte, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		switch key.N.BitLen() {
		case 1024:
			return algRSA1024, nil
		case 2048:
			return algRSA2048, nil
		case 3072:
			return algRSA3072, nil
		case 4096:
			return algRSA4096, nil
		default:
			return 0, fmt.Errorf("unsupported RSA key size %d", key.N.BitLen())
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case 256:
			return algECCP256, nil
		case 384:
			return algECCP384, nil
		default:
			return 0, fmt.Errorf("unsupported curve %s", key.Curve.Params().Name)
		}
	default:
		return 0, fmt.Errorf("unsupported key type %T", pub)
	}
}

// sha256DigestInfo is the ASN.1 DigestInfo prefix for SHA-256, as used in
// PKCS#1 v1.5 signatures.
var sha256DigestInfo = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
	0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
}

// pkcs1v15SHA256 builds the padded block a PIV card expects for an RSA
// signature, since the card performs the raw private-key operation only.
func pkcs1v15SHA256(digest []byte, modulusLen int) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("expected a 32-byte SHA-256 digest, got %d bytes", len(digest))
	}

	tail := append(append([]byte{}, sha256DigestInfo...), digest...)
	if modulusLen < len(tail)+11 {
		return nil, fmt.Errorf("RSA modulus of %d bytes is too small for a SHA-256 signature", modulusLen)
	}

	block := make([]byte, modulusLen)
	block[0] = 0x00
	block[1] = 0x01
	padEnd := modulusLen - len(tail) - 1
	for i := 2; i < padEnd; i++ {
		block[i] = 0xFF
	}
	block[padEnd] = 0x00
	copy(block[padEnd+1:], tail)

	return block, nil
}

// encodeTLV wraps a value in a BER-TLV with a single-byte tag.
func encodeTLV(tag byte, value []byte) []byte {
	out := []byte{tag}

	switch n := len(value); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}

	return append(out, value...)
}

// tlvValue finds a single-byte tag at the top level of a BER-TLV sequence and
// returns its value.
func tlvValue(data []byte, tag byte) ([]byte, error) {
	for offset := 0; offset < len(data); {
		t := data[offset]
		offset++

		if offset >= len(data) {
			return nil, fmt.Errorf("truncated TLV after tag %02X", t)
		}

		length := int(data[offset])
		offset++

		if length&0x80 != 0 {
			count := length & 0x7F
			if count == 0 || count > 3 {
				return nil, fmt.Errorf("unsupported TLV length form %02X for tag %02X", length, t)
			}
			if offset+count > len(data) {
				return nil, fmt.Errorf("truncated TLV length for tag %02X", t)
			}
			length = 0
			for i := 0; i < count; i++ {
				length = length<<8 | int(data[offset+i])
			}
			offset += count
		}

		if offset+length > len(data) {
			return nil, fmt.Errorf("TLV for tag %02X claims %d bytes but only %d remain", t, length, len(data)-offset)
		}

		if t == tag {
			return data[offset : offset+length], nil
		}

		offset += length
	}

	return nil, fmt.Errorf("tag %02X not found", tag)
}

// insGetMetadata is the YubiKey extension that reports a slot's algorithm,
// policies and public key without needing a certificate. It exists on firmware
// 5.3 and later; older cards answer "instruction not supported" and callers
// fall back to the slot certificate.
const insGetMetadata byte = 0xF7

// Policy values reported by GET METADATA. The PIN and touch policies share
// the value 0x02 for different meanings, so they are named separately rather
// than sharing one set of constants.
const (
	PINPolicyNever  byte = 0x01
	PINPolicyOnce   byte = 0x02
	PINPolicyAlways byte = 0x03

	TouchPolicyNever  byte = 0x01
	TouchPolicyAlways byte = 0x02
	TouchPolicyCached byte = 0x03
)

// ErrMetadataUnsupported means the card does not implement GET METADATA.
var ErrMetadataUnsupported = errors.New("the card does not report slot metadata")

// Metadata describes what a slot holds.
type Metadata struct {
	Algorithm   byte
	PINPolicy   byte
	TouchPolicy byte
	// Imported reports whether the key was generated off the card. A key
	// that was imported has existed somewhere other than the token.
	Imported  bool
	PublicKey crypto.PublicKey
}

// PINPolicyName renders a PIN policy for output.
func PINPolicyName(p byte) string {
	switch p {
	case 0x01:
		return "never"
	case 0x02:
		return "once per session"
	case 0x03:
		return "before every signature"
	default:
		return fmt.Sprintf("unknown (%02x)", p)
	}
}

// TouchPolicyName renders a touch policy for output.
func TouchPolicyName(p byte) string {
	switch p {
	case 0x01:
		return "never"
	case 0x02:
		return "before every signature"
	case 0x03:
		return "cached for 15 seconds"
	default:
		return fmt.Sprintf("unknown (%02x)", p)
	}
}

// SlotMetadata reads a slot's metadata.
func (c *Card) SlotMetadata(slot byte) (*Metadata, error) {
	rsp, err := c.send(0x00, insGetMetadata, 0x00, slot, nil, 256)
	if err != nil {
		if errors.Is(err, errFileNotFound) {
			return nil, fmt.Errorf("%w: slot %02x", ErrSlotEmpty, slot)
		}
		// 6D00/6E00 mean the instruction is not implemented.
		if isUnsupportedInstruction(err) {
			return nil, ErrMetadataUnsupported
		}
		return nil, err
	}

	md := &Metadata{}

	if alg, err := tlvValue(rsp, 0x01); err == nil && len(alg) == 1 {
		md.Algorithm = alg[0]
	}
	if policy, err := tlvValue(rsp, 0x02); err == nil && len(policy) == 2 {
		md.PINPolicy = policy[0]
		md.TouchPolicy = policy[1]
	}
	if origin, err := tlvValue(rsp, 0x03); err == nil && len(origin) == 1 {
		md.Imported = origin[0] == 0x02
	}

	keyTLV, err := tlvValue(rsp, 0x04)
	if err != nil {
		return nil, fmt.Errorf("%w: slot %02x reports no public key", ErrSlotEmpty, slot)
	}

	md.PublicKey, err = parsePublicKeyTLV(md.Algorithm, keyTLV)
	if err != nil {
		return nil, err
	}

	return md, nil
}

func isUnsupportedInstruction(err error) bool {
	return err != nil && (containsStatus(err, "6D00") || containsStatus(err, "6E00"))
}

func containsStatus(err error, sw string) bool {
	return err != nil && len(err.Error()) >= len(sw) &&
		stringsContains(err.Error(), sw)
}

func stringsContains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// parsePublicKeyTLV decodes the public key encoding a YubiKey uses in GET
// METADATA and GENERATE responses: tag 86 for an EC point, tags 81 and 82 for
// an RSA modulus and exponent.
func parsePublicKeyTLV(algorithm byte, data []byte) (crypto.PublicKey, error) {
	switch algorithm {
	case algECCP256, algECCP384:
		point, err := tlvValue(data, 0x86)
		if err != nil {
			return nil, fmt.Errorf("no EC point in the slot metadata: %w", err)
		}

		curve := ellipticCurveFor(algorithm)
		if curve == nil {
			return nil, fmt.Errorf("unsupported EC algorithm %02x", algorithm)
		}

		byteLen := (curve.Params().BitSize + 7) / 8
		if len(point) != 1+2*byteLen || point[0] != 0x04 {
			return nil, fmt.Errorf("unexpected EC point encoding (%d bytes)", len(point))
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(point[1 : 1+byteLen]),
			Y:     new(big.Int).SetBytes(point[1+byteLen:]),
		}, nil

	case algRSA1024, algRSA2048, algRSA3072, algRSA4096:
		modulus, err := tlvValue(data, 0x81)
		if err != nil {
			return nil, fmt.Errorf("no RSA modulus in the slot metadata: %w", err)
		}
		exponent, err := tlvValue(data, 0x82)
		if err != nil {
			return nil, fmt.Errorf("no RSA exponent in the slot metadata: %w", err)
		}

		e := new(big.Int).SetBytes(exponent)
		if !e.IsInt64() || e.Int64() > 1<<31 {
			return nil, fmt.Errorf("RSA public exponent is out of range")
		}

		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(e.Int64()),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported slot algorithm %02x", algorithm)
	}
}

func ellipticCurveFor(algorithm byte) elliptic.Curve {
	switch algorithm {
	case algECCP256:
		return elliptic.P256()
	case algECCP384:
		return elliptic.P384()
	default:
		return nil
	}
}
