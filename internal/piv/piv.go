// Package piv implements the read-and-sign subset of the PIV smart card
// applet, with the YubiKey extensions tpm2-kira needs to identify a token.
//
// It never writes to a card: there is no key generation, no certificate
// import and no management-key authentication. The only command that changes
// card state is VERIFY, which unlocks the PIN for a signature.
package piv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
)

// Transport sends one APDU and returns the response including SW1 SW2.
// *pcsc.Card satisfies it.
type Transport interface {
	Transmit(apdu []byte) ([]byte, error)
}

// Card is a PIV applet reached through a Transport.
type Card struct {
	t Transport
}

// aid is the PIV application identifier (NIST SP 800-73-4, part 1, §2.2).
var aid = []byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00}

// Instruction bytes. The F-range ones are YubiKey extensions.
const (
	insVerify        = 0x20
	insGeneralAuth   = 0x87
	insSelect        = 0xA4
	insGetResponse   = 0xC0
	insGetData       = 0xCB
	insGetMetadata   = 0xF7
	insGetSerial     = 0xF8
	insGetVersion    = 0xFD
	pinReference     = 0x80
	maxShortAPDUData = 255
)

// Status words.
const (
	swOK                   = 0x9000
	swFileNotFound         = 0x6A82
	swInsNotSupported      = 0x6D00
	swSecurityNotSatisfied = 0x6982
	swAuthBlocked          = 0x6983
	swWrongData            = 0x6A80
	swWrongP1P2            = 0x6A86
)

// Errors a caller may want to tell apart.
var (
	ErrNotSupported = errors.New("not supported by this card or firmware")
	ErrNotFound     = errors.New("not found on card")
	ErrPINBlocked   = errors.New("PIN is blocked; it must be reset with the PUK (ykman piv access unblock-pin)")
	ErrPINRequired  = errors.New("PIN verification required")
)

// WrongPINError reports a rejected PIN and the attempts left.
type WrongPINError struct{ Remaining int }

func (e *WrongPINError) Error() string {
	return fmt.Sprintf("wrong PIN (%d attempt(s) remaining)", e.Remaining)
}

// StatusError is an unexpected status word.
type StatusError struct {
	Op string
	SW uint16
}

func (e *StatusError) Error() string { return fmt.Sprintf("%s: card returned status %04X", e.Op, e.SW) }

// Open selects the PIV applet.
func Open(t Transport) (*Card, error) {
	c := &Card{t: t}
	if _, err := c.cmd("SELECT PIV", 0x00, insSelect, 0x04, 0x00, aid); err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.SW == swFileNotFound {
			return nil, fmt.Errorf("PIV applet not present or disabled: %w", ErrNotFound)
		}
		return nil, err
	}
	return c, nil
}

// Version is a YubiKey firmware version.
type Version struct{ Major, Minor, Patch int }

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// AtLeast reports whether v >= major.minor.
func (v Version) AtLeast(major, minor int) bool {
	return v.Major > major || (v.Major == major && v.Minor >= minor)
}

// Version reads the YubiKey firmware version (GET VERSION).
func (c *Card) Version() (Version, error) {
	resp, err := c.cmd("GET VERSION", 0x00, insGetVersion, 0x00, 0x00, nil)
	if err != nil {
		return Version{}, mapUnsupported(err)
	}
	if len(resp) != 3 {
		return Version{}, fmt.Errorf("GET VERSION: unexpected %d-byte response", len(resp))
	}
	return Version{int(resp[0]), int(resp[1]), int(resp[2])}, nil
}

// Serial reads the YubiKey serial number (GET SERIAL, firmware 5.0+).
func (c *Card) Serial() (uint32, error) {
	resp, err := c.cmd("GET SERIAL", 0x00, insGetSerial, 0x00, 0x00, nil)
	if err != nil {
		return 0, mapUnsupported(err)
	}
	if len(resp) != 4 {
		return 0, fmt.Errorf("GET SERIAL: unexpected %d-byte response", len(resp))
	}
	return uint32(resp[0])<<24 | uint32(resp[1])<<16 | uint32(resp[2])<<8 | uint32(resp[3]), nil
}

// PINRetries reports the PIN attempts left without spending one: VERIFY with
// no data answers 63Cx. verified is true when the PIN is already verified in
// this session, in which case the card does not report a count.
func (c *Card) PINRetries() (remaining int, verified bool, err error) {
	_, err = c.cmd("VERIFY (status)", 0x00, insVerify, 0x00, pinReference, nil)
	if err == nil {
		return 0, true, nil
	}
	var se *StatusError
	if errors.As(err, &se) {
		switch {
		case se.SW&0xFFF0 == 0x63C0:
			return int(se.SW & 0x0F), false, nil
		case se.SW == swAuthBlocked:
			return 0, false, nil
		}
	}
	return 0, false, err
}

// VerifyPIN verifies the PIV PIN. A rejected PIN returns *WrongPINError and
// costs one attempt; callers must not retry it.
func (c *Card) VerifyPIN(pin string) error {
	if len(pin) < 6 || len(pin) > 8 {
		// Refused here, without a round trip: the card counts a
		// malformed PIN as a wrong one.
		return fmt.Errorf("a PIV PIN is 6 to 8 characters, got %d", len(pin))
	}
	data := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	copy(data, pin)
	_, err := c.cmd("VERIFY", 0x00, insVerify, 0x00, pinReference, data)
	for i := range data {
		data[i] = 0
	}
	if err == nil {
		return nil
	}
	var se *StatusError
	if errors.As(err, &se) {
		switch {
		case se.SW&0xFFF0 == 0x63C0:
			return &WrongPINError{Remaining: int(se.SW & 0x0F)}
		case se.SW == swAuthBlocked:
			return ErrPINBlocked
		}
	}
	return err
}

// Sign computes a signature with the key in slot over a SHA-256 digest.
//
// For ECDSA the result is ASN.1 DER, exactly what the card returns. For RSA
// the card performs a raw private-key operation, so the digest is wrapped in
// PKCS #1 v1.5 padding here and the result is a PKCS #1 v1.5 signature.
func (c *Card) Sign(slot Slot, pub crypto.PublicKey, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("expected a 32-byte SHA-256 digest, got %d bytes", len(digest))
	}
	var alg Algorithm
	var input []byte
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		switch k.Curve {
		case elliptic.P256():
			alg = AlgECCP256
		case elliptic.P384():
			alg = AlgECCP384
		default:
			return nil, fmt.Errorf("unsupported curve %s", k.Curve.Params().Name)
		}
		// The card expects an input as long as the field. Left-padding
		// keeps the digest's integer value, which is what ECDSA signs
		// when the hash is shorter than the curve order.
		input = make([]byte, size)
		copy(input[size-len(digest):], digest)
	case *rsa.PublicKey:
		switch k.Size() {
		case 256:
			alg = AlgRSA2048
		case 384:
			alg = AlgRSA3072
		case 512:
			alg = AlgRSA4096
		default:
			return nil, fmt.Errorf("unsupported RSA key size %d bits", k.N.BitLen())
		}
		input = pkcs1v15SHA256(digest, k.Size())
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}

	// 7C { 82 00 (response placeholder), 81 L input (challenge) }
	inner := append([]byte{0x82, 0x00, 0x81}, berLen(len(input))...)
	inner = append(inner, input...)
	data := append([]byte{0x7C}, berLen(len(inner))...)
	data = append(data, inner...)

	resp, err := c.cmd("GENERAL AUTHENTICATE", 0x00, insGeneralAuth, byte(alg), byte(slot), data)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.SW == swSecurityNotSatisfied {
			return nil, ErrPINRequired
		}
		return nil, err
	}
	outer, _, err := parseTLV(resp, 0x7C)
	if err != nil {
		return nil, fmt.Errorf("GENERAL AUTHENTICATE response: %w", err)
	}
	sig, _, err := parseTLV(outer, 0x82)
	if err != nil {
		return nil, fmt.Errorf("GENERAL AUTHENTICATE response: %w", err)
	}
	if k, ok := pub.(*rsa.PublicKey); ok && len(sig) < k.Size() {
		padded := make([]byte, k.Size())
		copy(padded[k.Size()-len(sig):], sig)
		sig = padded
	}
	return sig, nil
}

// pkcs1v15SHA256 builds EMSA-PKCS1-v1_5 (RFC 8017 §9.2) for a SHA-256 digest.
func pkcs1v15SHA256(digest []byte, k int) []byte {
	prefix := []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	t := append(prefix, digest...)
	em := make([]byte, k)
	em[1] = 0x01
	for i := 2; i < k-len(t)-1; i++ {
		em[i] = 0xFF
	}
	copy(em[k-len(t):], t)
	return em
}

// KeyMetadata describes the key in a slot (GET METADATA, firmware 5.3+).
type KeyMetadata struct {
	Algorithm   Algorithm
	PINPolicy   PINPolicy
	TouchPolicy TouchPolicy
	Generated   bool // generated on the card, as opposed to imported
	PublicKey   crypto.PublicKey
}

// Metadata reads the metadata of the key in slot. It returns ErrNotFound for
// an empty slot and ErrNotSupported on firmware before 5.3.
func (c *Card) Metadata(slot Slot) (*KeyMetadata, error) {
	resp, err := c.cmd("GET METADATA", 0x00, insGetMetadata, 0x00, byte(slot), nil)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.SW == swFileNotFound {
			return nil, ErrNotFound
		}
		return nil, mapUnsupported(err)
	}
	tlvs, err := parseTLVs(resp)
	if err != nil {
		return nil, fmt.Errorf("GET METADATA response: %w", err)
	}
	md := &KeyMetadata{}
	if v := tlvs[0x01]; len(v) == 1 {
		md.Algorithm = Algorithm(v[0])
	}
	if v := tlvs[0x02]; len(v) == 2 {
		md.PINPolicy, md.TouchPolicy = PINPolicy(v[0]), TouchPolicy(v[1])
	}
	if v := tlvs[0x03]; len(v) == 1 {
		md.Generated = v[0] == 0x01
	}
	if v, ok := tlvs[0x04]; ok {
		pub, err := decodePublicKey(md.Algorithm, v)
		if err != nil {
			return nil, fmt.Errorf("GET METADATA public key: %w", err)
		}
		md.PublicKey = pub
	}
	return md, nil
}

// decodePublicKey reads the public key template of GET METADATA and
// GENERATE ASYMMETRIC KEY PAIR: 86 (EC point) or 81/82 (RSA modulus and
// exponent).
func decodePublicKey(alg Algorithm, b []byte) (crypto.PublicKey, error) {
	tlvs, err := parseTLVs(b)
	if err != nil {
		return nil, err
	}
	switch alg {
	case AlgECCP256, AlgECCP384:
		curve := elliptic.P256()
		if alg == AlgECCP384 {
			curve = elliptic.P384()
		}
		point := tlvs[0x86]
		size := (curve.Params().BitSize + 7) / 8
		if len(point) != 1+2*size || point[0] != 0x04 {
			return nil, errors.New("malformed EC point")
		}
		x := new(big.Int).SetBytes(point[1 : 1+size])
		y := new(big.Int).SetBytes(point[1+size:])
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("EC point is not on the curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case AlgRSA1024, AlgRSA2048, AlgRSA3072, AlgRSA4096:
		n, e := tlvs[0x81], tlvs[0x82]
		if len(n) == 0 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("malformed RSA public key")
		}
		exp := 0
		for _, b := range e {
			exp = exp<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}, nil
	default:
		return nil, fmt.Errorf("public key for algorithm %s is not decoded", alg)
	}
}

// Certificate reads the X.509 certificate stored for slot. It returns
// ErrNotFound when the slot has none.
func (c *Card) Certificate(slot Slot) (*x509.Certificate, error) {
	obj, ok := slot.certObject()
	if !ok {
		return nil, fmt.Errorf("slot %s has no certificate object", slot)
	}
	data := append([]byte{0x5C, byte(len(obj))}, obj...)
	resp, err := c.cmd("GET DATA", 0x00, insGetData, 0x3F, 0xFF, data)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.SW == swFileNotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}
	content, _, err := parseTLV(resp, 0x53)
	if err != nil {
		return nil, fmt.Errorf("certificate object: %w", err)
	}
	tlvs, err := parseTLVs(content)
	if err != nil {
		return nil, fmt.Errorf("certificate object: %w", err)
	}
	if info := tlvs[0x71]; len(info) == 1 && info[0] != 0 {
		return nil, errors.New("compressed certificates are not supported")
	}
	der, ok := tlvs[0x70]
	if !ok || len(der) == 0 {
		return nil, ErrNotFound
	}
	return x509.ParseCertificate(der)
}

// cmd sends one command, using command chaining for data longer than a short
// APDU allows and GET RESPONSE for replies that do not fit one response.
// It returns the response data without the status word, or *StatusError.
func (c *Card) cmd(op string, cla, ins, p1, p2 byte, data []byte) ([]byte, error) {
	for len(data) > maxShortAPDUData {
		chunk := data[:maxShortAPDUData]
		data = data[maxShortAPDUData:]
		apdu := append([]byte{cla | 0x10, ins, p1, p2, byte(len(chunk))}, chunk...)
		_, sw, err := c.transmit(apdu)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		if sw != swOK {
			return nil, &StatusError{Op: op, SW: sw}
		}
	}
	apdu := []byte{cla, ins, p1, p2}
	if len(data) > 0 {
		apdu = append(apdu, byte(len(data)))
		apdu = append(apdu, data...)
	}
	// Le is left out on commands with no response data expected (VERIFY);
	// with Le=00 some cards append data to a bare status.
	if ins != insVerify {
		apdu = append(apdu, 0x00)
	}

	var out []byte
	for {
		resp, sw, err := c.transmit(apdu)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		out = append(out, resp...)
		if sw>>8 == 0x61 {
			apdu = []byte{0x00, insGetResponse, 0x00, 0x00, byte(sw)}
			continue
		}
		if sw != swOK {
			return nil, &StatusError{Op: op, SW: sw}
		}
		return out, nil
	}
}

func (c *Card) transmit(apdu []byte) ([]byte, uint16, error) {
	resp, err := c.t.Transmit(apdu)
	if err != nil {
		return nil, 0, err
	}
	if len(resp) < 2 {
		return nil, 0, fmt.Errorf("response of %d bytes has no status word", len(resp))
	}
	n := len(resp) - 2
	return resp[:n], uint16(resp[n])<<8 | uint16(resp[n+1]), nil
}

func mapUnsupported(err error) error {
	var se *StatusError
	if errors.As(err, &se) && (se.SW == swInsNotSupported || se.SW == swWrongP1P2 || se.SW == swWrongData) {
		return fmt.Errorf("%s: %w", se.Op, ErrNotSupported)
	}
	return err
}
