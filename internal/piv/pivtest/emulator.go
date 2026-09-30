// Package pivtest provides a software PIV card for tests: a piv.Transport
// that answers APDUs the way a YubiKey 5 does, backed by in-memory keys.
package pivtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/matthias/tpm2-kira/internal/piv"
)

// Key is one populated slot.
type Key struct {
	Signer      crypto.Signer
	PINPolicy   piv.PINPolicy
	TouchPolicy piv.TouchPolicy
	WithCert    bool // store a self-signed certificate in the slot
}

// Card is an emulated YubiKey PIV applet.
type Card struct {
	Serial     uint32
	Firmware   [3]byte
	PIN        string
	Retries    int
	NoMetadata bool // behave like firmware before 5.3
	Keys       map[piv.Slot]*Key
	Log        [][]byte // every APDU received
	SignCount  int
	Unplugged  bool

	selected bool
	verified bool
	chain    []byte
	pending  []byte
	certs    map[piv.Slot][]byte
}

// ErrUnplugged is returned by Transmit once Unplugged is set.
type ErrUnplugged struct{}

func (ErrUnplugged) Error() string { return "card removed" }

// New returns a firmware 5.7.1 card with PIN 123456 and three retries.
func New(serial uint32) *Card {
	return &Card{Serial: serial, Firmware: [3]byte{5, 7, 1}, PIN: "123456", Retries: 3, Keys: map[piv.Slot]*Key{}}
}

// AddECKey generates a P-256 key in slot and returns it.
func (c *Card) AddECKey(slot piv.Slot, pin piv.PINPolicy, touch piv.TouchPolicy, withCert bool) *ecdsa.PrivateKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Keys[slot] = &Key{Signer: k, PINPolicy: pin, TouchPolicy: touch, WithCert: withCert}
	return k
}

// AddRSAKey generates an RSA key of bits in slot and returns it.
func (c *Card) AddRSAKey(slot piv.Slot, bits int, pin piv.PINPolicy, touch piv.TouchPolicy, withCert bool) *rsa.PrivateKey {
	k, _ := rsa.GenerateKey(rand.Reader, bits)
	c.Keys[slot] = &Key{Signer: k, PINPolicy: pin, TouchPolicy: touch, WithCert: withCert}
	return k
}

// Reset behaves like a card reset: the applet is deselected and a verified
// PIN is forgotten.
func (c *Card) Reset() {
	c.selected, c.verified, c.chain, c.pending = false, false, nil, nil
}

// Sent reports whether any APDU with instruction ins was received.
func (c *Card) Sent(ins byte) bool {
	for _, a := range c.Log {
		if len(a) > 1 && a[1] == ins {
			return true
		}
	}
	return false
}

func sw(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func ok(data []byte) []byte { return append(append([]byte{}, data...), 0x90, 0x00) }

// Transmit implements piv.Transport.
func (c *Card) Transmit(apdu []byte) ([]byte, error) {
	if c.Unplugged {
		return nil, ErrUnplugged{}
	}
	c.Log = append(c.Log, append([]byte(nil), apdu...))
	if len(apdu) < 4 {
		return sw(0x6700), nil
	}
	cla, ins, p1, p2 := apdu[0], apdu[1], apdu[2], apdu[3]
	var data []byte
	if len(apdu) > 5 || (len(apdu) == 5 && ins == 0x20) {
		n := int(apdu[4])
		if len(apdu) < 5+n {
			return sw(0x6700), nil
		}
		data = apdu[5 : 5+n]
	}
	if ins == 0xC0 { // GET RESPONSE
		return c.respond(nil)
	}
	c.pending = nil
	if cla&0x10 != 0 {
		c.chain = append(c.chain, data...)
		return sw(0x9000), nil
	}
	if c.chain != nil {
		data = append(c.chain, data...)
		c.chain = nil
	}

	if ins == 0xA4 {
		c.selected = true
		return ok(nil), nil
	}
	if !c.selected {
		return sw(0x6D00), nil
	}
	switch ins {
	case 0xFD:
		return ok(c.Firmware[:]), nil
	case 0xF8:
		return ok([]byte{byte(c.Serial >> 24), byte(c.Serial >> 16), byte(c.Serial >> 8), byte(c.Serial)}), nil
	case 0xF7:
		if c.NoMetadata {
			return sw(0x6D00), nil
		}
		return c.metadata(piv.Slot(p2))
	case 0xCB:
		return c.getData(data)
	case 0x20:
		return c.verify(p2, data), nil
	case 0x87:
		return c.sign(piv.Algorithm(p1), piv.Slot(p2), data)
	}
	return sw(0x6D00), nil
}

// respond returns data in 256-byte pieces with 61xx, like a card talking
// through a short-APDU transport.
func (c *Card) respond(data []byte) ([]byte, error) {
	if data != nil {
		c.pending = data
	}
	if len(c.pending) <= 256 {
		out := ok(c.pending)
		c.pending = nil
		return out, nil
	}
	chunk := c.pending[:256]
	c.pending = c.pending[256:]
	rest := len(c.pending)
	if rest > 255 {
		rest = 0
	}
	return append(append([]byte{}, chunk...), 0x61, byte(rest)), nil
}

func tlv(tag byte, v []byte) []byte {
	var l []byte
	switch n := len(v); {
	case n < 0x80:
		l = []byte{byte(n)}
	case n <= 0xFF:
		l = []byte{0x81, byte(n)}
	default:
		l = []byte{0x82, byte(n >> 8), byte(n)}
	}
	return append(append([]byte{tag}, l...), v...)
}

func algOf(pub crypto.PublicKey) piv.Algorithm {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P384() {
			return piv.AlgECCP384
		}
		return piv.AlgECCP256
	case *rsa.PublicKey:
		switch k.Size() {
		case 384:
			return piv.AlgRSA3072
		case 512:
			return piv.AlgRSA4096
		case 128:
			return piv.AlgRSA1024
		}
		return piv.AlgRSA2048
	}
	return 0
}

func (c *Card) metadata(slot piv.Slot) ([]byte, error) {
	k := c.Keys[slot]
	if k == nil {
		return sw(0x6A82), nil
	}
	var pubT []byte
	switch p := k.Signer.Public().(type) {
	case *ecdsa.PublicKey:
		pubT = tlv(0x86, elliptic.Marshal(p.Curve, p.X, p.Y))
	case *rsa.PublicKey:
		pubT = append(tlv(0x81, p.N.Bytes()), tlv(0x82, big.NewInt(int64(p.E)).Bytes())...)
	}
	var out []byte
	out = append(out, tlv(0x01, []byte{byte(algOf(k.Signer.Public()))})...)
	out = append(out, tlv(0x02, []byte{byte(k.PINPolicy), byte(k.TouchPolicy)})...)
	out = append(out, tlv(0x03, []byte{0x01})...)
	out = append(out, tlv(0x04, pubT)...)
	return c.respond(out)
}

func (c *Card) getData(data []byte) ([]byte, error) {
	if len(data) != 5 || data[0] != 0x5C || data[1] != 3 {
		return sw(0x6A80), nil
	}
	for slot, k := range c.Keys {
		obj := certObject(slot)
		if obj != [3]byte{data[2], data[3], data[4]} || !k.WithCert {
			continue
		}
		if c.certs == nil {
			c.certs = map[piv.Slot][]byte{}
		}
		if c.certs[slot] == nil {
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pivtest"},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Signer.Public(), k.Signer)
			if err != nil {
				return nil, err
			}
			c.certs[slot] = der
		}
		inner := append(tlv(0x70, c.certs[slot]), tlv(0x71, []byte{0})...)
		inner = append(inner, 0xFE, 0x00)
		return c.respond(tlv(0x53, inner))
	}
	return sw(0x6A82), nil
}

func certObject(s piv.Slot) [3]byte {
	switch s {
	case piv.SlotAuthentication:
		return [3]byte{0x5F, 0xC1, 0x05}
	case piv.SlotSignature:
		return [3]byte{0x5F, 0xC1, 0x0A}
	case piv.SlotKeyManagement:
		return [3]byte{0x5F, 0xC1, 0x0B}
	case piv.SlotCardAuth:
		return [3]byte{0x5F, 0xC1, 0x01}
	}
	return [3]byte{0x5F, 0xC1, 0x0D + byte(s-0x82)}
}

func (c *Card) verify(ref byte, data []byte) []byte {
	if ref != 0x80 {
		return sw(0x6A88)
	}
	if c.Retries == 0 {
		return sw(0x6983)
	}
	if len(data) == 0 {
		if c.verified {
			return sw(0x9000)
		}
		return sw(0x63C0 | uint16(c.Retries))
	}
	pin := string(data)
	for len(pin) > 0 && pin[len(pin)-1] == 0xFF {
		pin = pin[:len(pin)-1]
	}
	if pin != c.PIN {
		c.verified = false
		c.Retries--
		if c.Retries == 0 {
			return sw(0x6983)
		}
		return sw(0x63C0 | uint16(c.Retries))
	}
	c.Retries = 3
	c.verified = true
	return sw(0x9000)
}

func (c *Card) sign(alg piv.Algorithm, slot piv.Slot, data []byte) ([]byte, error) {
	k := c.Keys[slot]
	if k == nil {
		return sw(0x6A82), nil
	}
	if alg != algOf(k.Signer.Public()) {
		return sw(0x6A80), nil
	}
	policy := k.PINPolicy
	if policy == piv.PINPolicyDefault {
		policy = piv.PINPolicyOnce
		if slot == piv.SlotSignature {
			policy = piv.PINPolicyAlways
		}
		if slot == piv.SlotCardAuth {
			policy = piv.PINPolicyNever
		}
	}
	if policy != piv.PINPolicyNever && !c.verified {
		return sw(0x6982), nil
	}
	// 7C L { 82 00, 81 L challenge }
	outer, err := child(data, 0x7C)
	if err != nil {
		return sw(0x6A80), nil
	}
	challenge, err := findTag(outer, 0x81)
	if err != nil {
		return sw(0x6A80), nil
	}
	var sig []byte
	switch key := k.Signer.(type) {
	case *ecdsa.PrivateKey:
		size := (key.Curve.Params().BitSize + 7) / 8
		if len(challenge) != size {
			return sw(0x6A80), nil
		}
		sig, err = ecdsa.SignASN1(rand.Reader, key, challenge)
	case *rsa.PrivateKey:
		if len(challenge) != key.Size() {
			return sw(0x6A80), nil
		}
		m := new(big.Int).SetBytes(challenge)
		sig = new(big.Int).Exp(m, key.D, key.N).FillBytes(make([]byte, key.Size()))
	}
	if err != nil {
		return nil, err
	}
	if policy == piv.PINPolicyAlways {
		c.verified = false
	}
	c.SignCount++
	return c.respond(tlv(0x7C, tlv(0x82, sig)))
}

func child(b []byte, tag byte) ([]byte, error) {
	v, _, err := split(b)
	if err != nil || b[0] != tag {
		return nil, errBad
	}
	return v, nil
}

func findTag(b []byte, tag byte) ([]byte, error) {
	for len(b) > 0 {
		v, rest, err := split(b)
		if err != nil {
			return nil, err
		}
		if b[0] == tag {
			return v, nil
		}
		b = rest
	}
	return nil, errBad
}

type badTLV struct{}

func (badTLV) Error() string { return "bad TLV" }

var errBad = badTLV{}

func split(b []byte) (value, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, errBad
	}
	n, hdr := int(b[1]), 2
	switch {
	case n < 0x80:
	case n == 0x81 && len(b) >= 3:
		n, hdr = int(b[2]), 3
	case n == 0x82 && len(b) >= 4:
		n, hdr = int(b[2])<<8|int(b[3]), 4
	default:
		return nil, nil, errBad
	}
	if len(b) < hdr+n {
		return nil, nil, errBad
	}
	return b[hdr : hdr+n], b[hdr+n:], nil
}
