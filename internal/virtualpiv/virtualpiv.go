// Package virtualpiv emulates a YubiKey PIV application for tests.
//
// It is test scaffolding: nothing in tpm2-kira imports it, so it is never
// linked into the binary. It exists as a normal package rather than a test file
// so that the card tests, the PC/SC transport tests and the top-level
// integration tests can all drive the same emulator.
//
// The card is backed by a software key and answers the four instructions
// internal/piv sends, plus the two YubiKey extensions — GET SERIAL and GET
// METADATA — that decide which code path tpm2-kira takes. It honours PIN and
// touch policy, and counts verifications and signatures, so a test can assert
// that a slot with PIN policy "always" really is re-verified per signature.
//
// Attached to the vsmartcard virtual reader (vpcd), it appears to pcscd as an
// ordinary card, which makes it possible to exercise the whole stack — key
// reference, PC/SC transport, PIV APDUs, TPM PolicySigned, NVRAM write — with
// no hardware at all.
package virtualpiv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"
)

// DefaultAddr is where the Debian vsmartcard-vpcd configuration listens.
const DefaultAddr = "127.0.0.1:35963"

// Policy values, mirroring the YubiKey PIV extensions. The PIN and touch
// policies share the value 2 for different meanings, hence two sets.
const (
	PINPolicyNever  byte = 0x01
	PINPolicyOnce   byte = 0x02
	PINPolicyAlways byte = 0x03

	TouchPolicyNever  byte = 0x01
	TouchPolicyAlways byte = 0x02
	TouchPolicyCached byte = 0x03
)

// Algorithm identifiers from SP 800-73-4 and the YubiKey extensions.
const (
	algRSA2048 byte = 0x07
	algECCP256 byte = 0x11
	algECCP384 byte = 0x14
)

// Instruction bytes.
const (
	insSelect              byte = 0xA4
	insVerify              byte = 0x20
	insGetData             byte = 0xCB
	insGeneralAuthenticate byte = 0x87
	insGetResponse         byte = 0xC0
	insGetSerial           byte = 0xF8
	insGetMetadata         byte = 0xF7
)

// Options configures a virtual card. The zero value is not useful; use New.
type Options struct {
	// Key backs the slot. When nil, New generates an ECC P-256 key.
	Key crypto.Signer

	// Slot is the PIV slot the key lives in. Defaults to 0x9A.
	Slot byte

	// Serial is reported by GET SERIAL. Defaults to 12345678.
	Serial uint32

	// PIN is the correct PIN. Defaults to "123456".
	PIN string

	// PINPolicy and TouchPolicy default to "once" and "never".
	PINPolicy   byte
	TouchPolicy byte

	// Retries is the starting PIN retry counter. Defaults to 3.
	Retries int

	// NoMetadata makes GET METADATA answer "instruction not supported", as
	// YubiKey firmware older than 5.3 does, so the fallback to reading the
	// slot certificate is exercised.
	NoMetadata bool

	// NoCertificate leaves the slot without a certificate. Combined with
	// NoMetadata this is a slot tpm2-kira cannot use, which is worth being
	// able to produce on purpose.
	NoCertificate bool
}

// Card is a virtual PIV card.
type Card struct {
	mu sync.Mutex

	key    crypto.Signer
	cert   []byte
	opts   Options
	closed chan struct{}

	pending     []byte
	pinVerified bool
	retries     int

	verifications int
	signatures    int
	touches       int
}

// New builds a virtual card.
func New(opts Options) (*Card, error) {
	if opts.Key == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate a key: %w", err)
		}
		opts.Key = key
	}
	if opts.Slot == 0 {
		opts.Slot = 0x9A
	}
	if opts.Serial == 0 {
		opts.Serial = 12345678
	}
	if opts.PIN == "" {
		opts.PIN = "123456"
	}
	if opts.PINPolicy == 0 {
		opts.PINPolicy = PINPolicyOnce
	}
	if opts.TouchPolicy == 0 {
		opts.TouchPolicy = TouchPolicyNever
	}
	if opts.Retries == 0 {
		opts.Retries = 3
	}

	card := &Card{
		key:     opts.Key,
		opts:    opts,
		retries: opts.Retries,
		closed:  make(chan struct{}),
	}

	if !opts.NoCertificate {
		cert, err := selfSignedCertificate(opts.Key)
		if err != nil {
			return nil, err
		}
		card.cert = cert
	}

	return card, nil
}

// PublicKey returns the public half of the key in the slot.
func (c *Card) PublicKey() crypto.PublicKey { return c.key.Public() }

// Serial returns the serial the card reports.
func (c *Card) Serial() uint32 { return c.opts.Serial }

// Counters reports how many PIN verifications, signatures and simulated
// touches the card has performed. A slot with PIN policy "always" should show
// one verification per signature.
func (c *Card) Counters() (verifications, signatures, touches int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.verifications, c.signatures, c.touches
}

// Attach connects the card to a vpcd reader and serves it until Close.
//
// settle gives pcscd time to notice the card before the caller starts using it;
// pcscd polls reader state rather than being told.
func (c *Card) Attach(addr string, settle time.Duration) error {
	if addr == "" {
		addr = DefaultAddr
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("cannot reach vpcd at %s: %w", addr, err)
	}

	go c.serve(conn)

	time.Sleep(settle)
	return nil
}

// Close detaches the card.
func (c *Card) Close() {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
}

// atr is a plausible T=1 ATR; pcscd only needs it to be well formed.
var atr = []byte{0x3B, 0x8C, 0x80, 0x01, 0x50, 0x49, 0x56, 0x5F, 0x49, 0x49, 0x49, 0x00, 0x00, 0x00, 0x00, 0x0D}

// vpcd control bytes. A one-byte message is a control command; anything longer
// is an APDU to answer.
const (
	vpcdPowerOff byte = 0x00
	vpcdPowerOn  byte = 0x01
	vpcdReset    byte = 0x02
	vpcdGetATR   byte = 0x04
)

func (c *Card) serve(conn net.Conn) {
	defer conn.Close()

	go func() {
		<-c.closed
		conn.Close()
	}()

	for {
		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			return
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}

		var response []byte

		if length == 1 {
			switch payload[0] {
			case vpcdGetATR:
				response = atr
			case vpcdPowerOn, vpcdPowerOff, vpcdReset:
				continue
			default:
				continue
			}
		} else {
			response = c.Handle(payload)
		}

		buf := make([]byte, 2+len(response))
		binary.BigEndian.PutUint16(buf, uint16(len(response)))
		copy(buf[2:], response)

		if _, err := conn.Write(buf); err != nil {
			return
		}
	}
}

// Handle answers one command APDU. It is exported so tests can drive the card
// directly, without a reader.
func (c *Card) Handle(apdu []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(apdu) < 4 {
		return sw(0x6F00)
	}

	switch ins := apdu[1]; ins {
	case insSelect:
		return c.respond(nil)

	case insGetResponse:
		return c.respond(c.pending)

	case insGetSerial:
		serial := make([]byte, 4)
		binary.BigEndian.PutUint32(serial, c.opts.Serial)
		return c.respond(serial)

	case insGetMetadata:
		return c.metadata(apdu[3])

	case insVerify:
		return c.verify(apdu)

	case insGetData:
		return c.getData()

	case insGeneralAuthenticate:
		return c.sign(apdu)

	default:
		return sw(0x6D00)
	}
}

func (c *Card) metadata(slot byte) []byte {
	if c.opts.NoMetadata {
		return sw(0x6D00)
	}
	if slot != c.opts.Slot {
		return sw(0x6A82)
	}

	alg, err := algorithmFor(c.key.Public())
	if err != nil {
		return sw(0x6F00)
	}

	body := append([]byte{}, tlv(0x01, []byte{alg})...)
	body = append(body, tlv(0x02, []byte{c.opts.PINPolicy, c.opts.TouchPolicy})...)
	body = append(body, tlv(0x03, []byte{0x01})...) // generated on the card
	body = append(body, tlv(0x04, encodePublicKey(c.key.Public()))...)

	return c.respond(body)
}

func (c *Card) verify(apdu []byte) []byte {
	// VERIFY with no data queries the retry counter and must not consume an
	// attempt.
	if len(apdu) == 4 {
		if c.pinVerified {
			return sw(0x9000)
		}
		if c.retries <= 0 {
			return sw(0x6983)
		}
		return sw(uint16(0x63C0 | c.retries))
	}

	if c.retries <= 0 {
		return sw(0x6983)
	}
	if len(apdu) < 5 {
		return sw(0x6700)
	}

	offered := apdu[5:]
	expected := make([]byte, 8)
	for i := range expected {
		expected[i] = 0xFF
	}
	copy(expected, c.opts.PIN)

	if string(offered) != string(expected) {
		c.retries--
		return sw(uint16(0x63C0 | maxInt(c.retries, 0)))
	}

	c.pinVerified = true
	c.retries = c.opts.Retries
	c.verifications++

	return sw(0x9000)
}

func (c *Card) getData() []byte {
	if c.cert == nil {
		return sw(0x6A82)
	}
	body := append(tlv(0x70, c.cert), tlv(0x71, []byte{0x00})...)
	return c.respond(tlv(0x53, body))
}

func (c *Card) sign(apdu []byte) []byte {
	if c.opts.PINPolicy != PINPolicyNever && !c.pinVerified {
		return sw(0x6982)
	}

	body := commandData(apdu)

	template, err := tlvValue(body, 0x7C)
	if err != nil {
		return sw(0x6A80)
	}
	challenge, err := tlvValue(template, 0x81)
	if err != nil {
		return sw(0x6A80)
	}

	if c.opts.TouchPolicy != TouchPolicyNever {
		c.touches++
	}

	var signature []byte

	switch key := c.key.(type) {
	case *ecdsa.PrivateKey:
		signature, err = ecdsa.SignASN1(rand.Reader, key, challenge)
		if err != nil {
			return sw(0x6F00)
		}

	case *rsa.PrivateKey:
		// The raw private-key operation a PIV card performs: the caller has
		// already built the padded block.
		m := new(big.Int).SetBytes(challenge)
		signature = new(big.Int).Exp(m, key.D, key.N).FillBytes(make([]byte, key.Size()))

	default:
		return sw(0x6F00)
	}

	c.signatures++

	// A slot with PIN policy "always" discards the verified state after each
	// operation, which is what forces a fresh VERIFY per signature.
	if c.opts.PINPolicy == PINPolicyAlways {
		c.pinVerified = false
	}

	return c.respond(tlv(0x7C, tlv(0x82, signature)))
}

// respond returns at most 256 bytes and reports the remainder with 61xx, the
// way a real card paces a large reply.
func (c *Card) respond(data []byte) []byte {
	const chunk = 256

	if len(data) <= chunk {
		c.pending = nil
		return append(append([]byte{}, data...), 0x90, 0x00)
	}

	c.pending = data[chunk:]

	remaining := len(c.pending)
	if remaining > 0xFF {
		remaining = 0xFF
	}

	return append(append([]byte{}, data[:chunk]...), 0x61, byte(remaining))
}

// ── encoding helpers ──────────────────────────────────────────────────────

func sw(status uint16) []byte {
	return []byte{byte(status >> 8), byte(status)}
}

func tlv(tag byte, value []byte) []byte {
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

func tlvValue(data []byte, tag byte) ([]byte, error) {
	for off := 0; off < len(data); {
		t := data[off]
		off++
		if off >= len(data) {
			return nil, errors.New("truncated TLV")
		}

		length := int(data[off])
		off++
		if length&0x80 != 0 {
			count := length & 0x7F
			if count == 0 || count > 3 || off+count > len(data) {
				return nil, errors.New("bad TLV length")
			}
			length = 0
			for i := 0; i < count; i++ {
				length = length<<8 | int(data[off+i])
			}
			off += count
		}

		if off+length > len(data) {
			return nil, errors.New("truncated TLV value")
		}
		if t == tag {
			return data[off : off+length], nil
		}
		off += length
	}
	return nil, fmt.Errorf("tag %02X not found", tag)
}

// commandData extracts the data field of a short or extended command APDU.
func commandData(apdu []byte) []byte {
	if len(apdu) < 5 {
		return nil
	}

	if apdu[4] != 0x00 {
		lc := int(apdu[4])
		if len(apdu) < 5+lc {
			return nil
		}
		return apdu[5 : 5+lc]
	}

	if len(apdu) < 7 {
		return nil
	}
	lc := int(apdu[5])<<8 | int(apdu[6])
	if len(apdu) < 7+lc {
		return nil
	}
	return apdu[7 : 7+lc]
}

func encodePublicKey(pub crypto.PublicKey) []byte {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		byteLen := (key.Curve.Params().BitSize + 7) / 8
		point := append([]byte{0x04}, append(
			key.X.FillBytes(make([]byte, byteLen)),
			key.Y.FillBytes(make([]byte, byteLen))...)...)
		return tlv(0x86, point)

	case *rsa.PublicKey:
		return append(
			tlv(0x81, key.N.Bytes()),
			tlv(0x82, big.NewInt(int64(key.E)).Bytes())...)

	default:
		return nil
	}
}

func algorithmFor(pub crypto.PublicKey) (byte, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() == 2048 {
			return algRSA2048, nil
		}
		return 0, fmt.Errorf("unsupported RSA size %d", key.N.BitLen())
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case 256:
			return algECCP256, nil
		case 384:
			return algECCP384, nil
		}
		return 0, fmt.Errorf("unsupported curve %s", key.Curve.Params().Name)
	default:
		return 0, fmt.Errorf("unsupported key type %T", pub)
	}
}

func selfSignedCertificate(key crypto.Signer) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tpm2-kira virtual PIV"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("failed to build the slot certificate: %w", err)
	}
	return der, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
