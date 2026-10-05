package attest

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// A minimal implementation of the Noise Protocol Framework (revision 34),
// restricted to what tpm2-kira uses:
//
//	Noise_XX_25519_ChaChaPoly_SHA256   enrolment: neither side knows the other
//	Noise_IK_25519_ChaChaPoly_SHA256   attestation: the phone knows the machine
//
// The phone (BLE central) is always the initiator and the machine always the
// responder. Only these two patterns, one DH, one cipher and one hash are
// implemented; there is no negotiation, so there is nothing to downgrade.
//
// After the handshake the handshake hash h is the channel binding value `cb`
// of PLAN-REMOTEATTESTATION.md §6.2: both ends of one session hold the same h,
// and nobody outside the session can produce it.

// NoisePrologue is mixed into every handshake. A peer speaking another
// protocol revision fails the first decryption instead of misreading data.
const NoisePrologue = "tpm2-kira/v1"

// NoiseKeySize is the size of X25519 keys and of the channel binding value.
const NoiseKeySize = 32

const (
	noiseTagSize    = 16
	noiseMaxMessage = 65535
	// MaxNoisePlaintext is the largest payload one transport message carries.
	MaxNoisePlaintext = noiseMaxMessage - noiseTagSize
)

// HandshakePattern selects one of the two supported patterns.
type HandshakePattern uint8

const (
	// PatternXX is used once, at enrolment, and must be confirmed with the
	// short authentication string (sas.go).
	PatternXX HandshakePattern = 1
	// PatternIK is used for every attestation after enrolment.
	PatternIK HandshakePattern = 2
)

func (p HandshakePattern) protocolName() string {
	switch p {
	case PatternXX:
		return "Noise_XX_25519_ChaChaPoly_SHA256"
	case PatternIK:
		return "Noise_IK_25519_ChaChaPoly_SHA256"
	}
	return ""
}

type token uint8

const (
	tokE token = iota
	tokS
	tokEE
	tokES
	tokSE
	tokSS
)

func (p HandshakePattern) messages() [][]token {
	switch p {
	case PatternXX:
		return [][]token{{tokE}, {tokE, tokEE, tokS, tokES}, {tokS, tokSE}}
	case PatternIK:
		return [][]token{{tokE, tokES, tokS, tokSS}, {tokE, tokEE, tokSE}}
	}
	return nil
}

// NoiseKeypair is an X25519 key pair.
type NoiseKeypair struct {
	Private []byte
	Public  []byte
}

// GenerateNoiseKeypair creates a fresh X25519 key pair.
func GenerateNoiseKeypair(r io.Reader) (*NoiseKeypair, error) {
	if r == nil {
		r = rand.Reader
	}
	k, err := ecdh.X25519().GenerateKey(r)
	if err != nil {
		return nil, err
	}
	return &NoiseKeypair{Private: k.Bytes(), Public: k.PublicKey().Bytes()}, nil
}

// NoiseKeypairFromPrivate reconstructs a key pair from a stored private key.
func NoiseKeypairFromPrivate(priv []byte) (*NoiseKeypair, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("attest: invalid X25519 private key: %w", err)
	}
	return &NoiseKeypair{Private: k.Bytes(), Public: k.PublicKey().Bytes()}, nil
}

func dh(priv, pub []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	p, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	// crypto/ecdh rejects low-order points (an all-zero shared secret), so a
	// peer cannot force a known key.
	return k.ECDH(p)
}

// CipherState is one direction of an established session.
type CipherState struct {
	k   [32]byte
	n   uint64
	has bool
}

func (c *CipherState) init(k []byte) {
	copy(c.k[:], k)
	c.n = 0
	c.has = true
}

func (c *CipherState) nonce() []byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], c.n)
	return nonce[:]
}

// Encrypt seals plaintext with associated data ad.
func (c *CipherState) Encrypt(ad, plaintext []byte) ([]byte, error) {
	if !c.has {
		return append([]byte(nil), plaintext...), nil
	}
	if c.n == ^uint64(0) {
		return nil, errors.New("attest: noise nonce exhausted")
	}
	aead, err := chacha20poly1305.New(c.k[:])
	if err != nil {
		return nil, err
	}
	out := aead.Seal(nil, c.nonce(), plaintext, ad)
	c.n++
	return out, nil
}

// Decrypt opens ciphertext with associated data ad.
func (c *CipherState) Decrypt(ad, ciphertext []byte) ([]byte, error) {
	if !c.has {
		return append([]byte(nil), ciphertext...), nil
	}
	if c.n == ^uint64(0) {
		return nil, errors.New("attest: noise nonce exhausted")
	}
	aead, err := chacha20poly1305.New(c.k[:])
	if err != nil {
		return nil, err
	}
	out, err := aead.Open(nil, c.nonce(), ciphertext, ad)
	if err != nil {
		return nil, errors.New("attest: noise decryption failed")
	}
	c.n++
	return out, nil
}

type symmetricState struct {
	cs CipherState
	ck [32]byte
	h  [32]byte
}

func (s *symmetricState) init(name string) {
	if len(name) <= 32 {
		copy(s.h[:], name)
	} else {
		s.h = sha256.Sum256([]byte(name))
	}
	s.ck = s.h
}

func hmacSHA256(key []byte, data ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

func noiseHKDF2(ck, ikm []byte) ([]byte, []byte) {
	tmp := hmacSHA256(ck, ikm)
	o1 := hmacSHA256(tmp, []byte{0x01})
	o2 := hmacSHA256(tmp, o1, []byte{0x02})
	return o1, o2
}

func (s *symmetricState) mixKey(ikm []byte) {
	ck, k := noiseHKDF2(s.ck[:], ikm)
	copy(s.ck[:], ck)
	s.cs.init(k)
}

func (s *symmetricState) mixHash(data []byte) {
	hh := sha256.New()
	hh.Write(s.h[:])
	hh.Write(data)
	copy(s.h[:], hh.Sum(nil))
}

func (s *symmetricState) encryptAndHash(p []byte) ([]byte, error) {
	c, err := s.cs.Encrypt(s.h[:], p)
	if err != nil {
		return nil, err
	}
	s.mixHash(c)
	return c, nil
}

func (s *symmetricState) decryptAndHash(c []byte) ([]byte, error) {
	p, err := s.cs.Decrypt(s.h[:], c)
	if err != nil {
		return nil, err
	}
	s.mixHash(c)
	return p, nil
}

func (s *symmetricState) split() (*CipherState, *CipherState) {
	k1, k2 := noiseHKDF2(s.ck[:], nil)
	c1, c2 := &CipherState{}, &CipherState{}
	c1.init(k1)
	c2.init(k2)
	return c1, c2
}

// Handshake runs one Noise handshake.
type Handshake struct {
	pattern   HandshakePattern
	initiator bool
	ss        symmetricState
	s         *NoiseKeypair
	e         *NoiseKeypair
	rs        []byte
	re        []byte
	msgs      [][]token
	idx       int
	rng       io.Reader

	send, recv *CipherState

	fixedEphemeral []byte // tests only: the ephemeral private key of a test vector
}

// NewHandshake prepares a handshake. For PatternIK the initiator must pass
// the responder's static public key as remoteStatic; in every other case it
// must be nil. rng may be nil for crypto/rand.
func NewHandshake(p HandshakePattern, initiator bool, static *NoiseKeypair, remoteStatic []byte, rng io.Reader) (*Handshake, error) {
	return newHandshake(p, initiator, static, remoteStatic, rng, []byte(NoisePrologue))
}

// newHandshake takes the prologue as a parameter so the implementation can be
// checked against the published Noise test vectors (noise_vectors_test.go).
func newHandshake(p HandshakePattern, initiator bool, static *NoiseKeypair, remoteStatic []byte, rng io.Reader, prologue []byte) (*Handshake, error) {
	name := p.protocolName()
	if name == "" {
		return nil, fmt.Errorf("attest: unknown handshake pattern %d", p)
	}
	if static == nil {
		return nil, errors.New("attest: a static key is required")
	}
	if rng == nil {
		rng = rand.Reader
	}
	hs := &Handshake{pattern: p, initiator: initiator, s: static, msgs: p.messages(), rng: rng}
	hs.ss.init(name)
	hs.ss.mixHash(prologue)

	if p == PatternIK {
		// Pre-message pattern "<- s": the responder's static key is known to
		// the initiator beforehand and is mixed in by both sides.
		if initiator {
			if len(remoteStatic) != NoiseKeySize {
				return nil, errors.New("attest: IK initiator needs the responder's static key")
			}
			hs.rs = append([]byte(nil), remoteStatic...)
			hs.ss.mixHash(hs.rs)
		} else {
			if remoteStatic != nil {
				return nil, errors.New("attest: IK responder learns the initiator's key from the handshake")
			}
			hs.ss.mixHash(static.Public)
		}
	} else if remoteStatic != nil {
		return nil, errors.New("attest: XX takes no pre-shared remote key")
	}
	return hs, nil
}

// ephemeral returns a fresh ephemeral key, or the one a test vector fixes.
// (Go's X25519 key generation deliberately reads a varying number of bytes
// from its random source, so vectors cannot be replayed through rng.)
func (hs *Handshake) ephemeral() (*NoiseKeypair, error) {
	if hs.fixedEphemeral != nil {
		return NoiseKeypairFromPrivate(hs.fixedEphemeral)
	}
	return GenerateNoiseKeypair(hs.rng)
}

// myTurn reports whether this side writes the next handshake message.
func (hs *Handshake) myTurn() bool { return (hs.idx%2 == 0) == hs.initiator }

// Complete reports whether the handshake has finished.
func (hs *Handshake) Complete() bool { return hs.idx >= len(hs.msgs) }

// WriteMessage produces the next handshake message, carrying payload.
func (hs *Handshake) WriteMessage(payload []byte) ([]byte, error) {
	if hs.Complete() {
		return nil, errors.New("attest: handshake already complete")
	}
	if !hs.myTurn() {
		return nil, errors.New("attest: not this side's turn to write")
	}
	var out []byte
	for _, t := range hs.msgs[hs.idx] {
		switch t {
		case tokE:
			e, err := hs.ephemeral()
			if err != nil {
				return nil, err
			}
			hs.e = e
			out = append(out, e.Public...)
			hs.ss.mixHash(e.Public)
		case tokS:
			c, err := hs.ss.encryptAndHash(hs.s.Public)
			if err != nil {
				return nil, err
			}
			out = append(out, c...)
		default:
			if err := hs.mixDH(t); err != nil {
				return nil, err
			}
		}
	}
	c, err := hs.ss.encryptAndHash(payload)
	if err != nil {
		return nil, err
	}
	out = append(out, c...)
	if len(out) > noiseMaxMessage {
		return nil, errors.New("attest: handshake message too large")
	}
	hs.advance()
	return out, nil
}

// ReadMessage consumes the peer's next handshake message and returns its payload.
func (hs *Handshake) ReadMessage(msg []byte) ([]byte, error) {
	if hs.Complete() {
		return nil, errors.New("attest: handshake already complete")
	}
	if hs.myTurn() {
		return nil, errors.New("attest: not the peer's turn to write")
	}
	if len(msg) > noiseMaxMessage {
		return nil, errors.New("attest: handshake message too large")
	}
	for _, t := range hs.msgs[hs.idx] {
		switch t {
		case tokE:
			if len(msg) < NoiseKeySize {
				return nil, errors.New("attest: handshake message truncated")
			}
			hs.re = append([]byte(nil), msg[:NoiseKeySize]...)
			msg = msg[NoiseKeySize:]
			hs.ss.mixHash(hs.re)
		case tokS:
			n := NoiseKeySize
			if hs.ss.cs.has {
				n += noiseTagSize
			}
			if len(msg) < n {
				return nil, errors.New("attest: handshake message truncated")
			}
			rs, err := hs.ss.decryptAndHash(msg[:n])
			if err != nil {
				return nil, err
			}
			hs.rs = rs
			msg = msg[n:]
		default:
			if err := hs.mixDH(t); err != nil {
				return nil, err
			}
		}
	}
	p, err := hs.ss.decryptAndHash(msg)
	if err != nil {
		return nil, err
	}
	hs.advance()
	return p, nil
}

func (hs *Handshake) mixDH(t token) error {
	var priv, pub []byte
	// Tokens are named from the initiator's point of view: "es" is the
	// initiator's ephemeral with the responder's static.
	switch t {
	case tokEE:
		priv, pub = hs.e.Private, hs.re
	case tokSS:
		priv, pub = hs.s.Private, hs.rs
	case tokES:
		if hs.initiator {
			priv, pub = hs.e.Private, hs.rs
		} else {
			priv, pub = hs.s.Private, hs.re
		}
	case tokSE:
		if hs.initiator {
			priv, pub = hs.s.Private, hs.re
		} else {
			priv, pub = hs.e.Private, hs.rs
		}
	}
	if priv == nil || pub == nil {
		return errors.New("attest: handshake key missing for DH")
	}
	shared, err := dh(priv, pub)
	if err != nil {
		return fmt.Errorf("attest: handshake DH failed: %w", err)
	}
	hs.ss.mixKey(shared)
	return nil
}

func (hs *Handshake) advance() {
	hs.idx++
	if hs.Complete() {
		c1, c2 := hs.ss.split()
		if hs.initiator {
			hs.send, hs.recv = c1, c2
		} else {
			hs.send, hs.recv = c2, c1
		}
		hs.e = nil
	}
}

// Session is an established, encrypted, mutually authenticated channel.
type Session struct {
	send, recv *CipherState
	cb         [32]byte
	remote     []byte
}

// Session returns the transport session once the handshake is complete.
func (hs *Handshake) Session() (*Session, error) {
	if !hs.Complete() {
		return nil, errors.New("attest: handshake not complete")
	}
	s := &Session{send: hs.send, recv: hs.recv, cb: hs.ss.h, remote: append([]byte(nil), hs.rs...)}
	return s, nil
}

// ChannelBinding returns the handshake hash, the value `cb` that the quote's
// qualifying data commits to.
func (s *Session) ChannelBinding() []byte { return append([]byte(nil), s.cb[:]...) }

// RemoteStatic returns the peer's static public key as authenticated by the handshake.
func (s *Session) RemoteStatic() []byte { return append([]byte(nil), s.remote...) }

// Seal encrypts one transport message.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxNoisePlaintext {
		return nil, fmt.Errorf("attest: transport message of %d bytes exceeds %d", len(plaintext), MaxNoisePlaintext)
	}
	return s.send.Encrypt(nil, plaintext)
}

// Open decrypts one transport message. Messages must arrive in order; one
// that does not fails, and the session must then be dropped.
func (s *Session) Open(ciphertext []byte) ([]byte, error) {
	return s.recv.Decrypt(nil, ciphertext)
}

// EqualKeys compares two public keys in constant time.
func EqualKeys(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}
