package cmd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/matthias/tpm2-kira/internal/pcsc"
	"github.com/matthias/tpm2-kira/internal/piv"
	"golang.org/x/sys/unix"
)

// ── Key file stub ────────────────────────────────────────────────────────────
//
// A signing key held on a YubiKey is represented on disk the way sbctl does
// it: the private key file holds a small JSON document naming the token
// instead of a PEM key. Everything that reads the key by path keeps working;
// only LoadSigningPrivateKey tells the two formats apart. Unlike sbctl, the
// stub records the serial number, so the right token is found even with
// several plugged in, and a wrong one is named before any PIN is sent.

const (
	yubiKeyStubBackend = "yubikey"
	yubiKeyStubVersion = 1
)

// YubiKeyStub is the content of a private key file that refers to a key held
// in a YubiKey PIV slot.
type YubiKeyStub struct {
	Backend     string `json:"backend"`
	Version     int    `json:"version"`
	Serial      uint32 `json:"serial"`
	Slot        string `json:"slot"`
	Algorithm   string `json:"algorithm"`
	PINPolicy   string `json:"pinPolicy"`
	TouchPolicy string `json:"touchPolicy"`
	PublicKey   string `json:"publicKey"` // base64 PKIX DER
}

// isYubiKeyStub reports whether key file content is a stub rather than PEM.
func isYubiKeyStub(data []byte) bool {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// ParseYubiKeyStub decodes and validates a stub. Unknown backends and
// versions are refused rather than guessed at.
func ParseYubiKeyStub(data []byte) (*YubiKeyStub, crypto.PublicKey, piv.Slot, error) {
	var stub YubiKeyStub
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&stub); err != nil {
		return nil, nil, 0, fmt.Errorf("malformed YubiKey key file: %w", err)
	}
	if stub.Backend != yubiKeyStubBackend {
		return nil, nil, 0, fmt.Errorf("key file names unknown backend %q", stub.Backend)
	}
	if stub.Version != yubiKeyStubVersion {
		return nil, nil, 0, fmt.Errorf("YubiKey key file version %d is not supported (want %d)", stub.Version, yubiKeyStubVersion)
	}
	if stub.Serial == 0 {
		return nil, nil, 0, errors.New("YubiKey key file has no serial number")
	}
	slot, err := piv.ParseSlot(stub.Slot)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("YubiKey key file: %w", err)
	}
	der, err := base64.StdEncoding.DecodeString(stub.PublicKey)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("YubiKey key file: public key is not base64: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("YubiKey key file: %w", err)
	}
	if reason := tokenKeyUnsuitable(pub); reason != "" {
		return nil, nil, 0, fmt.Errorf("YubiKey key file: %s", reason)
	}
	return &stub, pub, slot, nil
}

// MarshalYubiKeyStub encodes the stub for a key found on a token.
func MarshalYubiKeyStub(serial uint32, s TokenSlot) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(s.PublicKey)
	if err != nil {
		return nil, err
	}
	stub := YubiKeyStub{
		Backend:     yubiKeyStubBackend,
		Version:     yubiKeyStubVersion,
		Serial:      serial,
		Slot:        s.Slot.String(),
		Algorithm:   s.Algorithm.String(),
		PINPolicy:   s.pinPolicyString(),
		TouchPolicy: s.touchPolicyString(),
		PublicKey:   base64.StdEncoding.EncodeToString(der),
	}
	out, err := json.MarshalIndent(stub, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// tokenKeyUnsuitable returns why a token key cannot serve as the tpm2-kira
// signing key, or "" if it can. The TPM must be able to load the public key
// for PolicySigned: RSA-2048, P-256 and P-384 are what TPMs support broadly.
func tokenKeyUnsuitable(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() {
			return ""
		}
		return fmt.Sprintf("curve %s is not supported by the TPM", k.Curve.Params().Name)
	case *rsa.PublicKey:
		if k.N.BitLen() == 2048 {
			return ""
		}
		return fmt.Sprintf("RSA-%d cannot be loaded by most TPMs (RSA-2048 required)", k.N.BitLen())
	case nil:
		return "no public key available"
	}
	return fmt.Sprintf("%T keys are not supported by the TPM", pub)
}

// ── Token discovery ──────────────────────────────────────────────────────────

// TokenProbeTimeout bounds each exchange with pcscd while looking for tokens,
// so a wedged daemon cannot hang setup.
const TokenProbeTimeout = 2 * time.Second

// tokenConn is one card reachable for PIV commands.
type tokenConn struct {
	reader    string
	transport piv.Transport
	begin     func() error // start an exclusive transaction; nil if not needed
	end       func() error
	close     func(reset bool) error
}

// dialTokens opens every card present. Tests replace it with emulated cards.
var dialTokens = dialPCSCTokens

func dialPCSCTokens(timeout time.Duration) ([]*tokenConn, func(), error) {
	client, err := pcsc.Dial(timeout)
	if err != nil {
		return nil, nil, err
	}
	readers, err := client.Readers()
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	var conns []*tokenConn
	for _, r := range readers {
		if !r.CardPresent {
			continue
		}
		card, err := client.Connect(r.Name)
		if err != nil {
			continue
		}
		conns = append(conns, &tokenConn{
			reader:    r.Name,
			transport: card,
			begin:     card.BeginTransaction,
			end:       card.EndTransaction,
			close: func(reset bool) error {
				if reset {
					return card.DisconnectReset()
				}
				return card.Disconnect()
			},
		})
	}
	return conns, func() {
		for _, c := range conns {
			c.close(false)
		}
		client.Close()
	}, nil
}

// TokenInfo describes one card found while probing.
type TokenInfo struct {
	Reader  string
	Serial  uint32 // 0 if the card does not report one
	Version piv.Version
	Err     error // why the card could not be inspected, if it could not
	Slots   []TokenSlot
}

// TokenSlot is one populated key slot.
type TokenSlot struct {
	Slot          piv.Slot
	Algorithm     piv.Algorithm
	PINPolicy     piv.PINPolicy
	TouchPolicy   piv.TouchPolicy
	PoliciesKnown bool // false on firmware before 5.3, which has no metadata
	PublicKey     crypto.PublicKey
	Unsuitable    string // "" if the key can be the tpm2-kira signing key
	CertOnly      bool   // key found through its certificate, not metadata
}

// Suitable reports whether the token has at least one usable key.
func (t TokenInfo) Suitable() bool {
	if t.Err != nil || t.Serial == 0 {
		return false
	}
	for _, s := range t.Slots {
		if s.Unsuitable == "" {
			return true
		}
	}
	return false
}

// SlotByID returns the populated slot, if any.
func (t TokenInfo) SlotByID(id piv.Slot) (TokenSlot, bool) {
	for _, s := range t.Slots {
		if s.Slot == id {
			return s, true
		}
	}
	return TokenSlot{}, false
}

func (s TokenSlot) effectivePINPolicy() piv.PINPolicy {
	if s.PINPolicy != piv.PINPolicyDefault {
		return s.PINPolicy
	}
	switch s.Slot {
	case piv.SlotSignature:
		return piv.PINPolicyAlways
	case piv.SlotCardAuth:
		return piv.PINPolicyNever
	}
	return piv.PINPolicyOnce
}

func (s TokenSlot) effectiveTouchPolicy() piv.TouchPolicy {
	if s.TouchPolicy == piv.TouchPolicyDefault {
		return piv.TouchPolicyNever
	}
	return s.TouchPolicy
}

func (s TokenSlot) pinPolicyString() string {
	if !s.PoliciesKnown {
		return "unknown"
	}
	return s.effectivePINPolicy().String()
}

func (s TokenSlot) touchPolicyString() string {
	if !s.PoliciesKnown {
		return "unknown"
	}
	return s.effectiveTouchPolicy().String()
}

// ProbeYubiKeys lists the PIV tokens present and the keys they hold.
//
// It is read-only and PIN-free: SELECT, GET VERSION, GET SERIAL, and per slot
// GET METADATA or the slot certificate. No VERIFY is ever sent, so probing
// cannot cost a PIN attempt. The error is non-nil only when no token could be
// looked for at all (no pcscd, for example).
func ProbeYubiKeys(timeout time.Duration) ([]TokenInfo, error) {
	conns, closeAll, err := dialTokens(timeout)
	if err != nil {
		return nil, err
	}
	defer closeAll()
	var infos []TokenInfo
	for _, c := range conns {
		infos = append(infos, inspectToken(c))
	}
	return infos, nil
}

func inspectToken(c *tokenConn) TokenInfo {
	info := TokenInfo{Reader: c.reader}
	card, err := piv.Open(c.transport)
	if err != nil {
		info.Err = err
		return info
	}
	if v, err := card.Version(); err == nil {
		info.Version = v
	}
	if s, err := card.Serial(); err == nil {
		info.Serial = s
	} else {
		info.Err = fmt.Errorf("the card does not report a serial number (a YubiKey with firmware 5 or later is required): %w", err)
		return info
	}
	for _, slot := range piv.KeySlots() {
		md, err := card.Metadata(slot)
		switch {
		case err == nil:
			ts := TokenSlot{Slot: slot, Algorithm: md.Algorithm, PINPolicy: md.PINPolicy,
				TouchPolicy: md.TouchPolicy, PoliciesKnown: true, PublicKey: md.PublicKey}
			ts.Unsuitable = tokenKeyUnsuitable(md.PublicKey)
			if md.PublicKey == nil {
				ts.Unsuitable = fmt.Sprintf("%s keys are not supported by the TPM", md.Algorithm)
			}
			info.Slots = append(info.Slots, ts)
		case errors.Is(err, piv.ErrNotFound):
			// empty slot
		case errors.Is(err, piv.ErrNotSupported):
			// Firmware before 5.3: fall back to the slot certificate.
			cert, cerr := card.Certificate(slot)
			if cerr != nil {
				continue
			}
			ts := TokenSlot{Slot: slot, PublicKey: cert.PublicKey, CertOnly: true}
			ts.Algorithm = algorithmOf(cert.PublicKey)
			ts.Unsuitable = tokenKeyUnsuitable(cert.PublicKey)
			info.Slots = append(info.Slots, ts)
		}
	}
	return info
}

func algorithmOf(pub crypto.PublicKey) piv.Algorithm {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return piv.AlgECCP256
		case elliptic.P384():
			return piv.AlgECCP384
		}
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 1024:
			return piv.AlgRSA1024
		case 2048:
			return piv.AlgRSA2048
		case 3072:
			return piv.AlgRSA3072
		case 4096:
			return piv.AlgRSA4096
		}
	}
	return 0
}

// recommendedSlot picks the slot setup uses without --slot: 9a, the slot the
// documentation tells people to create for tpm2-kira. Another slot is never
// picked implicitly, because it is likely shared (9c with sbctl, typically).
func recommendedSlot(t TokenInfo) (TokenSlot, bool) {
	s, ok := t.SlotByID(piv.SlotAuthentication)
	return s, ok && s.Unsuitable == ""
}

// PrintTokenReport writes what ProbeYubiKeys found, as setup and
// 'yubikey list' show it.
func PrintTokenReport(w io.Writer, infos []TokenInfo) {
	for _, t := range infos {
		switch {
		case t.Err != nil:
			fmt.Fprintf(w, "  %s: not usable — %v\n", t.Reader, t.Err)
			continue
		default:
			fmt.Fprintf(w, "  YubiKey serial %d, firmware %s (%s)\n", t.Serial, t.Version, t.Reader)
		}
		if len(t.Slots) == 0 {
			fmt.Fprintln(w, "    no keys in any PIV slot")
			continue
		}
		rec, hasRec := recommendedSlot(t)
		for _, s := range t.Slots {
			policies := fmt.Sprintf("PIN %-7s touch %-7s", s.pinPolicyString(), s.touchPolicyString())
			var notes []string
			switch {
			case s.Unsuitable != "":
				notes = append(notes, "not usable: "+s.Unsuitable)
			case hasRec && s.Slot == rec.Slot:
				notes = append(notes, "<- recommended")
			}
			if s.Unsuitable == "" && s.PoliciesKnown && s.effectivePINPolicy() == piv.PINPolicyNever {
				notes = append(notes, "WARNING: no PIN required (insecure)")
			}
			note := strings.Join(notes, "  ")
			line := fmt.Sprintf("    slot %s  %-8s %s %s", s.Slot, s.Algorithm, policies, note)
			fmt.Fprintln(w, strings.TrimRight(line, " "))
		}
	}
}

// ── Signing through the token ────────────────────────────────────────────────

// PINEnvVar supplies the PIV PIN for unattended use.
const PINEnvVar = "TPM2_KIRA_PIN"

// yubiKeySigner is a crypto.Signer whose private key lives in a PIV slot.
//
// Loading the key file does not touch the token: Public() is served from the
// stub, so blob verification and policy computation work with the token
// unplugged. The token is opened on the first Sign.
type yubiKeySigner struct {
	path string
	stub *YubiKeyStub
	pub  crypto.PublicKey
	slot piv.Slot
}

// Public returns the public key recorded in the key file.
func (s *yubiKeySigner) Public() crypto.PublicKey { return s.pub }

// Describe names the token and slot, for messages.
func (s *yubiKeySigner) Describe() string {
	return fmt.Sprintf("YubiKey %d, slot %s", s.stub.Serial, s.slot)
}

// YubiKeyDescription returns "YubiKey N, slot S" when key is token-backed.
func YubiKeyDescription(key crypto.Signer) (string, bool) {
	if s, ok := key.(*yubiKeySigner); ok {
		return s.Describe(), true
	}
	return "", false
}

// Sign signs a SHA-256 digest on the token. The result has the same format as
// the software keys produce: ASN.1 DER for ECDSA, PKCS #1 v1.5 for RSA.
func (s *yubiKeySigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, fmt.Errorf("token signing supports SHA-256 digests only")
	}
	sess, err := tokenSessionFor(s)
	if err != nil {
		return nil, err
	}
	return sess.sign(s, digest)
}

// tokenSession is one open card, shared by every signature in the process.
//
// The PIN rules live here. A PIV PIN allows three attempts, and exhausting
// the PUK after that destroys the key. So: the PIN is obtained once and
// verified once per need; a wrong PIN poisons the session and every later
// signature fails without touching the card; and nothing is tried when only
// one attempt is left.
type tokenSession struct {
	serial   uint32
	conn     *tokenConn
	card     *piv.Card
	closeAll func()
	pin      string
	unlocked bool  // this process has verified the PIN at least once
	fatal    error // sticky: set on anything that must not be retried
	touched  bool
}

var tokenSessions = map[uint32]*tokenSession{}

// ErrTokenUnavailable wraps every reason a token key cannot sign right now:
// no pcscd, no token or the wrong one, an empty slot, no PIN, a refused or
// blocked PIN. It never covers a key that is present but different from the
// key file; that is a configuration error, not an absence.
var ErrTokenUnavailable = errors.New("signing key on YubiKey is unavailable")

// TokenUnavailableError is ErrTokenUnavailable with its details.
type TokenUnavailableError struct {
	Token  string // "YubiKey N, slot S"
	Reason string
}

func (e *TokenUnavailableError) Error() string {
	return fmt.Sprintf("%v (%s): %s", ErrTokenUnavailable, e.Token, e.Reason)
}

func (e *TokenUnavailableError) Unwrap() error { return ErrTokenUnavailable }

func unavailable(s *yubiKeySigner, format string, a ...any) error {
	return &TokenUnavailableError{Token: s.Describe(), Reason: fmt.Sprintf(format, a...)}
}

func tokenSessionFor(s *yubiKeySigner) (*tokenSession, error) {
	if sess, ok := tokenSessions[s.stub.Serial]; ok {
		if sess.fatal != nil {
			return nil, sess.fatal
		}
		return sess, nil
	}
	conns, closeAll, err := dialTokens(TokenProbeTimeout)
	if err != nil {
		return nil, unavailable(s, "%v", err)
	}
	var seen []string
	for _, c := range conns {
		card, err := piv.Open(c.transport)
		if err != nil {
			continue
		}
		serial, err := card.Serial()
		if err != nil {
			continue
		}
		if serial != s.stub.Serial {
			seen = append(seen, fmt.Sprint(serial))
			continue
		}
		sess := &tokenSession{serial: serial, conn: c, card: card, closeAll: closeAll}
		if err := sess.checkKey(s); err != nil {
			closeAll()
			return nil, err
		}
		tokenSessions[serial] = sess
		return sess, nil
	}
	closeAll()
	if len(seen) > 0 {
		return nil, unavailable(s, "no YubiKey with serial %d is present (found: %s)", s.stub.Serial, strings.Join(seen, ", "))
	}
	return nil, unavailable(s, "no YubiKey with serial %d is present", s.stub.Serial)
}

// checkKey compares the key in the slot with the key file before any PIN is
// sent, when the card can tell (metadata, or a certificate). A replaced slot
// key is then reported as such, not as an obscure TPM policy failure later.
func (sess *tokenSession) checkKey(s *yubiKeySigner) error {
	var onCard crypto.PublicKey
	if md, err := sess.card.Metadata(s.slot); err == nil {
		onCard = md.PublicKey
	} else if errors.Is(err, piv.ErrNotFound) {
		return unavailable(s, "the slot is empty")
	} else if cert, err := sess.card.Certificate(s.slot); err == nil {
		onCard = cert.PublicKey
	}
	if onCard == nil {
		return nil // checked after the first signature instead
	}
	if !publicKeysEqual(onCard, s.pub) {
		return fmt.Errorf("the key in slot %s of YubiKey %d is not the key in %s — "+
			"the slot was regenerated or the key file belongs to a different setup", s.slot, s.stub.Serial, s.path)
	}
	return nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	ea, ok := a.(equaler)
	return ok && ea.Equal(b)
}

// PrepareSigningKey makes sure key can sign before a command changes
// anything. For a key on a token it finds the token, compares the slot key
// with the key file and verifies the PIN, so an absent token or a missing PIN
// is found while nothing has been touched. Software keys are always ready.
func PrepareSigningKey(key crypto.Signer) error {
	s, ok := key.(*yubiKeySigner)
	if !ok {
		return nil
	}
	sess, err := tokenSessionFor(s)
	if err != nil {
		return err
	}
	return sess.transaction(s, func() error { return sess.ensurePIN(s) })
}

// transaction runs fn with exclusive use of the card and the PIV applet
// selected.
func (sess *tokenSession) transaction(s *yubiKeySigner, fn func() error) error {
	if sess.fatal != nil {
		return sess.fatal
	}
	if sess.conn.begin != nil {
		if err := sess.conn.begin(); err != nil {
			return unavailable(s, "%v", err)
		}
		defer sess.conn.end()
	}
	// Another process may have selected a different applet since the last
	// transaction; select PIV again inside this one.
	if _, err := piv.Open(sess.conn.transport); err != nil {
		return unavailable(s, "%v", err)
	}
	return fn()
}

func (sess *tokenSession) sign(s *yubiKeySigner, digest []byte) (sig []byte, err error) {
	err = sess.transaction(s, func() error {
		sig, err = sess.signLocked(s, digest)
		return err
	})
	return sig, err
}

func (sess *tokenSession) signLocked(s *yubiKeySigner, digest []byte) (sig []byte, err error) {
	for attempt := 0; attempt < 2; attempt++ {
		if err := sess.ensurePIN(s); err != nil {
			return nil, err
		}
		if s.stub.TouchPolicy == piv.TouchPolicyAlways.String() ||
			(s.stub.TouchPolicy == piv.TouchPolicyCached.String() && !sess.touched) {
			fmt.Fprintf(os.Stderr, "Touch the YubiKey (serial %d) to sign...\n", s.stub.Serial)
			sess.touched = true
		}
		sig, err = sess.card.Sign(s.slot, s.pub, digest)
		if errors.Is(err, piv.ErrPINRequired) {
			// PIN policy ALWAYS: the card forgot the PIN after the last
			// signature. A correct VERIFY resets the counter, so
			// verifying again costs nothing.
			sess.unlocked = false
			continue
		}
		break
	}
	if err != nil {
		return nil, fmt.Errorf("signing on %s failed: %w", s.Describe(), err)
	}
	if !verifySignature(s.pub, digest, sig) {
		sess.fatal = fmt.Errorf("the signature from slot %s of YubiKey %d does not verify against the key in %s — "+
			"the slot holds a different key", s.slot, s.stub.Serial, s.path)
		return nil, sess.fatal
	}
	return sig, nil
}

// ensurePIN makes sure the PIN is verified, asking for it at most once per
// process and never retrying a rejected one.
func (sess *tokenSession) ensurePIN(s *yubiKeySigner) error {
	if s.stub.PINPolicy == piv.PINPolicyNever.String() {
		return nil
	}
	remaining, verified, err := sess.card.PINRetries()
	if err != nil {
		return unavailable(s, "reading the PIN retry counter: %v", err)
	}
	if verified {
		return nil
	}
	if remaining == 0 {
		sess.fatal = unavailable(s, "%v", piv.ErrPINBlocked)
		return sess.fatal
	}
	if remaining == 1 && !sess.unlocked {
		sess.fatal = unavailable(s, "only one PIN attempt is left, and tpm2-kira will not risk it.\n"+
			"  Check the PIN, then reset the counter with the PUK:\n"+
			"      ykman piv access unblock-pin")
		return sess.fatal
	}
	if remaining < 3 && !sess.unlocked {
		fmt.Fprintf(os.Stderr, "YubiKey %d: PIN retries remaining: %d\n", s.stub.Serial, remaining)
	}
	if sess.pin == "" {
		pin, err := pinSource(s)
		if err != nil {
			sess.fatal = unavailable(s, "%v", err)
			return sess.fatal
		}
		sess.pin = pin
	}
	if err := sess.card.VerifyPIN(sess.pin); err != nil {
		sess.pin = ""
		sess.fatal = unavailable(s, "%v — stopping here so no further attempt is spent", err)
		return sess.fatal
	}
	sess.unlocked = true
	return nil
}

// pinSource obtains the PIN; tests replace it.
var pinSource = readPIN

// readPIN takes the PIN from TPM2_KIRA_PIN, or asks on the terminal when
// there is one. Hooks have no terminal, so they need the variable.
func readPIN(s *yubiKeySigner) (string, error) {
	if pin, ok := os.LookupEnv(PINEnvVar); ok && pin != "" {
		return pin, nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no PIN: set %s (there is no terminal to ask on)", PINEnvVar)
	}
	defer tty.Close()
	fmt.Fprintf(tty, "PIN for %s: ", s.Describe())
	pin, err := readNoEcho(tty)
	fmt.Fprintln(tty)
	if err != nil {
		return "", fmt.Errorf("reading the PIN: %w", err)
	}
	if pin == "" {
		return "", errors.New("no PIN entered")
	}
	return pin, nil
}

func readNoEcho(tty *os.File) (string, error) {
	fd := int(tty.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", err
	}
	raw := *old
	raw.Lflag &^= unix.ECHO
	raw.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return "", err
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, old)

	var buf []byte
	b := make([]byte, 1)
	for len(buf) < 64 {
		n, err := tty.Read(b)
		if err != nil {
			return "", err
		}
		if n == 0 || b[0] == '\n' || b[0] == '\r' {
			break
		}
		buf = append(buf, b[0])
	}
	return string(buf), nil
}

// CloseTokenSessions resets and releases every token this process opened. The
// reset discards the verified PIN, so no other process can sign with the key
// after tpm2-kira exits. Safe to call when nothing was opened.
func CloseTokenSessions() {
	for serial, sess := range tokenSessions {
		if sess.unlocked {
			sess.conn.close(true)
		}
		sess.closeAll()
		sess.pin = ""
		delete(tokenSessions, serial)
	}
}
