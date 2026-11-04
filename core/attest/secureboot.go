package attest

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"unicode/utf16"

	"github.com/google/go-tpm/tpm2"
)

// Secure Boot's state as a verifier establishes it: from the PCR 7 the TPM signed
// in a quote, and the digests of PCR 7's events, replayed against it. Nothing the
// machine says is taken: the digests are believed only because they replay to the
// quoted value, and each state is read from a digest only that state's event has.
//
// Secure Boot's variables are measured as UEFI_VARIABLE_DATA, and the event's digest
// is the hash of that structure (TCG PC Client Platform Firmware Profile,
// EV_EFI_VARIABLE_DRIVER_CONFIG). So the verifier makes the structures itself, for
// SecureBoot = 1, SecureBoot = 0 or absent, and an empty PK, and looks for their
// hashes among the digests before PCR 7's separator; event types, which no signature
// covers, are not used, and no variable travels. An empty PK is what Setup Mode is:
// the firmware's SetupMode variable is not measured.
//
// The separator is the firmware's own end of this part: what runs after it (the boot
// loader, the system, a root user) can extend PCR 7 but cannot place an event before
// it. What the state rests on is the firmware that measured it, PCR 0's business:
// firmware that lies measures what it likes.
//
// On takes more than SecureBoot = 1. Two things the firmware says of its own part take
// it away, as go-attestation's ParseSecurebootState does too: the action "UEFI Debug
// Mode", a debugger that can go round any signature check, and a separator of the error
// value, firmware that says its measurements went wrong. Off and Setup Mode stay as they
// are then: they are red anyway, and say more.
//
// What a chain of digests cannot show, and on does not check: that a key was used
// (EV_EFI_VARIABLE_AUTHORITY has a digest of what the firmware's db holds, which no
// verifier knows here; on the one real machine's log seen, a certificate that verified two
// binaries was measured once, after the separator, and whether every firmware does so is
// not known), and that KEK and db hold anything. PCR 7 itself covers that event: a
// different or missing certificate does not match an approved value. A firmware's digest over
// the variable's data alone, not UEFI_VARIABLE_DATA, is no event of any state: it stays
// not established, as for go-attestation (docs/SECURITY-BACKGROUND.md, §13.5).
//
// A slot on the SHA-1 bank may have no SHA-1 events to replay: a firmware's log can hold
// SHA-256 digests alone. So the machine also quotes sha256:7 under the same qualifying data
// (SecureBootQuote), and the state is read from that where it is there. A machine that leaves
// it out loses "on", nothing else: the SHA-1 events are then all there is.

// SecureBootFinding is what a verifier established, for people: State is one of the
// states below; Detail says why, for a state not established.
type SecureBootFinding struct {
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// The states. Every state but SecureBootOn is shown red.
const (
	SecureBootOn             = "on"
	SecureBootOff            = "off"
	SecureBootSetupMode      = "setup_mode"
	SecureBootNotEstablished = "not_established"
)

// Red says the state is not one to trust a boot chain's signatures in.
func (f SecureBootFinding) Red() bool { return f.State != SecureBootOn }

// String is the state in a line, for a log or an audit entry.
func (f SecureBootFinding) String() string {
	switch f.State {
	case SecureBootOn:
		return "Secure Boot on"
	case SecureBootOff:
		return "Secure Boot OFF"
	case SecureBootSetupMode:
		return "Secure Boot in SETUP MODE"
	}
	if f.Detail != "" {
		return "Secure Boot NOT ESTABLISHED: " + f.Detail
	}
	return "Secure Boot NOT ESTABLISHED"
}

// MaxPCR7Chain bounds a chain: the digests of a boot's PCR 7 events. A machine has a
// few dozen.
const MaxPCR7Chain = 16 << 10

func notEstablished(why string) SecureBootFinding {
	return SecureBootFinding{State: SecureBootNotEstablished, Detail: why}
}

// EstablishSecureBoot replays chain, the concatenated digests of PCR 7's events in
// the bank alg, against pcr7, the register's value from a verified quote (nil when
// the quote does not cover it), and reads the state from the digests.
func EstablishSecureBoot(alg uint16, pcr7, chain []byte) SecureBootFinding {
	var h func() hash.Hash
	switch alg {
	case AlgSHA256:
		h = sha256.New
	case AlgSHA1:
		h = sha1.New
	default:
		return notEstablished("a PCR bank of no known hash")
	}
	size := h().Size()
	switch {
	case len(pcr7) != size:
		return notEstablished("the quote does not cover PCR 7")
	case len(chain) == 0:
		return notEstablished("the machine gave no events of PCR 7 in the " + bankName(alg) + " bank: no event log, or a log without that bank")
	case len(chain) > MaxPCR7Chain || len(chain)%size != 0:
		return notEstablished("the machine's events of PCR 7 are malformed")
	}
	cur := make([]byte, size)
	for off := 0; off < len(chain); off += size {
		d := h()
		d.Write(cur)
		d.Write(chain[off : off+size])
		cur = d.Sum(nil)
	}
	if !bytes.Equal(cur, pcr7) {
		return notEstablished("the event log does not replay to the quoted PCR 7")
	}

	sum := func(b []byte) []byte {
		d := h()
		d.Write(b)
		return d.Sum(nil)
	}
	separator, errorSeparator := sum([]byte{0, 0, 0, 0}), sum([]byte{0xff, 0xff, 0xff, 0xff})
	on, off, absent := sum(UEFIVariableData("SecureBoot", []byte{1})), sum(UEFIVariableData("SecureBoot", []byte{0})), sum(UEFIVariableData("SecureBoot", nil))
	noPK := sum(UEFIVariableData("PK", nil))
	debugMode := sum([]byte("UEFI Debug Mode"))
	var sawOn, sawOff, sawNoPK, sawSeparator, sawDebugMode, sawErrorSeparator bool
	states := 0
	for o := 0; o < len(chain) && !sawSeparator; o += size {
		e := chain[o : o+size]
		switch {
		case bytes.Equal(e, separator):
			sawSeparator = true
		case bytes.Equal(e, errorSeparator):
			sawSeparator, sawErrorSeparator = true, true
		case bytes.Equal(e, debugMode):
			sawDebugMode = true
		case bytes.Equal(e, on):
			sawOn = true
			states++
		case bytes.Equal(e, off), bytes.Equal(e, absent):
			sawOff = true
			states++
		case bytes.Equal(e, noPK):
			sawNoPK = true
		}
	}
	switch {
	case !sawSeparator:
		return notEstablished("no separator in PCR 7's events: the firmware's part has no end")
	case states == 0:
		return notEstablished("the firmware's events of PCR 7 name no SecureBoot variable")
	case states > 1:
		return notEstablished("the firmware's events of PCR 7 name the SecureBoot variable more than once")
	case sawNoPK:
		return SecureBootFinding{State: SecureBootSetupMode}
	case sawOn && sawDebugMode:
		return notEstablished("SecureBoot = 1, and the firmware measured UEFI Debug Mode: a debugger was there at this boot")
	case sawOn && sawErrorSeparator:
		return notEstablished("SecureBoot = 1, and the firmware ended its part with the error separator")
	case sawOn:
		return SecureBootFinding{State: SecureBootOn}
	case sawOff:
		return SecureBootFinding{State: SecureBootOff}
	}
	return notEstablished("the firmware's events of PCR 7 name no SecureBoot variable")
}

// bankName is a PCR bank in a sentence.
func bankName(alg uint16) string {
	if alg == AlgSHA1 {
		return "SHA-1"
	}
	return "SHA-256"
}

// SecureBootQuote is a quote of sha256:7 beside a selection on the SHA-1 bank, by the same
// attestation key and under the same qualifying data; PCR7 is the register's value, believed
// only as far as it reproduces the quoted digest.
type SecureBootQuote struct {
	Quoted    []byte `json:"quoted"`
	Signature []byte `json:"signature"`
	PCR7      []byte `json:"pcr7"`
}

// secureBootSelection is what a SecureBootQuote covers, and all it may cover.
func secureBootSelection() PCRSelection {
	return PCRSelection{Alg: AlgSHA256, Indices: []uint8{7}}
}

// QuoteSecureBoot makes the SecureBootQuote for a quote over sel. Nil unless sel is on the
// SHA-1 bank, and when the TPM has no SHA-256 bank to quote: that is not an error, the SHA-1
// events are then what there is.
func QuoteSecureBoot(quote func(qd []byte, sel PCRSelection) (*QuoteResult, error), qd []byte, sel PCRSelection) *SecureBootQuote {
	if sel.Alg != AlgSHA1 {
		return nil
	}
	q, err := quote(qd, secureBootSelection())
	if err != nil || len(q.Values) != 1 || q.Values[0].Index != 7 {
		return nil
	}
	return &SecureBootQuote{Quoted: q.Quoted, Signature: q.Signature, PCR7: q.Values[0].Digest}
}

// EstablishSecureBootOf is the state for a verified quote in the bank alg: from q and
// chainSHA256 on the SHA-1 bank where q is there, else EstablishSecureBoot's. A q that does
// not verify is not established: there is no going back to the weaker bank from it.
func EstablishSecureBootOf(alg uint16, pcr7, chain []byte, ak crypto.PublicKey, qd []byte, q *SecureBootQuote, chainSHA256 []byte) SecureBootFinding {
	if alg != AlgSHA1 || q == nil {
		return EstablishSecureBoot(alg, pcr7, chain)
	}
	if err := checkSecureBootQuote(ak, qd, q); err != nil {
		return notEstablished("the quote of sha256:7: " + err.Error())
	}
	return EstablishSecureBoot(AlgSHA256, q.PCR7, chainSHA256)
}

// checkSecureBootQuote says whether q is the TPM's word, for this session, on sha256:7.
func checkSecureBootQuote(ak crypto.PublicKey, qd []byte, q *SecureBootQuote) error {
	if ak == nil {
		return errors.New("no attestation key to check it with")
	}
	if err := VerifyTPMSignature(ak, q.Quoted, q.Signature); err != nil {
		return err
	}
	att, err := tpm2.Unmarshal[tpm2.TPMSAttest](q.Quoted)
	if err != nil {
		return errors.New("does not parse")
	}
	if att.Magic != tpm2.TPMGeneratedValue || att.Type != tpm2.TPMSTAttestQuote {
		return errors.New("the signed structure is not a TPM quote")
	}
	if !bytes.Equal(att.ExtraData.Buffer, qd) {
		return errors.New("not bound to this session")
	}
	info, err := att.Attested.Quote()
	if err != nil {
		return errors.New("no quote info")
	}
	sel := secureBootSelection()
	if got, err := selectionFromTPM(info.PCRSelect); err != nil || !got.Equal(sel) {
		return errors.New("covers another selection")
	}
	if len(q.PCR7) != sha256.Size || !bytes.Equal(CompositeDigest(sel, []PCRValue{{Index: 7, Digest: q.PCR7}}), info.PCRDigest.Buffer) {
		return errors.New("the value does not reproduce the quoted digest")
	}
	return nil
}

// efiGlobalVariable is EFI_GLOBAL_VARIABLE, {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}, as
// it is in memory.
var efiGlobalVariable = []byte{0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}

// UEFIVariableData is UEFI_VARIABLE_DATA of a variable of the UEFI specification's
// namespace: its GUID, the lengths of name (in characters) and data, then both. The
// name has no terminator.
func UEFIVariableData(name string, data []byte) []byte {
	chars := utf16.Encode([]rune(name))
	b := append([]byte(nil), efiGlobalVariable...)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(chars)))
	b = binary.LittleEndian.AppendUint64(b, uint64(len(data)))
	for _, c := range chars {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return append(b, data...)
}
