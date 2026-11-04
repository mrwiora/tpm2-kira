package attest

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"unicode/utf16"
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
		return notEstablished("the machine gave no events of PCR 7: no event log")
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
