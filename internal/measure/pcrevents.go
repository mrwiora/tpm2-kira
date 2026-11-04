package measure

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unicode/utf16"

	"github.com/google/go-attestation/attest"

	"github.com/mrwiora/tpm2-kira/internal/untrusted"
	"github.com/tpm2-trust/go-uefi-slim/sigdb"
)

// The event types of the TCG PC Client specification that name something in PCR 7.
const (
	evSeparator          = 0x00000004
	evEFIVariableConfig  = 0x80000001
	evEFIAction          = 0x80000007
	evEFIActionNoDigest  = 0x00000005 // EV_ACTION
	evEFIVariableSigner  = 0x800000e0
	shortDigestHexDigits = 16
)

// PCREvents names what this boot's event log says went into pcr, in order, one
// line each, for a person to read. The log is the firmware's word, not the TPM's:
// these are names, never anything to trust, and everything in them is quoted.
func PCREvents(eventlogPath string, pcr int, algo PCRHashAlgo) ([]string, error) {
	raw, err := ReadRawEventLogFromPath(eventlogPath)
	if err != nil {
		return nil, err
	}
	eventLog, err := attest.ParseEventLog(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse eventlog: %w", err)
	}
	var lines []string
	for _, e := range eventLog.Events(AttestHash(algo)) {
		if e.Index != pcr || e.Type == 0x03 { // EV_NO_ACTION extends nothing
			continue
		}
		lines = append(lines, describeEvent(e))
	}
	return lines, nil
}

// describeEvent is one event's line. Anything that does not parse is said as such.
func describeEvent(e attest.Event) string {
	digest := shortDigest(e.Digest)
	switch uint32(e.Type) {
	case evSeparator:
		return "separator"
	case evEFIAction, evEFIActionNoDigest:
		return "action " + untrusted.Quote(string(bytes.TrimRight(e.Data, "\x00")))
	case evEFIVariableConfig:
		name, data, ok := uefiVariableData(e.Data)
		if !ok {
			return "a Secure Boot variable, unreadable in the log, digest " + digest
		}
		if name == "SecureBoot" {
			if len(data) > 0 && data[0] == 1 {
				return "SecureBoot: on"
			}
			return "SecureBoot: off"
		}
		return untrusted.Quote(name) + ": " + describeDatabase(data) + ", digest " + digest
	case evEFIVariableSigner:
		name, data, ok := uefiVariableData(e.Data)
		if !ok {
			return "what verified an image, unreadable in the log, digest " + digest
		}
		return "verified by " + untrusted.Quote(name) + ": " + describeSigner(data) + ", digest " + digest
	}
	return e.Type.String() + ", digest " + digest
}

func shortDigest(d []byte) string {
	s := hex.EncodeToString(d)
	if len(s) > shortDigestHexDigits {
		s = s[:shortDigestHexDigits]
	}
	return s
}

// describeDatabase is a signature database in a few words.
func describeDatabase(data []byte) string {
	if len(data) == 0 {
		return "empty"
	}
	db, err := sigdb.Parse(data)
	if err != nil {
		return fmt.Sprintf("%d bytes", len(data))
	}
	n := 0
	for _, l := range db {
		n += len(l.Signatures)
	}
	return fmt.Sprintf("%d entries, %d bytes", n, len(data))
}

// describeSigner names the certificate of an EFI_SIGNATURE_DATA (an owner's GUID,
// then the certificate), or says its size.
func describeSigner(data []byte) string {
	for _, der := range [][]byte{data[min(16, len(data)):], data} {
		if cert, err := x509.ParseCertificate(der); err == nil {
			return untrusted.Quote(cert.Subject.String())
		}
	}
	return fmt.Sprintf("%d bytes", len(data))
}

// uefiVariableData parses a UEFI_VARIABLE_DATA: a GUID, the lengths of the name in
// characters and of the data in bytes, the name in UTF-16, the data.
func uefiVariableData(b []byte) (name string, data []byte, ok bool) {
	const header = 16 + 8 + 8
	if len(b) < header {
		return "", nil, false
	}
	nameLen := binary.LittleEndian.Uint64(b[16:])
	dataLen := binary.LittleEndian.Uint64(b[24:])
	rest := b[header:]
	if nameLen > uint64(len(rest))/2 {
		return "", nil, false
	}
	nameBytes := 2 * int(nameLen)
	if dataLen > uint64(len(rest)-nameBytes) {
		return "", nil, false
	}
	units := make([]uint16, nameLen)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(rest[2*i:])
	}
	return string(utf16.Decode(units)), rest[nameBytes : nameBytes+int(dataLen)], true
}
