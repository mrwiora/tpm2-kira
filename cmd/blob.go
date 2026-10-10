package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// PCRHashAlgo represents the hash algorithm used for PCR bank selection
type PCRHashAlgo string

const (
	// PCRHashAlgoSHA256 is the default SHA-256 hash algorithm (32-byte digests)
	PCRHashAlgoSHA256 PCRHashAlgo = "sha256"
	// PCRHashAlgoSHA1 is the legacy SHA-1 hash algorithm (20-byte digests)
	PCRHashAlgoSHA1 PCRHashAlgo = "sha1"
)

// TPMAlg returns the corresponding TPM algorithm ID for this hash algorithm
func (h PCRHashAlgo) TPMAlg() tpm2.TPMAlgID {
	switch h {
	case PCRHashAlgoSHA1:
		return tpm2.TPMAlgSHA1
	default:
		return tpm2.TPMAlgSHA256
	}
}

// DigestSize returns the digest size in bytes for this hash algorithm
func (h PCRHashAlgo) DigestSize() int {
	switch h {
	case PCRHashAlgoSHA1:
		return 20
	default:
		return 32
	}
}

// String returns a short identifier for this hash algorithm (e.g. "sha256")
func (h PCRHashAlgo) String() string {
	switch h {
	case PCRHashAlgoSHA1:
		return "sha1"
	default:
		return "sha256"
	}
}

// DisplayString returns a human-readable display name (e.g. "SHA-256")
func (h PCRHashAlgo) DisplayString() string {
	switch h {
	case PCRHashAlgoSHA1:
		return "SHA-1"
	default:
		return "SHA-256"
	}
}

// BlobVersionError is returned when a sealed blob has an incompatible version
type BlobVersionError struct {
	FoundVersion    uint32
	RequiredVersion uint32
	DataSize        int
}

func (e *BlobVersionError) Error() string {
	return fmt.Sprintf("tpm2-kira: incompatible blob version (found v%d, requires v%d). Re-seal with: tpm2-kira seal", e.FoundVersion, e.RequiredVersion)
}

// IsBlobVersionError checks if an error (or its wrapped chain) is a BlobVersionError
func IsBlobVersionError(err error) (*BlobVersionError, bool) {
	if err == nil {
		return nil, false
	}
	// Check direct type
	if bve, ok := err.(*BlobVersionError); ok {
		return bve, true
	}
	// Check wrapped errors (fmt.Errorf %w)
	if unwrapped, ok := err.(interface{ Unwrap() error }); ok {
		return IsBlobVersionError(unwrapped.Unwrap())
	}
	return nil, false
}

// BlobPeek contains basic information about a raw blob without full unmarshaling
type BlobPeek struct {
	DataSize int
	Version  uint32
}

// PeekBlobVersion reads just the version from raw blob data without full
// unmarshal: the first four bytes, in every version.
func PeekBlobVersion(data []byte) *BlobPeek {
	peek := &BlobPeek{DataSize: len(data)}
	if len(data) >= 4 {
		peek.Version = binary.LittleEndian.Uint32(data[0:4])
	}
	return peek
}

// AppVersion is the version of this build, set by the main package.
var AppVersion = "unknown"

// CurrentBlobVersion is the only supported blob format version.
const CurrentBlobVersion = 13

// MaxBlobSignatureLen is the maximum allowed signature size in bytes.
// Generous: RSA-4096 PKCS#1 v1.5 = 512 bytes, ECDSA P-384 DER ≈ 104 bytes.
const MaxBlobSignatureLen = 1024

// PCRSource indicates where a PCR value was obtained from
type PCRSource byte

const (
	// PCRSourceRegister means the PCR value was read from TPM registers ('r' suffix or default)
	PCRSourceRegister PCRSource = 0
	// PCRSourceEventlog means the PCR value was calculated from the TPM eventlog ('e' suffix)
	PCRSourceEventlog PCRSource = 1
	// Source byte 2 is retired and must not be reused; see HISTORY.md.
	// PCRSourceUKI means the PCR value was computed from a unified kernel image ('u' suffix)
	PCRSourceUKI PCRSource = 3
)

// String returns a human-readable label for the PCR source
func (s PCRSource) String() string {
	switch s {
	case PCRSourceEventlog:
		return "eventlog"
	case PCRSourceRegister:
		return "register"
	case PCRSourceUKI:
		return "uki"
	default:
		return "unknown"
	}
}

// Suffix returns the single-character suffix for the PCR source
func (s PCRSource) Suffix() string {
	switch s {
	case PCRSourceEventlog:
		return "e"
	case PCRSourceUKI:
		return "u"
	case PCRSourceRegister:
		return ""
	default:
		return ""
	}
}

// PCRDigestPair represents a PCR index paired with its source and digest value
// Maximum size constraints for blob deserialization to prevent memory exhaustion.
// These limits are generous for legitimate use while blocking malicious allocations.
const (
	MaxBlobSize         = 10 * 1024 * 1024 // 10MB maximum total blob size
	MaxPublicLen        = 2 * 1024 * 1024  // 2MB maximum public blob
	MaxPrivateLen       = 2 * 1024 * 1024  // 2MB maximum private blob
	MaxPCRDigests       = 100              // Maximum 100 PCR digest entries
	MaxDigestSize       = 1024             // Maximum 1KB per individual digest
	MaxCommandLen       = 4096             // Maximum 4KB for the UKI path string
	MaxPolicyRef        = 64               // Maximum 64 bytes for the PolicyAuthorize policyRef
	MaxSigningPublicLen = 2048             // Maximum 2KB for the signing key's TPMT_PUBLIC
	MaxApprovalSigLen   = 1024             // Maximum 1KB for the approval TPMT_SIGNATURE
)

// PCRDigestPair represents a PCR index paired with its digest value
type PCRDigestPair struct {
	Index   int              `json:"index"`             // PCR index
	Source  PCRSource        `json:"source"`            // Where the PCR value was obtained from
	Command string           `json:"command,omitempty"` // Unified kernel image path (only when Source == PCRSourceUKI)
	Digest  tpm2.TPM2BDigest `json:"digest"`            // PCR digest value at seal time
}

// EventlogInfo describes an eventlog-based PCR calculation. It is not
// stored: the blob keeps only whether the measure-point extends were applied.
type EventlogInfo struct {
	EventlogPath    string `json:"eventlog_path"`    // Path the eventlog was read from (never reopened from the blob)
	CalculationTime string `json:"calculation_time"` // When calculation was performed
	TotalEvents     int    `json:"total_events"`     // Total number of events processed
	ProcessedEvents int    `json:"processed_events"` // Number of events that extended PCRs
	// MeasurePointExtends records the userspace extends applied on top of the
	// event log replay, as "word:pcr,pcr;word:pcr". Empty means none were applied.
	MeasurePointExtends string `json:"measure_point_extends,omitempty"`
	// MeasurePointDetection records how that decision was reached.
	MeasurePointDetection string `json:"measure_point_detection,omitempty"`
}

// SealedBlobPayload contains every field that is covered by the blob
// signature.  When adding new fields to the blob, add them HERE and
// update MarshalPayload / UnmarshalPayload.  This guarantees that new
// fields are automatically included in the signed region.
type SealedBlobPayload struct {
	Public     []byte          `json:"public"`      // TPMT_PUBLIC of the TOTP HMAC key
	Private    []byte          `json:"private"`     // TPM2B_PRIVATE of the TOTP HMAC key (wrapped by the TPM)
	PCRDigests []PCRDigestPair `json:"pcr_digests"` // PCR indices with their source and digest values
	// TOTPAlgorithm is the HMAC hash of the TOTP key: TPMAlgSHA1, or
	// TPMAlgSHA256 on a TPM without SHA-1.
	TOTPAlgorithm tpm2.TPMAlgID `json:"totp_algorithm"`
	// Generation is the value the approved policy requires in the slot's
	// generation index (GenerationIndex). Each reseal raises it, which
	// revokes every earlier approval.
	Generation uint64 `json:"generation"`
	// PolicyRef qualifies the approvals for this key object: random per
	// seal, so an approval made for one object never fits another.
	PolicyRef []byte `json:"policy_ref"`
	// SigningPublic is the TPMT_PUBLIC of the signing key. The key object's
	// policy binds its Name, so a substituted key cannot approve anything.
	SigningPublic []byte `json:"signing_public"`
	// ApprovalSignature is the signing key's TPMT_SIGNATURE over
	// H(approvedPolicy ‖ PolicyRef), where approvedPolicy is PolicyPCR over
	// PCRDigests followed by PolicyNV(generation index == Generation).
	ApprovalSignature []byte `json:"approval_signature"`
	// MeasurePointApplied says the eventlog PCRs' values include the
	// measure-point extends (MeasurePointWordsAt, before the separator), so
	// verification recomputes exactly what was sealed. Always false
	// without eventlog PCRs.
	MeasurePointApplied bool `json:"measure_point_applied"`
	// Attestation is the slot's remote-attestation part, or nil without
	// one (attest_blob.go). It lives in the slot's blob, under the same
	// signature, so that a slot is one thing: sealed, resealed, enrolled
	// and deleted together.
	Attestation *Attestation `json:"-"`
}

// SealedBlob is the top-level envelope: version, signed payload, and
// detached signature.  Only BlobSignature lives outside the signed region.
//
// The TOTP key is an HMAC key used inside the TPM, authorized by
// PolicyAuthorize; see docs/SECURITY-BACKGROUND.md §4. The layout is in §10.
type SealedBlob struct {
	Version       uint32            `json:"version"`                  // Blob format version (must be CurrentBlobVersion)
	Payload       SealedBlobPayload `json:"payload"`                  // All authenticated content
	BlobSignature []byte            `json:"blob_signature,omitempty"` // Signature over [version ‖ payloadLen ‖ payload bytes]
}

// GetHashAlgo infers the PCR hash algorithm from the stored digest sizes.
// Returns SHA-256 by default, SHA-1 if all digests are 20 bytes.
func (sb *SealedBlob) GetHashAlgo() PCRHashAlgo {
	for _, pcrDigest := range sb.Payload.PCRDigests {
		digestLen := len(pcrDigest.Digest.Buffer)
		if digestLen == 20 {
			return PCRHashAlgoSHA1
		}
		if digestLen == 32 {
			return PCRHashAlgoSHA256
		}
	}
	// Default to SHA256 if no digests or unrecognized sizes
	return PCRHashAlgoSHA256
}

// GetPCRIndices returns a slice of PCR indices from the PCRDigests
func (sb *SealedBlob) GetPCRIndices() []int {
	indices := make([]int, len(sb.Payload.PCRDigests))
	for i, pcrDigest := range sb.Payload.PCRDigests {
		indices[i] = pcrDigest.Index
	}
	return indices
}

// GetPCRDigestValues returns a slice of digest values from the PCRDigests
func (sb *SealedBlob) GetPCRDigestValues() []tpm2.TPM2BDigest {
	digests := make([]tpm2.TPM2BDigest, len(sb.Payload.PCRDigests))
	for i, pcrDigest := range sb.Payload.PCRDigests {
		digests[i] = pcrDigest.Digest
	}
	return digests
}

// MeasurePointMode reproduces the measure-point handling this blob was sealed
// with, so verification recomputes exactly the values the policy was bound to.
func (sb *SealedBlob) MeasurePointMode() MeasurePointMode {
	if sb.Payload.MeasurePointApplied {
		return MeasurePointOn
	}
	return MeasurePointOff
}

// MeasurePointExtends describes the extends folded into the eventlog PCRs,
// as "word:pcr,pcr;word:pcr", or "" when none were. It is derived from the
// selection: the seal applies the same words to every eventlog PCR.
func (sb *SealedBlob) MeasurePointExtends() string {
	if !sb.Payload.MeasurePointApplied {
		return ""
	}
	byWord := map[string][]int{}
	for _, pcr := range sb.GetEventlogPCRIndices() {
		for _, word := range MeasurePointWordsAt(MeasurePointBeforeSeparator, pcr) {
			byWord[word] = append(byWord[word], pcr)
		}
	}
	return FormatMeasurePointExtends(byWord)
}

// HasEventlogPCRs returns true if any PCR in this blob uses eventlog as its source
func (sb *SealedBlob) HasEventlogPCRs() bool {
	for _, pair := range sb.Payload.PCRDigests {
		if pair.Source == PCRSourceEventlog {
			return true
		}
	}
	return false
}

// GetEventlogPCRIndices returns indices of PCRs that use eventlog as their source
func (sb *SealedBlob) GetEventlogPCRIndices() []int {
	var indices []int
	for _, pair := range sb.Payload.PCRDigests {
		if pair.Source == PCRSourceEventlog {
			indices = append(indices, pair.Index)
		}
	}
	return indices
}

// GetRegisterPCRIndices returns indices of PCRs that use TPM registers as their source
func (sb *SealedBlob) GetRegisterPCRIndices() []int {
	var indices []int
	for _, pair := range sb.Payload.PCRDigests {
		if pair.Source == PCRSourceRegister {
			indices = append(indices, pair.Index)
		}
	}
	return indices
}

// HasUKIPCRs returns true if any PCR in this blob is computed from a unified kernel image
func (sb *SealedBlob) HasUKIPCRs() bool {
	for _, pair := range sb.Payload.PCRDigests {
		if pair.Source == PCRSourceUKI {
			return true
		}
	}
	return false
}

// GetUKIPCRIndices returns indices of PCRs computed from a unified kernel image
func (sb *SealedBlob) GetUKIPCRIndices() []int {
	var indices []int
	for _, pair := range sb.Payload.PCRDigests {
		if pair.Source == PCRSourceUKI {
			indices = append(indices, pair.Index)
		}
	}
	return indices
}

// GetPCRSpecs reconstructs PCRSpec slice from the sealed blob's PCR digests
func (sb *SealedBlob) GetPCRSpecs() []PCRSpec {
	specs := make([]PCRSpec, len(sb.Payload.PCRDigests))
	for i, pair := range sb.Payload.PCRDigests {
		specs[i] = PCRSpec{Index: pair.Index, Source: pair.Source, Command: pair.Command}
	}
	return specs
}

// hasEventlogPCRsInPayload checks whether any PCR digest pair in the payload uses eventlog source.
func hasEventlogPCRsInPayload(p *SealedBlobPayload) bool {
	for _, pair := range p.PCRDigests {
		if pair.Source == PCRSourceEventlog {
			return true
		}
	}
	return false
}

// MarshalPayload serialises the payload fields in the length-prefixed binary format.
// The output does NOT include the version or signature — those belong to the outer envelope.
//
// Format:
//
//	[publicLen:4][public]
//	[privateLen:4][private]
//	[numPCRDigests:4][pcrDigestPairs...]
//	[totpAlgorithm:2][generation:8]
//	[policyRefLen:2][policyRef][signingPublicLen:2][signingPublic]
//	[approvalSignatureLen:2][approvalSignature]
//	[measurePointApplied:1]
//	[hasAttestation:1][attestationLen:4][attestation]
func (p *SealedBlobPayload) MarshalPayload() ([]byte, error) {
	size := 4 + len(p.Public) + // public blob
		4 + len(p.Private) + // private blob
		4 + // number of PCR digests
		2 + 8 + // TOTP algorithm + generation
		2 + len(p.PolicyRef) + 2 + len(p.SigningPublic) + 2 + len(p.ApprovalSignature) +
		1 // measure-point flag

	// Guard against integer overflow and unreasonable allocations
	if size < 0 || size > MaxBlobSize {
		return nil, fmt.Errorf("sealed blob payload base size %d exceeds maximum allowed %d bytes", size, MaxBlobSize)
	}

	// Calculate PCR digest pair size
	for _, pcrDigest := range p.PCRDigests {
		size += 4 + // PCR index
			1 + // source byte
			2 + len(pcrDigest.Digest.Buffer) // 2 bytes for length + digest data
		if pcrDigest.Source == PCRSourceUKI {
			size += 2 + len(pcrDigest.Command) // 2 bytes for path length + path string
		}
		if size < 0 || size > MaxBlobSize {
			return nil, fmt.Errorf("sealed blob payload size %d exceeds maximum allowed %d bytes after PCR digests", size, MaxBlobSize)
		}
	}

	// Final sanity check before allocation
	if size < 0 || size > MaxBlobSize {
		return nil, fmt.Errorf("sealed blob payload total size %d exceeds maximum allowed %d bytes", size, MaxBlobSize)
	}

	buf := make([]byte, size)
	offset := 0

	// Public blob
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(p.Public)))
	offset += 4
	copy(buf[offset:], p.Public)
	offset += len(p.Public)

	// Private blob
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(p.Private)))
	offset += 4
	copy(buf[offset:], p.Private)
	offset += len(p.Private)

	// PCR digest pairs (index + source + digest together)
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(p.PCRDigests)))
	offset += 4
	for _, pcrDigest := range p.PCRDigests {
		// PCR index
		binary.LittleEndian.PutUint32(buf[offset:], uint32(pcrDigest.Index))
		offset += 4

		// PCR source
		buf[offset] = byte(pcrDigest.Source)
		offset++

		// Command string (only for UKI source)
		if pcrDigest.Source == PCRSourceUKI {
			binary.LittleEndian.PutUint16(buf[offset:], uint16(len(pcrDigest.Command)))
			offset += 2
			copy(buf[offset:], pcrDigest.Command)
			offset += len(pcrDigest.Command)
		}

		// PCR digest
		binary.LittleEndian.PutUint16(buf[offset:], uint16(len(pcrDigest.Digest.Buffer)))
		offset += 2
		copy(buf[offset:], pcrDigest.Digest.Buffer)
		offset += len(pcrDigest.Digest.Buffer)
	}

	// Key object and approval
	binary.LittleEndian.PutUint16(buf[offset:], uint16(p.TOTPAlgorithm))
	offset += 2
	binary.LittleEndian.PutUint64(buf[offset:], p.Generation)
	offset += 8
	for _, field := range [][]byte{p.PolicyRef, p.SigningPublic, p.ApprovalSignature} {
		binary.LittleEndian.PutUint16(buf[offset:], uint16(len(field)))
		offset += 2
		copy(buf[offset:], field)
		offset += len(field)
	}

	// Whether the measure-point extends are in the eventlog PCRs' values
	if p.MeasurePointApplied && hasEventlogPCRsInPayload(p) {
		buf[offset] = 1
	}

	// The optional attestation part ends the payload:
	// [hasAttestation:1], then [len:4][attestation].
	if p.Attestation == nil {
		buf = append(buf, 0)
	} else {
		att, err := p.Attestation.marshal()
		if err != nil {
			return nil, err
		}
		if len(att) > MaxAttestationLen {
			return nil, fmt.Errorf("attestation part of %d bytes exceeds %d", len(att), MaxAttestationLen)
		}
		buf = append(buf, 1)
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(att)))
		buf = append(buf, att...)
	}

	return buf, nil
}

// UnmarshalPayload parses the payload bytes back into a SealedBlobPayload.
// The input must NOT include the outer envelope (version, payloadLen, signature).
func UnmarshalPayload(data []byte) (*SealedBlobPayload, error) {
	if len(data) > MaxBlobSize {
		return nil, fmt.Errorf("payload size %d exceeds maximum allowed %d bytes", len(data), MaxBlobSize)
	}

	offset := 0
	p := &SealedBlobPayload{}

	// Public blob
	if offset+4 > len(data) {
		return nil, fmt.Errorf("data too short for public blob length")
	}
	publicLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if publicLen > MaxPublicLen {
		return nil, fmt.Errorf("public blob length %d exceeds maximum %d", publicLen, MaxPublicLen)
	}
	if offset+int(publicLen) > len(data) {
		return nil, fmt.Errorf("invalid public blob length")
	}
	p.Public = make([]byte, publicLen)
	copy(p.Public, data[offset:offset+int(publicLen)])
	offset += int(publicLen)

	// Private blob
	if offset+4 > len(data) {
		return nil, fmt.Errorf("data too short for private blob length")
	}
	privateLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if privateLen > MaxPrivateLen {
		return nil, fmt.Errorf("private blob length %d exceeds maximum %d", privateLen, MaxPrivateLen)
	}
	if offset+int(privateLen) > len(data) {
		return nil, fmt.Errorf("invalid private blob length")
	}
	p.Private = make([]byte, privateLen)
	copy(p.Private, data[offset:offset+int(privateLen)])
	offset += int(privateLen)

	// PCR digest pairs
	if offset+4 > len(data) {
		return nil, fmt.Errorf("data too short for PCR digest count")
	}
	numPCRDigests := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if numPCRDigests > MaxPCRDigests {
		return nil, fmt.Errorf("PCR digest count %d exceeds maximum %d", numPCRDigests, MaxPCRDigests)
	}
	p.PCRDigests = make([]PCRDigestPair, numPCRDigests)
	for i := 0; i < int(numPCRDigests); i++ {
		// PCR index
		if offset+4 > len(data) {
			return nil, fmt.Errorf("data too short for PCR index")
		}
		p.PCRDigests[i].Index = int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4

		// PCR source
		if offset+1 > len(data) {
			return nil, fmt.Errorf("data too short for PCR source")
		}
		p.PCRDigests[i].Source = PCRSource(data[offset])
		offset++

		// Command string (only for UKI source)
		if p.PCRDigests[i].Source == PCRSourceUKI {
			if offset+2 > len(data) {
				return nil, fmt.Errorf("data too short for UKI path length")
			}
			commandLen := int(binary.LittleEndian.Uint16(data[offset:]))
			offset += 2
			if commandLen > MaxCommandLen {
				return nil, fmt.Errorf("UKI path length %d exceeds maximum %d", commandLen, MaxCommandLen)
			}
			if offset+commandLen > len(data) {
				return nil, fmt.Errorf("data too short for UKI path string")
			}
			p.PCRDigests[i].Command = string(data[offset : offset+commandLen])
			offset += commandLen
		}

		// PCR digest
		if offset+2 > len(data) {
			return nil, fmt.Errorf("data too short for digest size")
		}
		digestSize := int(binary.LittleEndian.Uint16(data[offset:]))
		offset += 2

		if digestSize > MaxDigestSize {
			return nil, fmt.Errorf("digest size %d exceeds maximum %d", digestSize, MaxDigestSize)
		}
		if offset+digestSize > len(data) {
			return nil, fmt.Errorf("data too short for digest buffer")
		}

		p.PCRDigests[i].Digest = tpm2.TPM2BDigest{
			Buffer: make([]byte, digestSize),
		}
		copy(p.PCRDigests[i].Digest.Buffer, data[offset:offset+digestSize])
		offset += digestSize
	}

	// Key object and approval
	if offset+2+8 > len(data) {
		return nil, fmt.Errorf("data too short for TOTP algorithm and generation")
	}
	p.TOTPAlgorithm = tpm2.TPMAlgID(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	p.Generation = binary.LittleEndian.Uint64(data[offset:])
	offset += 8
	for _, field := range []struct {
		name string
		max  int
		dst  *[]byte
	}{
		{"policy reference", MaxPolicyRef, &p.PolicyRef},
		{"signing public key", MaxSigningPublicLen, &p.SigningPublic},
		{"approval signature", MaxApprovalSigLen, &p.ApprovalSignature},
	} {
		if offset+2 > len(data) {
			return nil, fmt.Errorf("data too short for %s length", field.name)
		}
		n := int(binary.LittleEndian.Uint16(data[offset:]))
		offset += 2
		if n > field.max {
			return nil, fmt.Errorf("%s length %d exceeds maximum %d", field.name, n, field.max)
		}
		if offset+n > len(data) {
			return nil, fmt.Errorf("data too short for %s", field.name)
		}
		*field.dst = append([]byte(nil), data[offset:offset+n]...)
		offset += n
	}

	// Measure-point flag
	if offset >= len(data) {
		return nil, fmt.Errorf("data too short for the measure-point flag")
	}
	switch data[offset] {
	case 0:
	case 1:
		if !hasEventlogPCRsInPayload(p) {
			return nil, fmt.Errorf("measure-point flag set without eventlog PCRs")
		}
		p.MeasurePointApplied = true
	default:
		return nil, fmt.Errorf("invalid measure-point flag %d", data[offset])
	}
	offset++

	// The optional attestation part, which ends the payload.
	if offset+1 > len(data) {
		return nil, fmt.Errorf("data too short for the attestation flag")
	}
	hasAttestation := data[offset]
	offset++
	switch hasAttestation {
	case 0:
		if offset != len(data) {
			return nil, fmt.Errorf("payload has %d trailing bytes", len(data)-offset)
		}
	case 1:
		if offset+4 > len(data) {
			return nil, fmt.Errorf("data too short for the attestation length")
		}
		n := int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		if n <= 0 || n > MaxAttestationLen || offset+n != len(data) {
			return nil, fmt.Errorf("attestation part of %d bytes does not end the payload", n)
		}
		att, err := unmarshalAttestation(data[offset : offset+n])
		if err != nil {
			return nil, err
		}
		p.Attestation = att
	default:
		return nil, fmt.Errorf("invalid attestation flag %d", hasAttestation)
	}

	return p, nil
}

// Marshal produces the unsigned outer envelope bytes.
//
// Wire format:
//
//	[version:4][payloadLen:4][payloadBytes...]
//
// The signature trailer is NOT included — call SignBlobPayload to append it.
func (sb *SealedBlob) Marshal() ([]byte, error) {
	payloadBytes, err := sb.Payload.MarshalPayload()
	if err != nil {
		return nil, err
	}

	// [version:4][payloadLen:4][payloadBytes...]
	buf := make([]byte, 4+4+len(payloadBytes))
	binary.LittleEndian.PutUint32(buf[0:], CurrentBlobVersion)
	binary.LittleEndian.PutUint32(buf[4:], uint32(len(payloadBytes)))
	copy(buf[8:], payloadBytes)
	return buf, nil
}

// UnmarshalSealedBlob parses bytes back into a SealedBlob.
// Only supports version 6 format.
//
// Wire format:
//
//	[version:4][payloadLen:4][payloadBytes...][sigLen:2][signatureBytes...]
func UnmarshalSealedBlob(data []byte) (*SealedBlob, error) {
	// Validate total blob size to prevent resource exhaustion
	if len(data) > MaxBlobSize {
		return nil, fmt.Errorf("blob size %d exceeds maximum allowed %d bytes", len(data), MaxBlobSize)
	}

	if len(data) < 10 {
		return nil, fmt.Errorf("data too short to be a valid sealed blob")
	}

	// Version check
	version := binary.LittleEndian.Uint32(data[0:4])
	if version != CurrentBlobVersion {
		return nil, &BlobVersionError{
			FoundVersion:    version,
			RequiredVersion: CurrentBlobVersion,
			DataSize:        len(data),
		}
	}

	// Read payloadLen
	payloadLen := binary.LittleEndian.Uint32(data[4:8])
	if payloadLen > uint32(MaxBlobSize) {
		return nil, fmt.Errorf("payload length %d exceeds maximum allowed %d bytes", payloadLen, MaxBlobSize)
	}

	payloadEnd := 8 + int(payloadLen)
	if payloadEnd > len(data) {
		return nil, fmt.Errorf("data too short for declared payload length (need %d, have %d)", payloadEnd, len(data))
	}

	// Parse payload
	payloadBytes := data[8:payloadEnd]
	payload, err := UnmarshalPayload(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	sb := &SealedBlob{
		Version: version,
		Payload: *payload,
	}

	// Parse signature trailer: [sigLen:2][signatureBytes...]
	sigOffset := payloadEnd
	if sigOffset+2 > len(data) {
		return nil, fmt.Errorf("data too short for blob signature length")
	}
	sigLen := int(binary.LittleEndian.Uint16(data[sigOffset:]))
	sigOffset += 2

	if sigLen > MaxBlobSignatureLen {
		return nil, fmt.Errorf("blob signature length %d exceeds maximum %d", sigLen, MaxBlobSignatureLen)
	}
	if sigLen == 0 {
		return nil, fmt.Errorf("blob signature is empty — unsigned blobs are not accepted")
	}
	if sigOffset+sigLen > len(data) {
		return nil, fmt.Errorf("data too short for blob signature data")
	}

	sb.BlobSignature = make([]byte, sigLen)
	copy(sb.BlobSignature, data[sigOffset:sigOffset+sigLen])

	return sb, nil
}

// SignBlobPayload signs the unsigned blob bytes and appends the signature trailer.
//
// Input: the output of SealedBlob.Marshal() — [version:4][payloadLen:4][payload...]
// Output: [version:4][payloadLen:4][payload...][sigLen:2][signature...]
//
// The signed region is the entire input (version + payloadLen + payload bytes).
func SignBlobPayload(unsignedBlob []byte, privKey crypto.Signer) ([]byte, error) {
	if len(unsignedBlob) < 8 {
		return nil, fmt.Errorf("unsigned blob too short to sign")
	}

	// Compute SHA-256 digest of the entire unsigned blob (the signed region)
	digest := sha256.Sum256(unsignedBlob)

	// Sign based on key type
	var signature []byte
	var err error

	// Dispatch on the public key: a token-backed signer is neither
	// *rsa.PrivateKey nor *ecdsa.PrivateKey, but signs in the same formats
	// (PKCS #1 v1.5 for RSA, ASN.1 DER for ECDSA).
	switch privKey.Public().(type) {
	case *rsa.PublicKey:
		signature, err = privKey.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("RSA blob signing failed: %w", err)
		}
	case *ecdsa.PublicKey:
		signature, err = privKey.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("ECDSA blob signing failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported private key type %T for blob signing", privKey)
	}

	if len(signature) > MaxBlobSignatureLen {
		return nil, fmt.Errorf("signature length %d exceeds maximum %d", len(signature), MaxBlobSignatureLen)
	}

	// Append trailer: [sigLen:2 LE][signature bytes]
	trailer := make([]byte, 2+len(signature))
	binary.LittleEndian.PutUint16(trailer[0:], uint16(len(signature)))
	copy(trailer[2:], signature)

	return append(unsignedBlob, trailer...), nil
}

// VerifyBlobSignature verifies the integrity signature on a signed blob.
//
// The signed region is extracted from the raw signedBlob bytes (not re-marshalled
// from the parsed struct) to avoid any marshal/unmarshal round-trip fragility.
//
// signedBlob: the complete wire-format blob including signature trailer
// blob: the parsed SealedBlob (used to read BlobSignature)
// pubKey: the verification key (derived from the trust anchor, NOT from the blob)
func VerifyBlobSignature(signedBlob []byte, blob *SealedBlob, pubKey crypto.PublicKey) error {
	if len(signedBlob) < 10 {
		return fmt.Errorf("signed blob too short for verification")
	}

	if len(blob.BlobSignature) == 0 {
		return fmt.Errorf("blob has no signature")
	}

	// Extract the signed region: [version:4][payloadLen:4][payload bytes]
	payloadLen := binary.LittleEndian.Uint32(signedBlob[4:8])
	signedRegionEnd := 8 + int(payloadLen)
	if signedRegionEnd > len(signedBlob) {
		return fmt.Errorf("signed region extends beyond blob data")
	}
	return verifySignedRegion(signedBlob[:signedRegionEnd], blob.BlobSignature, pubKey)
}

// verifySignedRegion checks a SignBlobPayload signature over region. Shared
// by the sealed blob and the attestation blob, which use the same envelope.
func verifySignedRegion(region, signature []byte, pubKey crypto.PublicKey) error {
	digest := sha256.Sum256(region)
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
		if err != nil {
			return fmt.Errorf("RSA blob signature verification failed: %w", err)
		}
		return nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest[:], signature) {
			return fmt.Errorf("ECDSA blob signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T for blob signature verification", pubKey)
	}
}

// MarshalJSON provides custom JSON serialization for SealedBlob
func (sb *SealedBlob) MarshalJSON() ([]byte, error) {
	// Convert PCR digest pairs to hex strings for readable JSON output
	type PCRDigestJSON struct {
		Index   int    `json:"index"`
		Source  string `json:"source"`
		Command string `json:"command,omitempty"`
		Digest  string `json:"digest_hex"`
	}

	pcrDigests := make([]PCRDigestJSON, len(sb.Payload.PCRDigests))
	for i, pcrDigest := range sb.Payload.PCRDigests {
		pcrDigests[i] = PCRDigestJSON{
			Index:   pcrDigest.Index,
			Source:  pcrDigest.Source.String(),
			Command: pcrDigest.Command,
			Digest:  hex.EncodeToString(pcrDigest.Digest.Buffer),
		}
	}

	// Create a JSON-friendly structure
	type SealedBlobJSON struct {
		Version           uint32           `json:"version"`
		HashAlgorithm     string           `json:"hash_algorithm"`
		Public            string           `json:"public_hex"`
		PublicSize        int              `json:"public_size"`
		Private           string           `json:"private_hex"`
		PrivateSize       int              `json:"private_size"`
		PCRDigests        []PCRDigestJSON  `json:"pcr_digests"`
		TOTPAlgorithm     string           `json:"totp_algorithm"`
		Generation        uint64           `json:"generation"`
		PolicyRef         string           `json:"policy_ref_hex"`
		SigningPublic     string           `json:"signing_public_hex"`
		ApprovalSignature string           `json:"approval_signature_hex"`
		MeasurePoint      string           `json:"measure_point_extends,omitempty"`
		BlobSignature     string           `json:"blob_signature_hex,omitempty"`
		BlobSignatureSize int              `json:"blob_signature_size"`
		Attestation       *attestationJSON `json:"attestation,omitempty"`
	}

	jsonBlob := SealedBlobJSON{
		Version:           sb.Version,
		HashAlgorithm:     sb.GetHashAlgo().String(),
		Public:            hex.EncodeToString(sb.Payload.Public),
		PublicSize:        len(sb.Payload.Public),
		Private:           hex.EncodeToString(sb.Payload.Private),
		PrivateSize:       len(sb.Payload.Private),
		PCRDigests:        pcrDigests,
		TOTPAlgorithm:     totpAlgorithmName(sb.Payload.TOTPAlgorithm),
		Generation:        sb.Payload.Generation,
		PolicyRef:         hex.EncodeToString(sb.Payload.PolicyRef),
		SigningPublic:     hex.EncodeToString(sb.Payload.SigningPublic),
		ApprovalSignature: hex.EncodeToString(sb.Payload.ApprovalSignature),
		MeasurePoint:      sb.MeasurePointExtends(),
		BlobSignature:     hex.EncodeToString(sb.BlobSignature),
		BlobSignatureSize: len(sb.BlobSignature),
		Attestation:       sb.Payload.Attestation.json(),
	}

	return json.Marshal(jsonBlob)
}
