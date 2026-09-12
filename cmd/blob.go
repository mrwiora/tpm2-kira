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
	DataSize   int
	Version    uint32
	AppVersion string // empty if version is too old or data too short to read
}

// PeekBlobVersion reads just the version and app version from raw blob data without full unmarshal.
// For current blobs the layout is: [version:4][payloadLen:4][appVersionLen:4][appVersion...]
// For older blobs the layout is: [version:4][appVersionLen:4][appVersion...]
// PeekBlobVersion reads just the version and app version from raw blob data without full unmarshal.
// Layout: [version:4][payloadLen:4][appVersionLen:4][appVersion...]
func PeekBlobVersion(data []byte) *BlobPeek {
	peek := &BlobPeek{
		DataSize: len(data),
	}

	if len(data) < 4 {
		return peek
	}

	peek.Version = binary.LittleEndian.Uint32(data[0:4])

	if len(data) >= 12 {
		appVersionLen := binary.LittleEndian.Uint32(data[8:12])
		if appVersionLen > 0 && appVersionLen < 256 && len(data) >= 12+int(appVersionLen) {
			peek.AppVersion = string(data[12 : 12+appVersionLen])
		}
	}

	return peek
}

// AppVersion is the version of the application that created the sealed blob
// This should be set by the main package during initialization
var AppVersion = "unknown"

// CurrentBlobVersion is the only supported blob format version
const CurrentBlobVersion = 8

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
	MaxBlobSize           = 10 * 1024 * 1024 // 10MB maximum total blob size
	MaxAppVersionLen      = 1024             // 1KB maximum app version string
	MaxPublicLen          = 2 * 1024 * 1024  // 2MB maximum public blob
	MaxPrivateLen         = 2 * 1024 * 1024  // 2MB maximum private blob
	MaxPCRDigests         = 100              // Maximum 100 PCR digest entries
	MaxDigestSize         = 1024             // Maximum 1KB per individual digest
	MaxCommandLen         = 4096             // Maximum 4KB for the UKI path string
	MaxEventlogPath       = 4096             // Maximum 4KB for eventlog path
	MaxCalcTime           = 256              // Maximum 256 bytes for timestamp
	MaxMeasurePointLen    = 512              // Maximum 512 bytes for the measure-point extend description
	MaxSignedBranchDigest = 64               // Maximum 64 bytes for signed branch digest (SHA-256 = 32 bytes)
	MaxKeyPathLen         = 4096             // 4KB maximum for key filesystem paths
)

// PCRDigestPair represents a PCR index paired with its digest value
type PCRDigestPair struct {
	Index   int              `json:"index"`             // PCR index
	Source  PCRSource        `json:"source"`            // Where the PCR value was obtained from
	Command string           `json:"command,omitempty"` // Unified kernel image path (only when Source == PCRSourceUKI)
	Digest  tpm2.TPM2BDigest `json:"digest"`            // PCR digest value at seal time
}

// EventlogInfo represents metadata about eventlog-based PCR calculation
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
	AppVersion         string          `json:"app_version"`                // Application version that created this blob
	Public             []byte          `json:"public"`                     // TPM public key blob
	Private            []byte          `json:"private"`                    // TPM private key blob
	PCRDigests         []PCRDigestPair `json:"pcr_digests"`                // PCR indices with their source and digest values
	SignedBranchDigest []byte          `json:"signed_branch_digest"`       // Pre-computed PolicySigned branch digest (SHA-256, 32 bytes)
	EventlogInfo       *EventlogInfo   `json:"eventlog_info"`              // Eventlog calculation metadata (if any PCR uses eventlog)
	PublicKeyPath      string          `json:"public_key_path,omitempty"`  // Filesystem path to signing public key (stored for reseal convenience)
	PrivateKeyPath     string          `json:"private_key_path,omitempty"` // Filesystem path to signing private key (stored for reseal convenience)
}

// SealedBlob is the top-level envelope: version, signed payload, and
// detached signature.  Only BlobSignature lives outside the signed region.
//
// Version 7: UKI PCR source, measure-point metadata; external predict removed.
type SealedBlob struct {
	Version       uint32            `json:"version"`                  // Blob format version (must be 6)
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
	if info := sb.Payload.EventlogInfo; info != nil && info.MeasurePointExtends != "" {
		return MeasurePointOn
	}
	return MeasurePointOff
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
//	[appVersionLen:4][appVersion]
//	[publicLen:4][public]
//	[privateLen:4][private]
//	[numPCRDigests:4][pcrDigestPairs...]
//	[signedBranchDigestLen:2][signedBranchDigest]
//	[hasEventlogInfo:1][eventlogInfo...]
//	[hasKeyPaths:1][pubKeyPathLen:2][pubKeyPath][privKeyPathLen:2][privKeyPath]
func (p *SealedBlobPayload) MarshalPayload() ([]byte, error) {
	size := 4 + len(p.AppVersion) + // app version length + string
		4 + len(p.Public) + // public blob
		4 + len(p.Private) + // private blob
		4 + // number of PCR digests
		2 + len(p.SignedBranchDigest) + // signed branch digest length (2 bytes) + data
		1 + // hasEventlogInfo flag
		1 // hasKeyPaths flag

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

	// Calculate eventlog info size (if present)
	hasEventlogInfo := hasEventlogPCRsInPayload(p) && p.EventlogInfo != nil
	if hasEventlogInfo {
		size += 4 + len(p.EventlogInfo.EventlogPath) + // eventlog path
			4 + len(p.EventlogInfo.CalculationTime) + // calculation time
			4 + 4 + // total events + processed events (4 bytes each)
			2 + len(p.EventlogInfo.MeasurePointExtends) + // measure-point extends
			2 + len(p.EventlogInfo.MeasurePointDetection) // measure-point detection
		if size < 0 || size > MaxBlobSize {
			return nil, fmt.Errorf("sealed blob payload size %d exceeds maximum allowed %d bytes after eventlog info", size, MaxBlobSize)
		}
	}

	// Calculate key paths size (if present)
	hasKeyPaths := p.PublicKeyPath != "" || p.PrivateKeyPath != ""
	if hasKeyPaths {
		size += 2 + len(p.PublicKeyPath) + // pubkey path length + string
			2 + len(p.PrivateKeyPath) // privkey path length + string
		if size < 0 || size > MaxBlobSize {
			return nil, fmt.Errorf("sealed blob payload size %d exceeds maximum allowed %d bytes after key paths", size, MaxBlobSize)
		}
	}

	// Final sanity check before allocation
	if size < 0 || size > MaxBlobSize {
		return nil, fmt.Errorf("sealed blob payload total size %d exceeds maximum allowed %d bytes", size, MaxBlobSize)
	}

	buf := make([]byte, size)
	offset := 0

	// App version
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(p.AppVersion)))
	offset += 4
	copy(buf[offset:], p.AppVersion)
	offset += len(p.AppVersion)

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

	// Signed branch digest
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(p.SignedBranchDigest)))
	offset += 2
	copy(buf[offset:], p.SignedBranchDigest)
	offset += len(p.SignedBranchDigest)

	// Eventlog information flag
	if hasEventlogInfo {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}
	offset++

	// Eventlog metadata (only if flag is set)
	if hasEventlogInfo {
		// Eventlog path
		binary.LittleEndian.PutUint32(buf[offset:], uint32(len(p.EventlogInfo.EventlogPath)))
		offset += 4
		copy(buf[offset:], p.EventlogInfo.EventlogPath)
		offset += len(p.EventlogInfo.EventlogPath)

		// Calculation time
		binary.LittleEndian.PutUint32(buf[offset:], uint32(len(p.EventlogInfo.CalculationTime)))
		offset += 4
		copy(buf[offset:], p.EventlogInfo.CalculationTime)
		offset += len(p.EventlogInfo.CalculationTime)

		// Total events and processed events
		binary.LittleEndian.PutUint32(buf[offset:], uint32(p.EventlogInfo.TotalEvents))
		offset += 4
		binary.LittleEndian.PutUint32(buf[offset:], uint32(p.EventlogInfo.ProcessedEvents))
		offset += 4

		// Measure-point extends applied on top of the replay
		binary.LittleEndian.PutUint16(buf[offset:], uint16(len(p.EventlogInfo.MeasurePointExtends)))
		offset += 2
		copy(buf[offset:], p.EventlogInfo.MeasurePointExtends)
		offset += len(p.EventlogInfo.MeasurePointExtends)

		binary.LittleEndian.PutUint16(buf[offset:], uint16(len(p.EventlogInfo.MeasurePointDetection)))
		offset += 2
		copy(buf[offset:], p.EventlogInfo.MeasurePointDetection)
		offset += len(p.EventlogInfo.MeasurePointDetection)
	}

	// Key paths flag and data
	if hasKeyPaths {
		buf[offset] = 1
		offset++

		// Public key path
		binary.LittleEndian.PutUint16(buf[offset:], uint16(len(p.PublicKeyPath)))
		offset += 2
		copy(buf[offset:], p.PublicKeyPath)
		offset += len(p.PublicKeyPath)

		// Private key path
		binary.LittleEndian.PutUint16(buf[offset:], uint16(len(p.PrivateKeyPath)))
		offset += 2
		copy(buf[offset:], p.PrivateKeyPath)
		offset += len(p.PrivateKeyPath)
	} else {
		buf[offset] = 0
		offset++
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

	// App version
	if offset+4 > len(data) {
		return nil, fmt.Errorf("data too short for app version length")
	}
	appVersionLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if appVersionLen > MaxAppVersionLen {
		return nil, fmt.Errorf("app version length %d exceeds maximum %d", appVersionLen, MaxAppVersionLen)
	}
	if offset+int(appVersionLen) > len(data) {
		return nil, fmt.Errorf("invalid app version length")
	}
	p.AppVersion = string(data[offset : offset+int(appVersionLen)])
	offset += int(appVersionLen)

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

	// Signed branch digest
	if offset+2 > len(data) {
		return nil, fmt.Errorf("data too short for signed branch digest length")
	}
	digestLen := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if digestLen > MaxSignedBranchDigest {
		return nil, fmt.Errorf("signed branch digest length %d exceeds maximum %d", digestLen, MaxSignedBranchDigest)
	}
	if offset+digestLen > len(data) {
		return nil, fmt.Errorf("data too short for signed branch digest data")
	}
	p.SignedBranchDigest = make([]byte, digestLen)
	copy(p.SignedBranchDigest, data[offset:offset+digestLen])
	offset += digestLen

	// Eventlog info flag
	if offset >= len(data) {
		return nil, fmt.Errorf("data too short for eventlog info flag")
	}
	hasEventlogInfo := data[offset] == 1
	offset++

	// Read eventlog metadata if flag is set and there's more data
	if hasEventlogInfo && offset < len(data) {
		p.EventlogInfo = &EventlogInfo{}

		// Eventlog path
		if offset+4 > len(data) {
			return nil, fmt.Errorf("data too short for eventlog path length")
		}
		pathLen := binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		if pathLen > MaxEventlogPath {
			return nil, fmt.Errorf("eventlog path length %d exceeds maximum %d", pathLen, MaxEventlogPath)
		}
		if offset+int(pathLen) > len(data) {
			return nil, fmt.Errorf("data too short for eventlog path")
		}
		p.EventlogInfo.EventlogPath = string(data[offset : offset+int(pathLen)])
		offset += int(pathLen)

		// Calculation time
		if offset+4 > len(data) {
			return nil, fmt.Errorf("data too short for calculation time length")
		}
		timeLen := binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		if timeLen > MaxCalcTime {
			return nil, fmt.Errorf("calculation time length %d exceeds maximum %d", timeLen, MaxCalcTime)
		}
		if offset+int(timeLen) > len(data) {
			return nil, fmt.Errorf("data too short for calculation time")
		}
		p.EventlogInfo.CalculationTime = string(data[offset : offset+int(timeLen)])
		offset += int(timeLen)

		// Total and processed events
		if offset+8 > len(data) {
			return nil, fmt.Errorf("data too short for event counts")
		}
		p.EventlogInfo.TotalEvents = int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		p.EventlogInfo.ProcessedEvents = int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4

		// Measure-point extends
		if offset+2 > len(data) {
			return nil, fmt.Errorf("data too short for measure-point extends length")
		}
		extendsLen := binary.LittleEndian.Uint16(data[offset:])
		offset += 2
		if extendsLen > MaxMeasurePointLen {
			return nil, fmt.Errorf("measure-point extends length %d exceeds maximum %d", extendsLen, MaxMeasurePointLen)
		}
		if offset+int(extendsLen) > len(data) {
			return nil, fmt.Errorf("data too short for measure-point extends")
		}
		p.EventlogInfo.MeasurePointExtends = string(data[offset : offset+int(extendsLen)])
		offset += int(extendsLen)

		if offset+2 > len(data) {
			return nil, fmt.Errorf("data too short for measure-point detection length")
		}
		detectionLen := binary.LittleEndian.Uint16(data[offset:])
		offset += 2
		if detectionLen > MaxMeasurePointLen {
			return nil, fmt.Errorf("measure-point detection length %d exceeds maximum %d", detectionLen, MaxMeasurePointLen)
		}
		if offset+int(detectionLen) > len(data) {
			return nil, fmt.Errorf("data too short for measure-point detection")
		}
		p.EventlogInfo.MeasurePointDetection = string(data[offset : offset+int(detectionLen)])
		offset += int(detectionLen)
	}

	// Key paths (trailing optional section)
	if offset < len(data) {
		hasKeyPaths := data[offset] == 1
		offset++

		if hasKeyPaths && offset < len(data) {
			// Public key path
			if offset+2 > len(data) {
				return nil, fmt.Errorf("data too short for public key path length")
			}
			pubPathLen := int(binary.LittleEndian.Uint16(data[offset:]))
			offset += 2
			if pubPathLen > MaxKeyPathLen {
				return nil, fmt.Errorf("public key path length %d exceeds maximum %d", pubPathLen, MaxKeyPathLen)
			}
			if offset+pubPathLen > len(data) {
				return nil, fmt.Errorf("data too short for public key path")
			}
			p.PublicKeyPath = string(data[offset : offset+pubPathLen])
			offset += pubPathLen

			// Private key path
			if offset+2 > len(data) {
				return nil, fmt.Errorf("data too short for private key path length")
			}
			privPathLen := int(binary.LittleEndian.Uint16(data[offset:]))
			offset += 2
			if privPathLen > MaxKeyPathLen {
				return nil, fmt.Errorf("private key path length %d exceeds maximum %d", privPathLen, MaxKeyPathLen)
			}
			if offset+privPathLen > len(data) {
				return nil, fmt.Errorf("data too short for private key path")
			}
			p.PrivateKeyPath = string(data[offset : offset+privPathLen])
			offset += privPathLen
		}
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
		Version: CurrentBlobVersion,
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

	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			return nil, fmt.Errorf("RSA blob signing failed: %w", err)
		}
	case *ecdsa.PrivateKey:
		signature, err = ecdsa.SignASN1(rand.Reader, key, digest[:])
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
	signedRegion := signedBlob[:signedRegionEnd]

	// Compute SHA-256 digest of the signed region
	digest := sha256.Sum256(signedRegion)

	// Verify based on key type
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], blob.BlobSignature)
		if err != nil {
			return fmt.Errorf("RSA blob signature verification failed: %w", err)
		}
		return nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest[:], blob.BlobSignature) {
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
		Version                uint32          `json:"version"`
		AppVersion             string          `json:"app_version"`
		HashAlgorithm          string          `json:"hash_algorithm"`
		Public                 string          `json:"public_hex"`
		PublicSize             int             `json:"public_size"`
		Private                string          `json:"private_hex"`
		PrivateSize            int             `json:"private_size"`
		PCRDigests             []PCRDigestJSON `json:"pcr_digests"`
		SignedBranchDigest     string          `json:"signed_branch_digest_hex"`
		SignedBranchDigestSize int             `json:"signed_branch_digest_size"`
		PublicKeyPath          string          `json:"public_key_path,omitempty"`
		PrivateKeyPath         string          `json:"private_key_path,omitempty"`
		EventlogInfo           *EventlogInfo   `json:"eventlog_info,omitempty"`
		BlobSignature          string          `json:"blob_signature_hex,omitempty"`
		BlobSignatureSize      int             `json:"blob_signature_size"`
	}

	jsonBlob := SealedBlobJSON{
		Version:                sb.Version,
		AppVersion:             sb.Payload.AppVersion,
		HashAlgorithm:          sb.GetHashAlgo().String(),
		Public:                 hex.EncodeToString(sb.Payload.Public),
		PublicSize:             len(sb.Payload.Public),
		Private:                hex.EncodeToString(sb.Payload.Private),
		PrivateSize:            len(sb.Payload.Private),
		PCRDigests:             pcrDigests,
		SignedBranchDigest:     hex.EncodeToString(sb.Payload.SignedBranchDigest),
		SignedBranchDigestSize: len(sb.Payload.SignedBranchDigest),
		PublicKeyPath:          sb.Payload.PublicKeyPath,
		PrivateKeyPath:         sb.Payload.PrivateKeyPath,
		EventlogInfo:           sb.Payload.EventlogInfo,
		BlobSignature:          hex.EncodeToString(sb.BlobSignature),
		BlobSignatureSize:      len(sb.BlobSignature),
	}

	return json.Marshal(jsonBlob)
}
