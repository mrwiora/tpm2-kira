package cmd

import (
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

// PeekBlobVersion reads just the version and app version from raw blob data without full unmarshal
func PeekBlobVersion(data []byte) *BlobPeek {
	peek := &BlobPeek{
		DataSize: len(data),
	}

	if len(data) < 4 {
		return peek
	}

	peek.Version = binary.LittleEndian.Uint32(data[0:4])

	// Try to read app version (v3 layout: [version:4][appVersionLen:4][appVersion])
	if len(data) >= 8 {
		appVersionLen := binary.LittleEndian.Uint32(data[4:8])
		if appVersionLen > 0 && appVersionLen < 256 && len(data) >= 8+int(appVersionLen) {
			peek.AppVersion = string(data[8 : 8+appVersionLen])
		}
	}

	return peek
}

// AppVersion is the version of the application that created the sealed blob
// This should be set by the main package during initialization
var AppVersion = "unknown"

// CurrentBlobVersion is the only supported blob format version
const CurrentBlobVersion = 3

// PCRSource indicates where a PCR value was obtained from
type PCRSource byte

const (
	// PCRSourceRegister means the PCR value was read from TPM registers ('r' suffix or default)
	PCRSourceRegister PCRSource = 0
	// PCRSourceEventlog means the PCR value was calculated from the TPM eventlog ('e' suffix)
	PCRSourceEventlog PCRSource = 1
	// PCRSourcePredict means the PCR value was obtained by running an external command ('p' suffix)
	PCRSourcePredict PCRSource = 2
)

// String returns a human-readable label for the PCR source
func (s PCRSource) String() string {
	switch s {
	case PCRSourceEventlog:
		return "eventlog"
	case PCRSourceRegister:
		return "register"
	case PCRSourcePredict:
		return "predict"
	default:
		return "unknown"
	}
}

// Suffix returns the single-character suffix for the PCR source
func (s PCRSource) Suffix() string {
	switch s {
	case PCRSourceEventlog:
		return "e"
	case PCRSourcePredict:
		return "p"
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
	MaxBlobSize      = 10 * 1024 * 1024 // 10MB maximum total blob size
	MaxAppVersionLen = 1024             // 1KB maximum app version string
	MaxPublicLen     = 2 * 1024 * 1024  // 2MB maximum public blob
	MaxPrivateLen    = 2 * 1024 * 1024  // 2MB maximum private blob
	MaxPCRDigests    = 100              // Maximum 100 PCR digest entries
	MaxDigestSize    = 1024             // Maximum 1KB per individual digest
	MaxCommandLen    = 4096             // Maximum 4KB for predict command string
	MaxEventlogPath  = 4096             // Maximum 4KB for eventlog path
	MaxEventlogHash  = 128              // Maximum 128 bytes for hash string
	MaxCalcTime      = 256              // Maximum 256 bytes for timestamp
)

// PCRDigestPair represents a PCR index paired with its digest value
type PCRDigestPair struct {
	Index   int              `json:"index"`             // PCR index
	Source  PCRSource        `json:"source"`            // Where the PCR value was obtained from
	Command string           `json:"command,omitempty"` // External command for predict source (only when Source == PCRSourcePredict)
	Digest  tpm2.TPM2BDigest `json:"digest"`            // PCR digest value at seal time
}

// EventlogInfo represents metadata about eventlog-based PCR calculation
type EventlogInfo struct {
	EventlogPath    string `json:"eventlog_path"`    // Path to eventlog file used
	EventlogHash    string `json:"eventlog_hash"`    // SHA256 hash of eventlog file for verification
	CalculationTime string `json:"calculation_time"` // When calculation was performed
	TotalEvents     int    `json:"total_events"`     // Total number of events processed
	ProcessedEvents int    `json:"processed_events"` // Number of events that extended PCRs
}

// SealedBlob represents the complete sealed data structure
// Version 3: Per-PCR source tracking (register vs eventlog), no global EventlogBased flag
type SealedBlob struct {
	Version      uint32          `json:"version"`       // Blob format version (must be 3)
	AppVersion   string          `json:"app_version"`   // Application version that created this blob
	Public       []byte          `json:"public"`        // TPM public key blob
	Private      []byte          `json:"private"`       // TPM private key blob
	PCRDigests   []PCRDigestPair `json:"pcr_digests"`   // PCR indices with their source and digest values
	HasPassword  bool            `json:"has_password"`  // Whether password fallback is enabled
	EventlogInfo *EventlogInfo   `json:"eventlog_info"` // Eventlog calculation metadata (if any PCR uses eventlog)
}

// GetHashAlgo infers the PCR hash algorithm from the stored digest sizes.
// Returns SHA-256 by default, SHA-1 if all digests are 20 bytes.
func (sb *SealedBlob) GetHashAlgo() PCRHashAlgo {
	for _, pcrDigest := range sb.PCRDigests {
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
	indices := make([]int, len(sb.PCRDigests))
	for i, pcrDigest := range sb.PCRDigests {
		indices[i] = pcrDigest.Index
	}
	return indices
}

// GetPCRDigestValues returns a slice of digest values from the PCRDigests
func (sb *SealedBlob) GetPCRDigestValues() []tpm2.TPM2BDigest {
	digests := make([]tpm2.TPM2BDigest, len(sb.PCRDigests))
	for i, pcrDigest := range sb.PCRDigests {
		digests[i] = pcrDigest.Digest
	}
	return digests
}

// HasEventlogPCRs returns true if any PCR in this blob uses eventlog as its source
func (sb *SealedBlob) HasEventlogPCRs() bool {
	for _, pair := range sb.PCRDigests {
		if pair.Source == PCRSourceEventlog {
			return true
		}
	}
	return false
}

// GetEventlogPCRIndices returns indices of PCRs that use eventlog as their source
func (sb *SealedBlob) GetEventlogPCRIndices() []int {
	var indices []int
	for _, pair := range sb.PCRDigests {
		if pair.Source == PCRSourceEventlog {
			indices = append(indices, pair.Index)
		}
	}
	return indices
}

// GetRegisterPCRIndices returns indices of PCRs that use TPM registers as their source
func (sb *SealedBlob) GetRegisterPCRIndices() []int {
	var indices []int
	for _, pair := range sb.PCRDigests {
		if pair.Source == PCRSourceRegister {
			indices = append(indices, pair.Index)
		}
	}
	return indices
}

// HasPredictPCRs returns true if any PCR in this blob uses predict as its source
func (sb *SealedBlob) HasPredictPCRs() bool {
	for _, pair := range sb.PCRDigests {
		if pair.Source == PCRSourcePredict {
			return true
		}
	}
	return false
}

// GetPredictPCRIndices returns indices of PCRs that use prediction (external command) as their source
func (sb *SealedBlob) GetPredictPCRIndices() []int {
	var indices []int
	for _, pair := range sb.PCRDigests {
		if pair.Source == PCRSourcePredict {
			indices = append(indices, pair.Index)
		}
	}
	return indices
}

// GetPCRSpecs reconstructs PCRSpec slice from the sealed blob's PCR digests
func (sb *SealedBlob) GetPCRSpecs() []PCRSpec {
	specs := make([]PCRSpec, len(sb.PCRDigests))
	for i, pair := range sb.PCRDigests {
		specs[i] = PCRSpec{Index: pair.Index, Source: pair.Source, Command: pair.Command}
	}
	return specs
}

// Marshal converts the SealedBlob to bytes for storage (Version 3 format)
func (sb *SealedBlob) Marshal() ([]byte, error) {
	// Format v3: [version:4][appVersionLen:4][appVersion][publicLen:4][public][privateLen:4][private]
	//            [numPCRDigests:4][pcrDigestPairs...][hasPassword:1][hasEventlogInfo:1][eventlogInfo...]
	// where pcrDigestPairs = [pcrIndex:4][source:1][commandLen:2][command][digestLen:2][digest]...
	//   (commandLen+command only present when source == PCRSourcePredict)

	size := 4 + // version (4 bytes for alignment and future compatibility)
		4 + len(sb.AppVersion) + // app version length + string
		4 + len(sb.Public) + // public blob
		4 + len(sb.Private) + // private blob
		4 + // number of PCR digests
		1 + // hasPassword flag
		1 // hasEventlogInfo flag

	// Calculate PCR digest pair size
	for _, pcrDigest := range sb.PCRDigests {
		size += 4 + // PCR index
			1 + // source byte
			2 + len(pcrDigest.Digest.Buffer) // 2 bytes for length + digest data
		if pcrDigest.Source == PCRSourcePredict {
			size += 2 + len(pcrDigest.Command) // 2 bytes for command length + command string
		}
	}

	// Calculate eventlog info size (if present)
	hasEventlogInfo := sb.HasEventlogPCRs() && sb.EventlogInfo != nil
	if hasEventlogInfo {
		size += 4 + len(sb.EventlogInfo.EventlogPath) + // eventlog path
			4 + len(sb.EventlogInfo.EventlogHash) + // eventlog hash
			4 + len(sb.EventlogInfo.CalculationTime) + // calculation time
			4 + 4 // total events + processed events (4 bytes each)
	}

	buf := make([]byte, size)
	offset := 0

	// Version 3
	binary.LittleEndian.PutUint32(buf[offset:], CurrentBlobVersion)
	offset += 4

	// App version
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(sb.AppVersion)))
	offset += 4
	copy(buf[offset:], sb.AppVersion)
	offset += len(sb.AppVersion)

	// Public blob
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(sb.Public)))
	offset += 4
	copy(buf[offset:], sb.Public)
	offset += len(sb.Public)

	// Private blob
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(sb.Private)))
	offset += 4
	copy(buf[offset:], sb.Private)
	offset += len(sb.Private)

	// PCR digest pairs (index + source + digest together)
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(sb.PCRDigests)))
	offset += 4
	for _, pcrDigest := range sb.PCRDigests {
		// PCR index
		binary.LittleEndian.PutUint32(buf[offset:], uint32(pcrDigest.Index))
		offset += 4

		// PCR source
		buf[offset] = byte(pcrDigest.Source)
		offset++

		// Command string (only for predict source)
		if pcrDigest.Source == PCRSourcePredict {
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

	// Password flag (no hash/salt in v3)
	if sb.HasPassword {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}
	offset++

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
		binary.LittleEndian.PutUint32(buf[offset:], uint32(len(sb.EventlogInfo.EventlogPath)))
		offset += 4
		copy(buf[offset:], sb.EventlogInfo.EventlogPath)
		offset += len(sb.EventlogInfo.EventlogPath)

		// Eventlog hash
		binary.LittleEndian.PutUint32(buf[offset:], uint32(len(sb.EventlogInfo.EventlogHash)))
		offset += 4
		copy(buf[offset:], sb.EventlogInfo.EventlogHash)
		offset += len(sb.EventlogInfo.EventlogHash)

		// Calculation time
		binary.LittleEndian.PutUint32(buf[offset:], uint32(len(sb.EventlogInfo.CalculationTime)))
		offset += 4
		copy(buf[offset:], sb.EventlogInfo.CalculationTime)
		offset += len(sb.EventlogInfo.CalculationTime)

		// Total events and processed events
		binary.LittleEndian.PutUint32(buf[offset:], uint32(sb.EventlogInfo.TotalEvents))
		offset += 4
		binary.LittleEndian.PutUint32(buf[offset:], uint32(sb.EventlogInfo.ProcessedEvents))
		offset += 4
	}

	return buf, nil
}

// UnmarshalSealedBlob parses bytes back into a SealedBlob
// Only supports version 3 format
func UnmarshalSealedBlob(data []byte) (*SealedBlob, error) {
	// Validate total blob size to prevent resource exhaustion
	if len(data) > MaxBlobSize {
		return nil, fmt.Errorf("blob size %d exceeds maximum allowed %d bytes", len(data), MaxBlobSize)
	}

	if len(data) < 16 {
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

	offset := 4
	sb := &SealedBlob{Version: CurrentBlobVersion}

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
	sb.AppVersion = string(data[offset : offset+int(appVersionLen)])
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
	sb.Public = make([]byte, publicLen)
	copy(sb.Public, data[offset:offset+int(publicLen)])
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
	sb.Private = make([]byte, privateLen)
	copy(sb.Private, data[offset:offset+int(privateLen)])
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
	sb.PCRDigests = make([]PCRDigestPair, numPCRDigests)
	for i := 0; i < int(numPCRDigests); i++ {
		// PCR index
		if offset+4 > len(data) {
			return nil, fmt.Errorf("data too short for PCR index")
		}
		sb.PCRDigests[i].Index = int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4

		// PCR source
		if offset+1 > len(data) {
			return nil, fmt.Errorf("data too short for PCR source")
		}
		sb.PCRDigests[i].Source = PCRSource(data[offset])
		offset++

		// Command string (only for predict source)
		if sb.PCRDigests[i].Source == PCRSourcePredict {
			if offset+2 > len(data) {
				return nil, fmt.Errorf("data too short for predict command length")
			}
			commandLen := int(binary.LittleEndian.Uint16(data[offset:]))
			offset += 2
			if commandLen > MaxCommandLen {
				return nil, fmt.Errorf("predict command length %d exceeds maximum %d", commandLen, MaxCommandLen)
			}
			if offset+commandLen > len(data) {
				return nil, fmt.Errorf("data too short for predict command string")
			}
			sb.PCRDigests[i].Command = string(data[offset : offset+commandLen])
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

		sb.PCRDigests[i].Digest = tpm2.TPM2BDigest{
			Buffer: make([]byte, digestSize),
		}
		copy(sb.PCRDigests[i].Digest.Buffer, data[offset:offset+digestSize])
		offset += digestSize
	}

	// Password flag
	if offset >= len(data) {
		return nil, fmt.Errorf("data too short for password flag")
	}
	sb.HasPassword = data[offset] == 1
	offset++

	// Eventlog info flag
	if offset >= len(data) {
		return nil, fmt.Errorf("data too short for eventlog info flag")
	}
	hasEventlogInfo := data[offset] == 1
	offset++

	// Read eventlog metadata if flag is set and there's more data
	if hasEventlogInfo && offset < len(data) {
		sb.EventlogInfo = &EventlogInfo{}

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
		sb.EventlogInfo.EventlogPath = string(data[offset : offset+int(pathLen)])
		offset += int(pathLen)

		// Eventlog hash
		if offset+4 > len(data) {
			return nil, fmt.Errorf("data too short for eventlog hash length")
		}
		hashLen := binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		if hashLen > MaxEventlogHash {
			return nil, fmt.Errorf("eventlog hash length %d exceeds maximum %d", hashLen, MaxEventlogHash)
		}
		if offset+int(hashLen) > len(data) {
			return nil, fmt.Errorf("data too short for eventlog hash")
		}
		sb.EventlogInfo.EventlogHash = string(data[offset : offset+int(hashLen)])
		offset += int(hashLen)

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
		sb.EventlogInfo.CalculationTime = string(data[offset : offset+int(timeLen)])
		offset += int(timeLen)

		// Total and processed events
		if offset+8 > len(data) {
			return nil, fmt.Errorf("data too short for event counts")
		}
		sb.EventlogInfo.TotalEvents = int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		sb.EventlogInfo.ProcessedEvents = int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
	}

	return sb, nil
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

	pcrDigests := make([]PCRDigestJSON, len(sb.PCRDigests))
	for i, pcrDigest := range sb.PCRDigests {
		pcrDigests[i] = PCRDigestJSON{
			Index:   pcrDigest.Index,
			Source:  pcrDigest.Source.String(),
			Command: pcrDigest.Command,
			Digest:  hex.EncodeToString(pcrDigest.Digest.Buffer),
		}
	}

	// Create a JSON-friendly structure
	type SealedBlobJSON struct {
		Version       uint32          `json:"version"`
		AppVersion    string          `json:"app_version"`
		HashAlgorithm string          `json:"hash_algorithm"`
		Public        string          `json:"public_hex"`
		PublicSize    int             `json:"public_size"`
		Private       string          `json:"private_hex"`
		PrivateSize   int             `json:"private_size"`
		PCRDigests    []PCRDigestJSON `json:"pcr_digests"`
		HasPassword   bool            `json:"has_password"`
		EventlogInfo  *EventlogInfo   `json:"eventlog_info,omitempty"`
	}

	jsonBlob := SealedBlobJSON{
		Version:       sb.Version,
		AppVersion:    sb.AppVersion,
		HashAlgorithm: sb.GetHashAlgo().String(),
		Public:        hex.EncodeToString(sb.Public),
		PublicSize:    len(sb.Public),
		Private:       hex.EncodeToString(sb.Private),
		PrivateSize:   len(sb.Private),
		PCRDigests:    pcrDigests,
		HasPassword:   sb.HasPassword,
		EventlogInfo:  sb.EventlogInfo,
	}

	return json.Marshal(jsonBlob)
}
