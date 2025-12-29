package cmd

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// AppVersion is the version of the application that created the sealed blob
// This should be set by the main package during initialization
var AppVersion = "unknown"

// CurrentBlobVersion is the only supported blob format version
const CurrentBlobVersion = 2

// PCRDigestPair represents a PCR index paired with its digest value
type PCRDigestPair struct {
	Index  int              `json:"index"`  // PCR index
	Digest tpm2.TPM2BDigest `json:"digest"` // PCR digest value at seal time
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
// Version 2: Password validation is done solely by TPM, no hash/salt stored
type SealedBlob struct {
	Version       uint32          `json:"version"`        // Blob format version (must be 2)
	AppVersion    string          `json:"app_version"`    // Application version that created this blob
	Public        []byte          `json:"public"`         // TPM public key blob
	Private       []byte          `json:"private"`        // TPM private key blob
	PCRDigests    []PCRDigestPair `json:"pcr_digests"`    // PCR indices with their digest values
	HasPassword   bool            `json:"has_password"`   // Whether password fallback is enabled
	EventlogBased bool            `json:"eventlog_based"` // Whether PCR values were calculated from eventlog
	EventlogInfo  *EventlogInfo   `json:"eventlog_info"`  // Eventlog calculation metadata (if eventlog_based is true)
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

// Marshal converts the SealedBlob to bytes for storage (Version 2 format)
func (sb *SealedBlob) Marshal() ([]byte, error) {
	// Format v2: [version:4][appVersionLen:4][appVersion][publicLen:4][public][privateLen:4][private]
	//            [numPCRDigests:4][pcrDigestPairs...][hasPassword:1][eventlogBased:1][eventlogInfo...]
	// where pcrDigestPairs = [pcrIndex:4][digestLen:2][digest]... (repeated for each PCR)

	size := 4 + // version (4 bytes for alignment and future compatibility)
		4 + len(sb.AppVersion) + // app version length + string
		4 + len(sb.Public) + // public blob
		4 + len(sb.Private) + // private blob
		4 + // number of PCR digests
		1 + // hasPassword flag
		1 // eventlogBased flag

	// Calculate PCR digest pair size
	for _, pcrDigest := range sb.PCRDigests {
		size += 4 + // PCR index
			2 + len(pcrDigest.Digest.Buffer) // 2 bytes for length + digest data
	}

	// Calculate eventlog info size (if present)
	if sb.EventlogBased && sb.EventlogInfo != nil {
		size += 4 + len(sb.EventlogInfo.EventlogPath) + // eventlog path
			4 + len(sb.EventlogInfo.EventlogHash) + // eventlog hash
			4 + len(sb.EventlogInfo.CalculationTime) + // calculation time
			4 + 4 // total events + processed events (4 bytes each)
	}

	buf := make([]byte, size)
	offset := 0

	// Version 2
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

	// PCR digest pairs (index + digest together)
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(sb.PCRDigests)))
	offset += 4
	for _, pcrDigest := range sb.PCRDigests {
		// PCR index
		binary.LittleEndian.PutUint32(buf[offset:], uint32(pcrDigest.Index))
		offset += 4

		// PCR digest
		binary.LittleEndian.PutUint16(buf[offset:], uint16(len(pcrDigest.Digest.Buffer)))
		offset += 2
		copy(buf[offset:], pcrDigest.Digest.Buffer)
		offset += len(pcrDigest.Digest.Buffer)
	}

	// Password flag (no hash/salt in v2)
	if sb.HasPassword {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}
	offset++

	// Eventlog information
	if sb.EventlogBased {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}
	offset++

	// Eventlog metadata (only if eventlog-based and info is available)
	if sb.EventlogBased && sb.EventlogInfo != nil {
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
// Only supports version 2 format
func UnmarshalSealedBlob(data []byte) (*SealedBlob, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("data too short to be a valid sealed blob")
	}

	// Version check
	version := binary.LittleEndian.Uint32(data[0:4])
	if version != CurrentBlobVersion {
		return nil, fmt.Errorf("tpm2-kira: restart sealing process due to incompatibility (found version %d, requires version %d)", version, CurrentBlobVersion)
	}

	offset := 4
	sb := &SealedBlob{Version: CurrentBlobVersion}

	// App version
	if offset+4 > len(data) {
		return nil, fmt.Errorf("data too short for app version length")
	}
	appVersionLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
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
	sb.PCRDigests = make([]PCRDigestPair, numPCRDigests)
	for i := 0; i < int(numPCRDigests); i++ {
		// PCR index
		if offset+4 > len(data) {
			return nil, fmt.Errorf("data too short for PCR index")
		}
		sb.PCRDigests[i].Index = int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4

		// PCR digest
		if offset+2 > len(data) {
			return nil, fmt.Errorf("data too short for digest size")
		}
		digestSize := int(binary.LittleEndian.Uint16(data[offset:]))
		offset += 2

		if offset+digestSize > len(data) {
			return nil, fmt.Errorf("data too short for digest buffer")
		}

		sb.PCRDigests[i].Digest = tpm2.TPM2BDigest{
			Buffer: make([]byte, digestSize),
		}
		copy(sb.PCRDigests[i].Digest.Buffer, data[offset:offset+digestSize])
		offset += digestSize
	}

	// Password flag (no hash/salt in v2)
	if offset >= len(data) {
		return nil, fmt.Errorf("data too short for password flag")
	}
	sb.HasPassword = data[offset] == 1
	offset++

	// Eventlog flag
	if offset >= len(data) {
		return nil, fmt.Errorf("data too short for eventlog flag")
	}
	sb.EventlogBased = data[offset] == 1
	offset++

	// Read eventlog metadata if eventlog-based and there's more data
	if sb.EventlogBased && offset < len(data) {
		sb.EventlogInfo = &EventlogInfo{}

		// Eventlog path
		if offset+4 > len(data) {
			return nil, fmt.Errorf("data too short for eventlog path length")
		}
		pathLen := binary.LittleEndian.Uint32(data[offset:])
		offset += 4
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
		Index  int    `json:"index"`
		Digest string `json:"digest_hex"`
	}

	pcrDigests := make([]PCRDigestJSON, len(sb.PCRDigests))
	for i, pcrDigest := range sb.PCRDigests {
		pcrDigests[i] = PCRDigestJSON{
			Index:  pcrDigest.Index,
			Digest: hex.EncodeToString(pcrDigest.Digest.Buffer),
		}
	}

	// Create a JSON-friendly structure
	type SealedBlobJSON struct {
		Version       uint32          `json:"version"`
		AppVersion    string          `json:"app_version"`
		Public        string          `json:"public_hex"`
		PublicSize    int             `json:"public_size"`
		Private       string          `json:"private_hex"`
		PrivateSize   int             `json:"private_size"`
		PCRDigests    []PCRDigestJSON `json:"pcr_digests"`
		HasPassword   bool            `json:"has_password"`
		EventlogBased bool            `json:"eventlog_based"`
		EventlogInfo  *EventlogInfo   `json:"eventlog_info,omitempty"`
	}

	jsonBlob := SealedBlobJSON{
		Version:       sb.Version,
		AppVersion:    sb.AppVersion,
		Public:        hex.EncodeToString(sb.Public),
		PublicSize:    len(sb.Public),
		Private:       hex.EncodeToString(sb.Private),
		PrivateSize:   len(sb.Private),
		PCRDigests:    pcrDigests,
		HasPassword:   sb.HasPassword,
		EventlogBased: sb.EventlogBased,
		EventlogInfo:  sb.EventlogInfo,
	}

	return json.Marshal(jsonBlob)
}
