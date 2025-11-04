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

// PCRDigestPair represents a PCR index paired with its digest value
type PCRDigestPair struct {
	Index  int              `json:"index"`  // PCR index
	Digest tpm2.TPM2BDigest `json:"digest"` // PCR digest value at seal time
}

// SealedBlob represents the complete sealed data structure
type SealedBlob struct {
	Version      uint32          `json:"version"`       // Blob format version
	AppVersion   string          `json:"app_version"`   // Application version that created this blob
	Public       []byte          `json:"public"`        // TPM public key blob
	Private      []byte          `json:"private"`       // TPM private key blob
	PCRDigests   []PCRDigestPair `json:"pcr_digests"`   // PCR indices with their digest values
	HasPassword  bool            `json:"has_password"`  // Whether password fallback is enabled
	PasswordHash []byte          `json:"password_hash"` // Argon2id hash of password (for verification)
	PasswordSalt []byte          `json:"password_salt"` // Salt for password hashing
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

// Marshal converts the SealedBlob to bytes for storage
func (sb *SealedBlob) Marshal() ([]byte, error) {
	// Calculate total size
	// Format v1: [version:4][appVersionLen:4][appVersion][publicLen:4][public][privateLen:4][private][numPCRDigests:4][pcrDigestPairs...][hasPassword:1][passwordHashLen:4][passwordHash][passwordSaltLen:4][passwordSalt]
	// where pcrDigestPairs = [pcrIndex:4][digestLen:2][digest]... (repeated for each PCR)

	size := 4 + // version (4 bytes for alignment and future compatibility)
		4 + len(sb.AppVersion) + // app version length + string
		4 + len(sb.Public) + // public blob
		4 + len(sb.Private) + // private blob
		4 + // number of PCR digests
		1 + // hasPassword flag
		4 + len(sb.PasswordHash) + // password hash length + hash
		4 + len(sb.PasswordSalt) // password salt length + salt

	// Calculate PCR digest pair size
	for _, pcrDigest := range sb.PCRDigests {
		size += 4 + // PCR index
			2 + len(pcrDigest.Digest.Buffer) // 2 bytes for length + digest data
	}

	buf := make([]byte, size)
	offset := 0

	// Version 1
	binary.LittleEndian.PutUint32(buf[offset:], 1)
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

	// Password information
	if sb.HasPassword {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}
	offset++

	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(sb.PasswordHash)))
	offset += 4
	if len(sb.PasswordHash) > 0 {
		copy(buf[offset:], sb.PasswordHash)
		offset += len(sb.PasswordHash)
	}

	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(sb.PasswordSalt)))
	offset += 4
	if len(sb.PasswordSalt) > 0 {
		copy(buf[offset:], sb.PasswordSalt)
		offset += len(sb.PasswordSalt)
	}

	return buf, nil
}

// UnmarshalSealedBlob parses bytes back into a SealedBlob
func UnmarshalSealedBlob(data []byte) (*SealedBlob, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("data too short to be a valid sealed blob")
	}

	offset := 0
	sb := &SealedBlob{}

	// Version
	version := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if version != 1 {
		return nil, fmt.Errorf("unsupported blob version: %d (only version 1 is supported)", version)
	}
	sb.Version = version

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

	// Password information
	if offset >= len(data) {
		return nil, fmt.Errorf("data too short for password flag")
	}
	sb.HasPassword = data[offset] == 1
	offset++

	if offset+4 > len(data) {
		return nil, fmt.Errorf("data too short for password hash length")
	}
	passwordHashLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	if passwordHashLen > 0 {
		if offset+int(passwordHashLen) > len(data) {
			return nil, fmt.Errorf("data too short for password hash")
		}
		sb.PasswordHash = make([]byte, passwordHashLen)
		copy(sb.PasswordHash, data[offset:offset+int(passwordHashLen)])
		offset += int(passwordHashLen)
	}

	// Password salt
	if offset+4 > len(data) {
		return nil, fmt.Errorf("data too short for password salt length")
	}
	passwordSaltLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	if passwordSaltLen > 0 {
		if offset+int(passwordSaltLen) > len(data) {
			return nil, fmt.Errorf("data too short for password salt")
		}
		sb.PasswordSalt = make([]byte, passwordSaltLen)
		copy(sb.PasswordSalt, data[offset:offset+int(passwordSaltLen)])
		offset += int(passwordSaltLen)
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
		Version      uint32          `json:"version"`
		AppVersion   string          `json:"app_version"`
		Public       string          `json:"public_hex"`
		PublicSize   int             `json:"public_size"`
		Private      string          `json:"private_hex"`
		PrivateSize  int             `json:"private_size"`
		PCRDigests   []PCRDigestJSON `json:"pcr_digests"`
		HasPassword  bool            `json:"has_password"`
		PasswordHash string          `json:"password_hash_hex,omitempty"`
		PasswordSalt string          `json:"password_salt_hex,omitempty"`
	}

	jsonBlob := SealedBlobJSON{
		Version:     sb.Version,
		AppVersion:  sb.AppVersion,
		Public:      hex.EncodeToString(sb.Public),
		PublicSize:  len(sb.Public),
		Private:     hex.EncodeToString(sb.Private),
		PrivateSize: len(sb.Private),
		PCRDigests:  pcrDigests,
		HasPassword: sb.HasPassword,
	}

	if len(sb.PasswordHash) > 0 {
		jsonBlob.PasswordHash = hex.EncodeToString(sb.PasswordHash)
	}
	if len(sb.PasswordSalt) > 0 {
		jsonBlob.PasswordSalt = hex.EncodeToString(sb.PasswordSalt)
	}

	return json.Marshal(jsonBlob)
}
