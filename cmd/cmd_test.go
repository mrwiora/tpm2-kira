//go:build unit || !integration
// +build unit !integration

package cmd

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// TestParsePCRs tests PCR parsing from string format
func TestParsePCRs(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  []int
		shouldErr bool
	}{
		{
			name:     "Single PCR",
			input:    "0",
			expected: []int{0},
		},
		{
			name:     "Multiple PCRs",
			input:    "0,2,4,7",
			expected: []int{0, 2, 4, 7},
		},
		{
			name:     "PCRs with spaces",
			input:    "0, 2, 4, 7",
			expected: []int{0, 2, 4, 7},
		},
		{
			name:     "All common PCRs",
			input:    "0,1,2,3,4,5,6,7",
			expected: []int{0, 1, 2, 3, 4, 5, 6, 7},
		},
		{
			name:      "Invalid PCR number",
			input:     "0,25",
			shouldErr: true,
		},
		{
			name:      "Non-numeric PCR",
			input:     "0,abc",
			shouldErr: true,
		},
		{
			name:      "Empty string",
			input:     "",
			shouldErr: true,
		},
		{
			name:      "Negative PCR",
			input:     "0,-1",
			shouldErr: true,
		},
		{
			name:     "PCRs in random order",
			input:    "7,2,0,4",
			expected: []int{7, 2, 0, 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParsePCRs(tt.input)

			if tt.shouldErr {
				if err == nil {
					t.Errorf("Expected error for input %q, got nil", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for input %q: %v", tt.input, err)
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d PCRs, got %d", len(tt.expected), len(result))
				return
			}

			for i, pcr := range result {
				if pcr != tt.expected[i] {
					t.Errorf("PCR[%d]: expected %d, got %d", i, tt.expected[i], pcr)
				}
			}
		})
	}
}

// TestSealedBlobMarshalUnmarshal tests blob serialization and deserialization
func TestSealedBlobMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		blob *SealedBlob
	}{
		{
			name: "Basic blob with password",
			blob: &SealedBlob{
				Version:    2,
				AppVersion: "test-1.0.0",
				Public:     []byte("public-data-test"),
				Private:    []byte("private-data-test"),
				PCRDigests: []PCRDigestPair{
					{Index: 0, Digest: tpm2.TPM2BDigest{Buffer: []byte("digest0")}},
					{Index: 2, Digest: tpm2.TPM2BDigest{Buffer: []byte("digest2")}},
				},
				HasPassword: true,
			},
		},
		{
			name: "Blob without password",
			blob: &SealedBlob{
				Version:    2,
				AppVersion: "test-0.0.0",
				Public:     []byte("public"),
				Private:    []byte("private"),
				PCRDigests: []PCRDigestPair{
					{Index: 7, Digest: tpm2.TPM2BDigest{Buffer: []byte("digest7")}},
				},
				HasPassword: false,
			},
		},
		{
			name: "Blob with multiple PCRs",
			blob: &SealedBlob{
				Version:    2,
				AppVersion: "v2.0.0",
				Public:     []byte("test-public-key-data"),
				Private:    []byte("test-private-key-data"),
				PCRDigests: []PCRDigestPair{
					{Index: 0, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 1, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 2, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 4, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 7, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
				},
				HasPassword: true,
			},
		},
		{
			name: "Blob with empty PCR list",
			blob: &SealedBlob{
				Version:     2,
				AppVersion:  "test",
				Public:      []byte("pub"),
				Private:     []byte("priv"),
				PCRDigests:  []PCRDigestPair{},
				HasPassword: false,
			},
		},
		{
			name: "Blob with eventlog info",
			blob: &SealedBlob{
				Version:    2,
				AppVersion: "test-eventlog",
				Public:     []byte("public-data"),
				Private:    []byte("private-data"),
				PCRDigests: []PCRDigestPair{
					{Index: 0, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
				},
				HasPassword:   true,
				EventlogBased: true,
				EventlogInfo: &EventlogInfo{
					EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
					EventlogHash:    "abc123def456",
					CalculationTime: "2024-01-01T00:00:00Z",
					TotalEvents:     100,
					ProcessedEvents: 50,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.blob.Marshal()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			// Unmarshal
			unmarshaled, err := UnmarshalSealedBlob(data)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			// Compare
			if unmarshaled.Version != CurrentBlobVersion {
				t.Errorf("Version should be %d, got %d", CurrentBlobVersion, unmarshaled.Version)
			}

			if unmarshaled.AppVersion != tt.blob.AppVersion {
				t.Errorf("AppVersion mismatch: expected %s, got %s", tt.blob.AppVersion, unmarshaled.AppVersion)
			}

			if !bytes.Equal(unmarshaled.Public, tt.blob.Public) {
				t.Errorf("Public data mismatch")
			}

			if !bytes.Equal(unmarshaled.Private, tt.blob.Private) {
				t.Errorf("Private data mismatch")
			}

			if len(unmarshaled.PCRDigests) != len(tt.blob.PCRDigests) {
				t.Errorf("PCRDigests length mismatch: expected %d, got %d",
					len(tt.blob.PCRDigests), len(unmarshaled.PCRDigests))
			}

			for i := range tt.blob.PCRDigests {
				if unmarshaled.PCRDigests[i].Index != tt.blob.PCRDigests[i].Index {
					t.Errorf("PCR[%d] index mismatch: expected %d, got %d",
						i, tt.blob.PCRDigests[i].Index, unmarshaled.PCRDigests[i].Index)
				}
				if !bytes.Equal(unmarshaled.PCRDigests[i].Digest.Buffer, tt.blob.PCRDigests[i].Digest.Buffer) {
					t.Errorf("PCR[%d] digest mismatch", i)
				}
			}

			if unmarshaled.HasPassword != tt.blob.HasPassword {
				t.Errorf("HasPassword mismatch: expected %v, got %v", tt.blob.HasPassword, unmarshaled.HasPassword)
			}

			if unmarshaled.EventlogBased != tt.blob.EventlogBased {
				t.Errorf("EventlogBased mismatch: expected %v, got %v", tt.blob.EventlogBased, unmarshaled.EventlogBased)
			}

			if tt.blob.EventlogInfo != nil {
				if unmarshaled.EventlogInfo == nil {
					t.Errorf("EventlogInfo should not be nil")
				} else {
					if unmarshaled.EventlogInfo.EventlogPath != tt.blob.EventlogInfo.EventlogPath {
						t.Errorf("EventlogPath mismatch")
					}
					if unmarshaled.EventlogInfo.EventlogHash != tt.blob.EventlogInfo.EventlogHash {
						t.Errorf("EventlogHash mismatch")
					}
					if unmarshaled.EventlogInfo.TotalEvents != tt.blob.EventlogInfo.TotalEvents {
						t.Errorf("TotalEvents mismatch")
					}
				}
			}
		})
	}
}

// TestUnmarshalSealedBlobInvalid tests unmarshaling invalid data
func TestUnmarshalSealedBlobInvalid(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		errContains string
	}{
		{
			name:        "Too short",
			data:        []byte{0x01, 0x00},
			errContains: "data too short",
		},
		{
			name: "Version 1 incompatible",
			data: func() []byte {
				d := make([]byte, 20)
				d[0] = 0x01 // version 1
				return d
			}(),
			errContains: "restart sealing process due to incompatibility",
		},
		{
			name: "Version 99 incompatible",
			data: func() []byte {
				d := make([]byte, 20)
				d[0] = 0x63 // version 99
				return d
			}(),
			errContains: "restart sealing process due to incompatibility",
		},
		{
			name: "Truncated data",
			data: []byte{
				0x02, 0x00, 0x00, 0x00, // version 2
				0x05, 0x00, 0x00, 0x00, // app version length 5
				0x00, 0x00, 0x00, 0x00, // padding to pass minimum length check
				0x00, 0x00, 0x00, 0x00, // more padding
				// missing app version data (only 0 bytes, need 5)
			},
			errContains: "data too short", // generic truncation error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalSealedBlob(tt.data)
			if err == nil {
				t.Errorf("Expected error unmarshaling invalid data, got nil")
				return
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("Expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}

// TestUnmarshalIncompatibleVersion tests the specific incompatibility error message
func TestUnmarshalIncompatibleVersion(t *testing.T) {
	// Create data with version 1
	data := make([]byte, 20)
	data[0] = 0x01 // version 1
	data[1] = 0x00
	data[2] = 0x00
	data[3] = 0x00

	_, err := UnmarshalSealedBlob(data)
	if err == nil {
		t.Fatal("Expected error for incompatible version, got nil")
	}

	expectedMsg := "tpm2-kira: restart sealing process due to incompatibility"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error message to contain %q, got: %v", expectedMsg, err)
	}

	// Verify it mentions the version numbers
	if !strings.Contains(err.Error(), "found version 1") {
		t.Errorf("Expected error to mention found version 1, got: %v", err)
	}
	if !strings.Contains(err.Error(), "requires version 2") {
		t.Errorf("Expected error to mention requires version 2, got: %v", err)
	}
}

// TestGetPCRIndices tests extracting PCR indices from SealedBlob
func TestGetPCRIndices(t *testing.T) {
	blob := &SealedBlob{
		PCRDigests: []PCRDigestPair{
			{Index: 0, Digest: tpm2.TPM2BDigest{Buffer: []byte("d0")}},
			{Index: 2, Digest: tpm2.TPM2BDigest{Buffer: []byte("d2")}},
			{Index: 4, Digest: tpm2.TPM2BDigest{Buffer: []byte("d4")}},
			{Index: 7, Digest: tpm2.TPM2BDigest{Buffer: []byte("d7")}},
		},
	}

	indices := blob.GetPCRIndices()

	expected := []int{0, 2, 4, 7}
	if len(indices) != len(expected) {
		t.Fatalf("Expected %d indices, got %d", len(expected), len(indices))
	}

	for i, idx := range indices {
		if idx != expected[i] {
			t.Errorf("Index[%d]: expected %d, got %d", i, expected[i], idx)
		}
	}
}

// TestGetPCRDigestValues tests extracting PCR digest values from SealedBlob
func TestGetPCRDigestValues(t *testing.T) {
	digest0 := []byte("digest0-value")
	digest2 := []byte("digest2-value")

	blob := &SealedBlob{
		PCRDigests: []PCRDigestPair{
			{Index: 0, Digest: tpm2.TPM2BDigest{Buffer: digest0}},
			{Index: 2, Digest: tpm2.TPM2BDigest{Buffer: digest2}},
		},
	}

	digests := blob.GetPCRDigestValues()

	if len(digests) != 2 {
		t.Fatalf("Expected 2 digests, got %d", len(digests))
	}

	if !bytes.Equal(digests[0].Buffer, digest0) {
		t.Errorf("Digest[0] mismatch")
	}

	if !bytes.Equal(digests[1].Buffer, digest2) {
		t.Errorf("Digest[1] mismatch")
	}
}

// TestVerifyPCRValues tests PCR value verification
func TestVerifyPCRValues(t *testing.T) {
	digest1 := tpm2.TPM2BDigest{Buffer: []byte("test-digest-1")}
	digest2 := tpm2.TPM2BDigest{Buffer: []byte("test-digest-2")}
	digest3 := tpm2.TPM2BDigest{Buffer: []byte("test-digest-3")}

	tests := []struct {
		name     string
		sealed   []tpm2.TPM2BDigest
		current  []tpm2.TPM2BDigest
		expected bool
	}{
		{
			name:     "Matching digests",
			sealed:   []tpm2.TPM2BDigest{digest1, digest2},
			current:  []tpm2.TPM2BDigest{digest1, digest2},
			expected: true,
		},
		{
			name:     "Non-matching digests",
			sealed:   []tpm2.TPM2BDigest{digest1, digest2},
			current:  []tpm2.TPM2BDigest{digest1, digest3},
			expected: false,
		},
		{
			name:     "Different lengths",
			sealed:   []tpm2.TPM2BDigest{digest1, digest2},
			current:  []tpm2.TPM2BDigest{digest1},
			expected: false,
		},
		{
			name:     "Empty lists",
			sealed:   []tpm2.TPM2BDigest{},
			current:  []tpm2.TPM2BDigest{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyPCRValues(tt.sealed, tt.current)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestPcrsToBitmapBytes tests PCR to bitmap conversion
func TestPcrsToBitmapBytes(t *testing.T) {
	tests := []struct {
		name     string
		pcrs     []int
		expected []byte
	}{
		{
			name:     "PCR 0",
			pcrs:     []int{0},
			expected: []byte{0x01, 0x00, 0x00},
		},
		{
			name:     "PCR 7",
			pcrs:     []int{7},
			expected: []byte{0x80, 0x00, 0x00},
		},
		{
			name:     "PCRs 0,2,4,7",
			pcrs:     []int{0, 2, 4, 7},
			expected: []byte{0x95, 0x00, 0x00}, // 10010101 = 0x95
		},
		{
			name:     "Multiple PCRs",
			pcrs:     []int{0, 1, 2, 3, 4, 5, 6, 7},
			expected: []byte{0xFF, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PcrsToBitmapBytes(tt.pcrs)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("Expected %v (0x%s), got %v (0x%s)",
					tt.expected, hex.EncodeToString(tt.expected),
					result, hex.EncodeToString(result))
			}
		})
	}
}

// TestSealedBlobMarshalJSON tests JSON serialization
func TestSealedBlobMarshalJSON(t *testing.T) {
	blob := &SealedBlob{
		Version:    2,
		AppVersion: "test-1.0.0",
		Public:     []byte{0x01, 0x02, 0x03},
		Private:    []byte{0x04, 0x05, 0x06},
		PCRDigests: []PCRDigestPair{
			{Index: 0, Digest: tpm2.TPM2BDigest{Buffer: []byte{0xAA, 0xBB}}},
		},
		HasPassword: true,
	}

	jsonData, err := blob.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	jsonStr := string(jsonData)

	// Check for expected fields
	expectedFields := []string{
		`"version"`,
		`"app_version"`,
		`"public_hex"`,
		`"private_hex"`,
		`"pcr_digests"`,
		`"has_password"`,
	}

	for _, field := range expectedFields {
		if !bytes.Contains(jsonData, []byte(field)) {
			t.Errorf("Expected JSON to contain %s, got: %s", field, jsonStr)
		}
	}

	// Ensure password_hash_hex and password_salt_hex are NOT present
	unexpectedFields := []string{
		`"password_hash_hex"`,
		`"password_salt_hex"`,
	}

	for _, field := range unexpectedFields {
		if bytes.Contains(jsonData, []byte(field)) {
			t.Errorf("JSON should NOT contain %s, got: %s", field, jsonStr)
		}
	}

	// Verify hex encoding is correct
	if !bytes.Contains(jsonData, []byte("010203")) { // public hex
		t.Error("Public data not hex encoded correctly")
	}

	if !bytes.Contains(jsonData, []byte("aabb")) { // PCR digest hex
		t.Error("PCR digest not hex encoded correctly")
	}
}

// TestCreatePCRSelection tests PCR selection creation
func TestCreatePCRSelection(t *testing.T) {
	pcrs := []int{0, 2, 4, 7}
	selection := CreatePCRSelection(pcrs)

	if len(selection.PCRSelections) == 0 {
		t.Fatal("Expected at least one PCR selection")
	}

	pcrSel := selection.PCRSelections[0]

	if pcrSel.Hash != tpm2.TPMAlgSHA256 {
		t.Errorf("Expected SHA256 hash algorithm, got %v", pcrSel.Hash)
	}

	// Verify bitmap is set correctly
	bitmap := PcrsToBitmapBytes(pcrs)
	if !bytes.Equal(pcrSel.PCRSelect, bitmap) {
		t.Error("PCR selection bitmap mismatch")
	}
}

// TestSealedBlobRoundTrip tests a complete round trip with realistic data
func TestSealedBlobRoundTrip(t *testing.T) {
	// Create a blob with realistic TPM data sizes
	original := &SealedBlob{
		Version:    2,
		AppVersion: "v1.2.3",
		Public:     make([]byte, 100), // Typical public key size
		Private:    make([]byte, 150), // Typical private key size
		PCRDigests: []PCRDigestPair{
			{Index: 0, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			{Index: 2, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			{Index: 4, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			{Index: 7, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
		},
		HasPassword: true,
	}

	// Fill with test data
	for i := range original.Public {
		original.Public[i] = byte(i % 256)
	}
	for i := range original.Private {
		original.Private[i] = byte((i * 2) % 256)
	}
	for _, pcr := range original.PCRDigests {
		for i := range pcr.Digest.Buffer {
			pcr.Digest.Buffer[i] = byte(i * 3 % 256)
		}
	}

	// Marshal
	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	t.Logf("Marshaled size: %d bytes", len(data))

	// Unmarshal
	restored, err := UnmarshalSealedBlob(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify all fields match
	if restored.Version != CurrentBlobVersion {
		t.Errorf("Version should be %d, got %d", CurrentBlobVersion, restored.Version)
	}
	if restored.AppVersion != original.AppVersion {
		t.Error("AppVersion mismatch")
	}
	if !bytes.Equal(restored.Public, original.Public) {
		t.Error("Public data mismatch")
	}
	if !bytes.Equal(restored.Private, original.Private) {
		t.Error("Private data mismatch")
	}
	if restored.HasPassword != original.HasPassword {
		t.Error("HasPassword mismatch")
	}
}

// TestIsTPMAuthError tests TPM authentication error detection
func TestIsTPMAuthError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "TPM_RC_AUTH_FAIL",
			err:      &testError{msg: "TPM returned: TPM_RC_AUTH_FAIL"},
			expected: true,
		},
		{
			name:     "TPM_RC_BAD_AUTH",
			err:      &testError{msg: "error: TPM_RC_BAD_AUTH"},
			expected: true,
		},
		{
			name:     "authorization failure",
			err:      &testError{msg: "authorization failure during unseal"},
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      &testError{msg: "failed to open TPM device"},
			expected: false,
		},
		{
			name:     "auth fail lowercase",
			err:      &testError{msg: "auth fail"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsTPMAuthError(tt.err)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for error: %v", tt.expected, result, tt.err)
			}
		})
	}
}

// TestCurrentBlobVersion verifies the constant is set correctly
func TestCurrentBlobVersion(t *testing.T) {
	if CurrentBlobVersion != 2 {
		t.Errorf("CurrentBlobVersion should be 2, got %d", CurrentBlobVersion)
	}
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
