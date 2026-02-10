//go:build unit || !integration
// +build unit !integration

package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
)

// TestParsePCRSpecs tests PCR spec parsing with source suffixes
func TestParsePCRSpecs(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  []PCRSpec
		shouldErr bool
	}{
		{
			name:  "Single PCR no suffix (default register)",
			input: "0",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceRegister},
			},
		},
		{
			name:  "Single PCR explicit register suffix",
			input: "0r",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceRegister},
			},
		},
		{
			name:  "Single PCR eventlog suffix",
			input: "0e",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceEventlog},
			},
		},
		{
			name:  "Multiple PCRs all register (no suffix)",
			input: "0,2,4,7",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceRegister},
				{Index: 2, Source: PCRSourceRegister},
				{Index: 4, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceRegister},
			},
		},
		{
			name:  "Multiple PCRs all eventlog",
			input: "0e,2e,7e",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceEventlog},
				{Index: 7, Source: PCRSourceEventlog},
			},
		},
		{
			name:  "Mixed register and eventlog",
			input: "0e,2,7e",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceEventlog},
			},
		},
		{
			name:  "Mixed with explicit r suffix",
			input: "0e,2r,4r,7e",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceRegister},
				{Index: 4, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceEventlog},
			},
		},
		{
			name:  "PCRs with spaces",
			input: "0e, 2, 7e",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceEventlog},
			},
		},
		{
			name:  "All firmware PCRs eventlog",
			input: "0e,1e,2e,3e,4e,5e,6e,7e",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 1, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceEventlog},
				{Index: 3, Source: PCRSourceEventlog},
				{Index: 4, Source: PCRSourceEventlog},
				{Index: 5, Source: PCRSourceEventlog},
				{Index: 6, Source: PCRSourceEventlog},
				{Index: 7, Source: PCRSourceEventlog},
			},
		},
		{
			name:  "PCR 7 eventlog is allowed",
			input: "7e",
			expected: []PCRSpec{
				{Index: 7, Source: PCRSourceEventlog},
			},
		},
		{
			name:  "PCR 8 eventlog is allowed",
			input: "8e",
			expected: []PCRSpec{
				{Index: 8, Source: PCRSourceEventlog},
			},
		},
		{
			name:  "PCR 12 eventlog is allowed",
			input: "0e,12e",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 12, Source: PCRSourceEventlog},
			},
		},
		{
			name:  "PCR 11 predict with command",
			input: "11p:tpm2-pcr11predict",
			expected: []PCRSpec{
				{Index: 11, Source: PCRSourcePredict, Command: "tpm2-pcr11predict"},
			},
		},
		{
			name:  "PCR 11 predict with absolute path command",
			input: "11p:/usr/local/bin/tpm2-pcr11predict",
			expected: []PCRSpec{
				{Index: 11, Source: PCRSourcePredict, Command: "/usr/local/bin/tpm2-pcr11predict"},
			},
		},
		{
			name:  "Mixed eventlog register and predict",
			input: "0e,2,7e,11p:my-predict",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceEventlog},
				{Index: 11, Source: PCRSourcePredict, Command: "my-predict"},
			},
		},
		{
			name:      "Predict suffix rejected for PCR 0",
			input:     "0p:cmd",
			shouldErr: true,
		},
		{
			name:      "Predict suffix rejected for PCR 7",
			input:     "7p:cmd",
			shouldErr: true,
		},
		{
			name:      "Predict suffix rejected for PCR 12",
			input:     "12p:cmd",
			shouldErr: true,
		},
		{
			name:      "Predict suffix without command is rejected",
			input:     "11p:",
			shouldErr: true,
		},
		{
			name:      "PCR 13 eventlog is rejected",
			input:     "13e",
			shouldErr: true,
		},
		{
			name:      "PCR 14 eventlog is rejected",
			input:     "14e",
			shouldErr: true,
		},
		{
			name:      "PCR 23 eventlog is rejected",
			input:     "23e",
			shouldErr: true,
		},
		{
			name:  "PCR 8 register is allowed",
			input: "8",
			expected: []PCRSpec{
				{Index: 8, Source: PCRSourceRegister},
			},
		},
		{
			name:  "PCR 23 register is allowed",
			input: "23r",
			expected: []PCRSpec{
				{Index: 23, Source: PCRSourceRegister},
			},
		},
		{
			name:      "Invalid PCR number",
			input:     "0e,25",
			shouldErr: true,
		},
		{
			name:      "Non-numeric PCR",
			input:     "0e,abc",
			shouldErr: true,
		},
		{
			name:      "Empty string",
			input:     "",
			shouldErr: true,
		},
		{
			name:      "Negative PCR",
			input:     "-1e",
			shouldErr: true,
		},
		{
			name:      "Duplicate PCR different sources",
			input:     "0e,0r,7,9",
			shouldErr: true,
		},
		{
			name:      "Duplicate PCR same source",
			input:     "0e,2,0e",
			shouldErr: true,
		},
		{
			name:      "Duplicate PCR no suffix",
			input:     "0,2,7,0",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParsePCRSpecs(tt.input)

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
				t.Errorf("Expected %d specs, got %d", len(tt.expected), len(result))
				return
			}

			for i, spec := range result {
				if spec.Index != tt.expected[i].Index {
					t.Errorf("Spec[%d].Index: expected %d, got %d", i, tt.expected[i].Index, spec.Index)
				}
				if spec.Source != tt.expected[i].Source {
					t.Errorf("Spec[%d].Source: expected %v, got %v", i, tt.expected[i].Source, spec.Source)
				}
			}
		})
	}
}

// TestParsePCRs tests PCR parsing from string format (index-only convenience wrapper)
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
			name:     "PCRs with suffix stripped",
			input:    "0e,2r,7e",
			expected: []int{0, 2, 7},
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
		{
			name:      "Duplicate PCR simple",
			input:     "0,0",
			shouldErr: true,
		},
		{
			name:      "Duplicate PCR repeated many times",
			input:     "0,0,0,0,0",
			shouldErr: true,
		},
		{
			name:      "Duplicate PCR non-adjacent",
			input:     "0,2,7,2",
			shouldErr: true,
		},
		{
			name:      "Duplicate PCR mixed with valid",
			input:     "0,2,4,7,4",
			shouldErr: true,
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

// TestPCRSpecsToString tests converting PCR specs back to string format
func TestPCRSpecsToString(t *testing.T) {
	tests := []struct {
		name     string
		specs    []PCRSpec
		expected string
	}{
		{
			name:     "All register (no suffix)",
			specs:    []PCRSpec{{Index: 0, Source: PCRSourceRegister}, {Index: 2, Source: PCRSourceRegister}, {Index: 7, Source: PCRSourceRegister}},
			expected: "0,2,7",
		},
		{
			name:     "All eventlog",
			specs:    []PCRSpec{{Index: 0, Source: PCRSourceEventlog}, {Index: 2, Source: PCRSourceEventlog}, {Index: 7, Source: PCRSourceEventlog}},
			expected: "0e,2e,7e",
		},
		{
			name:     "Mixed sources",
			specs:    []PCRSpec{{Index: 0, Source: PCRSourceEventlog}, {Index: 2, Source: PCRSourceRegister}, {Index: 7, Source: PCRSourceEventlog}},
			expected: "0e,2,7e",
		},
		{
			name:     "Single register",
			specs:    []PCRSpec{{Index: 4, Source: PCRSourceRegister}},
			expected: "4",
		},
		{
			name:     "Single eventlog",
			specs:    []PCRSpec{{Index: 0, Source: PCRSourceEventlog}},
			expected: "0e",
		},
		{
			name:     "Single predict",
			specs:    []PCRSpec{{Index: 11, Source: PCRSourcePredict, Command: "tpm2-pcr11predict"}},
			expected: "11p:tpm2-pcr11predict",
		},
		{
			name:     "Mixed with predict",
			specs:    []PCRSpec{{Index: 0, Source: PCRSourceEventlog}, {Index: 2, Source: PCRSourceRegister}, {Index: 7, Source: PCRSourceEventlog}, {Index: 11, Source: PCRSourcePredict, Command: "my-cmd"}},
			expected: "0e,2,7e,11p:my-cmd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PCRSpecsToString(tt.specs)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestPCRSourceString tests the String() method on PCRSource
func TestPCRSourceString(t *testing.T) {
	if PCRSourceRegister.String() != "register" {
		t.Errorf("Expected 'register', got %q", PCRSourceRegister.String())
	}
	if PCRSourceEventlog.String() != "eventlog" {
		t.Errorf("Expected 'eventlog', got %q", PCRSourceEventlog.String())
	}
	if PCRSourcePredict.String() != "predict" {
		t.Errorf("Expected 'predict', got %q", PCRSourcePredict.String())
	}
}

// TestPCRSourceSuffix tests the Suffix() method on PCRSource
func TestPCRSourceSuffix(t *testing.T) {
	if PCRSourceRegister.Suffix() != "" {
		t.Errorf("Expected empty suffix for register, got %q", PCRSourceRegister.Suffix())
	}
	if PCRSourceEventlog.Suffix() != "e" {
		t.Errorf("Expected 'e' suffix for eventlog, got %q", PCRSourceEventlog.Suffix())
	}
	if PCRSourcePredict.Suffix() != "p" {
		t.Errorf("Expected 'p' suffix for predict, got %q", PCRSourcePredict.Suffix())
	}
}

// TestPCRSpecIndices tests extracting indices from specs
func TestPCRSpecIndices(t *testing.T) {
	specs := []PCRSpec{
		{Index: 0, Source: PCRSourceEventlog},
		{Index: 2, Source: PCRSourceRegister},
		{Index: 7, Source: PCRSourceEventlog},
	}
	indices := PCRSpecIndices(specs)
	expected := []int{0, 2, 7}
	if len(indices) != len(expected) {
		t.Fatalf("Expected %d indices, got %d", len(expected), len(indices))
	}
	for i, idx := range indices {
		if idx != expected[i] {
			t.Errorf("Index[%d]: expected %d, got %d", i, expected[i], idx)
		}
	}
}

func TestSealedBlobMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		blob *SealedBlob
	}{
		{
			name: "Basic blob (all register)",
			blob: &SealedBlob{
				Version:    4,
				AppVersion: "test-1.0.0",
				Public:     []byte("public-data-test"),
				Private:    []byte("private-data-test"),
				PCRDigests: []PCRDigestPair{
					{Index: 0, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte("digest0")}},
					{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte("digest2")}},
				},
				SigningKeyPEM: []byte("test-signing-key-pem"),
			},
		},
		{
			name: "Blob with predict PCR source",
			blob: &SealedBlob{
				Version:    4,
				AppVersion: "test-predict",
				Public:     []byte("public-predict"),
				Private:    []byte("private-predict"),
				PCRDigests: []PCRDigestPair{
					{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 7, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 11, Source: PCRSourcePredict, Command: "tpm2-pcr11predict", Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
				},
				SigningKeyPEM: []byte("test-signing-key-pem"),
				EventlogInfo: &EventlogInfo{
					EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
					EventlogHash:    "abc123",
					CalculationTime: "2024-01-01T00:00:00Z",
					TotalEvents:     100,
					ProcessedEvents: 50,
				},
			},
		},
		{
			name: "Blob without signing key",
			blob: &SealedBlob{
				Version:    4,
				AppVersion: "test-0.0.0",
				Public:     []byte("public"),
				Private:    []byte("private"),
				PCRDigests: []PCRDigestPair{
					{Index: 7, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte("digest7")}},
				},
			},
		},
		{
			name: "Blob with multiple PCRs (all register)",
			blob: &SealedBlob{
				Version:    4,
				AppVersion: "v2.0.0",
				Public:     []byte("test-public-key-data"),
				Private:    []byte("test-private-key-data"),
				PCRDigests: []PCRDigestPair{
					{Index: 0, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 1, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 4, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 7, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
				},
				SigningKeyPEM: []byte("test-signing-key-pem"),
			},
		},
		{
			name: "Blob with empty PCR list",
			blob: &SealedBlob{
				Version:    4,
				AppVersion: "test",
				Public:     []byte("pub"),
				Private:    []byte("priv"),
				PCRDigests: []PCRDigestPair{},
			},
		},
		{
			name: "Blob with all eventlog PCRs and eventlog info",
			blob: &SealedBlob{
				Version:    4,
				AppVersion: "test-eventlog",
				Public:     []byte("public-data"),
				Private:    []byte("private-data"),
				PCRDigests: []PCRDigestPair{
					{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 2, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 7, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
				},
				SigningKeyPEM: []byte("test-signing-key-pem"),
				EventlogInfo: &EventlogInfo{
					EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
					EventlogHash:    "abc123def456",
					CalculationTime: "2024-01-01T00:00:00Z",
					TotalEvents:     100,
					ProcessedEvents: 50,
				},
			},
		},
		{
			name: "Blob with mixed register and eventlog PCRs",
			blob: &SealedBlob{
				Version:    4,
				AppVersion: "test-mixed",
				Public:     []byte("public-mixed"),
				Private:    []byte("private-mixed"),
				PCRDigests: []PCRDigestPair{
					{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 4, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 7, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
				},
				SigningKeyPEM: []byte("test-signing-key-pem"),
				EventlogInfo: &EventlogInfo{
					EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
					EventlogHash:    "deadbeef",
					CalculationTime: "2024-06-15T12:00:00Z",
					TotalEvents:     200,
					ProcessedEvents: 80,
				},
			},
		},
		{
			name: "Blob with single eventlog PCR",
			blob: &SealedBlob{
				Version:    4,
				AppVersion: "test-single-e",
				Public:     []byte("pub"),
				Private:    []byte("priv"),
				PCRDigests: []PCRDigestPair{
					{Index: 7, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
				},
				EventlogInfo: &EventlogInfo{
					EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
					EventlogHash:    "cafebabe",
					CalculationTime: "2024-03-01T00:00:00Z",
					TotalEvents:     50,
					ProcessedEvents: 20,
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
				if i >= len(unmarshaled.PCRDigests) {
					break
				}
				if unmarshaled.PCRDigests[i].Index != tt.blob.PCRDigests[i].Index {
					t.Errorf("PCR[%d] index mismatch: expected %d, got %d",
						i, tt.blob.PCRDigests[i].Index, unmarshaled.PCRDigests[i].Index)
				}
				if unmarshaled.PCRDigests[i].Source != tt.blob.PCRDigests[i].Source {
					t.Errorf("PCR[%d] source mismatch: expected %v, got %v",
						i, tt.blob.PCRDigests[i].Source, unmarshaled.PCRDigests[i].Source)
				}
				if !bytes.Equal(unmarshaled.PCRDigests[i].Digest.Buffer, tt.blob.PCRDigests[i].Digest.Buffer) {
					t.Errorf("PCR[%d] digest mismatch", i)
				}
			}

			if !bytes.Equal(unmarshaled.SigningKeyPEM, tt.blob.SigningKeyPEM) {
				t.Errorf("SigningKeyPEM mismatch: expected %d bytes, got %d bytes", len(tt.blob.SigningKeyPEM), len(unmarshaled.SigningKeyPEM))
			}

			// Check HasEventlogPCRs derived method
			expectedHasEventlog := tt.blob.HasEventlogPCRs()
			if unmarshaled.HasEventlogPCRs() != expectedHasEventlog {
				t.Errorf("HasEventlogPCRs mismatch: expected %v, got %v", expectedHasEventlog, unmarshaled.HasEventlogPCRs())
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
					if unmarshaled.EventlogInfo.CalculationTime != tt.blob.EventlogInfo.CalculationTime {
						t.Errorf("CalculationTime mismatch")
					}
					if unmarshaled.EventlogInfo.TotalEvents != tt.blob.EventlogInfo.TotalEvents {
						t.Errorf("TotalEvents mismatch")
					}
					if unmarshaled.EventlogInfo.ProcessedEvents != tt.blob.EventlogInfo.ProcessedEvents {
						t.Errorf("ProcessedEvents mismatch")
					}
				}
			} else {
				if unmarshaled.EventlogInfo != nil {
					t.Errorf("EventlogInfo should be nil")
				}
			}
		})
	}
}

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
			errContains: "incompatible blob version",
		},
		{
			name: "Version 2 incompatible",
			data: func() []byte {
				d := make([]byte, 20)
				d[0] = 0x02 // version 2
				return d
			}(),
			errContains: "incompatible blob version",
		},
		{
			name: "Version 99 incompatible",
			data: func() []byte {
				d := make([]byte, 20)
				d[0] = 0x63 // version 99
				return d
			}(),
			errContains: "incompatible blob version",
		},
		{
			name: "Truncated data",
			data: []byte{
				0x04, 0x00, 0x00, 0x00, // version 4
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

// TestUnmarshalIncompatibleVersion tests the specific incompatibility error message and BlobVersionError type
func TestUnmarshalSealedBlob_OversizedFields(t *testing.T) {
	// Helper to build a minimal valid blob prefix up to a certain field,
	// then inject an oversized length value.
	makeBlob := func(appVersionLen, publicLen, privateLen, numPCRDigests uint32) []byte {
		// Build a blob with controlled length fields
		// We only need enough bytes to reach the field under test
		buf := make([]byte, 0, 256)
		b4 := make([]byte, 4)

		// version
		binary.LittleEndian.PutUint32(b4, CurrentBlobVersion)
		buf = append(buf, b4...)

		// appVersionLen
		binary.LittleEndian.PutUint32(b4, appVersionLen)
		buf = append(buf, b4...)
		// appVersion data (fill with zeros)
		buf = append(buf, make([]byte, appVersionLen)...)

		// publicLen
		binary.LittleEndian.PutUint32(b4, publicLen)
		buf = append(buf, b4...)
		// public data
		buf = append(buf, make([]byte, publicLen)...)

		// privateLen
		binary.LittleEndian.PutUint32(b4, privateLen)
		buf = append(buf, b4...)
		// private data
		buf = append(buf, make([]byte, privateLen)...)

		// numPCRDigests
		binary.LittleEndian.PutUint32(b4, numPCRDigests)
		buf = append(buf, b4...)

		// Pad to at least 16 bytes for minimum length check
		for len(buf) < 16 {
			buf = append(buf, 0)
		}

		return buf
	}

	tests := []struct {
		name      string
		blobMaker func() []byte
		expectErr string
	}{
		{
			name: "oversized app version length",
			blobMaker: func() []byte {
				blob := make([]byte, 16)
				binary.LittleEndian.PutUint32(blob[0:4], CurrentBlobVersion) // version
				binary.LittleEndian.PutUint32(blob[4:8], MaxAppVersionLen+1) // too large
				binary.LittleEndian.PutUint32(blob[8:12], 0)
				binary.LittleEndian.PutUint32(blob[12:16], 0)
				return blob
			},
			expectErr: "exceeds maximum",
		},
		{
			name: "oversized public blob length",
			blobMaker: func() []byte {
				blob := make([]byte, 16)
				binary.LittleEndian.PutUint32(blob[0:4], CurrentBlobVersion) // version
				binary.LittleEndian.PutUint32(blob[4:8], 0)                  // appVersionLen=0
				binary.LittleEndian.PutUint32(blob[8:12], MaxPublicLen+1)    // too large
				binary.LittleEndian.PutUint32(blob[12:16], 0)
				return blob
			},
			expectErr: "exceeds maximum",
		},
		{
			name: "oversized private blob length",
			blobMaker: func() []byte {
				blob := make([]byte, 20)
				binary.LittleEndian.PutUint32(blob[0:4], CurrentBlobVersion) // version
				binary.LittleEndian.PutUint32(blob[4:8], 0)                  // appVersionLen=0
				binary.LittleEndian.PutUint32(blob[8:12], 0)                 // publicLen=0
				binary.LittleEndian.PutUint32(blob[12:16], MaxPrivateLen+1)  // too large
				binary.LittleEndian.PutUint32(blob[16:20], 0)
				return blob
			},
			expectErr: "exceeds maximum",
		},
		{
			name: "oversized PCR digest count",
			blobMaker: func() []byte {
				return makeBlob(0, 0, 0, MaxPCRDigests+1)
			},
			expectErr: "exceeds maximum",
		},
		{
			name: "extreme public blob 4GB",
			blobMaker: func() []byte {
				blob := make([]byte, 16)
				binary.LittleEndian.PutUint32(blob[0:4], CurrentBlobVersion)
				binary.LittleEndian.PutUint32(blob[4:8], 0)
				binary.LittleEndian.PutUint32(blob[8:12], 0xFFFFFFFF) // ~4GB
				binary.LittleEndian.PutUint32(blob[12:16], 0)
				return blob
			},
			expectErr: "exceeds maximum",
		},
		{
			name: "extreme private blob 4GB",
			blobMaker: func() []byte {
				blob := make([]byte, 20)
				binary.LittleEndian.PutUint32(blob[0:4], CurrentBlobVersion)
				binary.LittleEndian.PutUint32(blob[4:8], 0)
				binary.LittleEndian.PutUint32(blob[8:12], 0)
				binary.LittleEndian.PutUint32(blob[12:16], 0xFFFFFFFF) // ~4GB
				binary.LittleEndian.PutUint32(blob[16:20], 0)
				return blob
			},
			expectErr: "exceeds maximum",
		},
		{
			name: "extreme PCR digest count 100 million",
			blobMaker: func() []byte {
				return makeBlob(0, 0, 0, 100_000_000)
			},
			expectErr: "exceeds maximum",
		},
		{
			name: "oversized total blob",
			blobMaker: func() []byte {
				// Create a blob larger than MaxBlobSize
				blob := make([]byte, MaxBlobSize+1)
				binary.LittleEndian.PutUint32(blob[0:4], CurrentBlobVersion) // version
				return blob
			},
			expectErr: "exceeds maximum",
		},
		{
			name: "valid small blob still accepted",
			blobMaker: func() []byte {
				// Construct a minimal valid complete blob
				sb := &SealedBlob{
					Version:    CurrentBlobVersion,
					AppVersion: "test",
					Public:     []byte{1, 2, 3},
					Private:    []byte{4, 5, 6},
					PCRDigests: []PCRDigestPair{
						{Index: 0, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					},
				}
				data, _ := sb.Marshal()
				return data
			},
			expectErr: "", // no error expected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blob := tt.blobMaker()
			_, err := UnmarshalSealedBlob(blob)

			if tt.expectErr == "" {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				return
			}

			if err == nil {
				t.Errorf("Expected error containing %q, got nil", tt.expectErr)
				return
			}
			if !strings.Contains(err.Error(), tt.expectErr) {
				t.Errorf("Expected error containing %q, got: %v", tt.expectErr, err)
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

	// Verify it's a BlobVersionError
	bve, ok := IsBlobVersionError(err)
	if !ok {
		t.Fatalf("Expected BlobVersionError, got: %T: %v", err, err)
	}
	if bve.FoundVersion != 1 {
		t.Errorf("Expected FoundVersion 1, got %d", bve.FoundVersion)
	}
	if bve.RequiredVersion != CurrentBlobVersion {
		t.Errorf("Expected RequiredVersion %d, got %d", CurrentBlobVersion, bve.RequiredVersion)
	}

	// Verify error message contains useful info
	if !strings.Contains(err.Error(), "incompatible blob version") {
		t.Errorf("Expected error to mention 'incompatible blob version', got: %v", err)
	}
	if !strings.Contains(err.Error(), "v1") {
		t.Errorf("Expected error to mention found v1, got: %v", err)
	}
	if !strings.Contains(err.Error(), "v4") {
		t.Errorf("Expected error to mention requires v4, got: %v", err)
	}
	if !strings.Contains(err.Error(), "tpm2-kira seal") {
		t.Errorf("Expected error to suggest re-sealing, got: %v", err)
	}
}

// TestBlobVersionErrorWrapped tests that IsBlobVersionError detects wrapped BlobVersionErrors
func TestBlobVersionErrorWrapped(t *testing.T) {
	original := &BlobVersionError{FoundVersion: 2, RequiredVersion: 3, DataSize: 500}
	wrapped := fmt.Errorf("failed to unmarshal sealed data: %w", original)

	bve, ok := IsBlobVersionError(wrapped)
	if !ok {
		t.Fatalf("Expected to detect wrapped BlobVersionError, got false")
	}
	if bve.FoundVersion != 2 {
		t.Errorf("Expected FoundVersion 2, got %d", bve.FoundVersion)
	}
	if bve.RequiredVersion != 3 {
		t.Errorf("Expected RequiredVersion 3, got %d", bve.RequiredVersion)
	}
	if bve.DataSize != 500 {
		t.Errorf("Expected DataSize 500, got %d", bve.DataSize)
	}
}

// TestBlobVersionErrorNotDetected tests that IsBlobVersionError returns false for non-version errors
func TestBlobVersionErrorNotDetected(t *testing.T) {
	_, ok := IsBlobVersionError(fmt.Errorf("some other error"))
	if ok {
		t.Error("Expected false for non-BlobVersionError")
	}

	_, ok = IsBlobVersionError(nil)
	if ok {
		t.Error("Expected false for nil error")
	}
}

// TestPeekBlobVersion tests raw blob inspection without full unmarshal
func TestPeekBlobVersion(t *testing.T) {
	tests := []struct {
		name               string
		data               []byte
		expectedVersion    uint32
		expectedAppVersion string
		expectedSize       int
	}{
		{
			name:            "Too short for version",
			data:            []byte{0x01, 0x02},
			expectedVersion: 0,
			expectedSize:    2,
		},
		{
			name: "Version 2 blob (old format)",
			data: func() []byte {
				d := make([]byte, 20)
				d[0] = 0x02 // version 2
				d[4] = 0x05 // app version length = 5
				copy(d[8:], "1.0.0")
				return d
			}(),
			expectedVersion:    2,
			expectedAppVersion: "1.0.0",
			expectedSize:       20,
		},
		{
			name: "Version 3 blob",
			data: func() []byte {
				d := make([]byte, 30)
				d[0] = 0x03 // version 3
				d[4] = 0x07 // app version length = 7
				copy(d[8:], "v2.0.0a")
				return d
			}(),
			expectedVersion:    3,
			expectedAppVersion: "v2.0.0a",
			expectedSize:       30,
		},
		{
			name: "Version present but app version truncated",
			data: func() []byte {
				d := make([]byte, 8)
				d[0] = 0x02
				d[4] = 0xFF // app version length way too long
				return d
			}(),
			expectedVersion:    2,
			expectedAppVersion: "", // can't read app version
			expectedSize:       8,
		},
		{
			name:            "Exactly 4 bytes",
			data:            []byte{0x01, 0x00, 0x00, 0x00},
			expectedVersion: 1,
			expectedSize:    4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peek := PeekBlobVersion(tt.data)
			if peek.DataSize != tt.expectedSize {
				t.Errorf("DataSize: expected %d, got %d", tt.expectedSize, peek.DataSize)
			}
			if peek.Version != tt.expectedVersion {
				t.Errorf("Version: expected %d, got %d", tt.expectedVersion, peek.Version)
			}
			if peek.AppVersion != tt.expectedAppVersion {
				t.Errorf("AppVersion: expected %q, got %q", tt.expectedAppVersion, peek.AppVersion)
			}
		})
	}
}

// TestGetPCRIndices tests extracting PCR indices from SealedBlob
func TestGetPCRIndices(t *testing.T) {
	blob := &SealedBlob{
		PCRDigests: []PCRDigestPair{
			{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: []byte("d0")}},
			{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte("d2")}},
			{Index: 4, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte("d4")}},
			{Index: 7, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: []byte("d7")}},
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
			{Index: 0, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: digest0}},
			{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: digest2}},
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

// TestHasEventlogPCRs tests the HasEventlogPCRs method
func TestHasEventlogPCRs(t *testing.T) {
	tests := []struct {
		name     string
		blob     *SealedBlob
		expected bool
	}{
		{
			name: "All register",
			blob: &SealedBlob{
				PCRDigests: []PCRDigestPair{
					{Index: 0, Source: PCRSourceRegister},
					{Index: 2, Source: PCRSourceRegister},
				},
			},
			expected: false,
		},
		{
			name: "All eventlog",
			blob: &SealedBlob{
				PCRDigests: []PCRDigestPair{
					{Index: 0, Source: PCRSourceEventlog},
					{Index: 2, Source: PCRSourceEventlog},
				},
			},
			expected: true,
		},
		{
			name: "Mixed",
			blob: &SealedBlob{
				PCRDigests: []PCRDigestPair{
					{Index: 0, Source: PCRSourceEventlog},
					{Index: 2, Source: PCRSourceRegister},
				},
			},
			expected: true,
		},
		{
			name: "Predict only does not count as eventlog",
			blob: &SealedBlob{
				PCRDigests: []PCRDigestPair{
					{Index: 11, Source: PCRSourcePredict, Command: "cmd"},
				},
			},
			expected: false,
		},
		{
			name: "Empty",
			blob: &SealedBlob{
				PCRDigests: []PCRDigestPair{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.blob.HasEventlogPCRs()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestHasPredictPCRs tests the HasPredictPCRs method
func TestHasPredictPCRs(t *testing.T) {
	tests := []struct {
		name     string
		blob     *SealedBlob
		expected bool
	}{
		{
			name: "All register",
			blob: &SealedBlob{
				PCRDigests: []PCRDigestPair{
					{Index: 0, Source: PCRSourceRegister},
					{Index: 2, Source: PCRSourceRegister},
				},
			},
			expected: false,
		},
		{
			name: "All eventlog",
			blob: &SealedBlob{
				PCRDigests: []PCRDigestPair{
					{Index: 0, Source: PCRSourceEventlog},
					{Index: 2, Source: PCRSourceEventlog},
				},
			},
			expected: false,
		},
		{
			name: "Has predict",
			blob: &SealedBlob{
				PCRDigests: []PCRDigestPair{
					{Index: 0, Source: PCRSourceEventlog},
					{Index: 11, Source: PCRSourcePredict, Command: "cmd"},
				},
			},
			expected: true,
		},
		{
			name: "Predict only",
			blob: &SealedBlob{
				PCRDigests: []PCRDigestPair{
					{Index: 11, Source: PCRSourcePredict, Command: "cmd"},
				},
			},
			expected: true,
		},
		{
			name: "Empty",
			blob: &SealedBlob{
				PCRDigests: []PCRDigestPair{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.blob.HasPredictPCRs()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestGetEventlogPCRIndices tests extracting eventlog PCR indices
func TestGetEventlogPCRIndices(t *testing.T) {
	blob := &SealedBlob{
		PCRDigests: []PCRDigestPair{
			{Index: 0, Source: PCRSourceEventlog},
			{Index: 2, Source: PCRSourceRegister},
			{Index: 4, Source: PCRSourceRegister},
			{Index: 7, Source: PCRSourceEventlog},
		},
	}

	eventlogIndices := blob.GetEventlogPCRIndices()
	if len(eventlogIndices) != 2 {
		t.Fatalf("Expected 2 eventlog indices, got %d", len(eventlogIndices))
	}
	if eventlogIndices[0] != 0 || eventlogIndices[1] != 7 {
		t.Errorf("Expected [0, 7], got %v", eventlogIndices)
	}

	registerIndices := blob.GetRegisterPCRIndices()
	if len(registerIndices) != 2 {
		t.Fatalf("Expected 2 register indices, got %d", len(registerIndices))
	}
	if registerIndices[0] != 2 || registerIndices[1] != 4 {
		t.Errorf("Expected [2, 4], got %v", registerIndices)
	}
}

// TestGetPredictPCRIndices tests extracting predict PCR indices
func TestGetPredictPCRIndices(t *testing.T) {
	blob := &SealedBlob{
		PCRDigests: []PCRDigestPair{
			{Index: 0, Source: PCRSourceEventlog},
			{Index: 2, Source: PCRSourceRegister},
			{Index: 7, Source: PCRSourceEventlog},
			{Index: 11, Source: PCRSourcePredict, Command: "tpm2-pcr11predict"},
		},
	}

	predictIndices := blob.GetPredictPCRIndices()
	if len(predictIndices) != 1 {
		t.Fatalf("Expected 1 predict index, got %d", len(predictIndices))
	}
	if predictIndices[0] != 11 {
		t.Errorf("Expected [11], got %v", predictIndices)
	}

	eventlogIndices := blob.GetEventlogPCRIndices()
	if len(eventlogIndices) != 2 {
		t.Fatalf("Expected 2 eventlog indices, got %d", len(eventlogIndices))
	}

	registerIndices := blob.GetRegisterPCRIndices()
	if len(registerIndices) != 1 {
		t.Fatalf("Expected 1 register index, got %d", len(registerIndices))
	}
	if registerIndices[0] != 2 {
		t.Errorf("Expected [2], got %v", registerIndices)
	}
}

// TestGetPCRSpecs tests reconstructing PCRSpecs from a SealedBlob
func TestGetPCRSpecs(t *testing.T) {
	blob := &SealedBlob{
		PCRDigests: []PCRDigestPair{
			{Index: 0, Source: PCRSourceEventlog},
			{Index: 2, Source: PCRSourceRegister},
			{Index: 7, Source: PCRSourceEventlog},
			{Index: 11, Source: PCRSourcePredict, Command: "tpm2-pcr11predict"},
		},
	}

	specs := blob.GetPCRSpecs()
	if len(specs) != 4 {
		t.Fatalf("Expected 4 specs, got %d", len(specs))
	}

	expected := []PCRSpec{
		{Index: 0, Source: PCRSourceEventlog},
		{Index: 2, Source: PCRSourceRegister},
		{Index: 7, Source: PCRSourceEventlog},
		{Index: 11, Source: PCRSourcePredict, Command: "tpm2-pcr11predict"},
	}

	for i, spec := range specs {
		if spec.Index != expected[i].Index {
			t.Errorf("Spec[%d].Index: expected %d, got %d", i, expected[i].Index, spec.Index)
		}
		if spec.Source != expected[i].Source {
			t.Errorf("Spec[%d].Source: expected %v, got %v", i, expected[i].Source, spec.Source)
		}
		if spec.Command != expected[i].Command {
			t.Errorf("Spec[%d].Command: expected %q, got %q", i, expected[i].Command, spec.Command)
		}
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
		Version:    4,
		AppVersion: "test-1.0.0",
		Public:     []byte{0x01, 0x02, 0x03},
		Private:    []byte{0x04, 0x05, 0x06},
		PCRDigests: []PCRDigestPair{
			{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: []byte{0xAA, 0xBB}}},
			{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte{0xCC, 0xDD}}},
		},
		SigningKeyPEM: []byte("test-signing-key"),
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
		`"hash_algorithm"`,
		`"public_hex"`,
		`"private_hex"`,
		`"pcr_digests"`,
		`"signing_key_pem_size"`,
		`"source"`,
	}

	for _, field := range expectedFields {
		if !bytes.Contains(jsonData, []byte(field)) {
			t.Errorf("Expected JSON to contain %s, got: %s", field, jsonStr)
		}
	}

	// Check for source values in JSON
	if !bytes.Contains(jsonData, []byte(`"eventlog"`)) {
		t.Errorf("Expected JSON to contain eventlog source, got: %s", jsonStr)
	}
	if !bytes.Contains(jsonData, []byte(`"register"`)) {
		t.Errorf("Expected JSON to contain register source, got: %s", jsonStr)
	}

	// Ensure old eventlog_based field is NOT present
	if bytes.Contains(jsonData, []byte(`"eventlog_based"`)) {
		t.Errorf("JSON should NOT contain eventlog_based, got: %s", jsonStr)
	}

	// Ensure old password fields are NOT present
	unexpectedFields := []string{
		`"password_hash_hex"`,
		`"password_salt_hex"`,
		`"has_password"`,
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

// TestSealedBlobMarshalJSONWithEventlogInfo tests JSON serialization with eventlog info
func TestSealedBlobMarshalJSONWithEventlogInfo(t *testing.T) {
	blob := &SealedBlob{
		Version:    4,
		AppVersion: "test-1.0.0",
		Public:     []byte{0x01},
		Private:    []byte{0x02},
		PCRDigests: []PCRDigestPair{
			{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: []byte{0xAA}}},
		},
		EventlogInfo: &EventlogInfo{
			EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
			EventlogHash:    "abc123",
			CalculationTime: "2024-01-01T00:00:00Z",
			TotalEvents:     100,
			ProcessedEvents: 50,
		},
	}

	jsonData, err := blob.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	// Check eventlog_info is present
	if !bytes.Contains(jsonData, []byte(`"eventlog_info"`)) {
		t.Errorf("Expected JSON to contain eventlog_info")
	}
	if !bytes.Contains(jsonData, []byte(`"eventlog_path"`)) {
		t.Errorf("Expected JSON to contain eventlog_path")
	}
}

// TestCreatePCRSelection tests PCR selection creation
func TestCreatePCRSelection(t *testing.T) {
	pcrs := []int{0, 2, 4, 7}

	// Test SHA256 (default)
	selection := CreatePCRSelection(pcrs, PCRHashAlgoSHA256)

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

	// Test SHA1
	selectionSHA1 := CreatePCRSelection(pcrs, PCRHashAlgoSHA1)

	if len(selectionSHA1.PCRSelections) == 0 {
		t.Fatal("Expected at least one PCR selection for SHA1")
	}

	pcrSelSHA1 := selectionSHA1.PCRSelections[0]

	if pcrSelSHA1.Hash != tpm2.TPMAlgSHA1 {
		t.Errorf("Expected SHA1 hash algorithm, got %v", pcrSelSHA1.Hash)
	}

	if !bytes.Equal(pcrSelSHA1.PCRSelect, bitmap) {
		t.Error("PCR selection bitmap mismatch for SHA1")
	}
}

// TestGetHashAlgo tests hash algorithm detection from PCR digest sizes
func TestGetHashAlgo(t *testing.T) {
	tests := []struct {
		name     string
		blob     *SealedBlob
		expected PCRHashAlgo
	}{
		{
			name: "SHA256 digests (32 bytes)",
			blob: &SealedBlob{
				Version:    3,
				AppVersion: "test",
				PCRDigests: []PCRDigestPair{
					{Index: 0, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					{Index: 7, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
				},
			},
			expected: PCRHashAlgoSHA256,
		},
		{
			name: "SHA1 digests (20 bytes)",
			blob: &SealedBlob{
				Version:    3,
				AppVersion: "test",
				PCRDigests: []PCRDigestPair{
					{Index: 0, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 20)}},
					{Index: 7, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 20)}},
				},
			},
			expected: PCRHashAlgoSHA1,
		},
		{
			name: "Empty digests defaults to SHA256",
			blob: &SealedBlob{
				Version:    3,
				AppVersion: "test",
				PCRDigests: []PCRDigestPair{},
			},
			expected: PCRHashAlgoSHA256,
		},
		{
			name: "No PCR digests defaults to SHA256",
			blob: &SealedBlob{
				Version:    3,
				AppVersion: "test",
			},
			expected: PCRHashAlgoSHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.blob.GetHashAlgo()
			if got != tt.expected {
				t.Errorf("GetHashAlgo() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestPCRHashAlgoMethods tests the PCRHashAlgo type methods
func TestPCRHashAlgoMethods(t *testing.T) {
	// SHA256
	sha256 := PCRHashAlgoSHA256
	if sha256.DigestSize() != 32 {
		t.Errorf("SHA256 DigestSize() = %d, want 32", sha256.DigestSize())
	}
	if sha256.String() != "sha256" {
		t.Errorf("SHA256 String() = %q, want \"sha256\"", sha256.String())
	}
	if sha256.DisplayString() != "SHA-256" {
		t.Errorf("SHA256 DisplayString() = %q, want \"SHA-256\"", sha256.DisplayString())
	}
	if sha256.TPMAlg() != tpm2.TPMAlgSHA256 {
		t.Errorf("SHA256 TPMAlg() mismatch")
	}

	// SHA1
	sha1 := PCRHashAlgoSHA1
	if sha1.DigestSize() != 20 {
		t.Errorf("SHA1 DigestSize() = %d, want 20", sha1.DigestSize())
	}
	if sha1.String() != "sha1" {
		t.Errorf("SHA1 String() = %q, want \"sha1\"", sha1.String())
	}
	if sha1.DisplayString() != "SHA-1" {
		t.Errorf("SHA1 DisplayString() = %q, want \"SHA-1\"", sha1.DisplayString())
	}
	if sha1.TPMAlg() != tpm2.TPMAlgSHA1 {
		t.Errorf("SHA1 TPMAlg() mismatch")
	}
}

// TestSealedBlobRoundTrip tests a complete round trip with realistic data
func TestSealedBlobRoundTrip(t *testing.T) {
	// Create a blob with realistic TPM data sizes and mixed sources
	original := &SealedBlob{
		Version:    4,
		AppVersion: "v1.2.3",
		Public:     make([]byte, 100), // Typical public key size
		Private:    make([]byte, 150), // Typical private key size
		PCRDigests: []PCRDigestPair{
			{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			{Index: 4, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			{Index: 7, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
		},
		SigningKeyPEM: []byte("test-signing-key-round-trip"),
		EventlogInfo: &EventlogInfo{
			EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
			EventlogHash:    "abcdef1234567890",
			CalculationTime: "2024-06-15T10:30:00Z",
			TotalEvents:     150,
			ProcessedEvents: 75,
		},
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
	if !bytes.Equal(restored.SigningKeyPEM, original.SigningKeyPEM) {
		t.Error("SigningKeyPEM mismatch")
	}
	// Verify per-PCR sources
	for i := range original.PCRDigests {
		if restored.PCRDigests[i].Source != original.PCRDigests[i].Source {
			t.Errorf("PCR[%d] source mismatch: expected %v, got %v",
				i, original.PCRDigests[i].Source, restored.PCRDigests[i].Source)
		}
	}
	// Verify HasEventlogPCRs
	if restored.HasEventlogPCRs() != original.HasEventlogPCRs() {
		t.Error("HasEventlogPCRs mismatch")
	}
	// Verify eventlog info
	if restored.EventlogInfo == nil {
		t.Fatal("EventlogInfo should not be nil")
	}
	if restored.EventlogInfo.EventlogPath != original.EventlogInfo.EventlogPath {
		t.Error("EventlogPath mismatch")
	}
	if restored.EventlogInfo.TotalEvents != original.EventlogInfo.TotalEvents {
		t.Error("TotalEvents mismatch")
	}
}

// TestSealedBlobRoundTripNoEventlog tests round trip with all-register PCRs (no eventlog info)
func TestSealedBlobRoundTripNoEventlog(t *testing.T) {
	original := &SealedBlob{
		Version:    4,
		AppVersion: "v1.0.0",
		Public:     []byte("pub-data"),
		Private:    []byte("priv-data"),
		PCRDigests: []PCRDigestPair{
			{Index: 0, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			{Index: 7, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
		},
	}

	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	restored, err := UnmarshalSealedBlob(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if restored.HasEventlogPCRs() {
		t.Error("Should not have eventlog PCRs")
	}
	if restored.EventlogInfo != nil {
		t.Error("EventlogInfo should be nil for all-register blob")
	}
	for i, pair := range restored.PCRDigests {
		if pair.Source != PCRSourceRegister {
			t.Errorf("PCR[%d] should be register source, got %v", i, pair.Source)
		}
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
func TestValidateNVRAMIndex(t *testing.T) {
	tests := []struct {
		name      string
		index     uint32
		shouldErr bool
	}{
		{
			name:      "Valid: default index 0x01803010",
			index:     0x01803010,
			shouldErr: false,
		},
		{
			name:      "Valid: range start 0x01803000",
			index:     AppNVRAMStart,
			shouldErr: false,
		},
		{
			name:      "Valid: range end 0x01803FFF",
			index:     AppNVRAMEnd,
			shouldErr: false,
		},
		{
			name:      "Valid: slot end 0x0180301F",
			index:     0x0180301F,
			shouldErr: false,
		},
		{
			name:      "Valid: mid-range 0x01803800",
			index:     0x01803800,
			shouldErr: false,
		},
		{
			name:      "Rejected: just below range 0x01802FFF",
			index:     AppNVRAMStart - 1,
			shouldErr: true,
		},
		{
			name:      "Rejected: just above range 0x01804000",
			index:     AppNVRAMEnd + 1,
			shouldErr: true,
		},
		{
			name:      "Rejected: zero index",
			index:     0x00000000,
			shouldErr: true,
		},
		{
			name:      "Rejected: max uint32",
			index:     0xFFFFFFFF,
			shouldErr: true,
		},
		{
			name:      "Rejected: platform hierarchy 0x01C00002",
			index:     0x01C00002,
			shouldErr: true,
		},
		{
			name:      "Rejected: platform primary seed 0x01C0000B",
			index:     0x01C0000B,
			shouldErr: true,
		},
		{
			name:      "Rejected: owner hierarchy reserved 0x01400001",
			index:     0x01400001,
			shouldErr: true,
		},
		{
			name:      "Rejected: endorsement hierarchy 0x01800001",
			index:     0x01800001,
			shouldErr: true,
		},
		{
			name:      "Rejected: system reserved 0x01000000",
			index:     0x01000000,
			shouldErr: true,
		},
		{
			name:      "Rejected: firmware range 0x013FFFFF",
			index:     0x013FFFFF,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNVRAMIndex(tt.index)

			if tt.shouldErr {
				if err == nil {
					t.Errorf("Expected error for index 0x%08X, got nil", tt.index)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for index 0x%08X: %v", tt.index, err)
			}
		})
	}
}

func TestCurrentBlobVersion(t *testing.T) {
	if CurrentBlobVersion != 4 {
		t.Errorf("CurrentBlobVersion should be 4, got %d", CurrentBlobVersion)
	}
}

// TestGetPCRDescription tests PCR description lookup
func TestGetPCRDescription(t *testing.T) {
	definedPCRs := map[int]string{
		0:  "Core System Firmware executable code (Firmware)",
		1:  "Core System Firmware data (UEFI settings)",
		2:  "Extended or pluggable executable code (OpROMs)",
		3:  "Extended or pluggable firmware data",
		4:  "Boot Manager Code and Boot Attempts",
		5:  "Boot Manager Configuration and Data (GPT table)",
		6:  "Resume from S4 and S5 Power State Events",
		7:  "Secure Boot State (PK/KEK/db certificates)",
		8:  "Hash of the kernel command line",
		9:  "Hash of the initramfs and EFI Load Options",
		10: "Reserved for Future Use",
		11: "Hash of the Unified kernel image",
		12: "Overridden kernel command line, Credentials",
		13: "System Extensions",
		14: "shim's MokList, MokListX, and MokSBState",
		15: "Hash of the LUKS volume key",
		16: "Debug (may be reset at any time)",
		23: "Application Support (OS can set/reset)",
	}

	for idx, expectedDesc := range definedPCRs {
		t.Run(fmt.Sprintf("PCR%d", idx), func(t *testing.T) {
			got := GetPCRDescription(idx)
			if got != expectedDesc {
				t.Errorf("GetPCRDescription(%d) = %q, want %q", idx, got, expectedDesc)
			}
		})
	}

	unknownTests := []struct {
		name  string
		index int
	}{
		{"PCR17", 17},
		{"PCR18", 18},
		{"PCR24", 24},
		{"Negative", -1},
		{"Large", 100},
	}
	for _, tt := range unknownTests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetPCRDescription(tt.index)
			if got != "Unknown PCR" {
				t.Errorf("GetPCRDescription(%d) = %q, want %q", tt.index, got, "Unknown PCR")
			}
		})
	}
}

// TestIsTOTPSecret tests Base32 TOTP secret validation
func TestIsTOTPSecret(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Valid 16-char secret", "JBSWY3DPEHPK3PXP", true},
		{"Valid 32-char secret", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX", true},
		{"Valid with spaces", "JBSW Y3DP EHPK 3PXP", true},
		{"Valid lowercase", "jbswy3dpehpk3pxp", true},
		{"Too short", "JBSWY3D", false},
		{"Too long", strings.Repeat("A", 129), false},
		{"Exactly 128 chars", strings.Repeat("ABCDEFGH", 16), true},
		{"Invalid Base32 chars", "JBSWY3DPEHPK3PX!", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTOTPSecret(tt.input)
			if got != tt.expected {
				t.Errorf("isTOTPSecret(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// TestGenerateTOTPURI tests TOTP URI generation
func TestGenerateTOTPURI(t *testing.T) {
	tests := []struct {
		name         string
		secret       string
		label        string
		issuer       string
		wantContains []string
	}{
		{
			name:   "Custom values",
			secret: "JBSWY3DPEHPK3PXP",
			label:  "MyLabel",
			issuer: "MyIssuer",
			wantContains: []string{
				"otpauth://totp/MyLabel",
				"secret=JBSWY3DPEHPK3PXP",
				"issuer=MyIssuer",
			},
		},
		{
			name:   "Empty label and issuer use defaults",
			secret: "JBSWY3DPEHPK3PXP",
			label:  "",
			issuer: "",
			wantContains: []string{
				"otpauth://totp/TPM2-KIRA",
				"secret=JBSWY3DPEHPK3PXP",
				"issuer=TPM2-KIRA",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateTOTPURI(tt.secret, tt.label, tt.issuer)
			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("generateTOTPURI() = %q, want to contain %q", got, want)
				}
			}
		})
	}
}

// TestGenerateHOTP tests HOTP code generation with RFC 4226 test vectors
func TestGenerateHOTP(t *testing.T) {
	key := []byte("12345678901234567890")
	tests := []struct {
		counter  int64
		expected string
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("counter_%d", tt.counter), func(t *testing.T) {
			got := generateHOTP(key, tt.counter)
			if got != tt.expected {
				t.Errorf("generateHOTP(key, %d) = %q, want %q", tt.counter, got, tt.expected)
			}
		})
	}
}

// TestGenerateTOTPCode tests TOTP code generation
func TestGenerateTOTPCode(t *testing.T) {
	t.Run("Valid secret", func(t *testing.T) {
		code, timeRemaining, err := generateTOTPCode("JBSWY3DPEHPK3PXP")
		if err != nil {
			t.Fatalf("generateTOTPCode() unexpected error: %v", err)
		}
		if len(code) != 6 {
			t.Errorf("generateTOTPCode() code length = %d, want 6", len(code))
		}
		if timeRemaining < 1 || timeRemaining > 30 {
			t.Errorf("generateTOTPCode() timeRemaining = %d, want 1-30", timeRemaining)
		}
	})

	t.Run("Invalid Base32", func(t *testing.T) {
		_, _, err := generateTOTPCode("!!!invalid!!!")
		if err == nil {
			t.Error("generateTOTPCode() expected error for invalid Base32, got nil")
		}
	})
}

// TestFormatKIRAOutput tests KIRA output formatting
func TestFormatKIRAOutput(t *testing.T) {
	got := FormatKIRAOutput("123456")
	if !strings.Contains(got, "KIRA") {
		t.Errorf("FormatKIRAOutput() = %q, want to contain KIRA", got)
	}
	if !strings.Contains(got, "123456") {
		t.Errorf("FormatKIRAOutput() = %q, want to contain 123456", got)
	}
}

// TestFormatKIRAError tests KIRA error formatting
func TestFormatKIRAError(t *testing.T) {
	got := FormatKIRAError(fmt.Errorf("test error"))
	if !strings.Contains(got, "KIRA") {
		t.Errorf("FormatKIRAError() = %q, want to contain KIRA", got)
	}
	if !strings.Contains(got, "ERROR") {
		t.Errorf("FormatKIRAError() = %q, want to contain ERROR", got)
	}
	if !strings.Contains(got, "test error") {
		t.Errorf("FormatKIRAError() = %q, want to contain 'test error'", got)
	}
}

// TestPCRMismatchErrorError tests PCRMismatchError.Error()
func TestPCRMismatchErrorError(t *testing.T) {
	e := &PCRMismatchError{
		Message:    "PCR values have changed",
		PCRIndices: []int{0, 7},
	}
	if got := e.Error(); got != "PCR values have changed" {
		t.Errorf("PCRMismatchError.Error() = %q, want %q", got, "PCR values have changed")
	}
}

// TestIsTPMPolicyFailure tests TPM policy failure detection
func TestIsTPMPolicyFailure(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"Nil error", nil, false},
		{"Unrelated error", fmt.Errorf("some random error"), false},
		{"TPM_RC_POLICY_FAIL", fmt.Errorf("TPM_RC_POLICY_FAIL"), true},
		{"Policy check failed", fmt.Errorf("policy check failed"), true},
		{"Failed to create PCR policy session", fmt.Errorf("failed to create PCR policy session"), true},
		{"Session policy check", fmt.Errorf("session 1): a policy check failed"), true},
		{"Wrapped error", fmt.Errorf("error: %s", "TPM_RC_POLICY_FAIL occurred"), true},
		{"Mid-string match", fmt.Errorf("TPM error: TPM_RC_POLICY_FAIL in session"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTPMPolicyFailure(tt.err)
			if got != tt.expected {
				t.Errorf("IsTPMPolicyFailure(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

// TestHandleNVRAMNotFoundError tests NVRAM error handling
func TestHandleNVRAMNotFoundError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		debug        bool
		expectNil    bool
		wantContains string
	}{
		{"Nil error", nil, false, true, ""},
		{"TPM_RC_HANDLE", fmt.Errorf("TPM_RC_HANDLE"), false, false, "has not been configured yet"},
		{"Does not exist", fmt.Errorf("does not exist"), false, false, "has not been configured yet"},
		{"TPM_RC_NV_UNINITIALIZED", fmt.Errorf("TPM_RC_NV_UNINITIALIZED"), false, false, "has not been configured yet"},
		{"Debug mode", fmt.Errorf("TPM_RC_HANDLE"), true, false, "debug"},
		{"Unrelated error", fmt.Errorf("some other error"), false, false, "some other error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HandleNVRAMNotFoundError(tt.err, tt.debug)
			if tt.expectNil {
				if got != nil {
					t.Errorf("HandleNVRAMNotFoundError() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("HandleNVRAMNotFoundError() = nil, want error")
			}
			if tt.wantContains != "" && !strings.Contains(got.Error(), tt.wantContains) {
				t.Errorf("HandleNVRAMNotFoundError() = %q, want to contain %q", got.Error(), tt.wantContains)
			}
		})
	}
}

// TestHasValidSlots tests valid slot detection
func TestHasValidSlots(t *testing.T) {
	tests := []struct {
		name     string
		slots    []NVRAMSlot
		expected bool
	}{
		{"Empty slice", []NVRAMSlot{}, false},
		{"All errors", []NVRAMSlot{
			{SlotNumber: 1, Error: fmt.Errorf("error"), Secret: "JBSWY3DPEHPK3PXP"},
		}, false},
		{"Empty secret", []NVRAMSlot{
			{SlotNumber: 1, Error: nil, Secret: ""},
		}, false},
		{"Valid slot", []NVRAMSlot{
			{SlotNumber: 1, Error: nil, Secret: "JBSWY3DPEHPK3PXP"},
		}, true},
		{"Mixed slots", []NVRAMSlot{
			{SlotNumber: 1, Error: fmt.Errorf("error"), Secret: "JBSWY3DPEHPK3PXP"},
			{SlotNumber: 2, Error: nil, Secret: "JBSWY3DPEHPK3PXP"},
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasValidSlots(tt.slots)
			if got != tt.expected {
				t.Errorf("HasValidSlots() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestGenerateTOTPCodesForSlots tests TOTP code generation for slots
func TestGenerateTOTPCodesForSlots(t *testing.T) {
	t.Run("Skips error slots", func(t *testing.T) {
		slots := []NVRAMSlot{
			{SlotNumber: 1, Error: fmt.Errorf("PCR mismatch"), Secret: "JBSWY3DPEHPK3PXP"},
			{SlotNumber: 2, Error: nil, Secret: "JBSWY3DPEHPK3PXP"},
		}
		codes, err := GenerateTOTPCodesForSlots(slots)
		if err != nil {
			t.Fatalf("GenerateTOTPCodesForSlots() unexpected error: %v", err)
		}
		if _, exists := codes[1]; exists {
			t.Error("GenerateTOTPCodesForSlots() should skip slot 1 with error")
		}
		if code, exists := codes[2]; !exists || len(code) != 6 {
			t.Errorf("GenerateTOTPCodesForSlots() slot 2 = %q, want 6-digit code", code)
		}
	})

	t.Run("All error slots", func(t *testing.T) {
		slots := []NVRAMSlot{
			{SlotNumber: 1, Error: fmt.Errorf("error")},
		}
		codes, err := GenerateTOTPCodesForSlots(slots)
		if err != nil {
			t.Fatalf("GenerateTOTPCodesForSlots() unexpected error: %v", err)
		}
		if len(codes) != 0 {
			t.Errorf("GenerateTOTPCodesForSlots() returned %d codes, want 0", len(codes))
		}
	})
}

// TestPcrIndicesToEventlogString tests PCR index formatting
func TestPcrIndicesToEventlogString(t *testing.T) {
	tests := []struct {
		name     string
		indices  []int
		expected string
	}{
		{"Single index", []int{0}, "0e"},
		{"Multiple indices", []int{0, 2, 7}, "0e,2e,7e"},
		{"Empty", []int{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pcrIndicesToEventlogString(tt.indices)
			if got != tt.expected {
				t.Errorf("pcrIndicesToEventlogString(%v) = %q, want %q", tt.indices, got, tt.expected)
			}
		})
	}
}

// TestBuildPCRDigest tests PCR digest building
func TestBuildPCRDigest(t *testing.T) {
	t.Run("SHA256 valid", func(t *testing.T) {
		pcrValue0 := make([]byte, 32)
		pcrValue7 := make([]byte, 32)
		for i := range pcrValue0 {
			pcrValue0[i] = 0xAA
		}
		for i := range pcrValue7 {
			pcrValue7[i] = 0xBB
		}

		pcrValues := map[int][]byte{0: pcrValue0, 7: pcrValue7}
		digest, err := buildPCRDigest([]int{0, 7}, pcrValues, PCRHashAlgoSHA256)
		if err != nil {
			t.Fatalf("buildPCRDigest() unexpected error: %v", err)
		}

		// Verify: digest should be SHA256 of concatenated PCR values
		concatenated := append(pcrValue0, pcrValue7...)
		expectedHash := sha256.Sum256(concatenated)
		if !bytes.Equal(digest.Buffer, expectedHash[:]) {
			t.Errorf("buildPCRDigest() digest mismatch")
		}
	})

	t.Run("SHA1 valid", func(t *testing.T) {
		pcrValue := make([]byte, 20)
		pcrValues := map[int][]byte{0: pcrValue}
		digest, err := buildPCRDigest([]int{0}, pcrValues, PCRHashAlgoSHA1)
		if err != nil {
			t.Fatalf("buildPCRDigest() unexpected error: %v", err)
		}
		if len(digest.Buffer) != 32 {
			t.Errorf("buildPCRDigest() digest length = %d, want 32", len(digest.Buffer))
		}
	})

	t.Run("Missing PCR value", func(t *testing.T) {
		pcrValues := map[int][]byte{0: make([]byte, 32)}
		_, err := buildPCRDigest([]int{0, 7}, pcrValues, PCRHashAlgoSHA256)
		if err == nil {
			t.Error("buildPCRDigest() expected error for missing PCR value")
		}
	})

	t.Run("Wrong length", func(t *testing.T) {
		pcrValues := map[int][]byte{0: make([]byte, 16)}
		_, err := buildPCRDigest([]int{0}, pcrValues, PCRHashAlgoSHA256)
		if err == nil {
			t.Error("buildPCRDigest() expected error for wrong PCR value length")
		}
	})
}

// TestAttestHash tests PCRHashAlgo to attest.HashAlg conversion
func TestAttestHash(t *testing.T) {
	tests := []struct {
		name     string
		algo     PCRHashAlgo
		expected attest.HashAlg
	}{
		{"SHA1", PCRHashAlgoSHA1, attest.HashSHA1},
		{"SHA256", PCRHashAlgoSHA256, attest.HashSHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := attestHash(tt.algo)
			if got != tt.expected {
				t.Errorf("attestHash(%v) = %v, want %v", tt.algo, got, tt.expected)
			}
		})
	}
}

// TestMin tests the min helper function
func TestMin(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{0, 0, 0},
		{-1, 1, -1},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("min(%d,%d)", tt.a, tt.b), func(t *testing.T) {
			got := min(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

// TestPCRSourceUnknown tests PCRSource with unknown value
func TestPCRSourceUnknown(t *testing.T) {
	unknown := PCRSource(99)
	if got := unknown.String(); got != "unknown" {
		t.Errorf("PCRSource(99).String() = %q, want %q", got, "unknown")
	}
	if got := unknown.Suffix(); got != "" {
		t.Errorf("PCRSource(99).Suffix() = %q, want %q", got, "")
	}
}

// TestPCRSourcePredict tests the predict PCR source value
func TestPCRSourcePredict(t *testing.T) {
	if PCRSourcePredict != PCRSource(2) {
		t.Errorf("PCRSourcePredict should be 2, got %d", PCRSourcePredict)
	}
	if got := PCRSourcePredict.String(); got != "predict" {
		t.Errorf("PCRSourcePredict.String() = %q, want %q", got, "predict")
	}
	if got := PCRSourcePredict.Suffix(); got != "p" {
		t.Errorf("PCRSourcePredict.Suffix() = %q, want %q", got, "p")
	}
}

// TestParsePCRSpecsPredictRoundTrip tests that predict specs round-trip through string conversion
func TestParsePCRSpecsPredictRoundTrip(t *testing.T) {
	input := "0e,2,7e,11p:tpm2-pcr11predict"
	specs, err := ParsePCRSpecs(input)
	if err != nil {
		t.Fatalf("ParsePCRSpecs(%q) unexpected error: %v", input, err)
	}
	output := PCRSpecsToString(specs)
	if output != input {
		t.Errorf("Round-trip failed: input=%q, output=%q", input, output)
	}
}

// TestParsePCRSpecsPredictAbsolutePath tests predict with an absolute path command
func TestParsePCRSpecsPredictAbsolutePath(t *testing.T) {
	input := "11p:/usr/local/bin/predict-pcr11"
	specs, err := ParsePCRSpecs(input)
	if err != nil {
		t.Fatalf("ParsePCRSpecs(%q) unexpected error: %v", input, err)
	}
	if len(specs) != 1 {
		t.Fatalf("Expected 1 spec, got %d", len(specs))
	}
	if specs[0].Index != 11 {
		t.Errorf("Expected index 11, got %d", specs[0].Index)
	}
	if specs[0].Source != PCRSourcePredict {
		t.Errorf("Expected PCRSourcePredict, got %v", specs[0].Source)
	}
	if specs[0].Command != "/usr/local/bin/predict-pcr11" {
		t.Errorf("Expected command '/usr/local/bin/predict-pcr11', got %q", specs[0].Command)
	}
}

// TestRunPredictCommand tests the external predict command runner
func TestRunPredictCommand(t *testing.T) {
	t.Run("Empty command is rejected", func(t *testing.T) {
		_, err := RunPredictCommand("", 32, false)
		if err == nil {
			t.Error("Expected error for empty command, got nil")
		}
	})

	t.Run("Non-existent command fails", func(t *testing.T) {
		_, err := RunPredictCommand("/nonexistent/binary/that/does/not/exist", 32, false)
		if err == nil {
			t.Error("Expected error for non-existent command, got nil")
		}
	})
}

// TestPCRHashAlgoUnknown tests PCRHashAlgo with unknown value (defaults to SHA256)
func TestPCRHashAlgoUnknown(t *testing.T) {
	unknown := PCRHashAlgo("unknown")
	if got := unknown.TPMAlg(); got != tpm2.TPMAlgSHA256 {
		t.Errorf("PCRHashAlgo(unknown).TPMAlg() = %v, want TPMAlgSHA256", got)
	}
	if got := unknown.DigestSize(); got != 32 {
		t.Errorf("PCRHashAlgo(unknown).DigestSize() = %d, want 32", got)
	}
	if got := unknown.String(); got != "sha256" {
		t.Errorf("PCRHashAlgo(unknown).String() = %q, want %q", got, "sha256")
	}
	if got := unknown.DisplayString(); got != "SHA-256" {
		t.Errorf("PCRHashAlgo(unknown).DisplayString() = %q, want %q", got, "SHA-256")
	}
}

// --- Tests for seal.go functions ---

// TestGenerateTOTPSecret tests the TOTP secret generation function
func TestGenerateTOTPSecret(t *testing.T) {
	t.Run("Returns valid Base32 encoded secret", func(t *testing.T) {
		secret, err := generateTOTPSecret()
		if err != nil {
			t.Fatalf("generateTOTPSecret() unexpected error: %v", err)
		}

		// Verify it's valid Base32 (no padding)
		_, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(secret))
		if err != nil {
			t.Errorf("generateTOTPSecret() returned invalid Base32: %v", err)
		}
	})

	t.Run("Returns correct length", func(t *testing.T) {
		secret, err := generateTOTPSecret()
		if err != nil {
			t.Fatalf("generateTOTPSecret() unexpected error: %v", err)
		}

		// 32 bytes of random data encoded as Base32 without padding
		// Base32 encodes 5 bytes into 8 characters: 32 bytes -> ceil(32/5)*8 = 7*8 = 56 chars
		// But actually: 32*8 = 256 bits / 5 = 51.2 -> 52 chars (no padding)
		expectedLen := base32.StdEncoding.WithPadding(base32.NoPadding).EncodedLen(32)
		if len(secret) != expectedLen {
			t.Errorf("generateTOTPSecret() length = %d, want %d", len(secret), expectedLen)
		}
	})

	t.Run("Is recognized as valid TOTP secret", func(t *testing.T) {
		secret, err := generateTOTPSecret()
		if err != nil {
			t.Fatalf("generateTOTPSecret() unexpected error: %v", err)
		}

		if !isTOTPSecret(string(secret)) {
			t.Errorf("generateTOTPSecret() result %q not recognized as valid TOTP secret", string(secret))
		}
	})

	t.Run("Can generate valid TOTP codes", func(t *testing.T) {
		secret, err := generateTOTPSecret()
		if err != nil {
			t.Fatalf("generateTOTPSecret() unexpected error: %v", err)
		}

		code, timeRemaining, err := generateTOTPCode(string(secret))
		if err != nil {
			t.Fatalf("generateTOTPCode() with generated secret failed: %v", err)
		}
		if len(code) != 6 {
			t.Errorf("TOTP code length = %d, want 6", len(code))
		}
		if timeRemaining < 1 || timeRemaining > 30 {
			t.Errorf("TOTP timeRemaining = %d, want 1-30", timeRemaining)
		}
	})

	t.Run("Generates unique secrets", func(t *testing.T) {
		secrets := make(map[string]bool)
		for i := 0; i < 10; i++ {
			secret, err := generateTOTPSecret()
			if err != nil {
				t.Fatalf("generateTOTPSecret() iteration %d failed: %v", i, err)
			}
			s := string(secret)
			if secrets[s] {
				t.Errorf("generateTOTPSecret() generated duplicate secret on iteration %d", i)
			}
			secrets[s] = true
		}
	})

	t.Run("Decodes to 32 bytes of random data", func(t *testing.T) {
		secret, err := generateTOTPSecret()
		if err != nil {
			t.Fatalf("generateTOTPSecret() unexpected error: %v", err)
		}

		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(secret))
		if err != nil {
			t.Fatalf("Failed to decode Base32 secret: %v", err)
		}

		if len(decoded) != 32 {
			t.Errorf("Decoded secret length = %d bytes, want 32 bytes (256 bits)", len(decoded))
		}
	})

	t.Run("Contains only valid Base32 characters", func(t *testing.T) {
		secret, err := generateTOTPSecret()
		if err != nil {
			t.Fatalf("generateTOTPSecret() unexpected error: %v", err)
		}

		validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
		for _, c := range string(secret) {
			if !strings.ContainsRune(validChars, c) {
				t.Errorf("generateTOTPSecret() contains invalid Base32 character: %c", c)
			}
		}
	})
}

// TestSealDataWithSpecsValidation tests input validation in sealDataWithSpecs
func TestSealDataWithSpecsValidation(t *testing.T) {
	// Create a dummy public key and PEM for tests that need to reach later validations
	dummyPubKeyPEM := []byte("dummy-pem-data")

	t.Run("Rejects empty PCR specs", func(t *testing.T) {
		err := sealDataWithSpecs("/dev/null", []PCRSpec{}, 0x01803010, []byte("data"), nil, dummyPubKeyPEM, "", "", false, PCRHashAlgoSHA256)
		if err == nil {
			t.Error("sealDataWithSpecs() expected error for empty specs, got nil")
		}
		if !strings.Contains(err.Error(), "no PCRs specified") {
			t.Errorf("sealDataWithSpecs() error = %q, want to contain 'no PCRs specified'", err.Error())
		}
	})

	t.Run("Rejects empty data", func(t *testing.T) {
		specs := []PCRSpec{{Index: 0, Source: PCRSourceRegister}}
		err := sealDataWithSpecs("/dev/null", specs, 0x01803010, []byte{}, nil, dummyPubKeyPEM, "", "", false, PCRHashAlgoSHA256)
		if err == nil {
			t.Error("sealDataWithSpecs() expected error for empty data, got nil")
		}
		if !strings.Contains(err.Error(), "no data to seal") {
			t.Errorf("sealDataWithSpecs() error = %q, want to contain 'no data to seal'", err.Error())
		}
	})

	t.Run("Rejects nil data", func(t *testing.T) {
		specs := []PCRSpec{{Index: 0, Source: PCRSourceRegister}}
		err := sealDataWithSpecs("/dev/null", specs, 0x01803010, nil, nil, dummyPubKeyPEM, "", "", false, PCRHashAlgoSHA256)
		if err == nil {
			t.Error("sealDataWithSpecs() expected error for nil data, got nil")
		}
		if !strings.Contains(err.Error(), "no data to seal") {
			t.Errorf("sealDataWithSpecs() error = %q, want to contain 'no data to seal'", err.Error())
		}
	})

	t.Run("Rejects empty signing key PEM", func(t *testing.T) {
		specs := []PCRSpec{{Index: 0, Source: PCRSourceRegister}}
		err := sealDataWithSpecs("/dev/null", specs, 0x01803010, []byte("test-data"), nil, []byte{}, "", "", false, PCRHashAlgoSHA256)
		if err == nil {
			t.Error("sealDataWithSpecs() expected error for empty signing key, got nil")
		}
		if !strings.Contains(err.Error(), "no signing public key provided") {
			t.Errorf("sealDataWithSpecs() error = %q, want to contain 'no signing public key provided'", err.Error())
		}
	})

	t.Run("Fails on invalid TPM path", func(t *testing.T) {
		specs := []PCRSpec{{Index: 0, Source: PCRSourceRegister}}
		err := sealDataWithSpecs("/nonexistent/tpm/path", specs, 0x01803010, []byte("test-data"), nil, dummyPubKeyPEM, "", "", false, PCRHashAlgoSHA256)
		if err == nil {
			t.Error("sealDataWithSpecs() expected error for invalid TPM path, got nil")
		}
		if !strings.Contains(err.Error(), "failed to open TPM") {
			t.Errorf("sealDataWithSpecs() error = %q, want to contain 'failed to open TPM'", err.Error())
		}
	})
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
