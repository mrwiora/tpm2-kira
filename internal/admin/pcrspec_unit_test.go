//go:build unit || !integration
// +build unit !integration

package admin

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tpm2-trust/tpm2-kira/internal/measure"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"

	"github.com/google/go-tpm/tpm2"
)

// TestParsePCRSpecs tests PCR spec parsing with source suffixes
func TestParsePCRSpecs(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  []measure.PCRSpec
		shouldErr bool
	}{
		{
			name:  "Single PCR register (default)",
			input: "7",
			expected: []measure.PCRSpec{
				{Index: 7, Source: measure.PCRSourceRegister},
			},
		},
		{
			name:  "Single PCR with explicit register suffix",
			input: "7r",
			expected: []measure.PCRSpec{
				{Index: 7, Source: measure.PCRSourceRegister},
			},
		},
		{
			name:  "Single PCR with eventlog suffix",
			input: "7e",
			expected: []measure.PCRSpec{
				{Index: 7, Source: measure.PCRSourceEventlog},
			},
		},
		{
			name:  "Multiple PCRs mixed sources",
			input: "0e,2,4r,7e",
			expected: []measure.PCRSpec{
				{Index: 0, Source: measure.PCRSourceEventlog},
				{Index: 2, Source: measure.PCRSourceRegister},
				{Index: 4, Source: measure.PCRSourceRegister},
				{Index: 7, Source: measure.PCRSourceEventlog},
			},
		},
		{
			name:  "Single UKI PCR with explicit path",
			input: "11u:/boot/EFI/Linux/arch-linux.efi",
			expected: []measure.PCRSpec{
				{Index: 11, Source: measure.PCRSourceUKI, Command: "/boot/EFI/Linux/arch-linux.efi"},
			},
		},
		{
			name:  "UKI PCR with default path",
			input: "11u",
			expected: []measure.PCRSpec{
				{Index: 11, Source: measure.PCRSourceUKI, Command: measure.DefaultUKIPath},
			},
		},
		{
			name:  "Multiple PCRs with UKI",
			input: "0e,2,7e,11u",
			expected: []measure.PCRSpec{
				{Index: 0, Source: measure.PCRSourceEventlog},
				{Index: 2, Source: measure.PCRSourceRegister},
				{Index: 7, Source: measure.PCRSourceEventlog},
				{Index: 11, Source: measure.PCRSourceUKI, Command: measure.DefaultUKIPath},
			},
		},
		{
			name:      "UKI source on a PCR other than 11",
			input:     "7u",
			shouldErr: true,
		},
		{
			name:      "UKI with empty path",
			input:     "11u:",
			shouldErr: true,
		},
		{
			name:      "Removed predict source is rejected",
			input:     "11p:/usr/bin/tpm2-pcr11predict",
			shouldErr: true,
		},
		{
			name:      "Invalid PCR index",
			input:     "abc",
			shouldErr: true,
		},
		{
			name:      "PCR index too high",
			input:     "24",
			shouldErr: true,
		},
		{
			name:      "Negative PCR index",
			input:     "-1",
			shouldErr: true,
		},
		{
			name:      "Unknown suffix",
			input:     "7x",
			shouldErr: true,
		},
		{
			name:      "Empty input",
			input:     "",
			shouldErr: true,
		},
		{
			name:  "Whitespace around values",
			input: " 0 , 7e , 2r ",
			expected: []measure.PCRSpec{
				{Index: 0, Source: measure.PCRSourceRegister},
				{Index: 7, Source: measure.PCRSourceEventlog},
				{Index: 2, Source: measure.PCRSourceRegister},
			},
		},
		{
			name:  "PCR 0 register",
			input: "0",
			expected: []measure.PCRSpec{
				{Index: 0, Source: measure.PCRSourceRegister},
			},
		},
		{
			name:  "Multiple register PCRs",
			input: "0,2,4,7",
			expected: []measure.PCRSpec{
				{Index: 0, Source: measure.PCRSourceRegister},
				{Index: 2, Source: measure.PCRSourceRegister},
				{Index: 4, Source: measure.PCRSourceRegister},
				{Index: 7, Source: measure.PCRSourceRegister},
			},
		},
		{
			name:  "All eventlog",
			input: "0e,2e,7e",
			expected: []measure.PCRSpec{
				{Index: 0, Source: measure.PCRSourceEventlog},
				{Index: 2, Source: measure.PCRSourceEventlog},
				{Index: 7, Source: measure.PCRSourceEventlog},
			},
		},
		{
			name:  "All PCR indices",
			input: "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23",
			expected: func() []measure.PCRSpec {
				specs := make([]measure.PCRSpec, 24)
				for i := range specs {
					specs[i] = measure.PCRSpec{Index: i, Source: measure.PCRSourceRegister}
				}
				return specs
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := measure.ParsePCRSpecs(tt.input)
			if tt.shouldErr {
				if err == nil {
					t.Errorf("Expected error for input %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(result) != len(tt.expected) {
				t.Fatalf("Expected %d specs, got %d", len(tt.expected), len(result))
			}

			for i, spec := range result {
				if spec.Index != tt.expected[i].Index {
					t.Errorf("Spec[%d].Index: expected %d, got %d", i, tt.expected[i].Index, spec.Index)
				}
				if spec.Source != tt.expected[i].Source {
					t.Errorf("Spec[%d].Source: expected %v, got %v", i, tt.expected[i].Source, spec.Source)
				}
				if spec.Command != tt.expected[i].Command {
					t.Errorf("Spec[%d].Command: expected %q, got %q", i, tt.expected[i].Command, spec.Command)
				}
			}
		})
	}
}

// TestPCRSpecsToString tests PCR spec serialization
func TestPCRSpecsToString(t *testing.T) {
	tests := []struct {
		name     string
		specs    []measure.PCRSpec
		expected string
	}{
		{
			name: "All register",
			specs: []measure.PCRSpec{
				{Index: 0, Source: measure.PCRSourceRegister},
				{Index: 7, Source: measure.PCRSourceRegister},
			},
			expected: "0,7",
		},
		{
			name: "Mixed sources",
			specs: []measure.PCRSpec{
				{Index: 0, Source: measure.PCRSourceEventlog},
				{Index: 2, Source: measure.PCRSourceRegister},
				{Index: 7, Source: measure.PCRSourceEventlog},
			},
			expected: "0e,2,7e",
		},
		{
			name: "With UKI",
			specs: []measure.PCRSpec{
				{Index: 0, Source: measure.PCRSourceEventlog},
				{Index: 11, Source: measure.PCRSourceUKI, Command: "/boot/EFI/Linux/arch-linux.efi"},
			},
			expected: "0e,11u:/boot/EFI/Linux/arch-linux.efi",
		},
		{
			name:     "Empty",
			specs:    []measure.PCRSpec{},
			expected: "",
		},
		{
			name: "Single register",
			specs: []measure.PCRSpec{
				{Index: 7, Source: measure.PCRSourceRegister},
			},
			expected: "7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := measure.PCRSpecsToString(tt.specs)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestPCRSourceString tests PCR source display
func TestPCRSourceString(t *testing.T) {
	if measure.PCRSourceRegister.String() != "register" {
		t.Errorf("Register String() = %q, want \"register\"", measure.PCRSourceRegister.String())
	}
	if measure.PCRSourceEventlog.String() != "eventlog" {
		t.Errorf("Eventlog String() = %q, want \"eventlog\"", measure.PCRSourceEventlog.String())
	}
	if measure.PCRSourceUKI.String() != "uki" {
		t.Errorf("UKI String() = %q, want \"uki\"", measure.PCRSourceUKI.String())
	}
}

// TestPCRSourceSuffix tests PCR source suffix
func TestPCRSourceSuffix(t *testing.T) {
	if measure.PCRSourceRegister.Suffix() != "" {
		t.Errorf("Register Suffix() = %q, want empty", measure.PCRSourceRegister.Suffix())
	}
	if measure.PCRSourceEventlog.Suffix() != "e" {
		t.Errorf("Eventlog Suffix() = %q, want \"e\"", measure.PCRSourceEventlog.Suffix())
	}
	if measure.PCRSourceUKI.Suffix() != "u" {
		t.Errorf("UKI Suffix() = %q, want \"u\"", measure.PCRSourceUKI.Suffix())
	}
}

// TestPCRSpecIndices tests extracting indices from specs
func TestPCRSpecIndices(t *testing.T) {
	specs := []measure.PCRSpec{
		{Index: 0, Source: measure.PCRSourceEventlog},
		{Index: 2, Source: measure.PCRSourceRegister},
		{Index: 7, Source: measure.PCRSourceEventlog},
	}

	indices := measure.PCRSpecIndices(specs)
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

// TestGetPCRIndices tests extracting PCR indices from SealedBlob
func TestGetPCRIndices(t *testing.T) {
	blob := &nvslot.SealedBlob{
		Payload: nvslot.SealedBlobPayload{
			PCRDigests: []nvslot.PCRDigestPair{
				{Index: 0, Source: measure.PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: []byte("d0")}},
				{Index: 2, Source: measure.PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte("d2")}},
				{Index: 4, Source: measure.PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte("d4")}},
				{Index: 7, Source: measure.PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: []byte("d7")}},
			},
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

	blob := &nvslot.SealedBlob{
		Payload: nvslot.SealedBlobPayload{
			PCRDigests: []nvslot.PCRDigestPair{
				{Index: 0, Source: measure.PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: digest0}},
				{Index: 2, Source: measure.PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: digest2}},
			},
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
		blob     *nvslot.SealedBlob
		expected bool
	}{
		{
			name: "All register",
			blob: &nvslot.SealedBlob{
				Payload: nvslot.SealedBlobPayload{
					PCRDigests: []nvslot.PCRDigestPair{
						{Index: 0, Source: measure.PCRSourceRegister},
						{Index: 2, Source: measure.PCRSourceRegister},
					},
				},
			},
			expected: false,
		},
		{
			name: "All eventlog",
			blob: &nvslot.SealedBlob{
				Payload: nvslot.SealedBlobPayload{
					PCRDigests: []nvslot.PCRDigestPair{
						{Index: 0, Source: measure.PCRSourceEventlog},
						{Index: 2, Source: measure.PCRSourceEventlog},
					},
				},
			},
			expected: true,
		},
		{
			name: "Mixed",
			blob: &nvslot.SealedBlob{
				Payload: nvslot.SealedBlobPayload{
					PCRDigests: []nvslot.PCRDigestPair{
						{Index: 0, Source: measure.PCRSourceEventlog},
						{Index: 2, Source: measure.PCRSourceRegister},
					},
				},
			},
			expected: true,
		},
		{
			name: "UKI only does not count as eventlog",
			blob: &nvslot.SealedBlob{
				Payload: nvslot.SealedBlobPayload{
					PCRDigests: []nvslot.PCRDigestPair{
						{Index: 11, Source: measure.PCRSourceUKI, Command: "/boot/uki.efi"},
					},
				},
			},
			expected: false,
		},
		{
			name: "Empty",
			blob: &nvslot.SealedBlob{
				Payload: nvslot.SealedBlobPayload{
					PCRDigests: []nvslot.PCRDigestPair{},
				},
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

// TestHasUKIPCRs tests the HasUKIPCRs method
func TestHasUKIPCRs(t *testing.T) {
	tests := []struct {
		name     string
		blob     *nvslot.SealedBlob
		expected bool
	}{
		{
			name: "All register",
			blob: &nvslot.SealedBlob{
				Payload: nvslot.SealedBlobPayload{
					PCRDigests: []nvslot.PCRDigestPair{
						{Index: 0, Source: measure.PCRSourceRegister},
						{Index: 2, Source: measure.PCRSourceRegister},
					},
				},
			},
			expected: false,
		},
		{
			name: "All eventlog",
			blob: &nvslot.SealedBlob{
				Payload: nvslot.SealedBlobPayload{
					PCRDigests: []nvslot.PCRDigestPair{
						{Index: 0, Source: measure.PCRSourceEventlog},
						{Index: 2, Source: measure.PCRSourceEventlog},
					},
				},
			},
			expected: false,
		},
		{
			name: "Has UKI",
			blob: &nvslot.SealedBlob{
				Payload: nvslot.SealedBlobPayload{
					PCRDigests: []nvslot.PCRDigestPair{
						{Index: 0, Source: measure.PCRSourceEventlog},
						{Index: 11, Source: measure.PCRSourceUKI, Command: "/boot/uki.efi"},
					},
				},
			},
			expected: true,
		},
		{
			name: "UKI only",
			blob: &nvslot.SealedBlob{
				Payload: nvslot.SealedBlobPayload{
					PCRDigests: []nvslot.PCRDigestPair{
						{Index: 11, Source: measure.PCRSourceUKI, Command: "/boot/uki.efi"},
					},
				},
			},
			expected: true,
		},
		{
			name: "Empty",
			blob: &nvslot.SealedBlob{
				Payload: nvslot.SealedBlobPayload{
					PCRDigests: []nvslot.PCRDigestPair{},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.blob.HasUKIPCRs()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestGetEventlogPCRIndices tests extracting eventlog PCR indices
func TestGetEventlogPCRIndices(t *testing.T) {
	blob := &nvslot.SealedBlob{
		Payload: nvslot.SealedBlobPayload{
			PCRDigests: []nvslot.PCRDigestPair{
				{Index: 0, Source: measure.PCRSourceEventlog},
				{Index: 2, Source: measure.PCRSourceRegister},
				{Index: 4, Source: measure.PCRSourceRegister},
				{Index: 7, Source: measure.PCRSourceEventlog},
			},
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

// TestGetUKIPCRIndices tests extracting UKI PCR indices
func TestGetUKIPCRIndices(t *testing.T) {
	blob := &nvslot.SealedBlob{
		Payload: nvslot.SealedBlobPayload{
			PCRDigests: []nvslot.PCRDigestPair{
				{Index: 0, Source: measure.PCRSourceEventlog},
				{Index: 2, Source: measure.PCRSourceRegister},
				{Index: 7, Source: measure.PCRSourceEventlog},
				{Index: 11, Source: measure.PCRSourceUKI, Command: "/boot/uki.efi"},
			},
		},
	}

	ukiIndices := blob.GetUKIPCRIndices()
	if len(ukiIndices) != 1 {
		t.Fatalf("Expected 1 uki index, got %d", len(ukiIndices))
	}
	if ukiIndices[0] != 11 {
		t.Errorf("Expected [11], got %v", ukiIndices)
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
	blob := &nvslot.SealedBlob{
		Payload: nvslot.SealedBlobPayload{
			PCRDigests: []nvslot.PCRDigestPair{
				{Index: 0, Source: measure.PCRSourceEventlog},
				{Index: 2, Source: measure.PCRSourceRegister},
				{Index: 7, Source: measure.PCRSourceEventlog},
				{Index: 11, Source: measure.PCRSourceUKI, Command: "/boot/uki.efi"},
			},
		},
	}

	specs := blob.GetPCRSpecs()
	if len(specs) != 4 {
		t.Fatalf("Expected 4 specs, got %d", len(specs))
	}

	expected := []measure.PCRSpec{
		{Index: 0, Source: measure.PCRSourceEventlog},
		{Index: 2, Source: measure.PCRSourceRegister},
		{Index: 7, Source: measure.PCRSourceEventlog},
		{Index: 11, Source: measure.PCRSourceUKI, Command: "/boot/uki.efi"},
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
			name:     "Different digests",
			sealed:   []tpm2.TPM2BDigest{digest1, digest2},
			current:  []tpm2.TPM2BDigest{digest1, digest3},
			expected: false,
		},
		{
			name:     "Different lengths",
			sealed:   []tpm2.TPM2BDigest{digest1},
			current:  []tpm2.TPM2BDigest{digest1, digest2},
			expected: false,
		},
		{
			name:     "Empty",
			sealed:   []tpm2.TPM2BDigest{},
			current:  []tpm2.TPM2BDigest{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := measure.VerifyPCRValues(tt.sealed, tt.current)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestPcrsToBitmapBytes tests PCR index to bitmap conversion
func TestPcrsToBitmapBytes(t *testing.T) {
	tests := []struct {
		name     string
		pcrs     []int
		expected []byte
	}{
		{
			name:     "PCR 0 only",
			pcrs:     []int{0},
			expected: []byte{0x01, 0x00, 0x00},
		},
		{
			name:     "PCR 7 only",
			pcrs:     []int{7},
			expected: []byte{0x80, 0x00, 0x00},
		},
		{
			name:     "PCRs 0, 2, 4, 7",
			pcrs:     []int{0, 2, 4, 7},
			expected: []byte{0x95, 0x00, 0x00},
		},
		{
			name:     "PCR 23",
			pcrs:     []int{23},
			expected: []byte{0x00, 0x00, 0x80},
		},
		{
			name:     "Empty",
			pcrs:     []int{},
			expected: []byte{0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := measure.PcrsToBitmapBytes(tt.pcrs)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestCreatePCRSelection tests PCR selection creation
func TestCreatePCRSelection(t *testing.T) {
	pcrs := []int{0, 2, 4, 7}

	// Test SHA256 (default)
	selection := measure.CreatePCRSelection(pcrs, measure.PCRHashAlgoSHA256)

	if len(selection.PCRSelections) == 0 {
		t.Fatal("Expected at least one PCR selection")
	}

	pcrSel := selection.PCRSelections[0]

	if pcrSel.Hash != tpm2.TPMAlgSHA256 {
		t.Errorf("Expected SHA256 hash algorithm, got %v", pcrSel.Hash)
	}

	// Verify bitmap is set correctly
	bitmap := measure.PcrsToBitmapBytes(pcrs)
	if !bytes.Equal(pcrSel.PCRSelect, bitmap) {
		t.Error("PCR selection bitmap mismatch")
	}

	// Test SHA1
	selectionSHA1 := measure.CreatePCRSelection(pcrs, measure.PCRHashAlgoSHA1)

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
		blob     *nvslot.SealedBlob
		expected measure.PCRHashAlgo
	}{
		{
			name: "SHA256 digests (32 bytes)",
			blob: &nvslot.SealedBlob{
				Version: 6,
				Payload: nvslot.SealedBlobPayload{
					PCRDigests: []nvslot.PCRDigestPair{
						{Index: 0, Source: measure.PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
						{Index: 7, Source: measure.PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					},
				},
			},
			expected: measure.PCRHashAlgoSHA256,
		},
		{
			name: "SHA1 digests (20 bytes)",
			blob: &nvslot.SealedBlob{
				Version: 6,
				Payload: nvslot.SealedBlobPayload{
					PCRDigests: []nvslot.PCRDigestPair{
						{Index: 0, Source: measure.PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 20)}},
						{Index: 7, Source: measure.PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 20)}},
					},
				},
			},
			expected: measure.PCRHashAlgoSHA1,
		},
		{
			name: "Empty digests defaults to SHA256",
			blob: &nvslot.SealedBlob{
				Version: 6,
				Payload: nvslot.SealedBlobPayload{
					PCRDigests: []nvslot.PCRDigestPair{},
				},
			},
			expected: measure.PCRHashAlgoSHA256,
		},
		{
			name: "No PCR digests defaults to SHA256",
			blob: &nvslot.SealedBlob{
				Version: 6,
				Payload: nvslot.SealedBlobPayload{},
			},
			expected: measure.PCRHashAlgoSHA256,
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
	sha256 := measure.PCRHashAlgoSHA256
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

	// SHA1: the legacy PCR bank (slot add --sha1). The SHA-1 here is the
	// test's subject, not a choice of the code's.
	sha1 := measure.PCRHashAlgoSHA1
	if sha1.DigestSize() != 20 {
		t.Errorf("SHA1 DigestSize() = %d, want 20", sha1.DigestSize())
	}
	if sha1.String() != "sha1" {
		t.Errorf("SHA1 String() = %q, want \"sha1\"", sha1.String())
	}
	if sha1.DisplayString() != "legacy SHA-1" {
		t.Errorf("SHA1 DisplayString() = %q, want \"legacy SHA-1\"", sha1.DisplayString())
	}
	if sha1.TPMAlg() != tpm2.TPMAlgSHA1 {
		t.Errorf("SHA1 TPMAlg() mismatch")
	}
}

// TestGetPCRDescription tests PCR description lookup
func TestGetPCRDescription(t *testing.T) {
	// PCR 0 should return a non-empty description
	desc := measure.GetPCRDescription(0)
	if desc == "" {
		t.Error("Expected non-empty description for PCR 0")
	}

	// PCR 7 should return a non-empty description
	desc = measure.GetPCRDescription(7)
	if desc == "" {
		t.Error("Expected non-empty description for PCR 7")
	}

	// Various PCR indices should all have descriptions
	tests := []struct {
		name  string
		index int
	}{
		{"PCR 0", 0},
		{"PCR 1", 1},
		{"PCR 2", 2},
		{"PCR 3", 3},
		{"PCR 4", 4},
		{"PCR 5", 5},
		{"PCR 6", 6},
		{"PCR 7", 7},
		{"PCR 8", 8},
		{"PCR 9", 9},
		{"PCR 10", 10},
		{"PCR 11", 11},
		{"PCR 12", 12},
		{"PCR 14", 14},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := measure.GetPCRDescription(tt.index)
			if d == "" {
				t.Errorf("Expected non-empty description for PCR %d", tt.index)
			}
		})
	}
}

func TestPCRMismatchErrorError(t *testing.T) {
	err := &measure.PCRMismatchError{
		Message: "test mismatch",
	}
	if !strings.Contains(err.Error(), "test mismatch") {
		t.Errorf("Expected error to contain message, got: %s", err.Error())
	}
}

func TestPcrIndicesToEventlogString(t *testing.T) {
	tests := []struct {
		name     string
		indices  []int
		expected string
	}{
		{
			name:     "Single index",
			indices:  []int{7},
			expected: "7e",
		},
		{
			name:     "Multiple indices",
			indices:  []int{0, 2, 7},
			expected: "0e,2e,7e",
		},
		{
			name:     "Empty",
			indices:  []int{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := measure.PCRIndicesToEventlogString(tt.indices)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestBuildPCRDigest(t *testing.T) {
	// Test that buildPCRDigest produces consistent results
	pcrValues := map[int][]byte{
		0: make([]byte, 32),
		7: make([]byte, 32),
	}

	// Fill with test values
	for i := range pcrValues[0] {
		pcrValues[0][i] = byte(i)
	}
	for i := range pcrValues[7] {
		pcrValues[7][i] = byte(i * 2)
	}

	digest1, err := measure.BuildPCRDigest([]int{0, 7}, pcrValues, measure.PCRHashAlgoSHA256)
	if err != nil {
		t.Fatalf("buildPCRDigest failed: %v", err)
	}
	digest2, err := measure.BuildPCRDigest([]int{0, 7}, pcrValues, measure.PCRHashAlgoSHA256)
	if err != nil {
		t.Fatalf("buildPCRDigest failed: %v", err)
	}

	if !bytes.Equal(digest1.Buffer, digest2.Buffer) {
		t.Error("buildPCRDigest should be deterministic")
	}

	// Different PCR values should produce different digests
	pcrValues[0][0] = 0xFF
	digest3, err := measure.BuildPCRDigest([]int{0, 7}, pcrValues, measure.PCRHashAlgoSHA256)
	if err != nil {
		t.Fatalf("buildPCRDigest failed: %v", err)
	}
	if bytes.Equal(digest1.Buffer, digest3.Buffer) {
		t.Error("Different PCR values should produce different digests")
	}
}

func TestPCRSourceUnknown(t *testing.T) {
	unknown := measure.PCRSource(99)
	if unknown.String() != "unknown" {
		t.Errorf("Unknown source String() = %q, want \"unknown\"", unknown.String())
	}
	if unknown.Suffix() != "" {
		t.Errorf("Unknown source Suffix() = %q, want empty", unknown.Suffix())
	}
}

func TestPCRSourceUKI(t *testing.T) {
	u := measure.PCRSourceUKI
	if u.String() != "uki" {
		t.Errorf("UKI String() = %q, want \"uki\"", u.String())
	}
	if u.Suffix() != "u" {
		t.Errorf("UKI Suffix() = %q, want \"u\"", u.Suffix())
	}
}

func TestParsePCRSpecsUKIRoundTrip(t *testing.T) {
	input := "0e,2,11u:/boot/EFI/Linux/arch-linux.efi"
	specs, err := measure.ParsePCRSpecs(input)
	if err != nil {
		t.Fatalf("ParsePCRSpecs failed: %v", err)
	}
	output := measure.PCRSpecsToString(specs)
	if output != input {
		t.Errorf("Round trip failed: %q -> %q", input, output)
	}
}

func TestParsePCRSpecsUKIAbsolutePath(t *testing.T) {
	input := "11u:/boot/EFI/Linux/other.efi"
	specs, err := measure.ParsePCRSpecs(input)
	if err != nil {
		t.Fatalf("ParsePCRSpecs failed: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("Expected 1 spec, got %d", len(specs))
	}
	if specs[0].Index != 11 {
		t.Errorf("Index = %d, want 11", specs[0].Index)
	}
	if specs[0].Source != measure.PCRSourceUKI {
		t.Errorf("Source = %v, want uki", specs[0].Source)
	}
	if specs[0].Command != "/boot/EFI/Linux/other.efi" {
		t.Errorf("Command = %q, want /boot/EFI/Linux/other.efi", specs[0].Command)
	}
}

func TestParsePCRSpecsRejectsRemovedPredictSource(t *testing.T) {
	if _, err := measure.ParsePCRSpecs("11p:/usr/bin/tpm2-pcr11predict"); err == nil {
		t.Error("Expected the removed predict source to be rejected, got nil")
	}
}

func TestPCRHashAlgoUnknown(t *testing.T) {
	unknown := measure.PCRHashAlgo("unknown")
	// Unknown should default to SHA256 behavior
	if unknown.DigestSize() != 32 {
		t.Errorf("Unknown DigestSize() = %d, want 32", unknown.DigestSize())
	}
	if unknown.String() != "sha256" {
		t.Errorf("Unknown String() = %q, want \"sha256\"", unknown.String())
	}
	if unknown.DisplayString() != "SHA-256" {
		t.Errorf("Unknown DisplayString() = %q, want \"SHA-256\"", unknown.DisplayString())
	}
	if unknown.TPMAlg() != tpm2.TPMAlgSHA256 {
		t.Errorf("Unknown TPMAlg() mismatch, expected SHA256")
	}
}
