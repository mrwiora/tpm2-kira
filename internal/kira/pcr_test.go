//go:build unit || !integration
// +build unit !integration

package kira

import (
	"bytes"
	"fmt"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
	"io"
	"os"
	"strings"
	"testing"
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
			name:  "Single PCR register (default)",
			input: "7",
			expected: []PCRSpec{
				{Index: 7, Source: PCRSourceRegister},
			},
		},
		{
			name:  "Single PCR with explicit register suffix",
			input: "7r",
			expected: []PCRSpec{
				{Index: 7, Source: PCRSourceRegister},
			},
		},
		{
			name:  "Single PCR with eventlog suffix",
			input: "7e",
			expected: []PCRSpec{
				{Index: 7, Source: PCRSourceEventlog},
			},
		},
		{
			name:  "Multiple PCRs mixed sources",
			input: "0e,2,4r,7e",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceRegister},
				{Index: 4, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceEventlog},
			},
		},
		{
			name:  "Single UKI PCR with explicit path",
			input: "11u:/boot/EFI/Linux/arch-linux.efi",
			expected: []PCRSpec{
				{Index: 11, Source: PCRSourceUKI, Command: "/boot/EFI/Linux/arch-linux.efi"},
			},
		},
		{
			name:  "UKI PCR with default path",
			input: "11u",
			expected: []PCRSpec{
				{Index: 11, Source: PCRSourceUKI, Command: DefaultUKIPath},
			},
		},
		{
			name:  "Multiple PCRs with UKI",
			input: "0e,2,7e,11u",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceEventlog},
				{Index: 11, Source: PCRSourceUKI, Command: DefaultUKIPath},
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
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceRegister},
			},
		},
		{
			name:  "PCR 0 register",
			input: "0",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceRegister},
			},
		},
		{
			name:  "Multiple register PCRs",
			input: "0,2,4,7",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceRegister},
				{Index: 2, Source: PCRSourceRegister},
				{Index: 4, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceRegister},
			},
		},
		{
			name:  "All eventlog",
			input: "0e,2e,7e",
			expected: []PCRSpec{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceEventlog},
				{Index: 7, Source: PCRSourceEventlog},
			},
		},
		{
			name:  "All PCR indices",
			input: "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23",
			expected: func() []PCRSpec {
				specs := make([]PCRSpec, 24)
				for i := range specs {
					specs[i] = PCRSpec{Index: i, Source: PCRSourceRegister}
				}
				return specs
			}(),
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
		specs    []PCRSpec
		expected string
	}{
		{
			name: "All register",
			specs: []PCRSpec{
				{Index: 0, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceRegister},
			},
			expected: "0,7",
		},
		{
			name: "Mixed sources",
			specs: []PCRSpec{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceEventlog},
			},
			expected: "0e,2,7e",
		},
		{
			name: "With UKI",
			specs: []PCRSpec{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 11, Source: PCRSourceUKI, Command: "/boot/EFI/Linux/arch-linux.efi"},
			},
			expected: "0e,11u:/boot/EFI/Linux/arch-linux.efi",
		},
		{
			name:     "Empty",
			specs:    []PCRSpec{},
			expected: "",
		},
		{
			name: "Single register",
			specs: []PCRSpec{
				{Index: 7, Source: PCRSourceRegister},
			},
			expected: "7",
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

// TestPCRSourceString tests PCR source display
func TestPCRSourceString(t *testing.T) {
	if PCRSourceRegister.String() != "register" {
		t.Errorf("Register String() = %q, want \"register\"", PCRSourceRegister.String())
	}
	if PCRSourceEventlog.String() != "eventlog" {
		t.Errorf("Eventlog String() = %q, want \"eventlog\"", PCRSourceEventlog.String())
	}
	if PCRSourceUKI.String() != "uki" {
		t.Errorf("UKI String() = %q, want \"uki\"", PCRSourceUKI.String())
	}
}

// TestPCRSourceSuffix tests PCR source suffix
func TestPCRSourceSuffix(t *testing.T) {
	if PCRSourceRegister.Suffix() != "" {
		t.Errorf("Register Suffix() = %q, want empty", PCRSourceRegister.Suffix())
	}
	if PCRSourceEventlog.Suffix() != "e" {
		t.Errorf("Eventlog Suffix() = %q, want \"e\"", PCRSourceEventlog.Suffix())
	}
	if PCRSourceUKI.Suffix() != "u" {
		t.Errorf("UKI Suffix() = %q, want \"u\"", PCRSourceUKI.Suffix())
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
			result := VerifyPCRValues(tt.sealed, tt.current)
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
			result := PcrsToBitmapBytes(tt.pcrs)
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

// TestGetPCRDescription tests PCR description lookup
func TestGetPCRDescription(t *testing.T) {
	// PCR 0 should return a non-empty description
	desc := GetPCRDescription(0)
	if desc == "" {
		t.Error("Expected non-empty description for PCR 0")
	}

	// PCR 7 should return a non-empty description
	desc = GetPCRDescription(7)
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
			d := GetPCRDescription(tt.index)
			if d == "" {
				t.Errorf("Expected non-empty description for PCR %d", tt.index)
			}
		})
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
			result := pcrIndicesToEventlogString(tt.indices)
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

	digest1, err := buildPCRDigest([]int{0, 7}, pcrValues, PCRHashAlgoSHA256)
	if err != nil {
		t.Fatalf("buildPCRDigest failed: %v", err)
	}
	digest2, err := buildPCRDigest([]int{0, 7}, pcrValues, PCRHashAlgoSHA256)
	if err != nil {
		t.Fatalf("buildPCRDigest failed: %v", err)
	}

	if !bytes.Equal(digest1.Buffer, digest2.Buffer) {
		t.Error("buildPCRDigest should be deterministic")
	}

	// Different PCR values should produce different digests
	pcrValues[0][0] = 0xFF
	digest3, err := buildPCRDigest([]int{0, 7}, pcrValues, PCRHashAlgoSHA256)
	if err != nil {
		t.Fatalf("buildPCRDigest failed: %v", err)
	}
	if bytes.Equal(digest1.Buffer, digest3.Buffer) {
		t.Error("Different PCR values should produce different digests")
	}
}
func TestAttestHash(t *testing.T) {
	tests := []struct {
		name     string
		algo     PCRHashAlgo
		expected attest.HashAlg
	}{
		{
			name:     "SHA256",
			algo:     PCRHashAlgoSHA256,
			expected: attest.HashSHA256,
		},
		{
			name:     "SHA1",
			algo:     PCRHashAlgoSHA1,
			expected: attest.HashSHA1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := attestHash(tt.algo)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
func TestPCRSourceUnknown(t *testing.T) {
	unknown := PCRSource(99)
	if unknown.String() != "unknown" {
		t.Errorf("Unknown source String() = %q, want \"unknown\"", unknown.String())
	}
	if unknown.Suffix() != "" {
		t.Errorf("Unknown source Suffix() = %q, want empty", unknown.Suffix())
	}
}
func TestPCRSourceUKI(t *testing.T) {
	u := PCRSourceUKI
	if u.String() != "uki" {
		t.Errorf("UKI String() = %q, want \"uki\"", u.String())
	}
	if u.Suffix() != "u" {
		t.Errorf("UKI Suffix() = %q, want \"u\"", u.Suffix())
	}
}
func TestParsePCRSpecsUKIRoundTrip(t *testing.T) {
	input := "0e,2,11u:/boot/EFI/Linux/arch-linux.efi"
	specs, err := ParsePCRSpecs(input)
	if err != nil {
		t.Fatalf("ParsePCRSpecs failed: %v", err)
	}
	output := PCRSpecsToString(specs)
	if output != input {
		t.Errorf("Round trip failed: %q -> %q", input, output)
	}
}
func TestParsePCRSpecsUKIAbsolutePath(t *testing.T) {
	input := "11u:/boot/EFI/Linux/other.efi"
	specs, err := ParsePCRSpecs(input)
	if err != nil {
		t.Fatalf("ParsePCRSpecs failed: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("Expected 1 spec, got %d", len(specs))
	}
	if specs[0].Index != 11 {
		t.Errorf("Index = %d, want 11", specs[0].Index)
	}
	if specs[0].Source != PCRSourceUKI {
		t.Errorf("Source = %v, want uki", specs[0].Source)
	}
	if specs[0].Command != "/boot/EFI/Linux/other.efi" {
		t.Errorf("Command = %q, want /boot/EFI/Linux/other.efi", specs[0].Command)
	}
}
func TestParsePCRSpecsRejectsRemovedPredictSource(t *testing.T) {
	if _, err := ParsePCRSpecs("11p:/usr/bin/tpm2-pcr11predict"); err == nil {
		t.Error("Expected the removed predict source to be rejected, got nil")
	}
}
func TestPCRHashAlgoUnknown(t *testing.T) {
	unknown := PCRHashAlgo("unknown")
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

// TestWarnAboutVolatileRegisters covers the guard that IsVolatileAfterMeasurePoint
// was written for but nothing called. Sealing PCR 9, 11 or 15 from the live
// register produces a policy that can never be satisfied — the register holds
// extends that happen after tpm2-kira reads the TPM at boot — and the symptom is
// no TOTP code at all, which looks exactly like tampering.
func TestWarnAboutVolatileRegisters(t *testing.T) {
	warned := func(specs []PCRSpec) string {
		original := os.Stdout
		read, write, _ := os.Pipe()
		os.Stdout = write

		done := make(chan string, 1)
		go func() {
			var buf strings.Builder
			io.Copy(&buf, read)
			done <- buf.String()
		}()

		warnAboutVolatileRegisters(specs)

		write.Close()
		os.Stdout = original
		return <-done
	}

	for _, pcr := range []int{9, 11, 15} {
		out := warned([]PCRSpec{{Index: pcr, Source: PCRSourceRegister}})
		if !strings.Contains(out, "cannot work") {
			t.Errorf("PCR %d from the register should be reported, got:\n%s", pcr, out)
		}
		if !strings.Contains(out, fmt.Sprintf("PCR %d", pcr)) {
			t.Errorf("the message should name PCR %d, got:\n%s", pcr, out)
		}
	}

	// Each one gets the fix that applies to it.
	if out := warned([]PCRSpec{{Index: 9, Source: PCRSourceRegister}}); !strings.Contains(out, "9e") {
		t.Errorf("PCR 9 should be pointed at the event log, got:\n%s", out)
	}
	if out := warned([]PCRSpec{{Index: 11, Source: PCRSourceRegister}}); !strings.Contains(out, "11u") {
		t.Errorf("PCR 11 should be pointed at the UKI source, got:\n%s", out)
	}
	if out := warned([]PCRSpec{{Index: 15, Source: PCRSourceRegister}}); !strings.Contains(out, "cannot be sealed at all") {
		t.Errorf("PCR 15 should be called unusable, got:\n%s", out)
	}

	// The stable registers are the normal case and must stay silent.
	for _, pcr := range []int{0, 1, 2, 4, 7, 8, 12, 13, 14} {
		if out := warned([]PCRSpec{{Index: pcr, Source: PCRSourceRegister}}); out != "" {
			t.Errorf("PCR %d stops changing at the measure point; no warning expected, got:\n%s", pcr, out)
		}
	}

	// And a volatile PCR with a source that does work must stay silent too.
	for _, spec := range []PCRSpec{
		{Index: 9, Source: PCRSourceEventlog},
		{Index: 11, Source: PCRSourceUKI},
		{Index: 11, Source: PCRSourceEventlog},
	} {
		if out := warned([]PCRSpec{spec}); out != "" {
			t.Errorf("PCR %d with source %s is fine; no warning expected, got:\n%s",
				spec.Index, spec.Source, out)
		}
	}
}
