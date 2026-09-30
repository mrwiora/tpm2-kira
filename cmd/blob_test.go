//go:build unit || !integration
// +build unit !integration

package cmd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"strings"
	"testing"
)

func TestSealedBlobMarshalUnmarshal(t *testing.T) {
	privKey := testGenECDSAKey(t)

	tests := []struct {
		name string
		blob *SealedBlob
	}{
		{
			name: "Basic blob (all register)",
			blob: &SealedBlob{
				Version: 6,
				Payload: SealedBlobPayload{
					AppVersion: "test-1.0.0",
					Public:     []byte("public-data-test"),
					Private:    []byte("private-data-test"),
					PCRDigests: []PCRDigestPair{
						{Index: 0, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte("digest0")}},
						{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte("digest2")}},
					},
					SignedBranchDigest: make([]byte, 32),
				},
			},
		},
		{
			name: "Blob with predict PCR source",
			blob: &SealedBlob{
				Version: 6,
				Payload: SealedBlobPayload{
					AppVersion: "test-predict",
					Public:     []byte("public-predict"),
					Private:    []byte("private-predict"),
					PCRDigests: []PCRDigestPair{
						{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
						{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
						{Index: 7, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
						{Index: 11, Source: PCRSourceUKI, Command: "/boot/uki.efi", Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					},
					SignedBranchDigest: make([]byte, 32),
					EventlogInfo: &EventlogInfo{
						EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
						CalculationTime: "2024-01-01T00:00:00Z",
						TotalEvents:     100,
						ProcessedEvents: 50,
					},
				},
			},
		},
		{
			name: "Blob without signed branch digest",
			blob: &SealedBlob{
				Version: 6,
				Payload: SealedBlobPayload{
					AppVersion: "test-0.0.0",
					Public:     []byte("public"),
					Private:    []byte("private"),
					PCRDigests: []PCRDigestPair{
						{Index: 7, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte("digest7")}},
					},
				},
			},
		},
		{
			name: "Blob with multiple PCRs (all register)",
			blob: &SealedBlob{
				Version: 6,
				Payload: SealedBlobPayload{
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
					SignedBranchDigest: make([]byte, 32),
				},
			},
		},
		{
			name: "Blob with empty PCR list",
			blob: &SealedBlob{
				Version: 6,
				Payload: SealedBlobPayload{
					AppVersion: "test",
					Public:     []byte("pub"),
					Private:    []byte("priv"),
					PCRDigests: []PCRDigestPair{},
				},
			},
		},
		{
			name: "Blob with all eventlog PCRs and eventlog info",
			blob: &SealedBlob{
				Version: 6,
				Payload: SealedBlobPayload{
					AppVersion: "test-eventlog",
					Public:     []byte("public-data"),
					Private:    []byte("private-data"),
					PCRDigests: []PCRDigestPair{
						{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
						{Index: 2, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
						{Index: 7, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					},
					SignedBranchDigest: make([]byte, 32),
					EventlogInfo: &EventlogInfo{
						EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
						CalculationTime: "2024-01-01T00:00:00Z",
						TotalEvents:     100,
						ProcessedEvents: 50,
					},
				},
			},
		},
		{
			name: "Blob with mixed register and eventlog PCRs",
			blob: &SealedBlob{
				Version: 6,
				Payload: SealedBlobPayload{
					AppVersion: "test-mixed",
					Public:     []byte("public-mixed"),
					Private:    []byte("private-mixed"),
					PCRDigests: []PCRDigestPair{
						{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
						{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
						{Index: 4, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
						{Index: 7, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					},
					SignedBranchDigest: make([]byte, 32),
					EventlogInfo: &EventlogInfo{
						EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
						CalculationTime: "2024-06-15T12:00:00Z",
						TotalEvents:     200,
						ProcessedEvents: 80,
					},
				},
			},
		},
		{
			name: "Blob with single eventlog PCR",
			blob: &SealedBlob{
				Version: 6,
				Payload: SealedBlobPayload{
					AppVersion: "test-single-e",
					Public:     []byte("pub"),
					Private:    []byte("priv"),
					PCRDigests: []PCRDigestPair{
						{Index: 7, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					},
					EventlogInfo: &EventlogInfo{
						EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
						CalculationTime: "2024-03-01T00:00:00Z",
						TotalEvents:     50,
						ProcessedEvents: 20,
					},
				},
			},
		},
		{
			name: "Blob with key paths",
			blob: &SealedBlob{
				Version: 6,
				Payload: SealedBlobPayload{
					AppVersion: "test-keypaths",
					Public:     []byte("pub-kp"),
					Private:    []byte("priv-kp"),
					PCRDigests: []PCRDigestPair{
						{Index: 7, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					},
					SignedBranchDigest: make([]byte, 32),
					PublicKeyRef:       KeyRef{Kind: KeyRefFile, Path: "/var/lib/tpm2-kira/keys/seal.pub"},
					PrivateKeyRef:      KeyRef{Kind: KeyRefFile, Path: "/var/lib/tpm2-kira/keys/seal.key"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal → Sign → Unmarshal round trip
			signedData := testSignBlob(t, tt.blob, privKey)

			// Unmarshal
			unmarshaled, err := UnmarshalSealedBlob(signedData)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			// Compare
			if unmarshaled.Version != CurrentBlobVersion {
				t.Errorf("Version should be %d, got %d", CurrentBlobVersion, unmarshaled.Version)
			}

			if unmarshaled.Payload.AppVersion != tt.blob.Payload.AppVersion {
				t.Errorf("AppVersion mismatch: expected %s, got %s", tt.blob.Payload.AppVersion, unmarshaled.Payload.AppVersion)
			}

			if !bytes.Equal(unmarshaled.Payload.Public, tt.blob.Payload.Public) {
				t.Errorf("Public data mismatch")
			}

			if !bytes.Equal(unmarshaled.Payload.Private, tt.blob.Payload.Private) {
				t.Errorf("Private data mismatch")
			}

			if len(unmarshaled.Payload.PCRDigests) != len(tt.blob.Payload.PCRDigests) {
				t.Errorf("PCRDigests length mismatch: expected %d, got %d",
					len(tt.blob.Payload.PCRDigests), len(unmarshaled.Payload.PCRDigests))
			}

			for i := range tt.blob.Payload.PCRDigests {
				if i >= len(unmarshaled.Payload.PCRDigests) {
					break
				}
				if unmarshaled.Payload.PCRDigests[i].Index != tt.blob.Payload.PCRDigests[i].Index {
					t.Errorf("PCR[%d] index mismatch: expected %d, got %d",
						i, tt.blob.Payload.PCRDigests[i].Index, unmarshaled.Payload.PCRDigests[i].Index)
				}
				if unmarshaled.Payload.PCRDigests[i].Source != tt.blob.Payload.PCRDigests[i].Source {
					t.Errorf("PCR[%d] source mismatch: expected %v, got %v",
						i, tt.blob.Payload.PCRDigests[i].Source, unmarshaled.Payload.PCRDigests[i].Source)
				}
				if !bytes.Equal(unmarshaled.Payload.PCRDigests[i].Digest.Buffer, tt.blob.Payload.PCRDigests[i].Digest.Buffer) {
					t.Errorf("PCR[%d] digest mismatch", i)
				}
			}

			if !bytes.Equal(unmarshaled.Payload.SignedBranchDigest, tt.blob.Payload.SignedBranchDigest) {
				t.Errorf("SignedBranchDigest mismatch: expected %d bytes, got %d bytes", len(tt.blob.Payload.SignedBranchDigest), len(unmarshaled.Payload.SignedBranchDigest))
			}

			// Check HasEventlogPCRs derived method
			expectedHasEventlog := tt.blob.HasEventlogPCRs()
			if unmarshaled.HasEventlogPCRs() != expectedHasEventlog {
				t.Errorf("HasEventlogPCRs mismatch: expected %v, got %v", expectedHasEventlog, unmarshaled.HasEventlogPCRs())
			}

			if tt.blob.Payload.EventlogInfo != nil {
				if unmarshaled.Payload.EventlogInfo == nil {
					t.Errorf("EventlogInfo should not be nil")
				} else {
					if unmarshaled.Payload.EventlogInfo.EventlogPath != tt.blob.Payload.EventlogInfo.EventlogPath {
						t.Errorf("EventlogPath mismatch")
					}
					if unmarshaled.Payload.EventlogInfo.CalculationTime != tt.blob.Payload.EventlogInfo.CalculationTime {
						t.Errorf("CalculationTime mismatch")
					}
					if unmarshaled.Payload.EventlogInfo.TotalEvents != tt.blob.Payload.EventlogInfo.TotalEvents {
						t.Errorf("TotalEvents mismatch")
					}
					if unmarshaled.Payload.EventlogInfo.ProcessedEvents != tt.blob.Payload.EventlogInfo.ProcessedEvents {
						t.Errorf("ProcessedEvents mismatch")
					}
				}
			} else {
				if unmarshaled.Payload.EventlogInfo != nil {
					t.Errorf("EventlogInfo should be nil")
				}
			}

			// Check key paths
			if unmarshaled.Payload.PublicKeyRef != tt.blob.Payload.PublicKeyRef {
				t.Errorf("PublicKeyRef mismatch: expected %+v, got %+v", tt.blob.Payload.PublicKeyRef, unmarshaled.Payload.PublicKeyRef)
			}
			if unmarshaled.Payload.PrivateKeyRef != tt.blob.Payload.PrivateKeyRef {
				t.Errorf("PrivateKeyRef mismatch: expected %+v, got %+v", tt.blob.Payload.PrivateKeyRef, unmarshaled.Payload.PrivateKeyRef)
			}

			// Check BlobSignature is populated
			if len(unmarshaled.BlobSignature) == 0 {
				t.Errorf("BlobSignature should not be empty after unmarshal of signed blob")
			}

			// Verify signature
			if err := VerifyBlobSignature(signedData, unmarshaled, &privKey.PublicKey); err != nil {
				t.Errorf("VerifyBlobSignature failed: %v", err)
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
			name: "Version 4 incompatible",
			data: func() []byte {
				d := make([]byte, 20)
				d[0] = 0x04 // version 4
				return d
			}(),
			errContains: "incompatible blob version",
		},
		{
			name: "Version 5 incompatible",
			data: func() []byte {
				d := make([]byte, 20)
				d[0] = 0x05 // version 5
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
			name: "Truncated payload length",
			data: func() []byte {
				d := make([]byte, 10)
				binary.LittleEndian.PutUint32(d[0:4], CurrentBlobVersion)
				binary.LittleEndian.PutUint32(d[4:8], 100) // payloadLen=100 but only 2 bytes left
				return d
			}(),
			errContains: "data too short",
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

// TestUnmarshalSealedBlob_OversizedFields tests that oversized field lengths are rejected
func TestUnmarshalSealedBlob_OversizedFields(t *testing.T) {
	privKey := testGenECDSAKey(t)

	// Helper: build a valid signed v6 blob with the given payload content
	makeSignedBlob := func(payloadBytes []byte) []byte {
		// [version:4][payloadLen:4][payload...][sigLen:2][sig...]
		header := make([]byte, 8)
		binary.LittleEndian.PutUint32(header[0:4], CurrentBlobVersion)
		binary.LittleEndian.PutUint32(header[4:8], uint32(len(payloadBytes)))
		unsigned := append(header, payloadBytes...)

		signed, _ := SignBlobPayload(unsigned, privKey)
		return signed
	}

	// Helper to build a minimal payload with controlled field lengths
	makePayload := func(appVersionLen, publicLen, privateLen, numPCRDigests uint32) []byte {
		buf := make([]byte, 0, 256)
		b4 := make([]byte, 4)

		// appVersionLen
		binary.LittleEndian.PutUint32(b4, appVersionLen)
		buf = append(buf, b4...)
		buf = append(buf, make([]byte, appVersionLen)...)

		// publicLen
		binary.LittleEndian.PutUint32(b4, publicLen)
		buf = append(buf, b4...)
		buf = append(buf, make([]byte, publicLen)...)

		// privateLen
		binary.LittleEndian.PutUint32(b4, privateLen)
		buf = append(buf, b4...)
		buf = append(buf, make([]byte, privateLen)...)

		// numPCRDigests
		binary.LittleEndian.PutUint32(b4, numPCRDigests)
		buf = append(buf, b4...)

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
				payload := make([]byte, 4)
				binary.LittleEndian.PutUint32(payload[0:4], MaxAppVersionLen+1) // too large
				return makeSignedBlob(payload)
			},
			expectErr: "exceeds maximum",
		},
		{
			name: "oversized public blob length",
			blobMaker: func() []byte {
				payload := makePayload(0, MaxPublicLen+1, 0, 0)
				return makeSignedBlob(payload)
			},
			expectErr: "exceeds maximum",
		},
		{
			name: "oversized private blob length",
			blobMaker: func() []byte {
				payload := makePayload(0, 0, MaxPrivateLen+1, 0)
				return makeSignedBlob(payload)
			},
			expectErr: "exceeds maximum",
		},
		{
			name: "oversized PCR digest count",
			blobMaker: func() []byte {
				payload := makePayload(0, 0, 0, MaxPCRDigests+1)
				return makeSignedBlob(payload)
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
				sb := &SealedBlob{
					Version: CurrentBlobVersion,
					Payload: SealedBlobPayload{
						AppVersion: "test",
						Public:     []byte{1, 2, 3},
						Private:    []byte{4, 5, 6},
						PCRDigests: []PCRDigestPair{
							{Index: 0, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
						},
					},
				}
				return testSignBlob(t, sb, privKey)
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
	if !strings.Contains(err.Error(), "v9") {
		t.Errorf("Expected error to mention requires v9, got: %v", err)
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
			name: "Unsupported older version still reports its version",
			data: func() []byte {
				d := make([]byte, 20)
				binary.LittleEndian.PutUint32(d[0:4], 2)
				return d
			}(),
			expectedVersion:    2,
			expectedAppVersion: "",
			expectedSize:       20,
		},
		{
			name: "Current version blob (appVersionLen at offset 8)",
			data: func() []byte {
				d := make([]byte, 30)
				binary.LittleEndian.PutUint32(d[0:4], CurrentBlobVersion)
				binary.LittleEndian.PutUint32(d[4:8], 20) // payloadLen (doesn't matter for peek)
				binary.LittleEndian.PutUint32(d[8:12], 5) // appVersionLen = 5
				copy(d[12:], "3.0.0")
				return d
			}(),
			expectedVersion:    CurrentBlobVersion,
			expectedAppVersion: "3.0.0",
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
		Payload: SealedBlobPayload{
			PCRDigests: []PCRDigestPair{
				{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: []byte("d0")}},
				{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte("d2")}},
				{Index: 4, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte("d4")}},
				{Index: 7, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: []byte("d7")}},
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

	blob := &SealedBlob{
		Payload: SealedBlobPayload{
			PCRDigests: []PCRDigestPair{
				{Index: 0, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: digest0}},
				{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: digest2}},
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
		blob     *SealedBlob
		expected bool
	}{
		{
			name: "All register",
			blob: &SealedBlob{
				Payload: SealedBlobPayload{
					PCRDigests: []PCRDigestPair{
						{Index: 0, Source: PCRSourceRegister},
						{Index: 2, Source: PCRSourceRegister},
					},
				},
			},
			expected: false,
		},
		{
			name: "All eventlog",
			blob: &SealedBlob{
				Payload: SealedBlobPayload{
					PCRDigests: []PCRDigestPair{
						{Index: 0, Source: PCRSourceEventlog},
						{Index: 2, Source: PCRSourceEventlog},
					},
				},
			},
			expected: true,
		},
		{
			name: "Mixed",
			blob: &SealedBlob{
				Payload: SealedBlobPayload{
					PCRDigests: []PCRDigestPair{
						{Index: 0, Source: PCRSourceEventlog},
						{Index: 2, Source: PCRSourceRegister},
					},
				},
			},
			expected: true,
		},
		{
			name: "UKI only does not count as eventlog",
			blob: &SealedBlob{
				Payload: SealedBlobPayload{
					PCRDigests: []PCRDigestPair{
						{Index: 11, Source: PCRSourceUKI, Command: "/boot/uki.efi"},
					},
				},
			},
			expected: false,
		},
		{
			name: "Empty",
			blob: &SealedBlob{
				Payload: SealedBlobPayload{
					PCRDigests: []PCRDigestPair{},
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
		blob     *SealedBlob
		expected bool
	}{
		{
			name: "All register",
			blob: &SealedBlob{
				Payload: SealedBlobPayload{
					PCRDigests: []PCRDigestPair{
						{Index: 0, Source: PCRSourceRegister},
						{Index: 2, Source: PCRSourceRegister},
					},
				},
			},
			expected: false,
		},
		{
			name: "All eventlog",
			blob: &SealedBlob{
				Payload: SealedBlobPayload{
					PCRDigests: []PCRDigestPair{
						{Index: 0, Source: PCRSourceEventlog},
						{Index: 2, Source: PCRSourceEventlog},
					},
				},
			},
			expected: false,
		},
		{
			name: "Has UKI",
			blob: &SealedBlob{
				Payload: SealedBlobPayload{
					PCRDigests: []PCRDigestPair{
						{Index: 0, Source: PCRSourceEventlog},
						{Index: 11, Source: PCRSourceUKI, Command: "/boot/uki.efi"},
					},
				},
			},
			expected: true,
		},
		{
			name: "UKI only",
			blob: &SealedBlob{
				Payload: SealedBlobPayload{
					PCRDigests: []PCRDigestPair{
						{Index: 11, Source: PCRSourceUKI, Command: "/boot/uki.efi"},
					},
				},
			},
			expected: true,
		},
		{
			name: "Empty",
			blob: &SealedBlob{
				Payload: SealedBlobPayload{
					PCRDigests: []PCRDigestPair{},
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
	blob := &SealedBlob{
		Payload: SealedBlobPayload{
			PCRDigests: []PCRDigestPair{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceRegister},
				{Index: 4, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceEventlog},
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
	blob := &SealedBlob{
		Payload: SealedBlobPayload{
			PCRDigests: []PCRDigestPair{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceEventlog},
				{Index: 11, Source: PCRSourceUKI, Command: "/boot/uki.efi"},
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
	blob := &SealedBlob{
		Payload: SealedBlobPayload{
			PCRDigests: []PCRDigestPair{
				{Index: 0, Source: PCRSourceEventlog},
				{Index: 2, Source: PCRSourceRegister},
				{Index: 7, Source: PCRSourceEventlog},
				{Index: 11, Source: PCRSourceUKI, Command: "/boot/uki.efi"},
			},
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
		{Index: 11, Source: PCRSourceUKI, Command: "/boot/uki.efi"},
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

// TestSealedBlobMarshalJSON tests JSON serialization
func TestSealedBlobMarshalJSON(t *testing.T) {
	blob := &SealedBlob{
		Version: 6,
		Payload: SealedBlobPayload{
			AppVersion: "test-1.0.0",
			Public:     []byte{0x01, 0x02, 0x03},
			Private:    []byte{0x04, 0x05, 0x06},
			PCRDigests: []PCRDigestPair{
				{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: []byte{0xAA, 0xBB}}},
				{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: []byte{0xCC, 0xDD}}},
			},
			SignedBranchDigest: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		},
		BlobSignature: []byte{0xDE, 0xAD},
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
		`"signed_branch_digest_hex"`,
		`"signed_branch_digest_size"`,
		`"source"`,
		`"blob_signature_hex"`,
		`"blob_signature_size"`,
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

	// Ensure old/removed fields are NOT present
	unexpectedFields := []string{
		`"password_hash_hex"`,
		`"password_salt_hex"`,
		`"has_password"`,
		`"signing_key_pem_size"`,
		`"signing_key_type"`,
		`"signing_key_fingerprint"`,
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

	// Verify blob signature hex appears
	if !bytes.Contains(jsonData, []byte("dead")) {
		t.Error("Blob signature not hex encoded correctly")
	}
}

// TestSealedBlobMarshalJSONWithEventlogInfo tests JSON serialization with eventlog info
func TestSealedBlobMarshalJSONWithEventlogInfo(t *testing.T) {
	blob := &SealedBlob{
		Version: 6,
		Payload: SealedBlobPayload{
			AppVersion: "test-1.0.0",
			Public:     []byte{0x01},
			Private:    []byte{0x02},
			PCRDigests: []PCRDigestPair{
				{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: []byte{0xAA}}},
			},
			SignedBranchDigest: make([]byte, 32),
			EventlogInfo: &EventlogInfo{
				EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
				CalculationTime: "2024-01-01T00:00:00Z",
				TotalEvents:     100,
				ProcessedEvents: 50,
			},
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
				Version: 6,
				Payload: SealedBlobPayload{
					AppVersion: "test",
					PCRDigests: []PCRDigestPair{
						{Index: 0, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
						{Index: 7, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					},
				},
			},
			expected: PCRHashAlgoSHA256,
		},
		{
			name: "SHA1 digests (20 bytes)",
			blob: &SealedBlob{
				Version: 6,
				Payload: SealedBlobPayload{
					AppVersion: "test",
					PCRDigests: []PCRDigestPair{
						{Index: 0, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 20)}},
						{Index: 7, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 20)}},
					},
				},
			},
			expected: PCRHashAlgoSHA1,
		},
		{
			name: "Empty digests defaults to SHA256",
			blob: &SealedBlob{
				Version: 6,
				Payload: SealedBlobPayload{
					AppVersion: "test",
					PCRDigests: []PCRDigestPair{},
				},
			},
			expected: PCRHashAlgoSHA256,
		},
		{
			name: "No PCR digests defaults to SHA256",
			blob: &SealedBlob{
				Version: 6,
				Payload: SealedBlobPayload{
					AppVersion: "test",
				},
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

// TestSealedBlobRoundTrip tests a complete round trip with realistic data
func TestSealedBlobRoundTrip(t *testing.T) {
	privKey := testGenECDSAKey(t)

	// Create a blob with realistic TPM data sizes and mixed sources
	original := &SealedBlob{
		Version: 6,
		Payload: SealedBlobPayload{
			AppVersion: "v1.2.3",
			Public:     make([]byte, 100), // Typical public key size
			Private:    make([]byte, 150), // Typical private key size
			PCRDigests: []PCRDigestPair{
				{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
				{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
				{Index: 4, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
				{Index: 7, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			},
			SignedBranchDigest: make([]byte, 32),
			EventlogInfo: &EventlogInfo{
				EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
				CalculationTime: "2024-06-15T10:30:00Z",
				TotalEvents:     150,
				ProcessedEvents: 75,
			},
		},
	}

	// Fill with test data
	for i := range original.Payload.Public {
		original.Payload.Public[i] = byte(i % 256)
	}
	for i := range original.Payload.Private {
		original.Payload.Private[i] = byte((i * 2) % 256)
	}
	for _, pcr := range original.Payload.PCRDigests {
		for i := range pcr.Digest.Buffer {
			pcr.Digest.Buffer[i] = byte(i * 3 % 256)
		}
	}

	// Marshal → Sign
	signedData := testSignBlob(t, original, privKey)

	t.Logf("Signed blob size: %d bytes", len(signedData))

	// Unmarshal
	restored, err := UnmarshalSealedBlob(signedData)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify all fields match
	if restored.Version != CurrentBlobVersion {
		t.Errorf("Version should be %d, got %d", CurrentBlobVersion, restored.Version)
	}
	if restored.Payload.AppVersion != original.Payload.AppVersion {
		t.Error("AppVersion mismatch")
	}
	if !bytes.Equal(restored.Payload.Public, original.Payload.Public) {
		t.Error("Public data mismatch")
	}
	if !bytes.Equal(restored.Payload.Private, original.Payload.Private) {
		t.Error("Private data mismatch")
	}
	if !bytes.Equal(restored.Payload.SignedBranchDigest, original.Payload.SignedBranchDigest) {
		t.Error("SignedBranchDigest mismatch")
	}
	// Verify per-PCR sources
	for i := range original.Payload.PCRDigests {
		if restored.Payload.PCRDigests[i].Source != original.Payload.PCRDigests[i].Source {
			t.Errorf("PCR[%d] source mismatch: expected %v, got %v",
				i, original.Payload.PCRDigests[i].Source, restored.Payload.PCRDigests[i].Source)
		}
	}
	// Verify HasEventlogPCRs
	if restored.HasEventlogPCRs() != original.HasEventlogPCRs() {
		t.Error("HasEventlogPCRs mismatch")
	}
	// Verify eventlog info
	if restored.Payload.EventlogInfo == nil {
		t.Fatal("EventlogInfo should not be nil")
	}
	if restored.Payload.EventlogInfo.EventlogPath != original.Payload.EventlogInfo.EventlogPath {
		t.Error("EventlogPath mismatch")
	}
	if restored.Payload.EventlogInfo.TotalEvents != original.Payload.EventlogInfo.TotalEvents {
		t.Error("TotalEvents mismatch")
	}

	// Verify signature
	if len(restored.BlobSignature) == 0 {
		t.Error("BlobSignature should not be empty")
	}
	if err := VerifyBlobSignature(signedData, restored, &privKey.PublicKey); err != nil {
		t.Errorf("VerifyBlobSignature failed: %v", err)
	}
}

// TestSealedBlobRoundTripNoEventlog tests round trip with all-register PCRs (no eventlog info)
func TestSealedBlobRoundTripNoEventlog(t *testing.T) {
	privKey := testGenECDSAKey(t)

	original := &SealedBlob{
		Version: 6,
		Payload: SealedBlobPayload{
			AppVersion: "v1.0.0",
			Public:     []byte("pub-data"),
			Private:    []byte("priv-data"),
			PCRDigests: []PCRDigestPair{
				{Index: 0, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
				{Index: 2, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
				{Index: 7, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			},
		},
	}

	signedData := testSignBlob(t, original, privKey)

	restored, err := UnmarshalSealedBlob(signedData)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if restored.HasEventlogPCRs() {
		t.Error("Should not have eventlog PCRs")
	}
	if restored.Payload.EventlogInfo != nil {
		t.Error("EventlogInfo should be nil for all-register blob")
	}
	for i, pair := range restored.Payload.PCRDigests {
		if pair.Source != PCRSourceRegister {
			t.Errorf("PCR[%d] should be register source, got %v", i, pair.Source)
		}
	}
}
func TestCurrentBlobVersion(t *testing.T) {
	if CurrentBlobVersion != 9 {
		t.Errorf("CurrentBlobVersion should be 9, got %d", CurrentBlobVersion)
	}
}
func TestMarshalPayloadUnmarshalPayloadRoundTrip(t *testing.T) {
	original := &SealedBlobPayload{
		AppVersion: "payload-test-v1",
		Public:     []byte("test-public-key-blob"),
		Private:    []byte("test-private-key-blob"),
		PCRDigests: []PCRDigestPair{
			{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			{Index: 7, Source: PCRSourceRegister, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			{Index: 11, Source: PCRSourceUKI, Command: "/boot/uki.efi", Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
		},
		SignedBranchDigest: make([]byte, 32),
		EventlogInfo: &EventlogInfo{
			EventlogPath:    "/sys/kernel/security/tpm0/binary_bios_measurements",
			CalculationTime: "2024-01-01T00:00:00Z",
			TotalEvents:     100,
			ProcessedEvents: 50,
		},
		PublicKeyRef:   KeyRef{Kind: KeyRefFile, Path: "/var/lib/tpm2-kira/keys/seal.pub"},
		PrivateKeyRef:  KeyRef{Kind: KeyRefYubiKey, Serial: 12345678, Slot: 0x9A},
		KeyFingerprint: bytes.Repeat([]byte{0xAB}, 32),
		TokenSerial:    12345678,
	}

	data, err := original.MarshalPayload()
	if err != nil {
		t.Fatalf("MarshalPayload failed: %v", err)
	}

	restored, err := UnmarshalPayload(data)
	if err != nil {
		t.Fatalf("UnmarshalPayload failed: %v", err)
	}

	if restored.AppVersion != original.AppVersion {
		t.Errorf("AppVersion mismatch: %q vs %q", restored.AppVersion, original.AppVersion)
	}
	if !bytes.Equal(restored.Public, original.Public) {
		t.Error("Public mismatch")
	}
	if !bytes.Equal(restored.Private, original.Private) {
		t.Error("Private mismatch")
	}
	if len(restored.PCRDigests) != len(original.PCRDigests) {
		t.Fatalf("PCRDigests count: %d vs %d", len(restored.PCRDigests), len(original.PCRDigests))
	}
	for i := range original.PCRDigests {
		if restored.PCRDigests[i].Index != original.PCRDigests[i].Index {
			t.Errorf("PCR[%d] index mismatch", i)
		}
		if restored.PCRDigests[i].Source != original.PCRDigests[i].Source {
			t.Errorf("PCR[%d] source mismatch", i)
		}
		if restored.PCRDigests[i].Command != original.PCRDigests[i].Command {
			t.Errorf("PCR[%d] command mismatch: %q vs %q", i, restored.PCRDigests[i].Command, original.PCRDigests[i].Command)
		}
	}
	if !bytes.Equal(restored.SignedBranchDigest, original.SignedBranchDigest) {
		t.Error("SignedBranchDigest mismatch")
	}
	if restored.EventlogInfo == nil {
		t.Fatal("EventlogInfo is nil")
	}
	if restored.EventlogInfo.EventlogPath != original.EventlogInfo.EventlogPath {
		t.Error("EventlogPath mismatch")
	}
	if restored.PublicKeyRef != original.PublicKeyRef {
		t.Errorf("PublicKeyRef: %+v vs %+v", restored.PublicKeyRef, original.PublicKeyRef)
	}
	if restored.PrivateKeyRef != original.PrivateKeyRef {
		t.Errorf("PrivateKeyRef: %+v vs %+v", restored.PrivateKeyRef, original.PrivateKeyRef)
	}
	if !bytes.Equal(restored.KeyFingerprint, original.KeyFingerprint) {
		t.Errorf("KeyFingerprint: %x vs %x", restored.KeyFingerprint, original.KeyFingerprint)
	}
	if restored.TokenSerial != original.TokenSerial {
		t.Errorf("TokenSerial: %d vs %d", restored.TokenSerial, original.TokenSerial)
	}
}
