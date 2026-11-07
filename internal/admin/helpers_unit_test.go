//go:build unit || !integration
// +build unit !integration

package admin

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/tpm2-trust/tpm2-kira/internal/measure"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"

	"github.com/google/go-attestation/attest"
)

// ── helpers for signing blobs in tests ──────────────────────────────────

// testGenECDSAKey generates an ECDSA P-256 key pair for test use.
func testGenECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	return key
}

// testGenRSAKey generates an RSA-2048 key pair for test use.
func testGenRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

// testSignBlob marshals, signs, and returns the signed blob bytes.
func testSignBlob(t *testing.T, blob *nvslot.SealedBlob, privKey crypto.Signer) []byte {
	t.Helper()
	unsigned, err := blob.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	signed, err := nvslot.SignBlobPayload(unsigned, privKey)
	if err != nil {
		t.Fatalf("SignBlobPayload failed: %v", err)
	}
	return signed
}

func TestAttestHash(t *testing.T) {
	tests := []struct {
		name     string
		algo     measure.PCRHashAlgo
		expected attest.HashAlg
	}{
		{
			name:     "SHA256",
			algo:     measure.PCRHashAlgoSHA256,
			expected: attest.HashSHA256,
		},
		{
			name:     "SHA1",
			algo:     measure.PCRHashAlgoSHA1,
			expected: attest.HashSHA1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := measure.AttestHash(tt.algo)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestMin(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{3, 3, 3},
		{0, 5, 0},
		{-1, 0, -1},
	}

	for _, tt := range tests {
		result := min(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, result, tt.expected)
		}
	}
}

// ── Blob Signature Tests ────────────────────────────────────────────────

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
