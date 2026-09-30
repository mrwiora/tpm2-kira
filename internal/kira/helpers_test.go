//go:build unit || !integration
// +build unit !integration

package kira

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

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
func testSignBlob(t *testing.T, blob *SealedBlob, privKey crypto.Signer) []byte {
	t.Helper()
	unsigned, err := blob.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	signed, err := SignBlobPayload(unsigned, privKey)
	if err != nil {
		t.Fatalf("SignBlobPayload failed: %v", err)
	}
	return signed
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
