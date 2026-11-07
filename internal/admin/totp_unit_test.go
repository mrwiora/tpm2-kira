//go:build unit || !integration
// +build unit !integration

package admin

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
	"testing"

	"github.com/tpm2-trust/tpm2-kira/internal/totp"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"

	"github.com/google/go-tpm/tpm2"
)

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
			name:         "Basic URI",
			secret:       "JBSWY3DPEHPK3PXP",
			label:        "test@example.com",
			issuer:       "TestIssuer",
			wantContains: []string{"otpauth://totp/", "secret=JBSWY3DPEHPK3PXP"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri := totp.URI(tt.secret, tt.label, tt.issuer, tpm2.TPMAlgSHA1)
			for _, want := range tt.wantContains {
				if !strings.Contains(uri, want) {
					t.Errorf("URI %q does not contain %q", uri, want)
				}
			}
			if strings.Contains(uri, "algorithm=") {
				t.Errorf("SHA-1 URI %q should leave the algorithm at its default", uri)
			}
			if uri := totp.URI(tt.secret, tt.label, tt.issuer, tpm2.TPMAlgSHA256); !strings.HasSuffix(uri, "&algorithm=SHA256") {
				t.Errorf("SHA-256 URI %q lacks algorithm=SHA256", uri)
			}
		})
	}
}

// TestGenerateHOTP tests HOTP code generation with RFC 4226 test vectors
func TestGenerateHOTP(t *testing.T) {
	// RFC 4226 test secret: "12345678901234567890" (raw bytes)
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
	}

	for _, tt := range tests {
		code := generateHOTP(key, tt.counter, sha1.New)
		if code != tt.expected {
			t.Errorf("generateHOTP(counter=%d) = %s, want %s", tt.counter, code, tt.expected)
		}
	}
}

// TestGenerateHOTPSHA256 checks the SHA-256 variant used on TPMs without
// SHA-1 against the RFC 6238 test vector (key "12345678901234567890123456789012",
// T = 59 s).
func TestGenerateHOTPSHA256(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	if code := generateHOTP(key, 59/30, sha256.New); code != "119246" {
		t.Errorf("generateHOTP(SHA-256, T=59) = %s, want 119246", code)
	}
}

// TestFormatKIRAError tests KIRA error formatting
func TestFormatKIRAError(t *testing.T) {
	// Test with a basic error
	err := fmt.Errorf("test error message")
	output := totp.FormatKIRAError(err)
	if output == "" {
		t.Error("Expected non-empty output")
	}
	if !strings.Contains(output, "test error message") {
		t.Error("Expected error message in output")
	}
}

func TestIsTPMPolicyFailure(t *testing.T) {
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
			name:     "policy failure",
			err:      &testError{msg: "TPM_RC_POLICY_FAIL"},
			expected: true,
		},
		{
			name:     "policy cc",
			err:      &testError{msg: "TPM_RC_POLICY_CC"},
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      &testError{msg: "some other error"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tpmdev.IsTPMPolicyFailure(tt.err)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGenerateTOTPCodesForSlots(t *testing.T) {
	slots := []totp.NVRAMSlot{
		{SlotNumber: 1, Code: "111111"},
		{SlotNumber: 2, Error: fmt.Errorf("error")},
		{SlotNumber: 3, Code: "333333"},
	}

	codes, err := totp.CodesForSlots(slots)
	if err != nil {
		t.Fatalf("GenerateTOTPCodesForSlots failed: %v", err)
	}

	if len(codes) != 2 {
		t.Fatalf("Expected 2 codes, got %d", len(codes))
	}

	if _, exists := codes[1]; !exists {
		t.Error("Expected code for slot 1")
	}
	if _, exists := codes[3]; !exists {
		t.Error("Expected code for slot 3")
	}
}

func TestTOTPKeySize(t *testing.T) {
	if n := totp.KeySize(tpm2.TPMAlgSHA1); n != 20 {
		t.Errorf("SHA-1 key size = %d, want 20", n)
	}
	if n := totp.KeySize(tpm2.TPMAlgSHA256); n != 32 {
		t.Errorf("SHA-256 key size = %d, want 32", n)
	}
}

// generateHOTP computes an HOTP code in software. tpm2-kira computes codes in
// the TPM; this is the reference the tests compare against.
func generateHOTP(key []byte, counter int64, newHash func() hash.Hash) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))
	mac := hmac.New(newHash, key)
	mac.Write(buf)
	return totp.HOTPTruncate(mac.Sum(nil))
}
