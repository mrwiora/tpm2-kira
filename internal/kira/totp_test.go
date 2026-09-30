//go:build unit || !integration
// +build unit !integration

package kira

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"strings"
	"testing"
)

// TestIsTOTPSecret tests TOTP secret detection
func TestIsTOTPSecret(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Valid Base32",
			input:    "JBSWY3DPEHPK3PXP",
			expected: true,
		},
		{
			name:     "Valid long Base32",
			input:    "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
			expected: true,
		},
		{
			name:     "Short string",
			input:    "AB",
			expected: false,
		},
		{
			name:     "Empty",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTOTPSecret(tt.input)
			if result != tt.expected {
				t.Errorf("isTOTPSecret(%q) = %v, want %v", tt.input, result, tt.expected)
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
			name:         "Basic URI",
			secret:       "JBSWY3DPEHPK3PXP",
			label:        "test@example.com",
			issuer:       "TestIssuer",
			wantContains: []string{"otpauth://totp/", "secret=JBSWY3DPEHPK3PXP"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri := generateTOTPURI(tt.secret, tt.label, tt.issuer)
			for _, want := range tt.wantContains {
				if !strings.Contains(uri, want) {
					t.Errorf("URI %q does not contain %q", uri, want)
				}
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
		code := generateHOTP(key, tt.counter)
		if code != tt.expected {
			t.Errorf("generateHOTP(counter=%d) = %s, want %s", tt.counter, code, tt.expected)
		}
	}
}

// TestGenerateTOTPCode tests that TOTP code generation works
func TestGenerateTOTPCode(t *testing.T) {
	// Use a known good Base32 secret
	secret := "JBSWY3DPEHPK3PXP"

	code, remaining, err := generateTOTPCode(secret)
	if err != nil {
		t.Fatalf("generateTOTPCode failed: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected 6-digit code, got %d digits: %s", len(code), code)
	}

	if remaining < 0 || remaining > 30 {
		t.Errorf("Expected remaining 0-30, got %d", remaining)
	}
}

// TestFormatKIRAOutput tests KIRA output formatting
func TestFormatKIRAOutput(t *testing.T) {
	// Just ensure it doesn't panic
	output := FormatKIRAOutput("test message")
	if output == "" {
		t.Error("Expected non-empty output")
	}
}

// TestFormatKIRAError tests KIRA error formatting
func TestFormatKIRAError(t *testing.T) {
	// Test with a basic error
	err := fmt.Errorf("test error message")
	output := FormatKIRAError(err)
	if output == "" {
		t.Error("Expected non-empty output")
	}
	if !strings.Contains(output, "test error message") {
		t.Error("Expected error message in output")
	}
}
func TestGenerateTOTPCodesForSlots(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	slots := []NVRAMSlot{
		{SlotNumber: 1, Secret: secret},
		{SlotNumber: 2, Error: fmt.Errorf("error")},
		{SlotNumber: 3, Secret: secret},
	}

	codes, err := GenerateTOTPCodesForSlots(slots)
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
func TestGenerateTOTPSecret(t *testing.T) {
	// Test that generateTOTPSecret returns valid Base32 encoded data
	secret1, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret failed: %v", err)
	}
	if len(secret1) == 0 {
		t.Error("Expected non-empty secret")
	}

	// Verify it's valid Base32
	_, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(secret1))
	if err != nil {
		t.Errorf("Secret is not valid Base32: %v", err)
	}

	// Test uniqueness
	secret2, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret failed: %v", err)
	}
	if bytes.Equal(secret1, secret2) {
		t.Error("Two generated secrets should not be identical")
	}

	// Test that generated secrets are at least 32 chars (256 bits encoded)
	if len(secret1) < 32 {
		t.Errorf("Secret too short: %d chars", len(secret1))
	}

	// Test that generated secrets can be used for TOTP
	code, remaining, err := generateTOTPCode(string(secret1))
	if err != nil {
		t.Fatalf("generateTOTPCode failed with generated secret: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("Expected 6-digit code, got %d digits", len(code))
	}
	if remaining < 0 || remaining > 30 {
		t.Errorf("Unexpected remaining time: %d", remaining)
	}

	// Test isTOTPSecret with generated secret
	if !isTOTPSecret(string(secret1)) {
		t.Error("Generated secret should be detected as TOTP secret")
	}

	// Test that the encoded output is the right length
	// 32 random bytes → 52 Base32 chars (without padding)
	if len(secret1) != 52 {
		t.Errorf("Expected 52-char Base32 string, got %d chars", len(secret1))
	}
}
