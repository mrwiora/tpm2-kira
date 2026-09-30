//go:build unit || !integration
// +build unit !integration

package kira

import (
	"strings"
	"testing"
)

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
func TestPCRMismatchErrorError(t *testing.T) {
	err := &PCRMismatchError{
		Message: "test mismatch",
	}
	if !strings.Contains(err.Error(), "test mismatch") {
		t.Errorf("Expected error to contain message, got: %s", err.Error())
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
			result := IsTPMPolicyFailure(tt.err)
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
