//go:build unit || !integration
// +build unit !integration

package kira

import (
	"fmt"
	"testing"
)

// TestValidateNVRAMIndex tests NVRAM index validation
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
func TestHandleNVRAMNotFoundError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		debug        bool
		expectNil    bool
		wantContains string
	}{
		{
			name:      "nil error returns nil",
			err:       nil,
			debug:     false,
			expectNil: true,
		},
		{
			name:         "non-nil error returns non-nil",
			err:          &testError{msg: "NVRAM index not found"},
			debug:        false,
			expectNil:    false,
			wantContains: "NVRAM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HandleNVRAMNotFoundError(tt.err, tt.debug)
			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil, got %v", result)
				}
			} else {
				if result == nil {
					t.Error("Expected non-nil error")
				}
			}
		})
	}
}
func TestHasValidSlots(t *testing.T) {
	tests := []struct {
		name     string
		slots    []NVRAMSlot
		expected bool
	}{
		{
			name:     "Empty slots",
			slots:    []NVRAMSlot{},
			expected: false,
		},
		{
			name: "All errors",
			slots: []NVRAMSlot{
				{Error: fmt.Errorf("error")},
			},
			expected: false,
		},
		{
			name: "One valid slot",
			slots: []NVRAMSlot{
				{Secret: "JBSWY3DPEHPK3PXP"},
			},
			expected: true,
		},
		{
			name: "Mixed",
			slots: []NVRAMSlot{
				{Error: fmt.Errorf("error")},
				{Secret: "JBSWY3DPEHPK3PXP"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasValidSlots(tt.slots)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
func TestResolveNVRAMIndex(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected uint32
	}{
		{
			name:     "Zero returns default",
			input:    0,
			expected: NVRAMSlotStart,
		},
		{
			name:     "Small number maps to slot",
			input:    1,
			expected: NVRAMSlotStart + 1,
		},
		{
			name:     "Full index passed through",
			input:    0x01803015,
			expected: 0x01803015,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ResolveNVRAMIndex(tt.input)
			if result != tt.expected {
				t.Errorf("ResolveNVRAMIndex(%d) = 0x%08X, want 0x%08X", tt.input, result, tt.expected)
			}
		})
	}
}
func TestSlotNumber(t *testing.T) {
	tests := []struct {
		name     string
		index    uint32
		expected int
	}{
		{
			name:     "First slot",
			index:    NVRAMSlotStart,
			expected: 0,
		},
		{
			name:     "Second slot",
			index:    NVRAMSlotStart + 1,
			expected: 1,
		},
		{
			name:     "Last slot",
			index:    NVRAMSlotEnd,
			expected: int(NVRAMSlotEnd - NVRAMSlotStart),
		},
		{
			name:     "Outside the shorthand range has no slot number",
			index:    NVRAMSlotEnd + 1,
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SlotNumber(tt.index)
			if result != tt.expected {
				t.Errorf("SlotNumber(0x%08X) = %d, want %d", tt.index, result, tt.expected)
			}
		})
	}
}
func TestMaxSlotNumber(t *testing.T) {
	if MaxSlotNumber != 15 {
		t.Errorf("MaxSlotNumber = %d, want 15", MaxSlotNumber)
	}
}
