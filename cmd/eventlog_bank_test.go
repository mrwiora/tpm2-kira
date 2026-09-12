package cmd

import (
	"strings"
	"testing"
)

func TestRegisterFallbackSpecs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		missing []int
		want    string
	}{
		{
			name:    "all eventlog PCRs fall back",
			input:   "0e,7e",
			missing: []int{0, 7},
			want:    "0,7",
		},
		{
			name:    "only the reported PCRs change",
			input:   "0e,2e,7e",
			missing: []int{0, 7},
			want:    "0,2e,7",
		},
		{
			name:    "other sources are left alone",
			input:   "0e,2,7e,11u:/boot/uki.efi",
			missing: []int{0, 7},
			want:    "0,2,7,11u:/boot/uki.efi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specs, err := ParsePCRSpecs(tt.input)
			if err != nil {
				t.Fatalf("ParsePCRSpecs(%q): %v", tt.input, err)
			}
			got := PCRSpecsToString(registerFallbackSpecs(specs, tt.missing))
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEventlogBankErrorMessage(t *testing.T) {
	err := &EventlogBankError{
		PCRIndices:   []int{0, 7},
		Requested:    PCRHashAlgoSHA256,
		Present:      []string{"SHA-1"},
		EventlogPath: DefaultEventlogPath,
	}
	if !err.HasSHA1() {
		t.Error("HasSHA1() = false, want true when SHA-1 digests are present")
	}
	msg := err.Error()
	for _, want := range []string{"PCR 0, 7", "SHA-256", "SHA-1"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not mention %q", msg, want)
		}
	}

	noFallback := &EventlogBankError{PCRIndices: []int{0}, Requested: PCRHashAlgoSHA1}
	if noFallback.HasSHA1() {
		t.Error("HasSHA1() = true, want false when no SHA-1 digests are present")
	}
}
