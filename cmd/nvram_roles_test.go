package cmd

import (
	"strings"
	"testing"
)

func TestKiraIndexRole(t *testing.T) {
	for idx, want := range map[uint32]string{
		NVRAMSlotStart:                           "TOTP key of slot #0",
		NVRAMSlotEnd:                             "TOTP key of slot #15",
		AttestNVRAMStart + 3:                     "phone enrolment",
		GenerationIndex(NVRAMSlotStart + 2):      "generation index of slot #2",
		AttestCounterIndex(AttestNVRAMStart + 3): "record counter of slot #3",
	} {
		if got := kiraIndexRole(idx); !strings.Contains(got, want) {
			t.Errorf("0x%08X: %q, want %q", idx, got, want)
		}
	}
	for _, idx := range []uint32{0x01C00002, AppNVRAMStart, NVRAMSlotStart - 1, AttestNVRAMEnd + 1, 0x01803830} {
		if got := kiraIndexRole(idx); got != "" {
			t.Errorf("0x%08X is not tpm2-kira's, but: %q", idx, got)
		}
	}
}
