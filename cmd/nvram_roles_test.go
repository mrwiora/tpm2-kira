package cmd

import (
	"strings"
	"testing"
)

func TestKiraIndexRole(t *testing.T) {
	for idx, want := range map[uint32]string{
		NVRAMSlotStart:                         "slot #0: its TOTP key",
		NVRAMSlotEnd:                           "slot #15: its TOTP key",
		GenerationIndex(NVRAMSlotStart + 2):    "generation index of slot #2",
		AttestCounterIndex(NVRAMSlotStart + 3): "record counter of slot #3",
		BootSettingsIndex:                      "the boot settings",
	} {
		if got := kiraIndexRole(idx); !strings.Contains(got, want) {
			t.Errorf("0x%08X: %q, want %q", idx, got, want)
		}
	}
	for _, idx := range []uint32{0x01C00002, AppNVRAMStart + 1, NVRAMSlotStart - 1, 0x01803020, 0x0180302F, 0x01803830} {
		if got := kiraIndexRole(idx); got != "" {
			t.Errorf("0x%08X is not tpm2-kira's, but: %q", idx, got)
		}
	}
}
