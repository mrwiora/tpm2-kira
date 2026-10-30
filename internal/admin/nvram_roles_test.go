package admin

import (
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/nvslot"
)

func TestKiraIndexRole(t *testing.T) {
	for idx, want := range map[uint32]string{
		nvslot.NVRAMSlotStart:                                "a blob of slot #0 of an earlier version",
		nvslot.NVRAMSlotEnd:                                  "a blob of slot #15 of an earlier version",
		nvslot.GenerationIndex(nvslot.NVRAMSlotStart + 2):    "generation index of slot #2",
		nvslot.AttestCounterIndex(nvslot.NVRAMSlotStart + 3): "record counter of slot #3",
		nvslot.BootSettingsIndex:                             "the boot settings",
	} {
		if got := kiraIndexRole(idx); !strings.Contains(got, want) {
			t.Errorf("0x%08X: %q, want %q", idx, got, want)
		}
	}
	for _, idx := range []uint32{0x01C00002, nvslot.AppNVRAMStart + 1, nvslot.NVRAMSlotStart - 1, 0x01803020, 0x0180302F, 0x01803830} {
		if got := kiraIndexRole(idx); got != "" {
			t.Errorf("0x%08X is not tpm2-kira's, but: %q", idx, got)
		}
	}
}
