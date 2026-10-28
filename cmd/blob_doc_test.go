package cmd

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/attest"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
)

// The format reference in docs/SECURITY-BACKGROUND.md §10 states numbers
// that are constants here. A change to one without the other fails this.
func TestBlobFormatReferenceMatchesTheCode(t *testing.T) {
	data, err := os.ReadFile("../docs/SECURITY-BACKGROUND.md")
	if err != nil {
		t.Skipf("no documentation next to the sources: %v", err)
	}
	doc := string(data)
	for what, want := range map[string]string{
		"the blob version (title)":   fmt.Sprintf("## 10. Blob Format (Version %d)", nvslot.CurrentBlobVersion),
		"the blob version (field)":   fmt.Sprintf("Version                 uint32      Must be %d", nvslot.CurrentBlobVersion),
		"the attestation size limit": fmt.Sprintf("Attestation length    uint32      ≤ %d", nvslot.MaxAttestationLen),
		"the phone method's number":  fmt.Sprintf("Method type         uint8       %d = phones over Bluetooth LE", nvslot.AttestMethodPhone),
		"the vault method's number":  fmt.Sprintf("%d = tpm2-kira-vault over HTTPS", nvslot.AttestMethodVault),
		"the number of phones":       fmt.Sprintf("Phone count         uint8       ≤ %d", nvslot.MaxVerifiers),
		"the PCR selection limit":    fmt.Sprintf("PCRSelection length   uint16      ≤ %d", attest.MaxPCRIndex),
		"the device id size":         fmt.Sprintf("DeviceID              [%d]byte", attest.DeviceIDSize),
		"the slot's blob index":      fmt.Sprintf("`0x%08X`", nvslot.NVRAMSlotStart),
		"the generation index":       fmt.Sprintf("`0x%08X` for slot", nvslot.GenerationIndex(nvslot.NVRAMSlotStart)),
		"the record counter index":   fmt.Sprintf("`0x%08X` + *n*: an", nvslot.AttestCounterIndex(nvslot.NVRAMSlotStart)),
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the documentation no longer states %s as the code has it (%q)", what, want)
		}
	}
}
