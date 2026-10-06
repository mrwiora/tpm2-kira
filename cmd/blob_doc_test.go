package cmd

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/matthias/tpm2-kira/attest"
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
		"the two blob versions":         fmt.Sprintf("## 10. Blob Format (Versions %d and %d)", CurrentBlobVersion, EnrolledBlobVersion),
		"the version field":             fmt.Sprintf("%d, or %d with a phone enrolment", CurrentBlobVersion, EnrolledBlobVersion),
		"the enrolment's format number": fmt.Sprintf("Enrolment format      uint8       Must be %d", attestSectionVersion),
		"the enrolment's magic":         fmt.Sprintf("Magic                 [4]byte     %q", attestBlobMagic),
		"the enrolment's size limit":    fmt.Sprintf("Enrolment length      uint32      ≤ %d", MaxAttestSectionLen),
		"the number of phones":          fmt.Sprintf("Verifier count        uint8       ≤ %d", MaxVerifiers),
		"the PCR selection limit":       fmt.Sprintf("PCRSelection length   uint16      ≤ %d", attest.MaxPCRIndex),
		"the device id size":            fmt.Sprintf("DeviceID              [%d]byte", attest.DeviceIDSize),
		"the slot's blob index":         fmt.Sprintf("`0x%08X`", NVRAMSlotStart),
		"the generation index":          fmt.Sprintf("`0x%08X` for slot", GenerationIndex(NVRAMSlotStart)),
		"the record counter index":      fmt.Sprintf("`0x%08X` + *n*: an", AttestCounterIndex(NVRAMSlotStart)),
		"the old enrolment index":       fmt.Sprintf("(`0x%08X` + *n*)", AttestNVRAMStart),
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the documentation no longer states %s as the code has it (%q)", what, want)
		}
	}
}
