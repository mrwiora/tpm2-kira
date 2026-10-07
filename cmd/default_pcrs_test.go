package cmd

import (
	"os"
	"testing"

	"github.com/google/go-attestation/attest"
)

func eventsOf(t *testing.T, file string) []attest.Event {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	log, err := attest.ParseEventLog(raw)
	if err != nil {
		t.Fatal(err)
	}
	return log.Events(attest.HashSHA256)
}

// The selection follows the boot: a UKI's section measurements in PCR 11,
// GRUB's commands in PCR 8, or neither.
func TestDefaultPCRSelection(t *testing.T) {
	if sel, _ := defaultPCRSelection(eventsOf(t, "testdata/arch-uki-eventlog.bin"), DefaultUKIPath); sel != "0e,2e,7e,11u" {
		t.Errorf("Arch with a UKI: %s", sel)
	}
	if sel, _ := defaultPCRSelection(eventsOf(t, "testdata/arch-uki-eventlog.bin"), "/efi/EFI/Linux/x.efi"); sel != "0e,2e,7e,11u:/efi/EFI/Linux/x.efi" {
		t.Errorf("a UKI elsewhere: %s", sel)
	}
	if sel, _ := defaultPCRSelection(eventsOf(t, "testdata/debian13-grub-eventlog.bin"), ""); sel != "0e,2e,7e,8e,9e" {
		t.Errorf("Debian with GRUB: %s", sel)
	}
	// --sha1 changes the bank the events are read from, not the selection.
	if sel, _ := DefaultPCRSelection("testdata/debian13-grub-eventlog.bin", PCRHashAlgoSHA1); sel != "0e,2e,7e,8e,9e" {
		t.Errorf("Debian in the SHA-1 bank: %s", sel)
	}
	if sel, _ := defaultPCRSelection(nil, ""); sel != "0e,2e,7e" {
		t.Errorf("neither: %s", sel)
	}
	for _, sel := range []string{"0e,2e,7e,11u:/efi/EFI/Linux/x.efi", "0e,2e,7e,8e,9e", FallbackPCRSelection} {
		if _, err := ParsePCRSpecs(sel); err != nil {
			t.Errorf("%s does not parse: %v", sel, err)
		}
	}
	if sel, why := DefaultPCRSelection("/nonexistent", PCRHashAlgoSHA256); sel != "0e,2e,7e" || why == "" {
		t.Errorf("without a log: %s (%s)", sel, why)
	}
}
