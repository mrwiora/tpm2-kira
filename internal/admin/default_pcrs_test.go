package admin

import (
	"os"
	"slices"
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/measure"

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
	if sel, _ := defaultPCRSelection(eventsOf(t, "testdata/arch-uki-eventlog.bin"), measure.DefaultUKIPath); sel != "0e,2e,7e,11u" {
		t.Errorf("Arch with a UKI: %s", sel)
	}
	if sel, _ := defaultPCRSelection(eventsOf(t, "testdata/arch-uki-eventlog.bin"), "/efi/EFI/Linux/x.efi"); sel != "0e,2e,7e,11u:/efi/EFI/Linux/x.efi" {
		t.Errorf("a UKI elsewhere: %s", sel)
	}
	if sel, _ := defaultPCRSelection(eventsOf(t, "testdata/debian13-grub-eventlog.bin"), ""); sel != "0e,2e,7e,8e,9e" {
		t.Errorf("Debian with GRUB: %s", sel)
	}
	// --sha1 changes the bank the events are read from, not the selection.
	if sel, _ := DefaultPCRSelection("testdata/debian13-grub-eventlog.bin", measure.PCRHashAlgoSHA1); sel != "0e,2e,7e,8e,9e" {
		t.Errorf("Debian in the SHA-1 bank: %s", sel)
	}
	if sel, _ := defaultPCRSelection(nil, ""); sel != "0e,2e,7e" {
		t.Errorf("neither: %s", sel)
	}
	for _, sel := range []string{"0e,2e,7e,11u:/efi/EFI/Linux/x.efi", "0e,2e,7e,8e,9e", FallbackPCRSelection} {
		if _, err := measure.ParsePCRSpecs(sel); err != nil {
			t.Errorf("%s does not parse: %v", sel, err)
		}
	}
	// Without a log nothing can be computed: the registers as they are.
	if sel, why := DefaultPCRSelection("/nonexistent", measure.PCRHashAlgoSHA256); sel != "0,2,7" || why == "" {
		t.Errorf("without a log: %s (%s)", sel, why)
	}
	if sel := defaultFallbackSelection("/nonexistent"); sel != FallbackRegisterSelection {
		t.Errorf("the fallback without a log: %s", sel)
	}
	if sel := defaultFallbackSelection("testdata/debian13-grub-eventlog.bin"); sel != GRUBFallbackPCRSelection {
		t.Errorf("the fallback on GRUB: %s", sel)
	}
	if sel := defaultFallbackSelection("testdata/arch-uki-eventlog.bin"); sel != FallbackPCRSelection {
		t.Errorf("the fallback with a UKI: %s", sel)
	}
	for sel, want := range map[string]bool{FallbackPCRSelection: true, GRUBFallbackPCRSelection: true, "7e": false, "0e,2e,7e": false} {
		specs, _ := measure.ParsePCRSpecs(sel)
		if isFallbackSelection(specs) != want {
			t.Errorf("%s a fallback selection: %v", sel, !want)
		}
	}
}

// On GRUB no slot lacks PCRs 8 and 9: Secure Boot does not cover GRUB's
// command line and the initrd. The SSH CA's slot 1 is {7, 8, 9} there,
// and a selection without 8 or 9 is refused; elsewhere slot 1 is PCR 7.
func TestGRUBHasNoSlotWithoutPCR8And9(t *testing.T) {
	if !GRUBBoot("testdata/debian13-grub-eventlog.bin") || GRUBBoot("testdata/arch-uki-eventlog.bin") || GRUBBoot("/nonexistent") {
		t.Fatal("GRUB's boot not told apart")
	}
	grub, err := sshCASlotsFor(DefaultPCRSelection("testdata/debian13-grub-eventlog.bin", measure.PCRHashAlgoSHA256))
	if err != nil || len(grub) != 2 || len(grub[0]) != 5 || grub[0][3] != 8 || grub[0][4] != 9 || !slices.Equal(grub[1], []int{7, 8, 9}) {
		t.Fatalf("the SSH CA's slots on GRUB: %v %v", grub, err)
	}
	uki, err := sshCASlotsFor(DefaultPCRSelection("testdata/arch-uki-eventlog.bin", measure.PCRHashAlgoSHA256))
	if err != nil || len(uki) != 2 || len(uki[1]) != 1 || uki[1][0] != 7 {
		t.Fatalf("the SSH CA's slots with a UKI: %v %v", uki, err)
	}
	for sel, ok := range map[string]bool{"0e,2e,7e,8e,9e": true, "0e,7e": false, "7": false, "0,2,7,8": false, "8,9": true} {
		specs, err := measure.ParsePCRSpecs(sel)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkGRUBSelection(specs, true); (err == nil) != ok {
			t.Errorf("%s on GRUB: %v", sel, err)
		}
		if err := checkGRUBSelection(specs, false); err != nil {
			t.Errorf("%s elsewhere: %v", sel, err)
		}
	}
}

// GRUB's password is judged from grub.cfg: a superuser and a PBKDF2
// password, both.
func TestGRUBPassword(t *testing.T) {
	dir := t.TempDir()
	for cfg, want := range map[string]bool{
		"menuentry 'Debian' {\n}\n": false,
		"set superusers=\"root\"\npassword_pbkdf2 root grub.pbkdf2.sha512.10000.AB.CD\nmenuentry 'Debian' --unrestricted {\n}\n": true,
		"set superusers=\"root\"\n":                         false,
		"  password_pbkdf2 root grub.pbkdf2.sha512.1.A.B\n": false,
	} {
		path := dir + "/grub.cfg"
		if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := GRUBPassword(path); err != nil || got != want {
			t.Errorf("%q: %v %v, want %v", cfg, got, err, want)
		}
	}
	if _, err := GRUBPassword(dir + "/none"); err == nil {
		t.Error("a grub.cfg that is not there")
	}
}
