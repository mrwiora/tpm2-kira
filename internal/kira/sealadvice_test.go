package kira

import (
	"strings"
	"testing"
)

func joined(lines []string) string { return strings.Join(lines, "\n") }

// TestAdviseSuggestion checks the selection recommended for each shape of
// machine. The rule that matters: PCRs 0 and 7 are enough when Secure Boot is
// verifying the boot chain, and when it is not, something has to measure the
// boot components themselves or the policy protects very little.
func TestAdviseSuggestion(t *testing.T) {
	tests := []struct {
		name    string
		profile SystemProfile
		wantPCR string
	}{
		{
			name: "Secure Boot verifying, UKI present",
			profile: SystemProfile{
				EFI:               true,
				SecureBoot:        SecureBootState{Known: true, Enabled: true},
				EventlogPresent:   true,
				EventlogHasSHA256: true,
				UKIPath:           "/boot/EFI/Linux/arch-linux.efi",
			},
			wantPCR: "0,7",
		},
		{
			name: "Secure Boot verifying, GRUB",
			profile: SystemProfile{
				EFI:        true,
				SecureBoot: SecureBootState{Known: true, Enabled: true},
				GRUB:       true,
			},
			wantPCR: "0,7",
		},
		{
			name: "Secure Boot off with a UKI: measure the image",
			profile: SystemProfile{
				EFI:        true,
				SecureBoot: SecureBootState{Known: true, Enabled: false},
				UKIPath:    "/boot/EFI/Linux/arch-linux.efi",
			},
			wantPCR: "0,7,11u",
		},
		{
			name: "Secure Boot off with GRUB: measure what GRUB reads",
			profile: SystemProfile{
				EFI:        true,
				SecureBoot: SecureBootState{Known: true, Enabled: false},
				GRUB:       true,
			},
			wantPCR: "0,7,8,9",
		},
		{
			name: "Secure Boot off, neither: measure the boot loader",
			profile: SystemProfile{
				EFI:        true,
				SecureBoot: SecureBootState{Known: true, Enabled: false},
			},
			wantPCR: "0,7,4",
		},
		{
			name: "Setup Mode counts as not verifying",
			profile: SystemProfile{
				EFI:        true,
				SecureBoot: SecureBootState{Known: true, Enabled: true, SetupMode: true},
				UKIPath:    "/boot/EFI/Linux/arch-linux.efi",
			},
			wantPCR: "0,7,11u",
		},
		{
			name: "Secure Boot unreadable is treated as not verifying",
			profile: SystemProfile{
				EFI:     true,
				UKIPath: "/boot/EFI/Linux/arch-linux.efi",
			},
			wantPCR: "0,7,11u",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			advice := tc.profile.Advise()

			if advice.PCRs != tc.wantPCR {
				t.Errorf("suggested %q, want %q", advice.PCRs, tc.wantPCR)
			}

			// Whatever is suggested has to be usable.
			if _, err := ParsePCRSpecs(advice.PCRs); err != nil {
				t.Errorf("the suggestion %q does not parse: %v", advice.PCRs, err)
			}

			if len(advice.Chosen) == 0 {
				t.Error("every suggested PCR should be explained")
			}
		})
	}
}

// TestAdviseRisks checks that the warnings track the machine rather than being
// printed unconditionally — a warning that always appears teaches nobody
// anything.
func TestAdviseRisks(t *testing.T) {
	t.Run("Secure Boot disabled is called out", func(t *testing.T) {
		advice := SystemProfile{SecureBoot: SecureBootState{Known: true}}.Advise()
		if !strings.Contains(joined(advice.Risks), "Secure Boot is disabled") {
			t.Errorf("expected a disabled-Secure-Boot risk, got:\n%s", joined(advice.Risks))
		}
	})

	t.Run("Setup Mode is called out", func(t *testing.T) {
		advice := SystemProfile{
			SecureBoot: SecureBootState{Known: true, Enabled: true, SetupMode: true},
		}.Advise()
		if !strings.Contains(joined(advice.Risks), "Setup Mode") {
			t.Errorf("expected a Setup Mode risk, got:\n%s", joined(advice.Risks))
		}
	})

	t.Run("an unreadable state is called out", func(t *testing.T) {
		advice := SystemProfile{}.Advise()
		if !strings.Contains(joined(advice.Risks), "could not be read") {
			t.Errorf("expected an unreadable-state risk, got:\n%s", joined(advice.Risks))
		}
	})

	t.Run("a verifying Secure Boot gets no Secure Boot risk", func(t *testing.T) {
		advice := SystemProfile{
			SecureBoot: SecureBootState{Known: true, Enabled: true},
		}.Advise()
		risks := joined(advice.Risks)
		for _, unwanted := range []string{"Secure Boot is disabled", "Setup Mode", "could not be read"} {
			if strings.Contains(risks, unwanted) {
				t.Errorf("a healthy Secure Boot should not warn about %q, got:\n%s", unwanted, risks)
			}
		}
	})

	t.Run("PCR 0 alone is always explained", func(t *testing.T) {
		advice := SystemProfile{SecureBoot: SecureBootState{Known: true, Enabled: true}}.Advise()
		if !strings.Contains(joined(advice.Risks), "PCR 0 on its own") {
			t.Errorf("expected the PCR 0 caveat, got:\n%s", joined(advice.Risks))
		}
	})

	t.Run("an event log without SHA-256 is called out", func(t *testing.T) {
		advice := SystemProfile{EventlogPresent: true}.Advise()
		if !strings.Contains(joined(advice.Risks), "no SHA-256 digests") {
			t.Errorf("expected a bank warning, got:\n%s", joined(advice.Risks))
		}
		if strings.Contains(joined(advice.Optional), "0e,7e") {
			t.Error("eventlog sources must not be offered when the log has no SHA-256 digests")
		}
	})

	t.Run("no event log at all is stated as a fact, not a risk", func(t *testing.T) {
		advice := SystemProfile{}.Advise()
		if !strings.Contains(joined(advice.Facts), "Event log: not available") {
			t.Errorf("expected the missing log to be reported, got:\n%s", joined(advice.Facts))
		}
		if strings.Contains(joined(advice.Risks), "no SHA-256 digests") {
			t.Error("a machine with no event log should not be warned about its digests")
		}
	})
}

// TestAdviseOptional checks that the churn cost of the heavier PCRs is stated
// where they are offered, since that cost is the whole reason they are optional.
func TestAdviseOptional(t *testing.T) {
	t.Run("UKI is offered with its reseal cost", func(t *testing.T) {
		advice := SystemProfile{
			SecureBoot:        SecureBootState{Known: true, Enabled: true},
			UKIPath:           "/boot/EFI/Linux/arch-linux.efi",
			EventlogPresent:   true,
			EventlogHasSHA256: true,
		}.Advise()

		optional := joined(advice.Optional)
		if !strings.Contains(optional, "11u") {
			t.Errorf("expected 11u to be offered, got:\n%s", optional)
		}
		if !strings.Contains(optional, "every kernel update") {
			t.Errorf("the reseal cost should be stated, got:\n%s", optional)
		}
		// The way out of that cost is the hook, so the offer has to name it.
		if !strings.Contains(optional, "install-mkinitcpio") {
			t.Errorf("the offer should say how to automate the reseal, got:\n%s", optional)
		}
	})

	t.Run("GRUB PCRs are offered with the after-reboot rule", func(t *testing.T) {
		advice := SystemProfile{
			SecureBoot: SecureBootState{Known: true, Enabled: true},
			GRUB:       true,
		}.Advise()

		optional := joined(advice.Optional)
		if !strings.Contains(optional, "8,9") {
			t.Errorf("expected 8,9 to be offered, got:\n%s", optional)
		}
		if !strings.Contains(optional, "after the reboot") {
			t.Errorf("the after-reboot rule should be stated, got:\n%s", optional)
		}
	})

	t.Run("nothing already suggested is also offered as optional", func(t *testing.T) {
		// Secure Boot off with a UKI puts 11u in the suggestion, so it must not
		// also appear as something to consider adding.
		advice := SystemProfile{
			SecureBoot: SecureBootState{Known: true, Enabled: false},
			UKIPath:    "/boot/EFI/Linux/arch-linux.efi",
		}.Advise()

		if strings.Contains(joined(advice.Optional), "11u") {
			t.Errorf("11u is already in %q; it should not be offered again:\n%s",
				advice.PCRs, joined(advice.Optional))
		}
	})
}

// TestAdviseFactsReportUEFI checks the plainest fact, since an absent efivarfs
// is the usual reason Secure Boot cannot be read.
func TestAdviseFactsReportUEFI(t *testing.T) {
	if got := joined(SystemProfile{EFI: true}.Advise().Facts); !strings.Contains(got, "UEFI") {
		t.Errorf("expected UEFI to be reported, got:\n%s", got)
	}
	if got := joined(SystemProfile{}.Advise().Facts); !strings.Contains(got, "not UEFI") {
		t.Errorf("expected a non-UEFI machine to be reported, got:\n%s", got)
	}
}

// TestAdviseStatesUpkeepForSuggestedPCRs covers a gap worth naming: when a
// component PCR ends up in the suggestion rather than in the optional list, its
// reseal cost has to be stated alongside the suggestion. Otherwise the cost only
// appears next to the options somebody did not choose.
func TestAdviseStatesUpkeepForSuggestedPCRs(t *testing.T) {
	t.Run("suggested 8,9 states the after-reboot rule", func(t *testing.T) {
		advice := SystemProfile{
			SecureBoot: SecureBootState{Known: true, Enabled: false},
			GRUB:       true,
		}.Advise()

		if !strings.Contains(advice.PCRs, "8,9") {
			t.Fatalf("precondition failed: expected 8,9 in %q", advice.PCRs)
		}

		risks := joined(advice.Risks)
		if !strings.Contains(risks, "AFTER the reboot") {
			t.Errorf("the after-reboot rule should be stated, got:\n%s", risks)
		}
		if !strings.Contains(risks, "every kernel or initramfs update") {
			t.Errorf("the churn should be stated, got:\n%s", risks)
		}
	})

	t.Run("suggested 11u states the per-kernel reseal", func(t *testing.T) {
		advice := SystemProfile{
			SecureBoot: SecureBootState{Known: true, Enabled: false},
			UKIPath:    "/boot/EFI/Linux/arch-linux.efi",
		}.Advise()

		if !strings.Contains(advice.PCRs, "11u") {
			t.Fatalf("precondition failed: expected 11u in %q", advice.PCRs)
		}
		if !strings.Contains(joined(advice.Risks), "every kernel update") {
			t.Errorf("the per-kernel reseal should be stated, got:\n%s", joined(advice.Risks))
		}
	})

	t.Run("suggested 4 states the bootloader update cost", func(t *testing.T) {
		advice := SystemProfile{SecureBoot: SecureBootState{Known: true, Enabled: false}}.Advise()

		if !strings.Contains(advice.PCRs, "4") {
			t.Fatalf("precondition failed: expected 4 in %q", advice.PCRs)
		}
		if !strings.Contains(joined(advice.Risks), "boot loader binary") {
			t.Errorf("the bootloader cost should be stated, got:\n%s", joined(advice.Risks))
		}
	})

	t.Run("a stable 0,7 suggestion carries no upkeep warning", func(t *testing.T) {
		advice := SystemProfile{
			SecureBoot: SecureBootState{Known: true, Enabled: true},
			UKIPath:    "/boot/EFI/Linux/arch-linux.efi",
		}.Advise()

		if advice.PCRs != "0,7" {
			t.Fatalf("precondition failed: got %q", advice.PCRs)
		}

		risks := joined(advice.Risks)
		for _, unwanted := range []string{"AFTER the reboot", "every kernel update", "boot loader binary"} {
			if strings.Contains(risks, unwanted) {
				t.Errorf("0,7 needs no reseal on kernel updates, so %q should not appear:\n%s", unwanted, risks)
			}
		}
	})
}

// TestAdviseRecommendsKernelPCRWhenResealIsAutomated is the case that prompted
// this: Arch with Secure Boot enforcing and a UKI. PCRs 0 and 7 are already
// sound there, so the question is whether measuring the kernel is worth a reseal
// per kernel update — and it costs nothing when the mkinitcpio hook does that
// reseal for you.
func TestAdviseRecommendsKernelPCRWhenResealIsAutomated(t *testing.T) {
	base := SystemProfile{
		EFI:               true,
		SecureBoot:        SecureBootState{Known: true, Enabled: true},
		EventlogPresent:   true,
		EventlogHasSHA256: true,
		TPMHasSHA256:      true,
		SourcesProbed:     true,
		UKIPath:           "/boot/EFI/Linux/arch-linux.efi",
	}

	t.Run("hook installed: 11u is suggested and the reason says why", func(t *testing.T) {
		p := base
		p.ResealHookInstalled = true
		advice := p.Advise()

		if advice.PCRs != "0,7,11u" {
			t.Errorf("suggested %q, want 0,7,11u", advice.PCRs)
		}
		because := joined(advice.Because)
		if !strings.Contains(because, "reseal hook is installed") {
			t.Errorf("the reason should name the hook, got:\n%s", because)
		}
		if strings.Contains(joined(advice.Optional), "11u") {
			t.Error("11u is in the suggestion; it should not also be offered")
		}
		// The upkeep is automated, and saying so is the point.
		if !strings.Contains(joined(advice.Risks), "does it for you") {
			t.Errorf("the risk note should say the hook handles the reseal, got:\n%s", joined(advice.Risks))
		}
	})

	t.Run("no hook: 11u is offered, not imposed", func(t *testing.T) {
		advice := base.Advise()

		if advice.PCRs != "0,7" {
			t.Errorf("suggested %q, want 0,7 when the reseal would be manual", advice.PCRs)
		}
		if !strings.Contains(joined(advice.Optional), "11u") {
			t.Errorf("11u should be offered, got:\n%s", joined(advice.Optional))
		}
		if !strings.Contains(joined(advice.Because), "survive kernel updates") {
			t.Errorf("the reason should explain the stable default, got:\n%s", joined(advice.Because))
		}
	})
}

// TestAdviseExplainsItself checks that every shape of machine gets a reason, not
// just a selection. The complaint that prompted this was as much about the
// missing explanation as about the selection.
func TestAdviseExplainsItself(t *testing.T) {
	profiles := map[string]SystemProfile{
		"arch, secure boot, uki": {
			EFI: true, SecureBoot: SecureBootState{Known: true, Enabled: true},
			EventlogPresent: true, EventlogHasSHA256: true, TPMHasSHA256: true,
			SourcesProbed: true, UKIPath: "/boot/EFI/Linux/arch.efi", ResealHookInstalled: true,
		},
		"debian, secure boot, grub": {
			EFI: true, SecureBoot: SecureBootState{Known: true, Enabled: true},
			EventlogPresent: true, EventlogHasSHA256: true, TPMHasSHA256: true,
			SourcesProbed: true, GRUB: true,
		},
		"debian, no secure boot, grub": {
			EFI: true, SecureBoot: SecureBootState{Known: true},
			EventlogPresent: true, EventlogHasSHA256: true, TPMHasSHA256: true,
			SourcesProbed: true, GRUB: true,
		},
		"sha-1 only tpm": {
			EFI: true, SecureBoot: SecureBootState{Known: true, Enabled: true},
			EventlogPresent: true, EventlogHasSHA1: true, TPMHasSHA1: true,
		},
		"nothing known": {},
	}

	for name, p := range profiles {
		t.Run(name, func(t *testing.T) {
			advice := p.Advise()

			if len(advice.Because) == 0 {
				t.Error("every suggestion needs a reason")
			}
			for _, line := range advice.Because {
				if strings.TrimSpace(line) == "" {
					t.Error("empty reason line")
				}
			}
			if _, err := ParsePCRSpecs(advice.PCRs); err != nil {
				t.Errorf("suggestion %q does not parse: %v", advice.PCRs, err)
			}
			// The bank is always stated, because it decides what is possible.
			if !strings.Contains(joined(advice.Facts), "TPM PCR banks:") {
				t.Errorf("the banks should be reported, got:\n%s", joined(advice.Facts))
			}
		})
	}
}

// TestAdviseSHA1Fallback covers a TPM with no SHA-256 bank: there is nothing to
// seal against but SHA-1, and that has to be both chosen and warned about.
func TestAdviseSHA1Fallback(t *testing.T) {
	advice := SystemProfile{
		EFI:             true,
		SecureBoot:      SecureBootState{Known: true, Enabled: true},
		EventlogPresent: true,
		EventlogHasSHA1: true,
		TPMHasSHA1:      true,
	}.Advise()

	if !advice.SHA1 {
		t.Error("a TPM with no SHA-256 bank has to fall back to SHA-1")
	}
	if !strings.Contains(joined(advice.Facts), "SHA-1 only") {
		t.Errorf("the missing bank should be reported, got:\n%s", joined(advice.Facts))
	}
	if !strings.Contains(joined(advice.Because), "--sha1") {
		t.Errorf("the reason should name the flag, got:\n%s", joined(advice.Because))
	}
	if !strings.Contains(joined(advice.Risks), "broken against collision") {
		t.Errorf("SHA-1 should carry its warning, got:\n%s", joined(advice.Risks))
	}

	// With a SHA-256 bank present, SHA-1 must not be chosen.
	ok := SystemProfile{TPMHasSHA256: true, TPMHasSHA1: true}.Advise()
	if ok.SHA1 {
		t.Error("SHA-1 should not be used when the TPM has a SHA-256 bank")
	}
}

// TestAdviseSourceConflictPrefersEventlog covers the case the user described:
// something extends the registers after tpm2-kira reads them, so the live value
// is not what the next boot reproduces and the reconstruction is the one to seal.
func TestAdviseSourceConflictPrefersEventlog(t *testing.T) {
	conflicted := SystemProfile{
		EFI:               true,
		SecureBoot:        SecureBootState{Known: true, Enabled: true},
		EventlogPresent:   true,
		EventlogHasSHA256: true,
		TPMHasSHA256:      true,
		SourcesProbed:     true,
		SourceConflict:    "PCR 7 cannot be reconstructed from the event log: ...",
	}

	advice := conflicted.Advise()

	if advice.PCRs != "0e,7e" {
		t.Errorf("suggested %q, want the eventlog source 0e,7e", advice.PCRs)
	}
	if !strings.Contains(joined(advice.Facts), "DISAGREE") {
		t.Errorf("the disagreement should be reported as a fact, got:\n%s", joined(advice.Facts))
	}
	if !strings.Contains(joined(advice.Because), "disagree") {
		t.Errorf("the reason should explain the source choice, got:\n%s", joined(advice.Because))
	}
	risks := joined(advice.Risks)
	if !strings.Contains(risks, "pcrtool.py verify") {
		t.Errorf("the risk should point at the diagnostic, got:\n%s", risks)
	}
	if !strings.Contains(risks, "next boot does not reproduce") {
		t.Errorf("the consequence of sealing the live value should be stated, got:\n%s", risks)
	}

	// Agreement means the register is the simpler choice.
	agreed := conflicted
	agreed.SourceConflict = ""
	if got := agreed.Advise().PCRs; got != "0,7" {
		t.Errorf("with the sources agreeing, suggested %q, want 0,7", got)
	}
}
