package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"
)

// Guidance for a bare "tpm2-kira seal".
//
// Choosing PCRs is the one decision in this tool that needs to know about the
// machine it is running on: PCR 7 attests nothing useful with Secure Boot off,
// PCR 11 needs a unified kernel image to exist, and an event log without
// SHA-256 digests rules out the eventlog sources entirely. Rather than leave
// that to the documentation, seal reads what it can and says what it found.
//
// This only happens when no --pcrs was given and someone is there to answer.
// An explicit selection is used exactly as written, because the person typing
// it may know something this code does not.

// SystemProfile is what could be learned about the machine. Every field is
// best-effort: probing never fails, it only comes back unknown.
type SystemProfile struct {
	EFI        bool
	SecureBoot SecureBootState

	// EventlogPresent is true when the firmware event log can be read.
	EventlogPresent bool
	// EventlogHasSHA256 is true when the log carries SHA-256 digests. When it
	// is false the eventlog sources cannot be used in the SHA-256 bank.
	EventlogHasSHA256 bool

	// UKIPath is a unified kernel image found on this system, if any.
	UKIPath string
	// GRUB is true when a GRUB installation was found, which changes which
	// PCRs carry the kernel and initrd measurements.
	GRUB bool
}

// ProfileSystem probes the machine for the facts that bear on a PCR selection.
func ProfileSystem(debug bool) SystemProfile {
	profile := SystemProfile{
		SecureBoot: ReadSecureBootState(),
	}

	if _, err := os.Stat("/sys/firmware/efi"); err == nil {
		profile.EFI = true
	}

	if _, err := os.Stat(DefaultEventlogPath); err == nil {
		profile.EventlogPresent = true

		// PCR 0 is measured by every firmware that logs at all, so it is the
		// cheapest probe for whether the selected bank has digests.
		if digests, err := EventDigestsForPCR(DefaultEventlogPath, 0, PCRHashAlgoSHA256); err == nil && len(digests) > 0 {
			profile.EventlogHasSHA256 = true
		}
	}

	profile.UKIPath = findUKI()

	for _, dir := range []string{"/boot/grub", "/boot/grub2"} {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			profile.GRUB = true
			break
		}
	}

	if debug {
		fmt.Printf("System profile: EFI=%v secureboot=%+v eventlog=%v sha256=%v uki=%q grub=%v\n",
			profile.EFI, profile.SecureBoot, profile.EventlogPresent,
			profile.EventlogHasSHA256, profile.UKIPath, profile.GRUB)
	}

	return profile
}

// findUKI looks for a unified kernel image in the conventional locations.
func findUKI() string {
	if _, err := os.Stat(DefaultUKIPath); err == nil {
		return DefaultUKIPath
	}

	for _, pattern := range []string{"/boot/EFI/Linux/*.efi", "/efi/EFI/Linux/*.efi", "/boot/efi/EFI/Linux/*.efi"} {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			continue
		}
		return matches[0]
	}

	return ""
}

// SealAdvice is a suggested selection with the reasoning behind it.
type SealAdvice struct {
	// PCRs is the suggested selection, in --pcrs syntax.
	PCRs string
	// Facts describes what was found, one line each.
	Facts []string
	// Chosen explains each PCR in the suggestion.
	Chosen []string
	// Optional describes PCRs worth considering but not suggested, with the
	// cost of each.
	Optional []string
	// Risks describes what the suggestion does not protect against on this
	// machine, and selections to avoid here.
	Risks []string
}

// Advise turns a profile into a suggested PCR selection.
//
// It is a pure function so the reasoning can be tested across the combinations
// that matter — Secure Boot on, off and unreadable; a UKI or GRUB; an event log
// with or without SHA-256 — none of which are easy to arrange on a real machine.
func (p SystemProfile) Advise() SealAdvice {
	advice := SealAdvice{}

	// ── Facts ──
	if p.EFI {
		advice.Facts = append(advice.Facts, "Firmware: UEFI")
	} else {
		advice.Facts = append(advice.Facts, "Firmware: not UEFI (or efivarfs is not mounted)")
	}

	switch {
	case !p.SecureBoot.Known:
		advice.Facts = append(advice.Facts,
			"Secure Boot: cannot be read, so whether the boot chain is verified is unknown")
	case p.SecureBoot.Enabled && p.SecureBoot.SetupMode:
		advice.Facts = append(advice.Facts,
			"Secure Boot: enabled, but the platform is in Setup Mode")
	case p.SecureBoot.Enabled:
		advice.Facts = append(advice.Facts, "Secure Boot: enabled")
	default:
		advice.Facts = append(advice.Facts, "Secure Boot: disabled")
	}

	switch {
	case !p.EventlogPresent:
		advice.Facts = append(advice.Facts,
			"Event log: not available, so only live TPM registers can be used")
	case p.EventlogHasSHA256:
		advice.Facts = append(advice.Facts, "Event log: present, with SHA-256 digests")
	default:
		advice.Facts = append(advice.Facts,
			"Event log: present but without SHA-256 digests, so the 'e' sources cannot be used")
	}

	if p.UKIPath != "" {
		advice.Facts = append(advice.Facts, "Unified kernel image: "+p.UKIPath)
	}
	if p.GRUB {
		advice.Facts = append(advice.Facts, "Bootloader: GRUB found, so the kernel and initrd land in PCRs 8 and 9")
	}

	// ── The suggestion ──
	// PCR 0 and 7 are the stable pair: they change on a firmware update and on
	// a Secure Boot policy change, and not otherwise, so they need no reseal
	// after an ordinary kernel update. That is the right default for something
	// a user has to compare by eye on every boot.
	selected := []string{"0", "7"}

	advice.Chosen = append(advice.Chosen,
		"PCR 0  firmware code — changes when you update the firmware")

	secureBootMeaningful := p.SecureBoot.Known && p.SecureBoot.Enabled && !p.SecureBoot.SetupMode
	if secureBootMeaningful {
		advice.Chosen = append(advice.Chosen,
			"PCR 7  Secure Boot policy — changes if the keys are rotated or Secure Boot is turned off")
	} else {
		advice.Chosen = append(advice.Chosen,
			"PCR 7  Secure Boot state — included so that turning Secure Boot on or off is noticed,\n"+
				"         though it does not attest a verified boot chain in its current state")
	}

	// With Secure Boot verifying the chain, PCRs 0 and 7 are enough. Without
	// it, nothing checks which kernel ran, so the suggestion has to measure the
	// boot components themselves or it protects very little.
	if !secureBootMeaningful {
		switch {
		case p.UKIPath != "":
			selected = append(selected, "11u")
			advice.Chosen = append(advice.Chosen,
				"PCR 11 the unified kernel image — added because Secure Boot is not verifying it.\n"+
					"         Computed from the image on disk, so a reseal before rebooting works")
		case p.GRUB:
			selected = append(selected, "8", "9")
			advice.Chosen = append(advice.Chosen,
				"PCR 8,9 GRUB's commands and the files it reads, including the kernel and initrd —\n"+
					"         added because Secure Boot is not verifying them")
		default:
			selected = append(selected, "4")
			advice.Chosen = append(advice.Chosen,
				"PCR 4  the boot loader binary the firmware ran — added because Secure Boot is\n"+
					"         not verifying it")
		}
	}

	advice.PCRs = strings.Join(selected, ",")

	// ── Other options on this machine ──
	if secureBootMeaningful && p.UKIPath != "" {
		advice.Optional = append(advice.Optional,
			"11u  the unified kernel image. The strongest measurement of the exact kernel that\n"+
				"       will run, but it changes on every kernel update, so each one needs a reseal.\n"+
				"       It is computed from the image on disk, so that reseal can happen before the\n"+
				"       reboot rather than after it.")
	}
	if secureBootMeaningful && p.GRUB {
		advice.Optional = append(advice.Optional,
			"8,9  GRUB's commands and the contents of every file it reads. Covers the kernel and\n"+
				"       initrd, but changes on every kernel or initramfs update, and every source on a\n"+
				"       GRUB system is read from the running system — so the reseal has to happen\n"+
				"       after the reboot, not before it.")
	}
	if p.EventlogHasSHA256 {
		advice.Optional = append(advice.Optional,
			"0e,7e  the same registers, reconstructed from the firmware event log instead of read\n"+
				"       live. Equivalent for PCRs 0-7, and useful mainly for diagnosing a mismatch.")
	}
	advice.Optional = append(advice.Optional,
		"2    option ROM code, for machines with add-in cards whose firmware you want covered.")

	// ── Risks ──
	if !p.SecureBoot.Known {
		advice.Risks = append(advice.Risks,
			"The Secure Boot state could not be read, so the value of PCR 7 here is unknown.\n"+
				"    If Secure Boot is off, a matching PCR 7 does not mean the boot chain was checked.")
	} else if !p.SecureBoot.Enabled {
		advice.Risks = append(advice.Risks,
			"Secure Boot is disabled, so nothing verifies which bootloader or kernel runs.\n"+
				"    PCR 7 faithfully records \"disabled\"; it does not attest a verified chain.\n"+
				"    Enabling Secure Boot would make this selection considerably stronger.")
	} else if p.SecureBoot.SetupMode {
		advice.Risks = append(advice.Risks,
			"The platform is in Setup Mode, so the Secure Boot keys can be replaced without\n"+
				"    physical presence. The policy PCR 7 attests is one any root user can rewrite.")
	}

	advice.Risks = append(advice.Risks,
		"PCR 0 on its own would identify a firmware build, not this machine — every device\n"+
			"    running the same firmware version holds the same value. It is only meaningful\n"+
			"    here in combination with the others.")

	// When a component PCR is in the suggestion rather than merely offered, its
	// upkeep has to be stated here — otherwise the cost only appears in the list
	// of things that were not suggested, which nobody reads for what they chose.
	if slices.Contains(selected, "8") || slices.Contains(selected, "9") {
		advice.Risks = append(advice.Risks,
			"PCRs 8 and 9 change on every kernel or initramfs update, so each one needs a\n"+
				"    reseal. Every PCR source on a GRUB system is read from the running system, so\n"+
				"    that reseal has to happen AFTER the reboot that follows an update, not before:\n"+
				"    expect no TOTP code on the first boot after one, then run 'tpm2-kira reseal'.")
	}
	if slices.Contains(selected, "11u") {
		advice.Risks = append(advice.Risks,
			"PCR 11 changes on every kernel update, so each one needs a reseal. It is computed\n"+
				"    from the image on disk rather than the running system, so that reseal can be\n"+
				"    done before rebooting — the mkinitcpio hook does it automatically.")
	}
	if slices.Contains(selected, "4") {
		advice.Risks = append(advice.Risks,
			"PCR 4 changes when the boot loader binary is updated, so a bootloader or shim\n"+
				"    package update needs a reseal.")
	}

	if !p.EventlogHasSHA256 && p.EventlogPresent {
		advice.Risks = append(advice.Risks,
			"The event log carries no SHA-256 digests, so an 'e' suffix would reconstruct an\n"+
				"    all-zero value this machine will never produce. tpm2-kira refuses that rather\n"+
				"    than sealing it, but it is why the suggestion uses live registers.")
	}

	return advice
}

// SealPlan is what a guided seal decided to do.
type SealPlan struct {
	PCRs  string
	Index uint32
	// Proceed is false when the user chose to stop.
	Proceed bool
}

// GuideSealSelection prints what was found, suggests a selection, and asks.
//
// requestedIndexGiven says whether the caller named a slot; when it did, the
// slot is left alone and only the PCR selection is discussed.
func GuideSealSelection(tpmPath string, requestedIndex uint32, requestedIndexGiven bool, debug bool) (SealPlan, error) {
	plan := SealPlan{Index: requestedIndex}

	profile := ProfileSystem(debug)
	advice := profile.Advise()

	fmt.Println("No --pcrs given, so here is what this machine looks like and what fits it.")
	fmt.Println("Pass --pcrs to skip all of this.")
	fmt.Println()

	fmt.Println("What was found:")
	for _, fact := range advice.Facts {
		fmt.Printf("  %s\n", fact)
	}
	fmt.Println()

	if !requestedIndexGiven {
		index, err := suggestFreeSlot(tpmPath, debug)
		if err != nil {
			return plan, err
		}
		plan.Index = index
	}

	fmt.Printf("Suggested selection: %s\n", advice.PCRs)
	for _, line := range advice.Chosen {
		fmt.Printf("  %s\n", line)
	}
	fmt.Println()

	if len(advice.Optional) > 0 {
		fmt.Println("Also possible here:")
		for _, line := range advice.Optional {
			fmt.Printf("  %s\n", line)
		}
		fmt.Println()
	}

	fmt.Println("Worth knowing:")
	for _, line := range advice.Risks {
		fmt.Printf("  - %s\n", line)
	}
	fmt.Println()

	fmt.Printf("  [Enter]      seal slot #%d (0x%08X) with PCRs %s\n",
		SlotNumber(plan.Index), plan.Index, advice.PCRs)
	fmt.Println("  <selection>  type your own, for example \"0,2,7\" or \"0e,7e,11u\"")
	fmt.Println("  [?]          show the full PCR reference and stop")
	fmt.Println("  [q]          quit without sealing")
	fmt.Print("\nChoice [Enter]: ")

	answer, _ := ReadLine()
	answer = strings.TrimSpace(answer)
	fmt.Println()

	switch {
	case answer == "":
		plan.PCRs = advice.PCRs

	case strings.EqualFold(answer, "q"):
		fmt.Println("Nothing was sealed.")
		return plan, nil

	case answer == "?":
		fmt.Println()
		if err := PCRTips(); err != nil {
			return plan, err
		}
		fmt.Println()
		fmt.Println("Run 'tpm2-kira seal' again, or 'tpm2-kira seal --pcrs \"...\"' with your choice.")
		return plan, nil

	default:
		// Validate before committing, so a typo is a question rather than a
		// policy bound to the wrong registers.
		if _, err := ParsePCRSpecs(answer); err != nil {
			return plan, fmt.Errorf("that selection cannot be used: %w\n"+
				"  Run 'tpm2-kira pcrtips' for the reference, then seal again", err)
		}
		plan.PCRs = answer
	}

	plan.Proceed = true
	return plan, nil
}

// suggestFreeSlot picks the lowest unused slot, preferring slot 0.
//
// A used slot holds someone's enrolled secret, so sealing over it without being
// asked would be destructive; the suggestion always moves to a free one and says
// which are taken.
func suggestFreeSlot(tpmPath string, debug bool) (uint32, error) {
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	populated := FindPopulatedSlots(tpmDev, debug)

	used := make(map[uint32]bool, len(populated))
	for _, index := range populated {
		used[index] = true
	}

	if len(populated) > 0 {
		var taken []string
		for _, index := range populated {
			taken = append(taken, fmt.Sprintf("#%d (0x%08X)", SlotNumber(index), index))
		}
		fmt.Printf("NVRAM slots already in use: %s\n", strings.Join(taken, ", "))
	}

	for slot := uint32(0); slot <= MaxSlotNumber; slot++ {
		index := NVRAMSlotStart + slot
		if !used[index] {
			fmt.Printf("Suggested NVRAM slot: #%d (0x%08X), which is free\n\n", slot, index)
			return index, nil
		}
	}

	return 0, fmt.Errorf("every NVRAM slot from #0 to #%d is in use;\n"+
		"  free one with 'tpm2-kira nvram delete --nvram <slot>' or name one with --nvram",
		MaxSlotNumber)
}
