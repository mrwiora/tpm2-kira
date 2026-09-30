package kira

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
	// EventlogHasSHA256 and EventlogHasSHA1 say which banks the log carries
	// digests in. A log with only SHA-1 digests cannot feed an eventlog source
	// in the SHA-256 bank.
	EventlogHasSHA256 bool
	EventlogHasSHA1   bool

	// TPMHasSHA256 and TPMHasSHA1 say which PCR banks the TPM itself provides.
	// Without a SHA-256 bank there is nothing to seal against but SHA-1.
	TPMHasSHA256 bool
	TPMHasSHA1   bool

	// UKIPath is a unified kernel image found on this system, if any.
	UKIPath string
	// GRUB is true when a GRUB installation was found, which changes which
	// PCRs carry the kernel and initrd measurements.
	GRUB bool

	// ResealHookInstalled is true when the mkinitcpio post hook that reseals
	// after an image rebuild is in place. It decides whether the upkeep of a
	// kernel-measuring PCR is automatic or manual, which is the difference
	// between recommending one and merely offering it.
	ResealHookInstalled bool

	// SourcesProbed is true when the live registers could be compared against
	// an event log replay. The three fields below mean nothing without it.
	SourcesProbed bool
	// MeasurePointActive reports whether systemd's userspace extends are in
	// effect, as established by that comparison rather than assumed.
	MeasurePointActive bool
	// SourceConflict is set when a register matches neither the replay nor the
	// replay plus the measure-point words. Then the two sources do not agree and
	// one of them does not describe the next boot.
	SourceConflict string
}

// PreferredSource returns the per-PCR source suffix to recommend, and why.
//
// Register and eventlog are equivalent for PCRs 0-7 on a healthy system, and the
// register needs no event log at all, so it is the default. The exception is a
// machine where the two disagree: there the register holds extends that happen
// after tpm2-kira reads the TPM, so sealing it would bind to a value the next
// boot does not reproduce, and the reconstruction is the one to trust.
func (p SystemProfile) PreferredSource() (suffix string, reason string) {
	if p.SourceConflict != "" && p.EventlogHasSHA256 {
		return "e", "the live registers disagree with the event log on this machine, " +
			"so the reconstruction is what describes the measure point"
	}
	if !p.EventlogHasSHA256 {
		return "", "the event log carries no SHA-256 digests to reconstruct from"
	}
	if !p.SourcesProbed {
		return "", "the two sources could not be compared, and the register needs no event log"
	}
	return "", "the register and the event log agree here, and the register needs no event log to reproduce"
}

// ProfileSystem probes the machine for the facts that bear on a PCR selection.
//
// tpmDev may be nil, in which case the questions that need the TPM — which PCR
// banks exist, and whether the live registers agree with the event log — come
// back unknown rather than failing.
func ProfileSystem(tpmDev transport.TPM, debug bool) SystemProfile {
	profile := SystemProfile{
		SecureBoot: ReadSecureBootState(),
	}

	if _, err := os.Stat("/sys/firmware/efi"); err == nil {
		profile.EFI = true
	}

	if _, err := os.Stat(DefaultEventlogPath); err == nil {
		profile.EventlogPresent = true

		// PCR 0 is measured by every firmware that logs at all, so it is the
		// cheapest probe for which banks the log carries.
		if digests, err := EventDigestsForPCR(DefaultEventlogPath, 0, PCRHashAlgoSHA256); err == nil && len(digests) > 0 {
			profile.EventlogHasSHA256 = true
		}
		if digests, err := EventDigestsForPCR(DefaultEventlogPath, 0, PCRHashAlgoSHA1); err == nil && len(digests) > 0 {
			profile.EventlogHasSHA1 = true
		}
	}

	profile.UKIPath = findUKI()

	for _, dir := range []string{"/boot/grub", "/boot/grub2"} {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			profile.GRUB = true
			break
		}
	}

	// Either location counts: the Makefile installs to /etc, packages to /usr.
	for _, hook := range []string{
		"/etc/initcpio/post/sd-tpm2-kira",
		"/usr/lib/initcpio/post/sd-tpm2-kira",
	} {
		if _, err := os.Stat(hook); err == nil {
			profile.ResealHookInstalled = true
			break
		}
	}

	if tpmDev != nil {
		profile.TPMHasSHA256 = TPMHasPCRBank(tpmDev, PCRHashAlgoSHA256)
		profile.TPMHasSHA1 = TPMHasPCRBank(tpmDev, PCRHashAlgoSHA1)
		profile.probeSources(tpmDev, debug)
	}

	if debug {
		fmt.Printf("System profile: %+v\n", profile)
	}

	return profile
}

// probeSources compares the live registers against an event log replay.
//
// This is the question that decides between the register and the eventlog source,
// and it can only be answered by looking. On a healthy machine the two agree, so
// the choice is a matter of taste; where they disagree, one of them will not
// describe the next boot and picking by taste would seal a policy that fails.
func (p *SystemProfile) probeSources(tpmDev transport.TPM, debug bool) {
	if !p.EventlogPresent || !p.EventlogHasSHA256 || !p.TPMHasSHA256 {
		return
	}

	// PCRs 0-7 are the ones that stop changing at the measure point, which is
	// what makes them comparable at all.
	indices := []int{0, 1, 2, 3, 4, 5, 6, 7}

	registers, err := ReadPCRRegisters(tpmDev, indices, PCRHashAlgoSHA256, debug)
	if err != nil {
		if debug {
			fmt.Printf("Source probe: cannot read registers: %v\n", err)
		}
		return
	}

	calc := NewEventlogPCRCalculator(tpmDev, indices, PCRHashAlgoSHA256, debug)
	replay, _, err := calc.CalculatePCRsFromEventlog()
	if err != nil {
		if debug {
			fmt.Printf("Source probe: cannot replay the event log: %v\n", err)
		}
		return
	}

	active, _, err := DetectMeasurePointExtends(replay, registers, PCRHashAlgoSHA256, debug)
	if err != nil {
		// The registers describe something the log does not account for. That
		// is the case worth reporting rather than smoothing over.
		p.SourcesProbed = true
		p.SourceConflict = firstLine(err.Error())
		return
	}

	p.SourcesProbed = true
	p.MeasurePointActive = active
}

// firstLine keeps a multi-line diagnostic to its headline, for a summary table.
func firstLine(text string) string {
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		return text[:i]
	}
	return text
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
	// SHA1 is true when the machine leaves no choice but the SHA-1 bank.
	SHA1 bool
	// Facts describes what was found, one line each.
	Facts []string
	// Because connects those facts to the suggestion: why this selection and
	// not another, on this machine.
	Because []string
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
// with or without SHA-256; a TPM with or without a SHA-256 bank — none of which
// are easy to arrange on a real machine.
func (p SystemProfile) Advise() SealAdvice {
	advice := SealAdvice{}

	suffix, sourceReason := p.PreferredSource()

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
		advice.Facts = append(advice.Facts, "Secure Boot: enabled and enforcing")
	default:
		advice.Facts = append(advice.Facts, "Secure Boot: disabled")
	}

	advice.Facts = append(advice.Facts, describeBanks(p))

	switch {
	case !p.EventlogPresent:
		advice.Facts = append(advice.Facts,
			"Event log: not available, so only live TPM registers can be used")
	case p.EventlogHasSHA256:
		advice.Facts = append(advice.Facts, "Event log: present, with SHA-256 digests")
	case p.EventlogHasSHA1:
		advice.Facts = append(advice.Facts,
			"Event log: present but SHA-1 only, so the 'e' sources cannot be used in the SHA-256 bank")
	default:
		advice.Facts = append(advice.Facts, "Event log: present but carries no usable digests")
	}

	if p.SourcesProbed {
		switch {
		case p.SourceConflict != "":
			advice.Facts = append(advice.Facts,
				"Source check: the live registers and the event log DISAGREE here")
		case p.MeasurePointActive:
			advice.Facts = append(advice.Facts,
				"Source check: registers and event log agree; systemd's measure-point extends are active")
		default:
			advice.Facts = append(advice.Facts,
				"Source check: registers and event log agree; no measure-point extends on this system")
		}
	}

	if p.UKIPath != "" {
		advice.Facts = append(advice.Facts, "Unified kernel image: "+p.UKIPath)
	}
	if p.GRUB {
		advice.Facts = append(advice.Facts, "Bootloader: GRUB, so the kernel and initrd land in PCRs 8 and 9")
	}
	if p.ResealHookInstalled {
		advice.Facts = append(advice.Facts,
			"Automatic reseal: the mkinitcpio hook is installed, so a rebuild reseals by itself")
	} else if p.UKIPath != "" || p.GRUB {
		advice.Facts = append(advice.Facts,
			"Automatic reseal: not installed, so any reseal after an update is manual")
	}

	// ── Bank ──
	// Nothing to seal against but SHA-1 means using it, deprecated or not.
	if !p.TPMHasSHA256 && p.TPMHasSHA1 {
		advice.SHA1 = true
		advice.Because = append(advice.Because,
			"This TPM provides no SHA-256 PCR bank, so the selection has to be sealed in the\n"+
				"    SHA-1 bank (--sha1). That is not a good place to be — see the risks below.")
	}

	// ── The suggestion ──
	selected := []string{"0" + suffix, "7" + suffix}

	advice.Chosen = append(advice.Chosen,
		"PCR 0  firmware code — changes when you update the firmware")

	secureBootEnforcing := p.SecureBoot.Known && p.SecureBoot.Enabled && !p.SecureBoot.SetupMode
	if secureBootEnforcing {
		advice.Chosen = append(advice.Chosen,
			"PCR 7  Secure Boot policy — changes if the keys are rotated or Secure Boot is turned off")
	} else {
		advice.Chosen = append(advice.Chosen,
			"PCR 7  Secure Boot state — included so that turning Secure Boot on or off is noticed,\n"+
				"         though it does not attest a verified boot chain in its current state")
	}

	// What measures the kernel, and whether to suggest it or merely offer it.
	// kernelSpec carries the source suffix; kernelLabel is for the explanation,
	// where a suffix would only be noise.
	kernelSpec, kernelLabel, kernelWhat := "", "", ""
	switch {
	case p.UKIPath != "":
		kernelSpec, kernelLabel, kernelWhat = "11u", "11", "the unified kernel image"
	case p.GRUB:
		kernelSpec, kernelLabel, kernelWhat = "8"+suffix+",9"+suffix, "8,9", "GRUB's commands and the files it reads"
	default:
		kernelSpec, kernelLabel, kernelWhat = "4"+suffix, "4", "the boot loader binary the firmware ran"
	}

	// Two reasons to include it: nothing else is verifying the kernel, or the
	// upkeep is automated so it costs nothing to keep.
	includeKernel := !secureBootEnforcing || (p.ResealHookInstalled && p.UKIPath != "")

	if includeKernel {
		selected = append(selected, strings.Split(kernelSpec, ",")...)
		advice.Chosen = append(advice.Chosen,
			fmt.Sprintf("PCR %-2s %s", kernelLabel, kernelWhat))
	}

	advice.PCRs = strings.Join(selected, ",")

	// ── Why this, here ──
	advice.Because = append(advice.Because,
		fmt.Sprintf("Source: reading the %s, because %s.",
			map[string]string{"": "live registers", "e": "event log ('e' suffix)"}[suffix], sourceReason))

	switch {
	case !secureBootEnforcing && p.UKIPath != "":
		advice.Because = append(advice.Because,
			"Secure Boot is not enforcing, so nothing verifies which kernel runs. PCR 11 is\n"+
				"    included because this machine has a unified kernel image, which is the only\n"+
				"    thing here that measures the kernel itself.")
	case !secureBootEnforcing && p.GRUB:
		advice.Because = append(advice.Because,
			"Secure Boot is not enforcing, so nothing verifies which kernel runs. PCRs 8 and 9\n"+
				"    are included because GRUB measures its commands and the files it reads,\n"+
				"    including the kernel and initrd.")
	case !secureBootEnforcing:
		advice.Because = append(advice.Because,
			"Secure Boot is not enforcing, so nothing verifies which kernel runs, and this\n"+
				"    machine has neither a unified kernel image nor GRUB to measure it. PCR 4 at\n"+
				"    least covers the boot loader the firmware ran.")
	case includeKernel:
		advice.Because = append(advice.Because,
			"Secure Boot is enforcing, so PCRs 0 and 7 would already be a sound policy that\n"+
				"    survives kernel updates. PCR 11 is included anyway because the mkinitcpio\n"+
				"    reseal hook is installed: the per-kernel reseal it would otherwise cost you\n"+
				"    happens automatically, so the stronger policy is free here.")
	default:
		advice.Because = append(advice.Because,
			"Secure Boot is enforcing, so the boot chain is verified before anything runs and\n"+
				"    PCRs 0 and 7 are enough. They also survive kernel updates, which matters for\n"+
				"    something compared by eye on every boot.")
	}

	// ── Other options on this machine ──
	if secureBootEnforcing && p.UKIPath != "" && !includeKernel {
		advice.Optional = append(advice.Optional,
			"11u  the unified kernel image. The strongest measurement of the exact kernel that\n"+
				"       will run, but it changes on every kernel update, so each one needs a reseal.\n"+
				"       Installing the mkinitcpio hook (make install-mkinitcpio) automates that, and\n"+
				"       this suggestion would then include it.")
	}
	if secureBootEnforcing && p.GRUB && !includeKernel {
		advice.Optional = append(advice.Optional,
			"8,9  GRUB's commands and the contents of every file it reads. Covers the kernel and\n"+
				"       initrd, but changes on every kernel or initramfs update, and every source on a\n"+
				"       GRUB system is read from the running system — so the reseal has to happen\n"+
				"       after the reboot, not before it.")
	}
	if p.EventlogHasSHA256 && suffix == "" {
		advice.Optional = append(advice.Optional,
			"0e,7e  the same registers, reconstructed from the event log instead of read live.\n"+
				"       Equivalent here — the source check above confirmed it — and useful mainly for\n"+
				"       diagnosing a mismatch.")
	}
	advice.Optional = append(advice.Optional,
		"2    option ROM code, for machines with add-in cards whose firmware you want covered.")

	advice.Risks = append(advice.Risks, riskLines(p, selected, secureBootEnforcing)...)

	return advice
}

// describeBanks reports which PCR banks are available, since that decides
// whether SHA-256 is even an option.
func describeBanks(p SystemProfile) string {
	switch {
	case p.TPMHasSHA256 && p.TPMHasSHA1:
		return "TPM PCR banks: SHA-256 and SHA-1"
	case p.TPMHasSHA256:
		return "TPM PCR banks: SHA-256"
	case p.TPMHasSHA1:
		return "TPM PCR banks: SHA-1 only"
	default:
		return "TPM PCR banks: could not be read"
	}
}

// riskLines lists what the suggestion does not cover on this machine.
func riskLines(p SystemProfile, selected []string, secureBootEnforcing bool) []string {
	var risks []string

	if !p.SecureBoot.Known {
		risks = append(risks,
			"The Secure Boot state could not be read, so the value of PCR 7 here is unknown.\n"+
				"    If Secure Boot is off, a matching PCR 7 does not mean the boot chain was checked.")
	} else if !p.SecureBoot.Enabled {
		risks = append(risks,
			"Secure Boot is disabled, so nothing verifies which bootloader or kernel runs.\n"+
				"    PCR 7 faithfully records \"disabled\"; it does not attest a verified chain.\n"+
				"    Enabling Secure Boot would make this selection considerably stronger.")
	} else if p.SecureBoot.SetupMode {
		risks = append(risks,
			"The platform is in Setup Mode, so the Secure Boot keys can be replaced without\n"+
				"    physical presence. The policy PCR 7 attests is one any root user can rewrite.")
	}

	risks = append(risks,
		"PCR 0 on its own would identify a firmware build, not this machine — every device\n"+
			"    running the same firmware version holds the same value. It is only meaningful\n"+
			"    here in combination with the others.")

	if p.SourceConflict != "" {
		risks = append(risks,
			"The live registers do not match the event log on this machine:\n"+
				"      "+p.SourceConflict+"\n"+
				"    Something extends those registers after the point tpm2-kira reads the TPM, so\n"+
				"    sealing the live value would bind to something the next boot does not reproduce.\n"+
				"    Confirm with:  sudo python3 tools/pcrtool.py verify")
	}

	if !p.TPMHasSHA256 && p.TPMHasSHA1 {
		risks = append(risks,
			"Sealing in the SHA-1 bank. SHA-1 is broken against collision attacks and TPMs are\n"+
				"    not required to provide a SHA-1 bank at all, so this policy may become\n"+
				"    unsatisfiable on replacement hardware. It is the only option this TPM offers.")
	} else if p.EventlogPresent && !p.EventlogHasSHA256 {
		risks = append(risks,
			"The event log carries no SHA-256 digests, so an 'e' suffix would reconstruct an\n"+
				"    all-zero value this machine will never produce. tpm2-kira refuses that rather\n"+
				"    than sealing it, which is why the suggestion uses live registers.")
	}

	hasAny := func(names ...string) bool {
		for _, n := range names {
			for _, sel := range selected {
				if strings.TrimSuffix(sel, "e") == n {
					return true
				}
			}
		}
		return false
	}

	if hasAny("8", "9") {
		risks = append(risks,
			"PCRs 8 and 9 change on every kernel or initramfs update, so each one needs a\n"+
				"    reseal. Every PCR source on a GRUB system is read from the running system, so\n"+
				"    that reseal has to happen AFTER the reboot that follows an update, not before:\n"+
				"    expect no TOTP code on the first boot after one, then run 'tpm2-kira reseal'.")
	}
	if slices.Contains(selected, "11u") {
		line := "PCR 11 changes on every kernel update, so each one needs a reseal. It is computed\n" +
			"    from the image on disk rather than the running system, so that reseal can be done\n" +
			"    before rebooting"
		if p.ResealHookInstalled {
			line += " — and the mkinitcpio hook does it for you."
		} else {
			line += ", but you will have to run it yourself after every kernel update."
		}
		risks = append(risks, line)
	}
	if hasAny("4") {
		risks = append(risks,
			"PCR 4 changes when the boot loader binary is updated, so a bootloader or shim\n"+
				"    package update needs a reseal.")
	}

	return risks
}

// SealPlan is what a guided seal decided to do.
type SealPlan struct {
	PCRs  string
	Index uint32
	// SHA1 is set when the machine offers no SHA-256 bank.
	SHA1 bool
	// Proceed is false when the user chose to stop.
	Proceed bool
}

// GuideSealSelection prints what was found, suggests a selection, and asks.
//
// requestedIndexGiven says whether the caller named a slot; when it did, the
// slot is left alone and only the PCR selection is discussed.
func GuideSealSelection(tpmPath string, requestedIndex uint32, requestedIndexGiven bool, debug bool) (SealPlan, error) {
	plan := SealPlan{Index: requestedIndex}

	// One open, shared by the profile probe and the slot suggestion.
	tpmDev, err := OpenTPMDevice(tpmPath)
	if err != nil {
		return plan, err
	}
	defer tpmDev.Close()

	profile := ProfileSystem(tpmDev, debug)
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
		index, err := suggestFreeSlot(tpmDev, debug)
		if err != nil {
			return plan, err
		}
		plan.Index = index
	}

	fmt.Printf("Suggested selection: %s", advice.PCRs)
	if advice.SHA1 {
		fmt.Print("   (in the SHA-1 bank, with --sha1)")
	}
	fmt.Println()
	for _, line := range advice.Chosen {
		fmt.Printf("  %s\n", line)
	}
	fmt.Println()

	fmt.Println("Why this, on this machine:")
	for _, line := range advice.Because {
		fmt.Printf("  - %s\n", line)
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

	bank := ""
	if advice.SHA1 {
		bank = " --sha1"
	}

	fmt.Printf("  [Enter]      seal slot #%d (0x%08X) with PCRs %s%s\n",
		SlotNumber(plan.Index), plan.Index, advice.PCRs, bank)
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
		plan.SHA1 = advice.SHA1

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
		plan.SHA1 = advice.SHA1
	}

	plan.Proceed = true
	return plan, nil
}

// suggestFreeSlot picks the lowest unused slot, preferring slot 0.
//
// A used slot holds someone's enrolled secret, so sealing over it without being
// asked would be destructive; the suggestion always moves to a free one and says
// which are taken.
func suggestFreeSlot(tpmDev transport.TPM, debug bool) (uint32, error) {
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
