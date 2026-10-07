package cmd

import (
	"fmt"
	"os"
	"slices"
)

// efiGlobalVariableGUID is the EFI_GLOBAL_VARIABLE namespace that holds
// SecureBoot and SetupMode.
const efiGlobalVariableGUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

// SecureBootState is a best-effort reading of the firmware's Secure Boot
// variables. Known is false when they cannot be read at all.
type SecureBootState struct {
	Enabled   bool
	SetupMode bool
	Known     bool
}

// readEFIBoolVar reads a one-byte EFI variable. efivarfs prefixes every value
// with a 4-byte attribute word.
func readEFIBoolVar(name string) (value bool, ok bool) {
	path := fmt.Sprintf("/sys/firmware/efi/efivars/%s-%s", name, efiGlobalVariableGUID)
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 5 {
		return false, false
	}
	return data[4] == 1, true
}

// ReadSecureBootState probes the firmware state. It never fails, so it is safe
// to use as an advisory input rather than a gate.
func ReadSecureBootState() SecureBootState {
	enabled, ok := readEFIBoolVar("SecureBoot")
	if !ok {
		return SecureBootState{}
	}
	setupMode, _ := readEFIBoolVar("SetupMode")
	return SecureBootState{Enabled: enabled, SetupMode: setupMode, Known: true}
}

// WarnAboutHashAlgo reports a PCR bank that should not be used for new policies.
func WarnAboutHashAlgo(hashAlgo PCRHashAlgo) {
	if hashAlgo != PCRHashAlgoSHA1 {
		return
	}
	fmt.Println("NOTE: sealing against the SHA-1 PCR bank, as --sha1 asked: this TPM or its")
	fmt.Println("  firmware log has no SHA-256 digests. SHA-1 is weak against collisions and")
	fmt.Println("  a TPM need not have the bank at all. Everything else is as with SHA-256.")
	fmt.Println()
}

// loaderInfoGUID is the vendor GUID of the variables systemd-boot and
// systemd-stub set for the OS.
const loaderInfoGUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

// bootedViaSystemdStub reports whether this boot went through systemd-stub,
// i.e. a unified kernel image. systemd-stub sets StubInfo. Tests replace it.
var bootedViaSystemdStub = func() bool {
	_, err := os.Stat("/sys/firmware/efi/efivars/StubInfo-" + loaderInfoGUID)
	return err == nil
}

// bootChainCoverage reports whether a PCR selection measures the kernel and
// initrd, and the kernel command line:
//
//   - PCR 11: a unified kernel image, which embeds kernel, initrd and command
//     line (systemd-stub measures its sections).
//   - PCR 9: files GRUB reads (kernel, initrd), or the initrd the EFI stub
//     loads.
//   - PCR 8: every GRUB command, which includes the kernel command line.
//   - PCR 12: the command line systemd-stub/systemd-boot passes when it is
//     not part of a UKI.
func bootChainCoverage(indices []int) (kernelInitrd, cmdline bool) {
	has := func(i int) bool { return slices.Contains(indices, i) }
	return has(11) || has(9), has(11) || has(8) || has(12)
}

// WarnAboutPCRSelection reports selections that attest less than they appear
// to. These are advisory: an unusual selection is still sealed.
func WarnAboutPCRSelection(specs []PCRSpec) {
	indices := PCRSpecIndices(specs)

	if kernelInitrd, cmdline := bootChainCoverage(indices); !kernelInitrd || !cmdline {
		var missing string
		switch {
		case !kernelInitrd && !cmdline:
			missing = "measure neither the kernel and initrd nor the kernel command line"
		case !kernelInitrd:
			missing = "measure neither the kernel nor the initrd"
		default:
			missing = "do not measure the kernel command line"
		}
		fmt.Printf("WARNING: the selected PCRs %s.\n", missing)
		fmt.Println("  Someone with access to the disk or the boot menu can then run their own code")
		fmt.Println("  before the passphrase prompt — a replaced initrd that logs the passphrase, or")
		fmt.Println("  a shell from an edited command line (rd.break, break=) — and this machine")
		fmt.Println("  still shows a valid code. From such a shell the TOTP secret itself can be")
		fmt.Println("  unsealed and copied.")
		if bootedViaSystemdStub() {
			fmt.Println("  This boot used a unified kernel image. Seal its measurements with PCR 11:")
			fmt.Printf("      tpm2-kira seal --pcrs \"%s\"\n", suggestWith(specs, "11u"))
		} else {
			fmt.Println("  With a unified kernel image, add PCR 11 (\"11u\"). With GRUB, add PCRs 8 and 9")
			fmt.Println("  (\"8e,9e\"); they change on every kernel or initrd update, so reseal after the")
			fmt.Println("  reboot that follows one (README, \"If you seal PCR 8 or 9\").")
		}
		fmt.Println("  README \"Hardening the boot path\" lists what else keeps a shell out of reach.")
		fmt.Println()
	}

	if len(indices) == 1 && indices[0] == 0 {
		fmt.Println("WARNING: PCR 0 alone identifies the firmware build, not this machine.")
		fmt.Println("  It measures firmware code only, so every device running the same firmware")
		fmt.Println("  version holds the same value, and an attacker can reproduce it on their own")
		fmt.Println("  hardware. It covers neither the bootloader, the kernel, nor the Secure Boot")
		fmt.Println("  policy. Add PCR 7, and 2/4 for the boot chain, to make the policy meaningful.")
		fmt.Println()
	}

	if !slices.Contains(indices, 7) {
		return
	}

	state := ReadSecureBootState()
	switch {
	case !state.Known:
		fmt.Println("WARNING: sealing against PCR 7, but the Secure Boot state could not be read.")
		fmt.Println("  /sys/firmware/efi/efivars is unavailable (non-EFI boot, or efivarfs not")
		fmt.Println("  mounted), so whether PCR 7 attests an enforced policy is unknown here.")
		fmt.Println()
	case state.SetupMode:
		fmt.Println("WARNING: sealing against PCR 7 while the platform is in Setup Mode.")
		fmt.Println("  In Setup Mode the Secure Boot keys can be replaced without physical presence,")
		fmt.Println("  so PCR 7 records a policy that any root user can rewrite. Enrol keys and")
		fmt.Println("  leave Setup Mode before treating this value as evidence.")
		fmt.Println()
	case !state.Enabled:
		fmt.Println("WARNING: sealing against PCR 7 while Secure Boot is disabled.")
		fmt.Println("  PCR 7 measures the Secure Boot state and policy. With Secure Boot off it")
		fmt.Println("  records \"disabled\" and nothing verifies which bootloader or kernel runs, so")
		fmt.Println("  a matching PCR 7 does not mean the boot chain was checked.")
		fmt.Println()
	}
}

// suggestWith returns the selection with extra appended.
func suggestWith(specs []PCRSpec, extra string) string {
	return PCRSpecsToString(specs) + "," + extra
}

// RecommendedPCRs is the selection setup suggests for this machine: one that
// also measures kernel, initrd and command line. With a unified kernel image
// that is PCR 11; otherwise the GRUB measurements in PCRs 8 and 9, which need
// a reseal after the reboot that follows each kernel or initrd update.
func RecommendedPCRs() string {
	if bootedViaSystemdStub() {
		return "0,7,11u"
	}
	return "0e,2e,4e,7e,8e,9e"
}
