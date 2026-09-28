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
	fmt.Println("WARNING: sealing against the SHA-1 PCR bank.")
	fmt.Println("  SHA-1 is broken against collision attacks and TPMs are not required to")
	fmt.Println("  provide a SHA-1 bank at all, so this policy may become unsatisfiable on")
	fmt.Println("  future hardware. Use it only where the firmware event log carries no")
	fmt.Println("  SHA-256 digests, and prefer the register source instead where possible:")
	fmt.Println("      tpm2-kira seal --pcrs \"0,7\"")
	fmt.Println()
}

// WarnAboutPCRSelection reports selections that attest less than they appear
// to. These are advisory: an unusual selection is still sealed.
func WarnAboutPCRSelection(specs []PCRSpec) {
	indices := PCRSpecIndices(specs)

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
