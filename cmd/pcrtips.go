package cmd

import (
	"fmt"
)

// PCRTips displays information about what each PCR measures
func PCRTips() error {
	fmt.Println("PCR (Platform Configuration Register) Reference")
	fmt.Println("================================================")
	fmt.Println()
	fmt.Printf("%-6s | %-70s | %-30s\n", "PCR", "Description", "Extended by")
	fmt.Println("-------|------------------------------------------------------------------------|--------------------------------")

	pcrInfo := []struct {
		pcr         string
		description string
		extendedBy  string
	}{
		{"PCR0", "Core System Firmware executable code (aka Firmware).", "Firmware"},
		{"", "May change if you upgrade your UEFI.", ""},
		{"PCR1", "Core System Firmware data (aka UEFI settings; configured boot", "Firmware"},
		{"", "order, for example)", ""},
		{"PCR2", "Extended or pluggable executable code (aka OpROMs)", "Firmware"},
		{"PCR3", "Extended or pluggable firmware data. Set during Boot Device", "Firmware"},
		{"", "Select UEFI boot phase.", ""},
		{"PCR4", "Boot Manager Code and Boot Attempts. Measures the boot manager", "Firmware"},
		{"", "and the devices that the firmware tried to boot from.", ""},
		{"PCR5", "Boot Manager Configuration and Data. Can measure configuration", "Firmware"},
		{"", "of boot loaders; includes the GPT Partition Table.", ""},
		{"PCR6", "Resume from S4 and S5 Power State Events", "Firmware"},
		{"PCR7", "Secure Boot State. Contains the full contents of PK/KEK/db, as", "Firmware, shim"},
		{"", "well as the specific certificates used to validate each boot app.", ""},
		{"PCR8¹", "GRUB: the commands it ran from grub.cfg (incl. the kernel", "GRUB"},
		{"", "cmdline). Unused when booting a UKI via systemd-stub.", ""},
		{"PCR9¹", "Files the boot loader loaded: kernel and initramfs, plus EFI", "GRUB, systemd-stub"},
		{"", "Load Options. Changes on every kernel/initramfs update.", ""},
		{"PCR10¹", "Runtime file measurements, by convention Linux IMA. Never", "Linux IMA"},
		{"", "appears in the firmware event log.", ""},
		{"PCR11¹", "Hash of the Unified kernel image (supports 'u' for direct computation)", "systemd-stub"},
		{"PCR12¹", "Overridden kernel command line, Credentials", "systemd-stub"},
		{"PCR13¹", "System Extensions", "systemd-stub"},
		{"PCR14¹", "shim's MokList, MokListX, and MokSBState", "shim"},
		{"PCR15¹", "Hash of the LUKS volume key", "systemd-cryptsetup"},
		{"PCR16¹", "Debug. May be used and reset at any time. May be absent from", ""},
		{"", "an official firmware release.", ""},
		{"PCR23", "Application Support. The OS can set and reset this PCR.", ""},
	}

	for _, info := range pcrInfo {
		fmt.Printf("%-6s | %-70s | %-30s\n", info.pcr, info.description, info.extendedBy)
	}

	fmt.Println()
	fmt.Println("Notes:")
	fmt.Println("  ¹ PCRs 8-16 usage may vary by bootloader and distribution")
	fmt.Println()
	fmt.Println("PCR source suffixes:")
	fmt.Println("  (none) or 'r' - Read from TPM registers (default)")
	fmt.Println("  'e'           - Calculate from TPM eventlog (PCRs 0-12 only)")
	fmt.Println("  'u[:PATH]'    - Compute from a unified kernel image, built in (PCR 11 only)")
	fmt.Println("                  Replays systemd-stub's section measurements; no external tools")
	fmt.Println()
	fmt.Println("Commonly used PCRs for sealing:")
	fmt.Println("  UKI + systemd initramfs (Arch):")
	fmt.Println("    0e,2e,7e         - Firmware + secure boot state")
	fmt.Println("    0e,2e,7e,11u     - Adds the unified kernel image (recommended)")
	fmt.Println("  GRUB + non-systemd initramfs (Debian):")
	fmt.Println("    0e,2e,4e,7e      - Stable across kernel updates (recommended)")
	fmt.Println("    0e,2e,4e,7e,8e,9e - Adds grub.cfg, kernel and initramfs. PCR 9")
	fmt.Println("                       changes on every kernel/initramfs update, and")
	fmt.Println("                       cannot be predicted ahead of the reboot, so it")
	fmt.Println("                       needs a reseal AFTER booting the new image.")
	fmt.Println()
	fmt.Println("Selections that attest less than they look like they do:")
	fmt.Println("  PCR 0 alone   - Identifies the firmware BUILD, not this machine. Any")
	fmt.Println("                  device on the same firmware version has the same value.")
	fmt.Println("  PCR 7 without - PCR 7 records the secure boot state. With secure boot")
	fmt.Println("  Secure Boot     off it records \"disabled\", and nothing verifies which")
	fmt.Println("                  bootloader or kernel ran.")
	fmt.Println()
	fmt.Println("PCRs 9, 11 and 15 keep being extended after tpm2-kira reads them, so a")
	fmt.Println("value read from the running system is NOT what the next boot will show.")
	fmt.Println()
	fmt.Println("Source: https://wiki.archlinux.org/title/Trusted_Platform_Module")

	return nil
}

// GetPCRDescription returns a short description for a given PCR index
func GetPCRDescription(pcrIndex int) string {
	descriptions := map[int]string{
		0:  "Core System Firmware executable code (Firmware)",
		1:  "Core System Firmware data (UEFI settings)",
		2:  "Extended or pluggable executable code (OpROMs)",
		3:  "Extended or pluggable firmware data",
		4:  "Boot Manager Code and Boot Attempts",
		5:  "Boot Manager Configuration and Data (GPT table)",
		6:  "Resume from S4 and S5 Power State Events",
		7:  "Secure Boot State (PK/KEK/db certificates)",
		8:  "GRUB commands from grub.cfg (incl. kernel cmdline)",
		9:  "Kernel and initramfs loaded by the boot loader",
		10: "Runtime measurements, by convention Linux IMA",
		11: "Hash of the Unified kernel image",
		12: "Overridden kernel command line, Credentials",
		13: "System Extensions",
		14: "shim's MokList, MokListX, and MokSBState",
		15: "Hash of the LUKS volume key",
		16: "Debug (may be reset at any time)",
		23: "Application Support (OS can set/reset)",
	}

	if desc, ok := descriptions[pcrIndex]; ok {
		return desc
	}
	return "Unknown PCR"
}
