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
		{"PCR8¹", "Hash of the kernel command line", "GRUB"},
		{"PCR9¹", "Hash of the initramfs and EFI Load Options", "Linux"},
		{"PCR10¹", "Reserved for Future Use", ""},
		{"PCR11¹", "Hash of the Unified kernel image (supports 'p:cmd' for prediction)", "systemd-stub"},
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
	fmt.Println("  'p:COMMAND'   - Predict via external command (PCR 11 only)")
	fmt.Println("                  The command must print a single hex digest line to stdout")
	fmt.Println()
	fmt.Println("Commonly used PCRs for sealing:")
	fmt.Println("  0,2,7      - Recommended default (firmware + secure boot)")
	fmt.Println("  0,2,4,7    - Include boot manager (may change on boot attempts)")
	fmt.Println("  0,2,7,9    - Include kernel/initramfs (if using systemd-based boot)")
	fmt.Println("  0e,2e,7e,11p:tpm2-pcr11predict - Eventlog + predicted UKI")
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
		8:  "Hash of the kernel command line",
		9:  "Hash of the initramfs and EFI Load Options",
		10: "Reserved for Future Use",
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
