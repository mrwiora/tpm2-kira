package measure

import (
	"fmt"

	"github.com/mrwiora/tpm2-kira/core/attest"
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
		{"PCR4", "Boot Manager Code and Boot Attempts: what the firmware loaded (systemd-", "Firmware"},
		{"", "boot and the UKI; shim and GRUB). Moves at every update: use 4u, predicted.", ""},
		{"PCR5", "Boot Manager Configuration and Data. Can measure configuration", "Firmware"},
		{"", "of boot loaders; includes the GPT Partition Table.", ""},
		{"PCR6", "Resume from S4 and S5 Power State Events", "Firmware"},
		{"PCR7", "Secure Boot State. Contains the full contents of PK/KEK/db, as", "Firmware, shim"},
		{"", "well as the specific certificates used to validate each boot app.", ""},
		{"PCR8¹", "GRUB: every command it ran, logged as 'grub_cmd: ...'. The", "GRUB"},
		{"", "kernel cmdline is only one of them. Unused under a UKI.", ""},
		{"PCR9¹", "GRUB: contents of every file it read - grub.cfg, modules,", "GRUB, systemd-stub"},
		{"", "kernel, initrd - plus LOADED_IMAGE::LoadOptions.", ""},
		{"PCR10¹", "Runtime file measurements, by convention Linux IMA. Never", "Linux IMA"},
		{"", "appears in the firmware event log.", ""},
		{"PCR11¹", "Hash of the Unified kernel image (supports 'u' for direct computation)", "systemd-stub"},
		{"PCR12¹", "Overridden kernel command line, Credentials", "systemd-stub"},
		{"PCR13¹", "System Extensions", "systemd-stub"},
		{"PCR14¹", "shim's MokList, MokListX, and MokSBState", "shim"},
		{"PCR15¹", "tpm2-kira's close: never in a slot, every slot object requires it at", "tpm2-kira, systemd-cryptsetup"},
		{"", "zero; extended when the code screen is over. Also the LUKS volume key.", ""},
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
	fmt.Println("  'e'           - Calculate from TPM eventlog (PCRs 0-12, not 4)")
	fmt.Println("  'u[:PATH]'    - Predict for the next boot, built in; no external tools (PCRs 4 and 11)")
	fmt.Println("                  11: systemd-stub's section measurements of the unified kernel image")
	fmt.Println("                  4:  this boot's log, its images hashed as they are on the ESP")
	fmt.Println()
	fmt.Println("One rule: every slot reads PCR 7 and the image; slot 0 adds the platform:")
	fmt.Println("  UKI + systemd initramfs (Arch):")
	fmt.Println("    0e,2e,4u,7e,11u   - Slot 0: firmware, option ROMs, what it loaded, secure")
	fmt.Println("                        boot state, the unified kernel image")
	fmt.Println("    7e,11u            - Slot 1: survives a firmware or option-ROM change")
	fmt.Println("  GRUB + non-systemd initramfs (Debian):")
	fmt.Println("    0e,2e,4u,7e,8e,9e - Slot 0: with GRUB's commands and the files it read,")
	fmt.Println("                        predicted for the next boot from the files on disk")
	fmt.Println("    7e,8e,9e          - Slot 1; no GRUB slot may lack 8 and 9: Secure Boot")
	fmt.Println("                        does not cover the command line and the initrd")
	fmt.Println("  The hooks approve after each update. PCR 4 is in by decision, and goes again")
	fmt.Println("  if it makes trouble (a firmware that measures more into it).")
	fmt.Println("  Left out: 1 (settings, boot order), 3, 5, 6 (noise), 12, 13 (inside 11 on a")
	fmt.Println("  UKI), 14 (a MOK that verifies a kernel is in 7 as well), 15 (the close).")
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
	fmt.Println("Adapted from https://wiki.archlinux.org/title/Trusted_Platform_Module")

	return nil
}

// GetPCRDescription returns a short description for a given PCR index. The
// table lives in the attestation core so the phone explains a PCR difference
// with the same words as the CLI.
func GetPCRDescription(pcrIndex int) string {
	if pcrIndex < 0 || pcrIndex > 255 {
		return "Unknown PCR"
	}
	return attest.PCRDescription(uint8(pcrIndex))
}
