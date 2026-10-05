package attest

import (
	"fmt"
	"sort"
	"strings"
)

// What each PCR measures, shared by the CLI (`pcrtips`, mismatch output) and
// the phone, so both explain a difference with the same words
// (PLAN-BLE.md §6.3).
var pcrDescriptions = map[uint8]string{
	0:  "Core System Firmware executable code (Firmware)",
	1:  "Core System Firmware data (UEFI settings)",
	2:  "Extended or pluggable executable code (OpROMs)",
	3:  "Extended or pluggable firmware data",
	4:  "Boot Manager Code and Boot Attempts",
	5:  "Boot Manager Configuration and Data (GPT table)",
	6:  "Resume from S4 and S5 Power State Events",
	7:  "Secure Boot State (PK/KEK/db certificates)",
	8:  "GRUB commands (logged as 'grub_cmd: ...')",
	9:  "Contents of files GRUB read, plus EFI LoadOptions",
	10: "Runtime measurements, by convention Linux IMA",
	11: "Hash of the Unified kernel image",
	12: "Overridden kernel command line, Credentials",
	13: "System Extensions",
	14: "shim's MokList, MokListX, and MokSBState",
	15: "Hash of the LUKS volume key",
	16: "Debug (may be reset at any time)",
	23: "Application Support (OS can set/reset)",
}

// PCRDescription returns a short description of a PCR.
func PCRDescription(idx uint8) string {
	if d, ok := pcrDescriptions[idx]; ok {
		return d
	}
	return "Unknown PCR"
}

// pcrClass groups registers by what usually moves them together.
type pcrClass int

const (
	classFirmware pcrClass = iota
	classFirmwareConfig
	classBootloader
	classKernel
	classSecureBoot
	classOther
)

func classify(idx uint8) pcrClass {
	switch idx {
	case 0, 2:
		return classFirmware
	case 1, 3, 5, 6:
		return classFirmwareConfig
	case 4, 8, 14:
		return classBootloader
	case 9, 11, 12, 13:
		return classKernel
	case 7:
		return classSecureBoot
	}
	return classOther
}

// ExplainDiff turns a list of differing PCRs into one sentence a person can
// act on. It describes what usually causes such a pattern; it does not claim
// to know the cause. The app shows it next to the raw diff, never instead of it.
func ExplainDiff(diff []PCRDiff) string {
	if len(diff) == 0 {
		return ""
	}
	classes := map[pcrClass]bool{}
	var idx []int
	for _, d := range diff {
		classes[classify(d.Index)] = true
		idx = append(idx, int(d.Index))
	}
	sort.Ints(idx)
	list := make([]string, len(idx))
	for i, v := range idx {
		list[i] = fmt.Sprint(v)
	}
	prefix := fmt.Sprintf("PCR %s changed. ", strings.Join(list, ", "))

	var parts []string
	switch {
	case classes[classSecureBoot]:
		parts = append(parts, "The Secure Boot policy changed (keys, db/dbx, or Secure Boot switched on or off). That is rare and should be explained by something you did")
	case classes[classFirmware]:
		parts = append(parts, "Firmware code changed, which a UEFI update causes")
	}
	if classes[classFirmwareConfig] && !classes[classFirmware] {
		parts = append(parts, "firmware settings or the partition table changed")
	}
	if classes[classKernel] && classes[classBootloader] {
		parts = append(parts, "the bootloader and the kernel or initrd measurements moved, which a kernel or bootloader update causes")
	} else if classes[classKernel] {
		parts = append(parts, "the kernel, initrd or kernel command line changed, which a kernel or initramfs update causes")
	} else if classes[classBootloader] {
		parts = append(parts, "the bootloader changed, which a shim, GRUB or systemd-boot update causes")
	}
	if !classes[classSecureBoot] {
		parts = append(parts, "the Secure Boot policy is unchanged")
	}
	if classes[classOther] {
		parts = append(parts, "registers outside the usual boot chain changed as well")
	}
	s := strings.Join(parts, "; ")
	if s != "" {
		s = strings.ToUpper(s[:1]) + s[1:] + "."
	}
	return prefix + s
}
