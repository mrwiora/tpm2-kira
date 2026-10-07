package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-attestation/attest"
)

// What 'seal' seals to when nobody says. The boot's own event log decides:
// the firmware, its configuration and the secure boot state always (0, 2,
// 7); with a unified kernel image, PCR 11 computed from the image, so the
// code survives a kernel update by prediction; with GRUB, its PCRs 8 and
// 9, predicted from grub.cfg and the files it loads. And a second slot
// sealed to 0 and 7 alone - the fallback: when a kernel or boot loader
// change was not predicted, the firmware and the secure boot state still
// vouch for the machine, and that slot's code still shows.

// FallbackPCRSelection is what the fallback slot is sealed to.
const FallbackPCRSelection = "0e,7e"

// FallbackSlot is the slot the fallback goes into.
const FallbackSlot = 1

// ukiDirs are where a unified kernel image is looked for when the default
// path is not there.
var ukiDirs = []string{"/boot/EFI/Linux", "/efi/EFI/Linux", "/boot/efi/EFI/Linux"}

// DefaultPCRSelection is the selection for this boot and the reason, from
// the event log at eventlogPath (the default when "") in the bank of algo
// (--sha1 changes the bank, nothing else). Without an event log the
// selection is the plain one.
func DefaultPCRSelection(eventlogPath string, algo PCRHashAlgo) (string, string) {
	if eventlogPath == "" {
		eventlogPath = DefaultEventlogPath
	}
	raw, err := readRawEventLogFromPath(eventlogPath)
	if err != nil {
		return "0e,2e,7e", "no event log to read: the firmware and the secure boot state"
	}
	log, err := attest.ParseEventLog(raw)
	if err != nil {
		return "0e,2e,7e", "the event log does not parse: the firmware and the secure boot state"
	}
	return defaultPCRSelection(log.Events(attestHash(algo)), findUKI())
}

// defaultPCRSelection decides from the events: systemd-stub's section
// measurements in PCR 11 mean a unified kernel image; "grub_cmd:" events in
// PCR 8 mean GRUB.
func defaultPCRSelection(events []attest.Event, uki string) (string, string) {
	stub, grub := false, false
	for _, e := range events {
		switch e.Index {
		case TPM2PCRKernelBoot:
			if t := eventText(e); strings.HasPrefix(t, ".") || t == EnterInitrdWord {
				stub = true
			}
		case 8:
			if strings.HasPrefix(eventText(e), "grub_cmd:") {
				grub = true
			}
		}
	}
	switch {
	case stub:
		spec := "11u"
		if uki != "" && uki != DefaultUKIPath {
			spec += ":" + uki
		}
		return "0e,2e,7e," + spec, "a unified kernel image booted: the firmware, the secure boot state, and PCR 11 computed from the image"
	case grub:
		return "0e,2e,7e,8e,9e", "GRUB booted: the firmware, the secure boot state, and GRUB's PCRs 8 and 9, predicted from grub.cfg"
	}
	return "0e,2e,7e", "the firmware and the secure boot state"
}

// findUKI is the unified kernel image's path: the default one when it
// exists, else the only .efi in one of the usual directories, else "".
func findUKI() string {
	if _, err := os.Stat(DefaultUKIPath); err == nil {
		return DefaultUKIPath
	}
	for _, dir := range ukiDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.efi"))
		if len(matches) == 1 {
			return matches[0]
		}
	}
	return ""
}
