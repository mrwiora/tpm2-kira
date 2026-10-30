package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"

	"github.com/google/go-attestation/attest"
)

// What 'slot add' seals to when nobody says. The boot's own event log decides:
// the firmware, its configuration and the secure boot state always (0, 2,
// 7); with a unified kernel image, PCR 11 computed from the image, so the
// code survives a kernel update by prediction; with GRUB, its PCRs 8 and
// 9, predicted from grub.cfg and the files it loads. And a second slot
// sealed to 0 and 7 alone - the fallback: when a kernel or boot loader
// change was not predicted, the firmware and the secure boot state still
// vouch for the machine, and that slot's code still shows.

// FallbackPCRSelection is what the fallback slot is sealed to; without an
// event log the registers as they are (FallbackRegisterSelection).
const FallbackPCRSelection = "0e,7e"

// FallbackRegisterSelection is the fallback selection read from the
// registers, for a machine whose event log cannot be read.
const FallbackRegisterSelection = "0,7"

// FallbackSlot is the slot the fallback goes into.
const FallbackSlot = 1

// ukiDirs are where a unified kernel image is looked for when the default
// path is not there.
var ukiDirs = []string{"/boot/EFI/Linux", "/efi/EFI/Linux", "/boot/efi/EFI/Linux"}

// DefaultPCRSelection is the selection for this boot and the reason, from
// the event log at eventlogPath (the default when "") in the bank of algo
// (--sha1 changes the bank, nothing else). Without an event log to read
// (a software TPM, a run without root) the selection is the registers as
// they are: nothing can be computed.
func DefaultPCRSelection(eventlogPath string, algo measure.PCRHashAlgo) (string, string) {
	if eventlogPath == "" {
		eventlogPath = measure.DefaultEventlogPath
	}
	raw, err := measure.ReadRawEventLogFromPath(eventlogPath)
	if err != nil {
		return "0,2,7", "no event log to read: the firmware and the secure boot state, as the registers hold them"
	}
	log, err := attest.ParseEventLog(raw)
	if err != nil {
		return "0,2,7", "the event log does not parse: the firmware and the secure boot state, as the registers hold them"
	}
	return defaultPCRSelection(log.Events(measure.AttestHash(algo)), findUKI())
}

// defaultFallbackSelection is the fallback slot's selection, from the
// event log when there is one to read.
func defaultFallbackSelection(eventlogPath string) string {
	if eventlogPath == "" {
		eventlogPath = measure.DefaultEventlogPath
	}
	if _, err := measure.ReadRawEventLogFromPath(eventlogPath); err != nil {
		return FallbackRegisterSelection
	}
	return FallbackPCRSelection
}

// defaultPCRSelection decides from the events: systemd-stub's section
// measurements in PCR 11 mean a unified kernel image; "grub_cmd:" events in
// PCR 8 mean GRUB.
func defaultPCRSelection(events []attest.Event, uki string) (string, string) {
	stub, grub := false, false
	for _, e := range events {
		switch e.Index {
		case measure.TPM2PCRKernelBoot:
			if t := measure.EventText(e); strings.HasPrefix(t, ".") || t == measure.EnterInitrdWord {
				stub = true
			}
		case 8:
			if strings.HasPrefix(measure.EventText(e), "grub_cmd:") {
				grub = true
			}
		}
	}
	switch {
	case stub:
		spec := "11u"
		if uki != "" && uki != measure.DefaultUKIPath {
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
	if _, err := os.Stat(measure.DefaultUKIPath); err == nil {
		return measure.DefaultUKIPath
	}
	for _, dir := range ukiDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.efi"))
		if len(matches) == 1 {
			return matches[0]
		}
	}
	return ""
}

// SealDefaults is 'slot add' without --pcrs and --nvram: slot 0 to what
// this boot measured and, with TOTP, slot 1 to the fallback selection -
// a second code for a boot whose kernel changed unpredicted, which only a
// code is for - with the signing key at the paths given ("" for the
// defaults).
func SealDefaults(tpmPath, pubKeyPath, privKeyPath string, algo measure.PCRHashAlgo, debug, withTOTP bool) error {
	sel, why := DefaultPCRSelection("", algo)
	fmt.Printf("PCRs: %s (%s)\n\n", sel, why)
	if err := Seal(tpmPath, sel, nvslot.ResolveNVRAMIndex(0), pubKeyPath, privKeyPath, debug, algo, true, withTOTP); err != nil {
		return err
	}
	if !withTOTP {
		return nil
	}
	return SealFallback(tpmPath, pubKeyPath, privKeyPath, algo, debug)
}

// SealFallback seals slot 1, the fallback, and says what it is for.
func SealFallback(tpmPath, pubKeyPath, privKeyPath string, algo measure.PCRHashAlgo, debug bool) error {
	fallback := defaultFallbackSelection("")
	fmt.Printf("\n=== Slot %d: the fallback, sealed to PCRs %s alone ===\n", FallbackSlot, fallback)
	fmt.Println("Its code shows in a boot whose kernel or boot loader changed unpredicted, as long")
	fmt.Println("as the firmware and the secure boot state are the same; it says the machine is")
	fmt.Println("not simply lost. Pair this one with your authenticator too.")
	fmt.Println()
	return Seal(tpmPath, fallback, nvslot.ResolveNVRAMIndex(FallbackSlot), pubKeyPath, privKeyPath, debug, algo, true, true)
}
