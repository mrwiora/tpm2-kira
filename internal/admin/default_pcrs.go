package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
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
// vouch for the machine, and that slot's code still shows. One rule for
// every slot: PCR 7 and the image's PCRs; slot 0 adds the platform (0, 2).
// On GRUB, Secure Boot checks GRUB and the kernel, not GRUB's command line
// or the initrd, so someone at the console edits the entry (break=,
// rdinit=/bin/sh) and has a shell before the close, with PCRs 0 and 7 as
// approved: there the image's PCRs are 8 and 9 (GRUBPCRs), which see that
// edit, and the fallback is 7, 8 and 9 - a slot without 8 and 9 is
// refused.

// FallbackPCRSelection is what the fallback slot is sealed to; without an
// event log the registers as they are (FallbackRegisterSelection); on a
// GRUB boot GRUBFallbackPCRSelection.
const FallbackPCRSelection = "0e,7e"

// GRUBFallbackPCRSelection is the fallback slot's selection on a GRUB
// boot: the secure boot state and GRUB's PCRs 8 and 9.
const GRUBFallbackPCRSelection = "7e,8e,9e"

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

// grubBootWhy begins DefaultPCRSelection's reason on a GRUB boot.
const grubBootWhy = "GRUB booted"

// GRUBPCRs are the PCRs every slot includes on a GRUB boot: 8, GRUB's
// commands and the kernel command line, and 9, the files it loads (the
// initrd).
var GRUBPCRs = []int{8, 9}

// grubSelectionWhy is why a slot without GRUBPCRs is refused on GRUB.
const grubSelectionWhy = "on a GRUB boot every slot includes PCRs 8 and 9: Secure Boot does not cover GRUB's command line and the initrd, so an entry edited at the console (break=, rdinit=) reaches a shell before the close with PCRs 0 and 7 unchanged"

// GRUBBoot says whether this boot was GRUB's, from its event log ("" for
// the default): GRUB's "grub_cmd:" events in PCR 8. Without a log to
// read, false.
func GRUBBoot(eventlogPath string) bool {
	if eventlogPath == "" {
		eventlogPath = measure.DefaultEventlogPath
	}
	raw, err := measure.ReadRawEventLogFromPath(eventlogPath)
	if err != nil {
		return false
	}
	log, err := attest.ParseEventLog(raw)
	if err != nil {
		return false
	}
	for _, algo := range []measure.PCRHashAlgo{measure.PCRHashAlgoSHA256, measure.PCRHashAlgoSHA1} {
		if events := log.Events(measure.AttestHash(algo)); len(events) > 0 {
			_, grub := bootKind(events)
			return grub
		}
	}
	return false
}

// checkGRUBSelection refuses, on a GRUB boot, a selection that lacks PCR
// 8 or 9.
func checkGRUBSelection(specs []measure.PCRSpec, grub bool) error {
	if !grub {
		return nil
	}
	for _, want := range GRUBPCRs {
		found := false
		for _, s := range specs {
			found = found || s.Index == want
		}
		if !found {
			return fmt.Errorf("PCR %d is not selected: %s", want, grubSelectionWhy)
		}
	}
	return nil
}

// grubCfgPath is GRUB's configuration, as update-grub writes it. A var:
// the tests point it elsewhere.
var grubCfgPath = "/boot/grub/grub.cfg"

// GRUBAdvice is how GRUB's entries are kept from being edited at the
// console - advised, never written: a superuser with a PBKDF2 password,
// and the menu entries booted without it.
const GRUBAdvice = "set a GRUB superuser password: 'set superusers=\"root\"' and 'password_pbkdf2 root <hash of grub-mkpasswd-pbkdf2>' in /etc/grub.d/40_custom, the menu entries --unrestricted (CLASS in /etc/grub.d/10_linux), then update-grub"

// GRUBPassword says whether grub.cfg at path asks for a superuser's
// password before an entry is edited: a 'set superusers=' and a
// 'password_pbkdf2' line.
func GRUBPassword(path string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	users, pbkdf2 := false, false
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		users = users || strings.HasPrefix(l, "set superusers=")
		pbkdf2 = pbkdf2 || strings.HasPrefix(l, "password_pbkdf2 ")
	}
	return users && pbkdf2, nil
}

// defaultFallbackSelection is the fallback slot's selection, from the
// event log when there is one to read: GRUBFallbackPCRSelection on a GRUB
// boot.
func defaultFallbackSelection(eventlogPath string) string {
	if eventlogPath == "" {
		eventlogPath = measure.DefaultEventlogPath
	}
	if _, err := measure.ReadRawEventLogFromPath(eventlogPath); err != nil {
		return FallbackRegisterSelection
	}
	if GRUBBoot(eventlogPath) {
		return GRUBFallbackPCRSelection
	}
	return FallbackPCRSelection
}

// isFallbackSelection says whether specs are a fallback slot's: PCRs 0
// and 7 alone, or 7, 8 and 9 alone (GRUB).
func isFallbackSelection(specs []measure.PCRSpec) bool {
	var idx []int
	for _, s := range specs {
		idx = append(idx, s.Index)
	}
	sort.Ints(idx)
	return slices.Equal(idx, []int{0, 7}) || slices.Equal(idx, []int{7, 8, 9})
}

// defaultPCRSelection decides from the events: systemd-stub's section
// measurements in PCR 11 mean a unified kernel image; "grub_cmd:" events in
// PCR 8 mean GRUB.
func defaultPCRSelection(events []attest.Event, uki string) (string, string) {
	stub, grub := bootKind(events)
	switch {
	case stub:
		spec := "11u"
		if uki != "" && uki != measure.DefaultUKIPath {
			spec += ":" + uki
		}
		return "0e,2e,7e," + spec, "a unified kernel image booted: the firmware, the secure boot state, and PCR 11 computed from the image"
	case grub:
		return "0e,2e,7e,8e,9e", grubBootWhy + ": the firmware, the secure boot state, and GRUB's PCRs 8 and 9, predicted from grub.cfg"
	}
	return "0e,2e,7e", "the firmware and the secure boot state"
}

// bootKind says from the events whether a unified kernel image (systemd-
// stub's measurements in PCR 11) or GRUB ("grub_cmd:" in PCR 8) booted.
func bootKind(events []attest.Event) (stub, grub bool) {
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
	return stub, grub
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
// defaults). On a GRUB boot the fallback is 7, 8 and 9 (GRUBPCRs).
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
	if fallback == GRUBFallbackPCRSelection {
		fmt.Println("Its code shows in a boot whose firmware or option ROMs changed unpredicted, as long")
		fmt.Println("as the secure boot state and GRUB's measurements are the same (on GRUB no slot")
		fmt.Println("may lack PCRs 8 and 9); it says the machine is not simply lost.")
	} else {
		fmt.Println("Its code shows in a boot whose kernel or boot loader changed unpredicted, as long")
		fmt.Println("as the firmware and the secure boot state are the same; it says the machine is")
		fmt.Println("not simply lost.")
	}
	fmt.Println("Pair this one with your authenticator too.")
	fmt.Println()
	return Seal(tpmPath, fallback, nvslot.ResolveNVRAMIndex(FallbackSlot), pubKeyPath, privKeyPath, debug, algo, true, true)
}
