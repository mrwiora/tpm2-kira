package cmd

import (
	"debug/pe"
	"fmt"
	"io"
	"os"
)

// DefaultUKIPath is the conventional unified kernel image location.
const DefaultUKIPath = "/boot/EFI/Linux/arch-linux.efi"

// Order in which systemd-stub measures unified kernel image sections into
// PCR 11. ".pcrsig" is deliberately absent: it carries the signature over
// these very measurements and is therefore never itself measured.
var ukiMeasuredSections = []string{
	".linux",
	".osrel",
	".cmdline",
	".initrd",
	".ucode",
	".splash",
	".dtb",
	".uname",
	".sbat",
	".pcrpkey",
}

// MeasurePointPhases are the boot phases systemd has already measured into
// PCR 11 by the time tpm2-kira runs. systemd-pcrphase-initrd is ordered before
// cryptsetup-pre.target, and tpm2-kira orders itself after it.
var MeasurePointPhases = []string{EnterInitrdWord}

// PredictPCR11FromUKI computes the PCR 11 value that systemd-stub produces for
// the given unified kernel image, followed by the given boot phases.
//
// systemd-stub measures each present section twice: first the NUL-terminated
// ASCII section name, then the section content. The firmware event log renders
// the name as UTF-16, but the digest is over the ASCII form.
func PredictPCR11FromUKI(ukiPath string, phases []string, algo PCRHashAlgo, debug bool) ([]byte, error) {
	if _, err := os.Stat(ukiPath); err != nil {
		return nil, fmt.Errorf("unified kernel image %s: %w", ukiPath, err)
	}

	file, err := pe.Open(ukiPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s as a PE image: %w", ukiPath, err)
	}
	defer file.Close()

	pcr := make([]byte, algo.DigestSize())
	measured := 0

	for _, name := range ukiMeasuredSections {
		section := file.Section(name)
		if section == nil || section.Size == 0 {
			continue
		}

		pcr = ExtendDigest(algo, pcr, DigestOf(algo, append([]byte(name), 0)))

		hasher := newHashFor(algo)
		reader := section.Open()
		if _, err := io.CopyN(hasher, reader, int64(section.Size)); err != nil {
			return nil, fmt.Errorf("failed to read section %s of %s: %w", name, ukiPath, err)
		}
		pcr = ExtendDigest(algo, pcr, hasher.Sum(nil))
		measured++

		if debug {
			fmt.Printf("  measured %-9s (%d bytes) -> %x\n", name, section.Size, pcr)
		}
	}

	if measured == 0 {
		return nil, fmt.Errorf("%s contains none of the sections systemd-stub measures; is it a unified kernel image?", ukiPath)
	}

	for _, phase := range phases {
		pcr = ExtendDigest(algo, pcr, DigestOf(algo, []byte(phase)))
		if debug {
			fmt.Printf("  phase    %-9s -> %x\n", phase, pcr)
		}
	}

	return pcr, nil
}

// VerifyUKIPredictionAgainstEventlog recomputes PCR 11 for the currently booted
// image and compares it with the event log replay. It proves that the section
// order and digest scheme used here match what the running systemd-stub did,
// before that scheme is trusted for a not-yet-booted image.
//
// replayPCR11 must be the bare event log replay, without measure-point extends.
func VerifyUKIPredictionAgainstEventlog(ukiPath string, replayPCR11 []byte, algo PCRHashAlgo, debug bool) error {
	predicted, err := PredictPCR11FromUKI(ukiPath, nil, algo, debug)
	if err != nil {
		return err
	}
	if string(predicted) != string(replayPCR11) {
		return fmt.Errorf(
			"UKI section measurement does not reproduce the event log for the running system:\n"+
				"  computed from %s: %x\n"+
				"  event log replay   : %x\n"+
				"systemd-stub's section set or order differs from what tpm2-kira models",
			ukiPath, predicted, replayPCR11)
	}
	if debug {
		fmt.Printf("UKI prediction matches the event log replay for PCR 11 (%x)\n", predicted)
	}
	return nil
}
