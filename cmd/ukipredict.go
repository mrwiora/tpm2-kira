package cmd

import (
	"bytes"
	"debug/pe"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm/tpm2/transport"
)

// DefaultUKIPath is the conventional unified kernel image location.
const DefaultUKIPath = "/boot/EFI/Linux/arch-linux.efi"

// TPM2PCRKernelBoot is the PCR systemd-stub measures the unified kernel image into.
const TPM2PCRKernelBoot = 11

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
		if section == nil {
			continue
		}
		// debug/pe's Section.Size is SizeOfRawData, which is padded up to the
		// file alignment; systemd-stub measures the unpadded contents.
		size := int64(section.VirtualSize)
		if size == 0 || size > int64(section.Size) {
			size = int64(section.Size)
		}
		if size == 0 {
			continue
		}

		pcr = ExtendDigest(algo, pcr, DigestOf(algo, append([]byte(name), 0)))

		hasher := newHashFor(algo)
		reader := section.Open()
		if _, err := io.CopyN(hasher, reader, size); err != nil {
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

// VerifyUKIPredictionAgainstEventlog recomputes PCR 11 for a unified kernel
// image and compares it with the firmware event log replay. It proves that the
// section set, order and digest scheme used here match what the running
// systemd-stub actually did, before that scheme is trusted for a policy.
//
// replayPCR11 must be the bare event log replay, without measure-point extends.
func VerifyUKIPredictionAgainstEventlog(ukiPath string, replayPCR11 []byte, algo PCRHashAlgo, debug bool) error {
	predicted, err := PredictPCR11FromUKI(ukiPath, nil, algo, debug)
	if err != nil {
		return err
	}
	if !bytes.Equal(predicted, replayPCR11) {
		return fmt.Errorf(
			"UKI section measurement does not reproduce this boot's event log:\n"+
				"  computed from %s : %x\n"+
				"  event log replay      : %x\n"+
				"Either the image on disk is not the one that booted (rebuild the\n"+
				"initramfs, reboot, then seal), or tpm2-kira models systemd-stub's\n"+
				"measurements incorrectly. Sealing now would bind PCR 11 to a value\n"+
				"that cannot be checked against anything this machine has produced.\n"+
				"Pass --verify-uki=false to seal anyway.",
			ukiPath, predicted, replayPCR11)
	}
	if debug {
		fmt.Printf("UKI computation verified against the event log for PCR 11 (%x)\n", predicted)
	}
	return nil
}

// VerifyUKISpecsAgainstEventlog checks every UKI-source spec against the running
// system's firmware event log. Skipped, with a notice, when the log cannot be
// read — an unreadable log is not evidence of a wrong computation.
func VerifyUKISpecsAgainstEventlog(tpmDev transport.TPM, specs []PCRSpec, algo PCRHashAlgo, debug bool) error {
	var ukiPaths []string
	for _, spec := range specs {
		if spec.Source == PCRSourceUKI {
			ukiPaths = append(ukiPaths, spec.Command)
		}
	}
	if len(ukiPaths) == 0 {
		return nil
	}

	calc := NewEventlogPCRCalculator(tpmDev, []int{TPM2PCRKernelBoot}, algo, debug)
	values, _, err := calc.CalculatePCRsFromEventlog()
	if err != nil {
		fmt.Printf("Note: cannot verify the UKI computation against the event log (%v); skipping\n", err)
		return nil
	}
	replay, ok := values[TPM2PCRKernelBoot]
	if !ok {
		fmt.Println("Note: event log contains no PCR 11 events; skipping UKI verification")
		return nil
	}

	for _, path := range ukiPaths {
		if err := VerifyUKIPredictionAgainstEventlog(path, replay, algo, debug); err != nil {
			return err
		}
	}
	fmt.Println("UKI PCR 11 computation verified against this boot's event log")
	return nil
}
