package cmd

import (
	"bytes"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
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

// ukiMeasurement is one digest systemd-stub extends into PCR 11, labelled by
// what produced it so a mismatch can be attributed to a specific section.
type ukiMeasurement struct {
	Section string
	Kind    string // "name" or "content"
	Digest  []byte
}

// ukiSectionMeasurements returns, in order, the digests systemd-stub extends
// for the given image: per present section the NUL-terminated ASCII name, then
// the section content. The firmware event log renders the name as UTF-16, but
// the digest is over the ASCII form.
func ukiSectionMeasurements(ukiPath string, algo PCRHashAlgo) ([]ukiMeasurement, error) {
	if _, err := os.Stat(ukiPath); err != nil {
		return nil, fmt.Errorf("unified kernel image %s: %w", ukiPath, err)
	}

	file, err := pe.Open(ukiPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s as a PE image: %w", ukiPath, err)
	}
	defer file.Close()

	var measurements []ukiMeasurement
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

		hasher := newHashFor(algo)
		if _, err := io.CopyN(hasher, section.Open(), size); err != nil {
			return nil, fmt.Errorf("failed to read section %s of %s: %w", name, ukiPath, err)
		}

		measurements = append(measurements,
			ukiMeasurement{Section: name, Kind: "name", Digest: DigestOf(algo, append([]byte(name), 0))},
			ukiMeasurement{Section: name, Kind: "content", Digest: hasher.Sum(nil)},
		)
	}

	if len(measurements) == 0 {
		return nil, fmt.Errorf("%s contains none of the sections systemd-stub measures; is it a unified kernel image?", ukiPath)
	}
	return measurements, nil
}

// PredictPCR11FromUKI computes the PCR 11 value that systemd-stub produces for
// the given unified kernel image, followed by the given boot phases.
func PredictPCR11FromUKI(ukiPath string, phases []string, algo PCRHashAlgo, debug bool) ([]byte, error) {
	measurements, err := ukiSectionMeasurements(ukiPath, algo)
	if err != nil {
		return nil, err
	}

	pcr := make([]byte, algo.DigestSize())
	for _, m := range measurements {
		pcr = ExtendDigest(algo, pcr, m.Digest)
		if debug && m.Kind == "content" {
			fmt.Printf("  measured %-9s -> %x\n", m.Section, pcr)
		}
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
// ukiChangedSinceBoot reports whether the image was written after this system
// booted. If so it cannot be the image that booted, so a measurement mismatch
// is expected rather than evidence of a wrong computation.
func ukiChangedSinceBoot(ukiPath string) (bool, error) {
	info, err := os.Stat(ukiPath)
	if err != nil {
		return false, err
	}
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return false, err
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return false, fmt.Errorf("/proc/uptime is empty")
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return false, fmt.Errorf("could not parse /proc/uptime: %w", err)
	}
	bootTime := time.Now().Add(-time.Duration(seconds * float64(time.Second)))
	return info.ModTime().After(bootTime), nil
}

// VerifyUKIPredictionAgainstEventlog checks tpm2-kira's UKI measurement against
// what the running systemd-stub actually recorded, comparing measurement by
// measurement so a mismatch can be attributed.
//
// A structural difference (section set or order) means the model is wrong and is
// always fatal. A content difference for an image that was rebuilt after boot
// only means the check is not applicable, and is reported as a warning.
func VerifyUKIPredictionAgainstEventlog(ukiPath string, logDigests [][]byte, algo PCRHashAlgo, debug bool) error {
	measurements, err := ukiSectionMeasurements(ukiPath, algo)
	if err != nil {
		return err
	}

	rebuilt, mtimeErr := ukiChangedSinceBoot(ukiPath)
	notApplicable := func(reason string) error {
		if mtimeErr != nil {
			return fmt.Errorf("%s\nCould not establish whether %s was rebuilt since boot (%v), so this\n"+
				"cannot be distinguished from a wrong computation. Reboot into this image\n"+
				"and seal again, or pass --verify-uki=false.", reason, ukiPath, mtimeErr)
		}
		if !rebuilt {
			return fmt.Errorf("%s\n%s has NOT been modified since this system booted, so it should be the\n"+
				"image that booted. tpm2-kira's model of systemd-stub's measurements is\n"+
				"therefore wrong. Sealing would bind PCR 11 to a value this machine will\n"+
				"never produce. Pass --verify-uki=false to seal anyway.", reason, ukiPath)
		}
		fmt.Printf("Note: %s\n", reason)
		fmt.Printf("Note: %s was rebuilt after this boot, so it cannot be verified against the\n"+
			"      current event log. PCR 11 will only be correct once you boot this image.\n", ukiPath)
		return nil
	}

	for i, m := range measurements {
		if i >= len(logDigests) {
			return fmt.Errorf(
				"this image produces %d PCR 11 measurements but this boot's event log has only %d;\n"+
					"the first unmatched one is %s (%s). systemd-stub's section set or order differs\n"+
					"from what tpm2-kira models. Pass --verify-uki=false to seal anyway.",
				len(measurements), len(logDigests), m.Section, m.Kind)
		}
		if bytes.Equal(m.Digest, logDigests[i]) {
			continue
		}
		if m.Kind == "name" {
			return fmt.Errorf(
				"PCR 11 measurement %d should be the name of section %s but the event log records\n"+
					"a different digest. systemd-stub's section set or order differs from what\n"+
					"tpm2-kira models. Pass --verify-uki=false to seal anyway.", i, m.Section)
		}
		return notApplicable(fmt.Sprintf(
			"section %s of %s does not match what this boot measured", m.Section, ukiPath))
	}

	if len(logDigests) > len(measurements) {
		return fmt.Errorf(
			"this boot's event log has %d PCR 11 measurements but this image produces only %d;\n"+
				"systemd-stub measured sections that tpm2-kira does not model.\n"+
				"Pass --verify-uki=false to seal anyway.", len(logDigests), len(measurements))
	}

	if debug {
		fmt.Printf("UKI computation verified against the event log across %d measurements\n", len(measurements))
	}
	return nil
}

// VerifyUKISpecsAgainstEventlog checks every UKI-source spec against the running
// system's firmware event log. Skipped, with a notice, when the log cannot be
// read — an unreadable log is not evidence of a wrong computation.
func VerifyUKISpecsAgainstEventlog(specs []PCRSpec, algo PCRHashAlgo, debug bool) error {
	var ukiPaths []string
	for _, spec := range specs {
		if spec.Source == PCRSourceUKI {
			ukiPaths = append(ukiPaths, spec.Command)
		}
	}
	if len(ukiPaths) == 0 {
		return nil
	}

	digests, err := EventDigestsForPCR(DefaultEventlogPath, TPM2PCRKernelBoot, algo)
	if err != nil {
		fmt.Printf("Note: cannot verify the UKI computation against the event log (%v); skipping\n", err)
		return nil
	}
	if len(digests) == 0 {
		fmt.Println("Note: event log contains no PCR 11 measurements; skipping UKI verification")
		return nil
	}

	verified := 0
	for _, path := range ukiPaths {
		if err := VerifyUKIPredictionAgainstEventlog(path, digests, algo, debug); err != nil {
			return err
		}
		verified++
	}
	if verified > 0 {
		fmt.Println("UKI PCR 11 computation checked against this boot's event log")
	}
	return nil
}
