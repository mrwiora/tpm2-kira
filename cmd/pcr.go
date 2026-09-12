package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// PCR selection, parsing, reading and comparison.

// DisplayPCRMismatch shows the differences between expected and current PCR values
func DisplayPCRMismatch(pcrIndices []int, expectedDigests, currentDigests []tpm2.TPM2BDigest) {
	if len(expectedDigests) != len(currentDigests) {
		fmt.Printf("Error: PCR digest count mismatch (expected: %d, current: %d)\n", len(expectedDigests), len(currentDigests))
		return
	}

	fmt.Printf("PCRs used for sealing: %v\n", pcrIndices)
	fmt.Println()

	for i, pcrIndex := range pcrIndices {
		if i >= len(expectedDigests) || i >= len(currentDigests) {
			break
		}

		expected := expectedDigests[i].Buffer
		current := currentDigests[i].Buffer

		status := "✓ MATCH"
		if !bytes.Equal(expected, current) {
			status = "✗ CHANGED"
		}

		fmt.Printf("  PCR%-2d: %s - %s\n", pcrIndex, GetPCRDescription(pcrIndex), status)
		fmt.Printf("    Expected (blob):    %x\n", expected)
		fmt.Printf("    Current (register): %x\n", current)
	}
}

// VerifyPCRValues compares sealed and current PCR digest values
func VerifyPCRValues(sealed, current []tpm2.TPM2BDigest) bool {
	if len(sealed) != len(current) {
		return false
	}
	for i := range sealed {
		if !bytes.Equal(sealed[i].Buffer, current[i].Buffer) {
			return false
		}
	}
	return true
}

// CreatePCRSelection creates a TPMLPCRSelection structure for the given PCR indices
// using the specified hash algorithm for the PCR bank.
func CreatePCRSelection(pcrIndices []int, hashAlgo PCRHashAlgo) tpm2.TPMLPCRSelection {
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      hashAlgo.TPMAlg(),
				PCRSelect: PcrsToBitmapBytes(pcrIndices),
			},
		},
	}
}

// PcrsToBitmapBytes converts PCR indices to bitmap bytes
func PcrsToBitmapBytes(pcrIndices []int) []byte {
	bitmap := make([]byte, 3)
	for _, pcr := range pcrIndices {
		if pcr >= 0 && pcr < 24 {
			bitmap[pcr/8] |= 1 << (pcr % 8)
		}
	}
	return bitmap
}

// PCRSpec represents a PCR index with its source (register or eventlog)
type PCRSpec struct {
	Index   int
	Source  PCRSource
	Command string // Unified kernel image path (only when Source == PCRSourceUKI)
}

// ParsePCRSpecs parses a comma-separated string of PCR indices with optional source suffixes.
// Supported formats:
//
//	"0"              - register (default)
//	"0r"             - register (explicit)
//	"0e"             - eventlog (PCRs 0-12 only)
//	"11u"            - unified kernel image at the default path (PCR 11 only)
//	"11u:/path.efi"  - unified kernel image at an explicit path
func ParsePCRSpecs(pcrsStr string) ([]PCRSpec, error) {
	parts := strings.Split(pcrsStr, ",")
	specs := make([]PCRSpec, 0, len(parts))
	seen := make(map[int]bool)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		source := PCRSourceRegister
		command := ""
		numStr := part

		if uIdx := strings.Index(part, "u:"); uIdx > 0 {
			source = PCRSourceUKI
			command = part[uIdx+2:]
			numStr = part[:uIdx]
		} else if strings.HasSuffix(part, "e") {
			source = PCRSourceEventlog
			numStr = part[:len(part)-1]
		} else if strings.HasSuffix(part, "u") {
			source = PCRSourceUKI
			command = DefaultUKIPath
			numStr = part[:len(part)-1]
		} else if strings.HasSuffix(part, "r") {
			source = PCRSourceRegister
			numStr = part[:len(part)-1]
		}

		pcr, err := strconv.Atoi(numStr)
		if err != nil {
			return nil, fmt.Errorf("invalid PCR value '%s': %w", part, err)
		}
		if pcr < 0 || pcr >= 24 {
			return nil, fmt.Errorf("PCR value %d out of range (0-23)", pcr)
		}
		if source == PCRSourceEventlog && pcr > 12 {
			return nil, fmt.Errorf("eventlog source (e suffix) is only valid for PCRs 0-12, got PCR %d", pcr)
		}
		if source == PCRSourceUKI && pcr != 11 {
			return nil, fmt.Errorf("uki source (u suffix) is only valid for PCR 11, got PCR %d", pcr)
		}
		if source == PCRSourceUKI && command == "" {
			return nil, fmt.Errorf("uki source for PCR %d requires a path (format: %du:/path/to/uki.efi)", pcr, pcr)
		}
		if strings.Contains(part, "p:") {
			return nil, fmt.Errorf("the external predict source (p: suffix) has been removed; use %du or %du:/path/to/uki.efi instead", pcr, pcr)
		}
		if seen[pcr] {
			return nil, fmt.Errorf("duplicate PCR %d specified (each PCR index can only appear once)", pcr)
		}
		seen[pcr] = true

		specs = append(specs, PCRSpec{Index: pcr, Source: source, Command: command})
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("no PCRs specified")
	}
	return specs, nil
}

// ParsePCRs parses a comma-separated string of PCR indices (with optional suffixes) and
// returns only the indices. This is a convenience wrapper around ParsePCRSpecs for code
// that only needs PCR indices without source information.
func ParsePCRs(pcrsStr string) ([]int, error) {
	specs, err := ParsePCRSpecs(pcrsStr)
	if err != nil {
		return nil, err
	}
	pcrs := make([]int, len(specs))
	for i, spec := range specs {
		pcrs[i] = spec.Index
	}
	return pcrs, nil
}

// PCRSpecsToString converts a slice of PCRSpec back to the comma-separated string format.
// Register-source PCRs omit the suffix (e.g. "0"), eventlog-source PCRs use "e" (e.g. "0e"),
// UKI-source PCRs use "u:PATH" (e.g. "11u:/boot/EFI/Linux/arch-linux.efi").
func PCRSpecsToString(specs []PCRSpec) string {
	parts := make([]string, len(specs))
	for i, spec := range specs {
		switch spec.Source {
		case PCRSourceUKI:
			parts[i] = fmt.Sprintf("%du:%s", spec.Index, spec.Command)
		default:
			parts[i] = fmt.Sprintf("%d%s", spec.Index, spec.Source.Suffix())
		}
	}
	return strings.Join(parts, ",")
}

// PCRSpecIndices extracts just the PCR indices from a slice of PCRSpec
func PCRSpecIndices(specs []PCRSpec) []int {
	indices := make([]int, len(specs))
	for i, spec := range specs {
		indices[i] = spec.Index
	}
	return indices
}

// ShowPCRDetails attempts to show PCR comparison details for the given error.
// Reads current PCR values from TPM registers only (no eventlog/uki reconstruction).
// Returns true if PCR details were successfully shown, false otherwise.
func ShowPCRDetails(tpmDev transport.TPM, nvramIndex uint32, debug bool) bool {
	// Try to show PCR details
	sealedData, readErr := ReadFromNVRAM(tpmDev, nvramIndex)
	if readErr == nil {
		blob, unmarshalErr := UnmarshalSealedBlob(sealedData)
		if unmarshalErr == nil {
			currentPCRs, pcrErr := GetCurrentPCRValuesFromRegisters(tpmDev, blob, debug)
			if pcrErr == nil {
				fmt.Println("=== PCR Mismatch Details ===")
				DisplayPCRMismatch(blob.GetPCRIndices(), blob.GetPCRDigestValues(), currentPCRs)
				fmt.Println()
				return true
			}
		}
	}
	return false
}

// HandleTPMPolicyFailureWithPCRDetails handles TPM policy failures by showing PCR details and guidance
// Returns true if the error was handled (is a TPM policy failure), false otherwise
func HandleTPMPolicyFailureWithPCRDetails(err error, tpmDev transport.TPM, nvramIndex uint32, debug bool) bool {
	if !IsTPMPolicyFailure(err) {
		return false
	}

	// Show the original error
	fmt.Println(FormatKIRAError(err))
	fmt.Println()

	// Show PCR details
	ShowPCRDetails(tpmDev, nvramIndex, debug)

	// Show guidance
	fmt.Println("To fix this, run: tpm2-kira reseal --privkey /path/to/private.key")
	fmt.Println("(Provide the signing private key that corresponds to the public key used during sealing)")

	return true
}

// ReadPCRValuesResult holds the result of reading PCR values from all sources.
type ReadPCRValuesResult struct {
	Values         map[int][]byte // PCR index -> digest value (eventlog-calculated for eventlog PCRs, register value for register PCRs)
	RegisterValues map[int][]byte // PCR index -> actual register value (always from TPM register)
	EventlogInfo   *EventlogInfo  // eventlog metadata (nil when no eventlog PCRs)
}

// ReadPCRRegisters reads PCR values directly from TPM registers for the given
// indices. This is used on the unseal/reveal/run path where neither eventlog
// nor UKI files are available (e.g. early boot). The result maps each PCR
// index to its current register digest.
func ReadPCRRegisters(tpmDev transport.TPM, pcrIndices []int, hashAlgo PCRHashAlgo, debug bool) (map[int][]byte, error) {
	if len(pcrIndices) == 0 {
		return make(map[int][]byte), nil
	}

	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: CreatePCRSelection(pcrIndices, hashAlgo),
	}

	pcrReadResp, err := pcrRead.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCRs from %s bank: %w", hashAlgo.DisplayString(), err)
	}

	if len(pcrReadResp.PCRValues.Digests) < len(pcrIndices) {
		return nil, fmt.Errorf(
			"TPM did not return %s PCR values for PCRs %v.\n"+
				"The %s PCR bank may not be enabled on this system.\n"+
				"Available digests: %d, expected: %d",
			hashAlgo.DisplayString(), pcrIndices,
			hashAlgo.DisplayString(),
			len(pcrReadResp.PCRValues.Digests), len(pcrIndices))
	}

	result := make(map[int][]byte, len(pcrIndices))
	for i, pcrIndex := range pcrIndices {
		result[pcrIndex] = pcrReadResp.PCRValues.Digests[i].Buffer
	}

	if debug {
		fmt.Println("Register-read PCR values:")
		for _, idx := range pcrIndices {
			fmt.Printf("  PCR%d: %x\n", idx, result[idx])
		}
	}

	return result, nil
}

// TPMHasPCRBank reports whether the TPM exposes PCRs in the given bank.
func TPMHasPCRBank(tpmDev transport.TPM, algo PCRHashAlgo) bool {
	rsp, err := (tpm2.PCRRead{PCRSelectionIn: CreatePCRSelection([]int{0}, algo)}).Execute(tpmDev)
	if err != nil || len(rsp.PCRValues.Digests) == 0 {
		return false
	}
	return len(rsp.PCRValues.Digests[0].Buffer) == algo.DigestSize()
}

// registerFallbackSpecs returns the same selection with the given PCRs switched
// from the eventlog source to the register source.
func registerFallbackSpecs(specs []PCRSpec, indices []int) []PCRSpec {
	fallback := make([]PCRSpec, len(specs))
	copy(fallback, specs)
	for i := range fallback {
		if fallback[i].Source == PCRSourceEventlog && slices.Contains(indices, fallback[i].Index) {
			fallback[i].Source = PCRSourceRegister
		}
	}
	return fallback
}

// explainEventlogBankError turns a missing-bank condition into the concrete
// command to run instead, preferring the register source and only falling back
// to SHA-1 when the requested bank is unavailable on this TPM.
func explainEventlogBankError(tpmDev transport.TPM, specs []PCRSpec, hashAlgo PCRHashAlgo, bankErr *EventlogBankError) error {
	registerSpecs := registerFallbackSpecs(specs, bankErr.PCRIndices)

	msg := fmt.Sprintf(
		"cannot reconstruct PCR %s from the event log: %s.\n"+
			"Replaying them would yield each PCR's all-zero reset value, which this\n"+
			"system will never produce, so the sealed policy could never be satisfied.\n\n",
		formatPCRList(bankErr.PCRIndices), bankErr.Error())

	if TPMHasPCRBank(tpmDev, hashAlgo) {
		return fmt.Errorf("%s"+
			"PCRs 0-7 do not change between the measure point and seal time, so reading\n"+
			"them from the TPM registers gives the same value and the same protection.\n\n"+
			"Try instead:\n\n    tpm2-kira seal --pcrs \"%s\"\n",
			msg, PCRSpecsToString(registerSpecs))
	}

	if bankErr.HasSHA1() && hashAlgo != PCRHashAlgoSHA1 {
		return fmt.Errorf("%s"+
			"This TPM has no %s PCR bank either, so the register source cannot be used.\n"+
			"The only remaining option is the SHA-1 bank:\n\n"+
			"    tpm2-kira seal --sha1 --pcrs \"%s\"\n\n"+
			"WARNING: SHA-1 is broken against collision attacks and is deprecated for\n"+
			"new deployments. Prefer firmware that provides a SHA-256 event log, or a\n"+
			"TPM with a SHA-256 PCR bank, and treat this as a stopgap.\n",
			msg, hashAlgo.DisplayString(), PCRSpecsToString(specs))
	}

	return fmt.Errorf("%s"+
		"This TPM has no %s PCR bank either, and the event log offers no usable\n"+
		"alternative, so these PCRs cannot be used for sealing on this machine.\n",
		msg, hashAlgo.DisplayString())
}

// ReadPCRValues reads PCR values from their respective sources (eventlog, UKI
// UKI and/or TPM registers). This is the single shared implementation used by seal,
// unseal, reveal and reseal paths.
//
// Values describe tpm2-kira's measure point in the initrd, which is where the TPM
// checks the policy, not the end of firmware and not the running system.
func ReadPCRValues(tpmDev transport.TPM, specs []PCRSpec, hashAlgo PCRHashAlgo, mode MeasurePointMode, debug bool) (*ReadPCRValuesResult, error) {
	// Separate PCRs by source
	var eventlogPCRIndices []int
	var ukiPCRIndices []int
	var registerPCRIndices []int
	for _, spec := range specs {
		switch spec.Source {
		case PCRSourceEventlog:
			eventlogPCRIndices = append(eventlogPCRIndices, spec.Index)
		case PCRSourceUKI:
			ukiPCRIndices = append(ukiPCRIndices, spec.Index)
		default:
			registerPCRIndices = append(registerPCRIndices, spec.Index)
		}
	}

	result := &ReadPCRValuesResult{
		Values:         make(map[int][]byte),
		RegisterValues: make(map[int][]byte),
	}

	// Calculate eventlog-based PCR values
	if len(eventlogPCRIndices) > 0 {
		calc := NewEventlogPCRCalculator(tpmDev, eventlogPCRIndices, hashAlgo, debug)
		calculatedPCRs, info, err := calc.CalculatePCRsFromEventlog()
		if err != nil {
			var bankErr *EventlogBankError
			if errors.As(err, &bankErr) {
				return nil, explainEventlogBankError(tpmDev, specs, hashAlgo, bankErr)
			}
			return nil, fmt.Errorf("failed to calculate PCRs from eventlog: %w", err)
		}
		result.EventlogInfo = info

		replay := make(map[int][]byte, len(calculatedPCRs))
		for idx, val := range calculatedPCRs {
			result.Values[idx] = val
			replay[idx] = val
		}

		if debug {
			fmt.Println("Eventlog-calculated PCR values (end of firmware):")
			for _, idx := range eventlogPCRIndices {
				fmt.Printf("  PCR%d: %x\n", idx, result.Values[idx])
			}
		}

		// Also read the actual register values for eventlog PCRs
		registers, err := ReadPCRRegisters(tpmDev, eventlogPCRIndices, hashAlgo, debug)
		if err != nil {
			return nil, err
		}
		for idx, val := range registers {
			result.RegisterValues[idx] = val
		}

		apply := mode == MeasurePointOn
		detection := "explicit (--measure-point=on)"
		switch mode {
		case MeasurePointOff:
			detection = "explicit (--measure-point=off)"
		case MeasurePointAuto:
			detected, how, detectErr := DetectMeasurePointExtends(replay, result.RegisterValues, hashAlgo, debug)
			if detectErr != nil {
				return nil, detectErr
			}
			apply, detection = detected, how
		}
		if apply {
			applied := ApplyMeasurePointExtends(result.Values, eventlogPCRIndices, hashAlgo, debug)
			if result.EventlogInfo != nil {
				result.EventlogInfo.MeasurePointExtends = applied
			}
		}
		if result.EventlogInfo != nil {
			result.EventlogInfo.MeasurePointDetection = detection
		}

		if debug {
			fmt.Println("Eventlog PCR values at the measure point:")
			for _, idx := range eventlogPCRIndices {
				fmt.Printf("  PCR%d: %x (register now: %x)\n", idx, result.Values[idx], result.RegisterValues[idx])
			}
		}
	}

	// Compute UKI-based PCR values natively: parse the image and replay the
	// section measurements systemd-stub performs, then the boot phases already
	// measured by the time tpm2-kira runs.
	if len(ukiPCRIndices) > 0 {
		for _, spec := range specs {
			if spec.Source != PCRSourceUKI {
				continue
			}
			value, err := PredictPCR11FromUKI(spec.Command, MeasurePointPhases, hashAlgo, debug)
			if err != nil {
				return nil, fmt.Errorf("failed to compute PCR %d from unified kernel image: %w", spec.Index, err)
			}
			result.Values[spec.Index] = value
		}

		registers, err := ReadPCRRegisters(tpmDev, ukiPCRIndices, hashAlgo, debug)
		if err != nil {
			return nil, err
		}
		for idx, val := range registers {
			result.RegisterValues[idx] = val
		}

		if debug {
			fmt.Println("UKI-computed PCR values:")
			for _, idx := range ukiPCRIndices {
				fmt.Printf("  PCR%d: %x\n", idx, result.Values[idx])
			}
		}
	}

	// Read register-based PCR values from TPM
	if len(registerPCRIndices) > 0 {
		registers, err := ReadPCRRegisters(tpmDev, registerPCRIndices, hashAlgo, debug)
		if err != nil {
			return nil, err
		}
		for idx, val := range registers {
			result.Values[idx] = val
			result.RegisterValues[idx] = val
		}
	}

	return result, nil
}

// GetCurrentPCRValues retrieves current PCR values for comparison, handling
// eventlog-based, UKI-based, and direct TPM reads. The hash algorithm is
// automatically detected from the sealed blob's digest sizes. Results are
// returned in the same order as the blob's PCR digests.
// NOTE: This uses source-aware reading (eventlog/uki/register). For the
// unseal/reveal/run path use GetCurrentPCRValuesFromRegisters instead.
func GetCurrentPCRValues(tpmDev transport.TPM, sealedBlob *SealedBlob, debug bool) ([]tpm2.TPM2BDigest, error) {
	hashAlgo := sealedBlob.GetHashAlgo()
	specs := sealedBlob.GetPCRSpecs()

	readResult, err := ReadPCRValues(tpmDev, specs, hashAlgo, sealedBlob.MeasurePointMode(), debug)
	if err != nil {
		return nil, err
	}

	// Map results back to blob PCR digest order
	currentPCRValues := make([]tpm2.TPM2BDigest, len(sealedBlob.Payload.PCRDigests))
	for i, pair := range sealedBlob.Payload.PCRDigests {
		if val, ok := readResult.Values[pair.Index]; ok {
			currentPCRValues[i] = tpm2.TPM2BDigest{Buffer: val}
		}
	}

	return currentPCRValues, nil
}

// GetCurrentPCRValuesFromRegisters reads current PCR values directly from TPM
// registers, regardless of the original PCR source stored in the blob. This is
// used on the unseal/reveal/run path so that neither the eventlog file nor
// the unified kernel image are required (critical for early-boot).
// Results are returned in the same order as the blob's PCR digests.
func GetCurrentPCRValuesFromRegisters(tpmDev transport.TPM, sealedBlob *SealedBlob, debug bool) ([]tpm2.TPM2BDigest, error) {
	hashAlgo := sealedBlob.GetHashAlgo()
	pcrIndices := sealedBlob.GetPCRIndices()

	regValues, err := ReadPCRRegisters(tpmDev, pcrIndices, hashAlgo, debug)
	if err != nil {
		return nil, err
	}

	// Map results back to blob PCR digest order
	currentPCRValues := make([]tpm2.TPM2BDigest, len(sealedBlob.Payload.PCRDigests))
	for i, pair := range sealedBlob.Payload.PCRDigests {
		if val, ok := regValues[pair.Index]; ok {
			currentPCRValues[i] = tpm2.TPM2BDigest{Buffer: val}
		}
	}

	return currentPCRValues, nil
}
