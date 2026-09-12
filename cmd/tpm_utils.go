package cmd

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	// AppNVRAMStart is the start of the safe NVRAM index range for application use
	AppNVRAMStart = 0x01803000
	// AppNVRAMEnd is the end of the safe NVRAM index range for application use
	AppNVRAMEnd = 0x01803FFF
)

// ValidateNVRAMIndex checks that the given NVRAM index is within the safe application range.
// Indices outside this range may belong to platform firmware, other applications, or
// reserved TPM hierarchy ranges and must not be accessed to prevent data destruction.
func ValidateNVRAMIndex(index uint32) error {
	if index < AppNVRAMStart || index > AppNVRAMEnd {
		return fmt.Errorf("NVRAM index 0x%08X is outside the safe application range (0x%08X-0x%08X)", index, AppNVRAMStart, AppNVRAMEnd)
	}
	return nil
}

// CleanupTPM flushes all transient handles and sessions to free TPM memory
func CleanupTPM(tpmDev transport.TPM, debug bool) {
	if err := flushAllTransientHandles(tpmDev); err != nil {
		if debug {
			fmt.Printf("Warning: failed to flush transient handles: %v\n", err)
		}
	}
	if err := flushAllSessions(tpmDev); err != nil {
		if debug {
			fmt.Printf("Warning: failed to flush sessions: %v\n", err)
		}
	}
}

// flushAllTransientHandles flushes all transient object handles to free TPM memory
func flushAllTransientHandles(tpmDev transport.TPM) error {
	getCap := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTTransient) << 24,
		PropertyCount: 128,
	}

	capResp, err := getCap.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to get transient handles: %w", err)
	}

	handleList, err := capResp.CapabilityData.Data.Handles()
	if err != nil {
		return fmt.Errorf("failed to parse handle list: %w", err)
	}

	for _, handle := range handleList.Handle {
		flushCmd := tpm2.FlushContext{FlushHandle: handle}
		_, _ = flushCmd.Execute(tpmDev) // Ignore errors, some handles might not be flushable
	}

	return nil
}

// flushAllSessions flushes all loaded sessions to free TPM session memory
func flushAllSessions(tpmDev transport.TPM) error {
	getCap := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTLoadedSession) << 24,
		PropertyCount: 128,
	}

	capResp, err := getCap.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to get session handles: %w", err)
	}

	handleList, err := capResp.CapabilityData.Data.Handles()
	if err != nil {
		return fmt.Errorf("failed to parse session handle list: %w", err)
	}

	for _, handle := range handleList.Handle {
		flushCmd := tpm2.FlushContext{FlushHandle: handle}
		_, _ = flushCmd.Execute(tpmDev) // Ignore errors
	}

	return nil
}

// DisplayPCRMismatch shows the differences between expected and current PCR values
// DisplayPCRMismatch is deprecated - use PrintKIRAError instead
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

		match := true
		if len(expected) != len(current) {
			match = false
		} else {
			for j := range expected {
				if expected[j] != current[j] {
					match = false
					break
				}
			}
		}

		status := "✓ MATCH"
		if !match {
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
		if len(sealed[i].Buffer) != len(current[i].Buffer) {
			return false
		}
		for j := range sealed[i].Buffer {
			if sealed[i].Buffer[j] != current[i].Buffer[j] {
				return false
			}
		}
	}
	return true
}

// CreatePCRPolicySession creates a TPM policy session for PCR authentication.
// The policy session always uses SHA256 for the policy digest, but the PCR bank
// selection uses the specified hash algorithm.
func CreatePCRPolicySession(tpmDev transport.TPM, pcrIndices []int, hashAlgo PCRHashAlgo) (tpm2.Session, func() error, error) {
	sess, cleanup, err := tpm2.PolicySession(tpmDev, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create policy session: %w", err)
	}

	// Apply PCR policy using the specified PCR bank hash algorithm
	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      hashAlgo.TPMAlg(),
					PCRSelect: PcrsToBitmapBytes(pcrIndices),
				},
			},
		},
	}.Execute(tpmDev)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to apply PCR policy: %w", err)
	}

	return sess, cleanup, nil
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

// ComputePolicyDigest computes the policy digest for the given PCR indices
// using the specified hash algorithm for PCR bank selection.
func ComputePolicyDigest(tpmDev transport.TPM, pcrs []int, hashAlgo PCRHashAlgo) (tpm2.TPM2BDigest, error) {
	sess, cleanup, err := tpm2.PolicySession(tpmDev, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to create policy session: %w", err)
	}
	defer cleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      hashAlgo.TPMAlg(),
					PCRSelect: PcrsToBitmapBytes(pcrs),
				},
			},
		},
	}.Execute(tpmDev)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to apply PCR policy: %w", err)
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(tpmDev)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to get policy digest: %w", err)
	}

	return pgd.PolicyDigest, nil
}

// HandleNVRAMNotFoundError converts NVRAM errors to user-friendly messages
func HandleNVRAMNotFoundError(err error, debug bool) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()
	if strings.Contains(errStr, "TPM_RC_HANDLE") ||
		strings.Contains(errStr, "does not exist") ||
		strings.Contains(errStr, "TPM_RC_NV_UNINITIALIZED") {
		if debug {
			return fmt.Errorf("tpm2-kira has not been configured yet. Run 'tpm2-kira seal' to set it up (debug: %w)", err)
		}
		return fmt.Errorf("tpm2-kira has not been configured yet. Run 'tpm2-kira seal' to set it up")
	}
	return err
}

// IsTPMPolicyFailure checks if an error is a TPM policy failure that can be recovered with password authentication
func IsTPMPolicyFailure(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	return strings.Contains(errStr, "TPM_RC_POLICY_FAIL") ||
		strings.Contains(errStr, "TPM_RC_POLICY_CC") ||
		strings.Contains(errStr, "policy check failed") ||
		strings.Contains(errStr, "failed to create PCR policy session") ||
		strings.Contains(errStr, "session 1): a policy check failed")
}

// ShowPCRDetails attempts to show PCR comparison details for the given error.
// Reads current PCR values from TPM registers only (no eventlog/predict).
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
// nor predict tools are available (e.g. early boot). The result maps each PCR
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

// ReadPCRValues reads PCR values from their respective sources (eventlog, predict,
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
		pcrRead := tpm2.PCRRead{
			PCRSelectionIn: CreatePCRSelection(eventlogPCRIndices, hashAlgo),
		}

		pcrReadResp, err := pcrRead.Execute(tpmDev)
		if err != nil {
			return nil, fmt.Errorf("failed to read eventlog PCRs from register: %w", err)
		}

		for i, pcrIndex := range eventlogPCRIndices {
			if i < len(pcrReadResp.PCRValues.Digests) {
				result.RegisterValues[pcrIndex] = pcrReadResp.PCRValues.Digests[i].Buffer
			}
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

		pcrRead := tpm2.PCRRead{
			PCRSelectionIn: CreatePCRSelection(ukiPCRIndices, hashAlgo),
		}
		pcrReadResp, err := pcrRead.Execute(tpmDev)
		if err != nil {
			return nil, fmt.Errorf("failed to read UKI PCRs from register: %w", err)
		}
		for i, pcrIndex := range ukiPCRIndices {
			if i < len(pcrReadResp.PCRValues.Digests) {
				result.RegisterValues[pcrIndex] = pcrReadResp.PCRValues.Digests[i].Buffer
			}
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
		pcrRead := tpm2.PCRRead{
			PCRSelectionIn: CreatePCRSelection(registerPCRIndices, hashAlgo),
		}

		pcrReadResp, err := pcrRead.Execute(tpmDev)
		if err != nil {
			return nil, fmt.Errorf("failed to read PCRs from %s bank: %w", hashAlgo.DisplayString(), err)
		}

		if len(pcrReadResp.PCRValues.Digests) < len(registerPCRIndices) {
			return nil, fmt.Errorf(
				"TPM did not return %s PCR values for register-based PCRs %v.\n"+
					"The %s PCR bank may not be enabled on this system.\n"+
					"Available digests: %d, expected: %d",
				hashAlgo.DisplayString(), registerPCRIndices,
				hashAlgo.DisplayString(),
				len(pcrReadResp.PCRValues.Digests), len(registerPCRIndices))
		}

		for i, pcrIndex := range registerPCRIndices {
			result.Values[pcrIndex] = pcrReadResp.PCRValues.Digests[i].Buffer
			result.RegisterValues[pcrIndex] = pcrReadResp.PCRValues.Digests[i].Buffer
		}

		if debug {
			fmt.Println("Register-read PCR values:")
			for _, idx := range registerPCRIndices {
				fmt.Printf("  PCR%d: %x\n", idx, result.Values[idx])
			}
		}
	}

	return result, nil
}

// GetCurrentPCRValues retrieves current PCR values for comparison, handling
// eventlog-based, predict-based, and direct TPM reads. The hash algorithm is
// automatically detected from the sealed blob's digest sizes. Results are
// returned in the same order as the blob's PCR digests.
// NOTE: This uses source-aware reading (eventlog/predict/register). For the
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
// external predict commands are required (critical for early-boot).
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

// UnsealWorkflowResult contains the results of the unseal workflow
type UnsealWorkflowResult struct {
	UnsealedData []byte
	SealedBlob   *SealedBlob
}

// UnsealWorkflow performs the complete unsealing workflow using PolicyOR PCR branch.
// This consolidates the common pattern used in run, reveal, and reseal commands.
// When PCRs don't match, returns a PCRMismatchError so the caller can fall back
// to the PolicySigned branch if a private key is available.
func UnsealWorkflow(tpmDev transport.TPM, nvramIndex uint32, debug bool) (*UnsealWorkflowResult, error) {
	// Read sealed blob from NVRAM
	sealedData, err := ReadFromNVRAM(tpmDev, nvramIndex)
	if err != nil {
		return nil, HandleNVRAMNotFoundError(err, debug)
	}

	// Unmarshal sealed blob
	sealedBlob, err := UnmarshalSealedBlob(sealedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sealed data: %w", err)
	}

	// Read current PCR values directly from TPM registers. This avoids any
	// dependency on the eventlog file or external predict commands, which may
	// not be available during early boot.
	currentPCRValues, err := GetCurrentPCRValuesFromRegisters(tpmDev, sealedBlob, debug)
	if err != nil {
		return nil, err
	}

	// Check if PCR values match
	pcrMatch := VerifyPCRValues(sealedBlob.GetPCRDigestValues(), currentPCRValues)

	if !pcrMatch {
		// Create structured PCR mismatch error with detailed information
		expectedDigests := make([][]byte, len(sealedBlob.GetPCRDigestValues()))
		for i, digest := range sealedBlob.GetPCRDigestValues() {
			expectedDigests[i] = digest.Buffer
		}

		currentDigests := make([][]byte, len(currentPCRValues))
		for i, digest := range currentPCRValues {
			currentDigests[i] = digest.Buffer
		}

		pcrSources := make([]PCRSource, len(sealedBlob.Payload.PCRDigests))
		for i, pcrDigest := range sealedBlob.Payload.PCRDigests {
			pcrSources[i] = pcrDigest.Source
		}

		pcrErr := &PCRMismatchError{
			Message:         "PCR values have changed. Use 'reseal' command with signing key to update",
			PCRIndices:      sealedBlob.GetPCRIndices(),
			ExpectedDigests: expectedDigests,
			CurrentDigests:  currentDigests,
			PCRSources:      pcrSources,
		}
		return nil, pcrErr
	}

	// Create primary key
	primaryKey, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, primaryKey.ObjectHandle)

	// Load sealed object
	loadedObject, err := LoadSealedObject(tpmDev, primaryKey, sealedBlob)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, loadedObject.ObjectHandle)

	// Unseal the data using PolicyOR PCR branch
	unsealedData, err := UnsealWithPCRBranch(tpmDev, loadedObject, sealedBlob, debug)
	if err != nil {
		return nil, err
	}

	return &UnsealWorkflowResult{
		UnsealedData: unsealedData,
		SealedBlob:   sealedBlob,
	}, nil
}

// ReadFromNVRAM reads data from a TPM NVRAM index
func ReadFromNVRAM(tpmDev transport.TPM, index uint32) ([]byte, error) {
	nvIndex := tpm2.TPMHandle(index)

	// Read public area to get size
	readPublic := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}

	readPublicResp, err := readPublic.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to read NVRAM public area (index may not exist): %w", err)
	}

	nvPublic, err := readPublicResp.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to parse NVRAM public area: %w", err)
	}

	dataSize := nvPublic.DataSize
	data := make([]byte, dataSize)

	// Read data from NVRAM in chunks
	maxChunkSize := uint16(1024)
	offset := uint16(0)

	for offset < dataSize {
		chunkSize := maxChunkSize
		if offset+chunkSize > dataSize {
			chunkSize = dataSize - offset
		}

		read := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: nvIndex,
				Name:   readPublicResp.NVName,
				Auth:   tpm2.PasswordAuth(nil),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: nvIndex,
				Name:   readPublicResp.NVName,
			},
			Size:   chunkSize,
			Offset: offset,
		}

		readResp, err := read.Execute(tpmDev)
		if err != nil {
			return nil, fmt.Errorf("failed to read from NVRAM at offset %d: %w", offset, err)
		}

		copy(data[offset:], readResp.Data.Buffer)
		offset += chunkSize
	}

	return data, nil
}

// WriteToNVRAM writes data to a TPM NVRAM index
func WriteToNVRAM(tpmDev transport.TPM, index uint32, data []byte, pubKey crypto.PublicKey, privKey crypto.Signer) error {
	// Validate index is within the safe application range
	if err := ValidateNVRAMIndex(index); err != nil {
		return fmt.Errorf("invalid NVRAM index: %w", err)
	}

	if pubKey == nil {
		return fmt.Errorf("signing public key is required for NV write authorization")
	}
	if privKey == nil {
		return fmt.Errorf("signing private key is required for NV write authorization")
	}

	nvIndex := tpm2.TPMHandle(index)

	// Try to undefine existing NVRAM space (if it exists)
	// NVUndefineSpace is an owner-hierarchy operation and works regardless
	// of the NV index's read/write attributes.
	readPub := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}
	if readPubResp, checkErr := readPub.Execute(tpmDev); checkErr == nil {
		// Index exists, undefine it
		undefine := tpm2.NVUndefineSpace{
			AuthHandle: tpm2.TPMRHOwner,
			NVIndex: tpm2.NamedHandle{
				Handle: nvIndex,
				Name:   readPubResp.NVName,
			},
		}
		if _, err := undefine.Execute(tpmDev); err != nil {
			return fmt.Errorf("failed to undefine existing NVRAM index 0x%08X: %w", index, err)
		}
	}
	// If checkErr != nil, index doesn't exist, which is fine

	// Load the signing public key into the TPM once — the handle is reused
	// for both the policy digest computation and the per-chunk PolicySigned
	// sessions, avoiding redundant LoadExternal round-trips.
	loadRsp, err := LoadExternalPublicKey(tpmDev, pubKey)
	if err != nil {
		return fmt.Errorf("failed to load signing key for NV write policy: %w", err)
	}
	defer FlushHandle(tpmDev, loadRsp.ObjectHandle)

	keyHandle := loadRsp.ObjectHandle
	keyName := loadRsp.Name

	// Compute the PolicySigned digest that will be the AuthPolicy on this
	// NV index.  Any future NVWrite must satisfy a PolicySigned session
	// proving possession of the corresponding private key.
	nvWritePolicy, err := ComputeNVWritePolicyDigestWithHandle(tpmDev, keyHandle, keyName, pubKey)
	if err != nil {
		return fmt.Errorf("failed to compute NV write policy digest: %w", err)
	}

	// Define NVRAM space with PolicySigned-protected writes.
	//
	// Key attribute changes vs. the old (vulnerable) definition:
	//   OwnerWrite  true  -> false  (prevent owner-hierarchy bypass of policy)
	//   AuthWrite   true  -> false  (remove unauthenticated write path)
	//   PolicyWrite unset -> true   (require policy session for writes)
	//   AuthPolicy  empty -> PolicySigned digest (bind writes to signing key)
	//
	// Read attributes are unchanged — reading the raw blob is harmless since
	// the TPM still protects the actual secret via the sealed object policy.
	define := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth: tpm2.TPM2BAuth{
			Buffer: []byte{},
		},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: nvIndex,
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				OwnerWrite:  false,
				OwnerRead:   true,
				PolicyWrite: true,
				AuthRead:    true,
			},
			AuthPolicy: nvWritePolicy,
			DataSize:   uint16(len(data)),
		}),
	}

	_, err = define.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to define NVRAM space: %w", err)
	}

	// Write data to NVRAM in chunks using PolicySigned sessions.
	//
	// Each chunk gets its own policy session because:
	//   1. The TPM nonce changes per session, requiring a fresh signature.
	//   2. After the first NVWrite the TPM sets TPMA_NV_WRITTEN which
	//      changes the NV public area and therefore the NV Name.  We
	//      re-read NVReadPublic before each chunk to pick up the new Name.
	maxChunkSize := 1024
	offset := 0

	for offset < len(data) {
		chunkSize := maxChunkSize
		if offset+chunkSize > len(data) {
			chunkSize = len(data) - offset
		}

		// Re-read NV public area to get the current Name.
		// The Name changes after the first write (TPMA_NV_WRITTEN is set).
		nvReadPub := tpm2.NVReadPublic{
			NVIndex: nvIndex,
		}
		nvReadPubRsp, err := nvReadPub.Execute(tpmDev)
		if err != nil {
			return fmt.Errorf("failed to read NV public: %w", err)
		}

		// Build a PolicySigned session for this chunk.  The callback is
		// invoked by the go-tpm library when the session is first used as
		// authorization; it signs the TPM-provided nonce to prove
		// possession of the private key.
		policySession := tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
			// aHash = SHA-256(nonceTPM || expiration(0))
			// expiration is a 4-byte big-endian int32 = 0
			// cpHashA and policyRef are empty (omitted per spec)
			aHashInput := make([]byte, 0, len(nonceTPM.Buffer)+4)
			aHashInput = append(aHashInput, nonceTPM.Buffer...)
			expirationBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(expirationBytes, 0)
			aHashInput = append(aHashInput, expirationBytes...)

			aHash := sha256.Sum256(aHashInput)

			// Sign the aHash with the private key
			tpmSig, signErr := signForTPM(privKey, aHash[:])
			if signErr != nil {
				return fmt.Errorf("failed to sign NV write policy nonce: %w", signErr)
			}

			// Execute PolicySigned — the TPM verifies the signature
			// against the loaded public key and extends the session
			// digest with the key Name.
			_, signedErr := tpm2.PolicySigned{
				AuthObject: tpm2.NamedHandle{
					Handle: keyHandle,
					Name:   keyName,
				},
				PolicySession: handle,
				NonceTPM:      nonceTPM,
				Expiration:    0,
				Auth:          tpmSig,
			}.Execute(tpm)
			if signedErr != nil {
				return fmt.Errorf("failed to execute PolicySigned for NV write: %w", signedErr)
			}

			return nil
		})

		// Write the chunk using the satisfied policy session as authorization
		write := tpm2.NVWrite{
			AuthHandle: tpm2.AuthHandle{
				Handle: nvIndex,
				Name:   nvReadPubRsp.NVName,
				Auth:   policySession,
			},
			NVIndex: tpm2.NamedHandle{
				Handle: nvIndex,
				Name:   nvReadPubRsp.NVName,
			},
			Data: tpm2.TPM2BMaxNVBuffer{
				Buffer: data[offset : offset+chunkSize],
			},
			Offset: uint16(offset),
		}

		_, err = write.Execute(tpmDev)
		if err != nil {
			return fmt.Errorf("failed to write to NVRAM at offset %d: %w", offset, err)
		}

		offset += chunkSize
	}

	return nil
}

// PrimaryKeyResponse contains the result of creating a primary key
type PrimaryKeyResponse struct {
	ObjectHandle tpm2.TPMHandle
	Name         tpm2.TPM2BName
}

// CreatePrimaryKey creates a primary key in the owner hierarchy
func CreatePrimaryKey(tpmDev transport.TPM) (*PrimaryKeyResponse, error) {
	createPrimaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Restricted:          true,
				Decrypt:             true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					Symmetric: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgAES,
						KeyBits: tpm2.NewTPMUSymKeyBits(
							tpm2.TPMAlgAES,
							tpm2.TPMKeyBits(128),
						),
						Mode: tpm2.NewTPMUSymMode(
							tpm2.TPMAlgAES,
							tpm2.TPMAlgCFB,
						),
					},
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgNull,
					},
					CurveID: tpm2.TPMECCNistP256,
				},
			),
		}),
	}

	createPrimaryRsp, err := createPrimaryCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to create primary key: %w", err)
	}

	return &PrimaryKeyResponse{
		ObjectHandle: createPrimaryRsp.ObjectHandle,
		Name:         createPrimaryRsp.Name,
	}, nil
}

// CreateSealedObjectResponse contains the result of creating a sealed object
type CreateSealedObjectResponse struct {
	Public  []byte
	Private []byte
}

// CreateSealedObject creates a sealed object with the given data and PCR policy.
// Password auth has been removed; use CreateSealedObjectPolicyOR in policy_or.go
// for PolicyOR-based sealing.
func CreateSealedObject(tpmDev transport.TPM, primaryKey *PrimaryKeyResponse, dataToSeal []byte, policyDigest tpm2.TPM2BDigest) (*CreateSealedObjectResponse, error) {
	createCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: nil,
				},
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: dataToSeal,
				}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
			},
			AuthPolicy: policyDigest,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgNull,
					},
				},
			),
		}),
	}

	createRsp, err := createCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to create sealed object: %w", err)
	}

	return &CreateSealedObjectResponse{
		Public:  createRsp.OutPublic.Bytes(),
		Private: createRsp.OutPrivate.Buffer,
	}, nil
}

// LoadSealedObjectResponse contains the result of loading a sealed object
type LoadSealedObjectResponse struct {
	ObjectHandle tpm2.TPMHandle
	Name         tpm2.TPM2BName
}

// LoadSealedObject loads a sealed object into the TPM
func LoadSealedObject(tpmDev transport.TPM, primaryKey *PrimaryKeyResponse, sealedBlob *SealedBlob) (*LoadSealedObjectResponse, error) {
	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](sealedBlob.Payload.Public),
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: sealedBlob.Payload.Private,
		},
	}

	loadRsp, err := loadCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to load sealed object: %w", err)
	}

	return &LoadSealedObjectResponse{
		ObjectHandle: loadRsp.ObjectHandle,
		Name:         loadRsp.Name,
	}, nil
}

// FlushHandle flushes a TPM handle
func FlushHandle(tpmDev transport.TPM, handle tpm2.TPMHandle) {
	flushCmd := tpm2.FlushContext{FlushHandle: handle}
	_, _ = flushCmd.Execute(tpmDev)
}

// UnsealData is kept for backward compatibility but now only supports PCR policy mode.
// Password-based unsealing has been removed; use UnsealWithPCRBranch or UnsealWithSignedBranch instead.
func UnsealData(tpmDev transport.TPM, loadedObject *LoadSealedObjectResponse, sealedBlob *SealedBlob) ([]byte, error) {
	// Use PCR policy session with the correct hash algorithm from the blob
	hashAlgo := sealedBlob.GetHashAlgo()
	sess, cleanup, err := CreatePCRPolicySession(tpmDev, sealedBlob.GetPCRIndices(), hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to create PCR policy session: %w", err)
	}
	defer cleanup()

	authHandle := tpm2.AuthHandle{
		Handle: loadedObject.ObjectHandle,
		Name:   loadedObject.Name,
		Auth:   sess,
	}

	// Unseal the data
	unsealCmd := tpm2.Unseal{
		ItemHandle: authHandle,
	}

	unsealRsp, err := unsealCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal data: %w", err)
	}

	return unsealRsp.OutData.Buffer, nil
}

// NVRAMList lists all defined NVRAM indices in the TPM
func NVRAMList(tpmPath string, nvramIndex uint32, debug bool) error {
	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	// Get capability to list NVRAM indices
	getCap := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTNVIndex) << 24,
		PropertyCount: 128,
	}

	capResp, err := getCap.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to get NVRAM capabilities: %w", err)
	}

	handles, err := capResp.CapabilityData.Data.Handles()
	if err != nil {
		return fmt.Errorf("failed to parse capability data: %w", err)
	}

	if len(handles.Handle) == 0 {
		fmt.Println("No NVRAM indices defined in TPM")
		return nil
	}

	fmt.Printf("Defined NVRAM Indices:\n")
	fmt.Printf("======================\n\n")

	for _, handle := range handles.Handle {
		// Read public area for each index
		readPublic := tpm2.NVReadPublic{
			NVIndex: handle,
		}

		readPublicResp, err := readPublic.Execute(tpmDev)
		if err != nil {
			fmt.Printf("Index: 0x%08X - Error reading details: %v\n", handle, err)
			continue
		}

		nvPublic, err := readPublicResp.NVPublic.Contents()
		if err != nil {
			fmt.Printf("Index: 0x%08X - Error parsing details\n", handle)
			continue
		}

		fmt.Printf("Index: 0x%08X\n", handle)
		fmt.Printf("  Size: %d bytes\n", nvPublic.DataSize)
		fmt.Printf("  Name Algorithm: %v\n", nvPublic.NameAlg)

		// Show key attributes
		attrs := []string{}
		if nvPublic.Attributes.OwnerWrite {
			attrs = append(attrs, "OwnerWrite")
		}
		if nvPublic.Attributes.OwnerRead {
			attrs = append(attrs, "OwnerRead")
		}
		if nvPublic.Attributes.AuthWrite {
			attrs = append(attrs, "AuthWrite")
		}
		if nvPublic.Attributes.AuthRead {
			attrs = append(attrs, "AuthRead")
		}
		if nvPublic.Attributes.Written {
			attrs = append(attrs, "Written")
		}
		if nvPublic.Attributes.WriteDefine {
			attrs = append(attrs, "WriteDefine")
		}
		if nvPublic.Attributes.ReadSTClear {
			attrs = append(attrs, "ReadSTClear")
		}

		fmt.Printf("  Attributes: %v\n", attrs)

		// Check if this is our configured index
		if handle == tpm2.TPMHandle(nvramIndex) {
			fmt.Printf("  ** Current configured index **\n")
		}

		fmt.Println()
	}

	return nil
}

// NVRAMDelete deletes the specified NVRAM index
func NVRAMDelete(tpmPath string, nvramIndex uint32, debug bool) error {
	// Validate index is within the safe application range
	if err := ValidateNVRAMIndex(nvramIndex); err != nil {
		return fmt.Errorf("invalid NVRAM index: %w", err)
	}

	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	nvIndex := tpm2.TPMHandle(nvramIndex)

	// Check if index exists
	readPublic := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}

	readPublicResp, err := readPublic.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("NVRAM index 0x%08X does not exist: %w", nvramIndex, err)
	}

	// Undefine NVRAM space
	undefine := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex: tpm2.NamedHandle{
			Handle: nvIndex,
			Name:   readPublicResp.NVName,
		},
	}

	_, err = undefine.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to delete NVRAM index 0x%08X: %w", nvramIndex, err)
	}

	fmt.Printf("Successfully deleted NVRAM index 0x%08X\n", nvramIndex)

	return nil
}

// NVRAMDeleteCommand is the top-level entry point for the nvram delete CLI
// command.  When nvramIndex is 0 it scans every default slot and deletes
// each populated one; otherwise it deletes only the requested index.
func NVRAMDeleteCommand(tpmPath string, nvramIndex uint32, debug bool) error {
	if nvramIndex != 0 {
		return NVRAMDelete(tpmPath, nvramIndex, debug)
	}

	// Multi-slot mode – discover populated slots, then delete each one.
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	slots := FindPopulatedSlots(tpmDev, debug)
	tpmDev.Close()

	if len(slots) == 0 {
		return fmt.Errorf("no sealed secrets found in NVRAM slots 0x%08X – 0x%08X", NVRAMSlotStart, NVRAMSlotEnd)
	}

	fmt.Printf("Found %d sealed slot(s) to delete\n\n", len(slots))

	var failed []uint32
	for _, slotIdx := range slots {
		slotNum := SlotNumber(slotIdx)
		fmt.Printf("Deleting slot #%d (0x%08X)... ", slotNum, slotIdx)

		if err := NVRAMDelete(tpmPath, slotIdx, debug); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			failed = append(failed, slotIdx)
		}
	}

	fmt.Println()
	if len(failed) > 0 {
		return fmt.Errorf("%d of %d slot(s) failed to delete", len(failed), len(slots))
	}
	fmt.Printf("All %d slot(s) deleted successfully\n", len(slots))
	return nil
}

// NVRAMStatus shows detailed status of the specified NVRAM index
func NVRAMStatus(tpmPath string, nvramIndex uint32, debug bool) error {
	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	nvIndex := tpm2.TPMHandle(nvramIndex)

	// Read public area
	readPublic := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}

	readPublicResp, err := readPublic.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("NVRAM index 0x%08X does not exist: %w", nvramIndex, err)
	}

	nvPublic, err := readPublicResp.NVPublic.Contents()
	if err != nil {
		return fmt.Errorf("failed to parse NVRAM public area: %w", err)
	}

	fmt.Printf("NVRAM Index Status:\n")
	fmt.Printf("===================\n")
	fmt.Printf("Index: 0x%08X\n", nvramIndex)
	fmt.Printf("Data Size: %d bytes\n", nvPublic.DataSize)
	fmt.Printf("Name Algorithm: %v\n", nvPublic.NameAlg)
	fmt.Printf("\n")

	fmt.Printf("Attributes:\n")
	fmt.Printf("  PPWRITE: %v\n", nvPublic.Attributes.PPWrite)
	fmt.Printf("  OWNERWRITE: %v\n", nvPublic.Attributes.OwnerWrite)
	fmt.Printf("  AUTHWRITE: %v\n", nvPublic.Attributes.AuthWrite)
	fmt.Printf("  POLICYWRITE: %v\n", nvPublic.Attributes.PolicyWrite)
	fmt.Printf("  PPREAD: %v\n", nvPublic.Attributes.PPRead)
	fmt.Printf("  OWNERREAD: %v\n", nvPublic.Attributes.OwnerRead)
	fmt.Printf("  AUTHREAD: %v\n", nvPublic.Attributes.AuthRead)
	fmt.Printf("  POLICYREAD: %v\n", nvPublic.Attributes.PolicyRead)
	fmt.Printf("  WRITTEN: %v\n", nvPublic.Attributes.Written)
	fmt.Printf("  WRITELOCKED: %v\n", nvPublic.Attributes.WriteLocked)
	fmt.Printf("  WRITEDEFINE: %v\n", nvPublic.Attributes.WriteDefine)
	fmt.Printf("  READLOCKED: %v\n", nvPublic.Attributes.ReadLocked)
	fmt.Printf("  READ_STCLEAR: %v\n", nvPublic.Attributes.ReadSTClear)
	fmt.Printf("  WRITE_STCLEAR: %v\n", nvPublic.Attributes.WriteSTClear)
	fmt.Printf("\n")

	// Try to determine if it contains sealed data
	if nvPublic.Attributes.Written {
		data, err := ReadFromNVRAM(tpmDev, nvramIndex)
		if err == nil {
			blob, err := UnmarshalSealedBlob(data)
			if err == nil {
				fmt.Printf("Contains Sealed Data:\n")
				fmt.Printf("  PCR Indices: %v\n", blob.GetPCRIndices())
				fmt.Printf("  Number of PCRs: %d\n", len(blob.Payload.PCRDigests))
				fmt.Printf("  Public Blob Size: %d bytes\n", len(blob.Payload.Public))
				fmt.Printf("  Private Blob Size: %d bytes\n", len(blob.Payload.Private))
			} else {
				fmt.Printf("Data Format: Unknown (not a sealed blob)\n")
			}
		}
	} else {
		fmt.Printf("Status: Not yet written\n")
	}

	return nil
}
