package cmd

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	// Default eventlog path on Linux systems
	DefaultEventlogPath = "/sys/kernel/security/tpm0/binary_bios_measurements"
)

// EventlogPCRCalculator handles PCR calculation from TPM eventlogs using go-attestation
type EventlogPCRCalculator struct {
	TPMDevice  transport.TPM
	PCRIndices []int
	HashAlgo   PCRHashAlgo
	Debug      bool
}

// NewEventlogPCRCalculator creates a new eventlog PCR calculator
func NewEventlogPCRCalculator(tpmDev transport.TPM, pcrIndices []int, hashAlgo PCRHashAlgo, debug bool) *EventlogPCRCalculator {
	return &EventlogPCRCalculator{
		TPMDevice:  tpmDev,
		PCRIndices: pcrIndices,
		HashAlgo:   hashAlgo,
		Debug:      debug,
	}
}

// attestHash converts a PCRHashAlgo to the corresponding attest hash type
func attestHash(algo PCRHashAlgo) attest.HashAlg {
	switch algo {
	case PCRHashAlgoSHA1:
		return attest.HashSHA1
	default:
		return attest.HashSHA256
	}
}

// CalculatePCRsFromEventlog calculates PCR values using go-attestation native eventlog parsing
func (calc *EventlogPCRCalculator) CalculatePCRsFromEventlog() (map[int][]byte, *EventlogInfo, error) {
	return calc.CalculatePCRsFromEventlogPath(DefaultEventlogPath)
}

// CalculatePCRsFromEventlogPath calculates PCR values from a specific eventlog file path
func (calc *EventlogPCRCalculator) CalculatePCRsFromEventlogPath(eventlogPath string) (map[int][]byte, *EventlogInfo, error) {
	if calc.Debug {
		fmt.Printf("Calculating PCR values from TPM eventlog: %s\n", eventlogPath)
		fmt.Printf("Target PCRs: %v\n", calc.PCRIndices)
		fmt.Printf("Hash algorithm: %s\n", calc.HashAlgo.DisplayString())
		fmt.Println()
	}

	// Read raw eventlog from file
	rawEventlog, err := readRawEventLogFromPath(eventlogPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read eventlog: %w", err)
	}

	// Parse eventlog using go-attestation
	eventLog, err := attest.ParseEventLog(rawEventlog)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse eventlog: %w", err)
	}

	// Get events for the requested hash algorithm
	requestedHash := attestHash(calc.HashAlgo)
	events := eventLog.Events(requestedHash)

	if len(events) == 0 {
		// If SHA256 was requested but not available, check if SHA1 is available
		// and give the user a helpful error message
		if calc.HashAlgo == PCRHashAlgoSHA256 {
			sha1Events := eventLog.Events(attest.HashSHA1)
			if len(sha1Events) > 0 {
				return nil, nil, fmt.Errorf(
					"eventlog does not contain SHA-256 digests, only SHA-1 is available.\n"+
						"This firmware does not support SHA-256 PCR bank in its eventlog.\n"+
						"To use SHA-1 digests instead, pass --sha1 during seal:\n"+
						"  tpm2-kira seal --sha1 --pcrs \"%s\"",
					pcrIndicesToEventlogString(calc.PCRIndices))
			}
			return nil, nil, fmt.Errorf("eventlog contains no SHA-256 events")
		}
		// SHA1 was explicitly requested but not available - check if SHA256 is available instead
		if calc.HashAlgo == PCRHashAlgoSHA1 {
			sha256Events := eventLog.Events(attest.HashSHA256)
			if len(sha256Events) > 0 {
				return nil, nil, fmt.Errorf(
					"eventlog does not contain SHA-1 digests, only SHA-256 is available.\n"+
						"This firmware provides SHA-256 but not SHA-1 in its eventlog.\n"+
						"Re-seal without --sha1 to use SHA-256 (default):\n"+
						"  tpm2-kira seal --pcrs \"%s\"",
					pcrIndicesToEventlogString(calc.PCRIndices))
			}
		}
		return nil, nil, fmt.Errorf("eventlog contains no %s events", calc.HashAlgo.DisplayString())
	}

	// Calculate eventlog hash for verification
	eventlogHash := sha256.Sum256(rawEventlog)

	// Calculate PCR values by replaying the eventlog
	pcrValues, extendsPerPCR, totalEvents, processedEvents, err := calc.replayEventLog(events)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to replay eventlog: %w", err)
	}

	// Filter to only requested PCRs
	filteredPCRs := make(map[int][]byte)
	var missing []int
	for _, pcrIndex := range calc.PCRIndices {
		pcrValue, exists := pcrValues[pcrIndex]
		if !exists {
			return nil, nil, fmt.Errorf("PCR %d not found in eventlog calculations", pcrIndex)
		}
		if extendsPerPCR[pcrIndex] == 0 {
			missing = append(missing, pcrIndex)
			continue
		}
		filteredPCRs[pcrIndex] = pcrValue
	}
	if len(missing) > 0 {
		return nil, nil, calc.bankError(eventLog, missing, eventlogPath)
	}

	// Create eventlog info
	eventlogInfo := &EventlogInfo{
		EventlogPath:    eventlogPath,
		EventlogHash:    fmt.Sprintf("%x", eventlogHash),
		CalculationTime: time.Now().UTC().Format(time.RFC3339),
		TotalEvents:     totalEvents,
		ProcessedEvents: processedEvents,
	}

	if calc.Debug {
		fmt.Println("Calculated PCR values:")
		for pcrIndex, pcrValue := range filteredPCRs {
			fmt.Printf("  PCR%d: %x\n", pcrIndex, pcrValue)
		}
		fmt.Println()
	}

	return filteredPCRs, eventlogInfo, nil
}

// EventlogBankError reports PCRs the event log carries no digests for in the
// selected bank. Replaying those yields the PCR's reset value, which is a
// well-formed digest the machine will never actually produce.
type EventlogBankError struct {
	PCRIndices   []int
	Requested    PCRHashAlgo
	Present      []string // hash algorithms the log does carry for these PCRs
	EventlogPath string
}

func (e *EventlogBankError) Error() string {
	present := "none"
	if len(e.Present) > 0 {
		present = strings.Join(e.Present, ", ")
	}
	return fmt.Sprintf("the event log %s carries no %s digests for PCR %s (it has: %s)",
		e.EventlogPath, e.Requested.DisplayString(), formatPCRList(e.PCRIndices), present)
}

// HasSHA1 reports whether falling back to the SHA-1 bank could work.
func (e *EventlogBankError) HasSHA1() bool {
	return slices.Contains(e.Present, "SHA-1")
}

func formatPCRList(indices []int) string {
	parts := make([]string, len(indices))
	for i, idx := range indices {
		parts[i] = fmt.Sprintf("%d", idx)
	}
	return strings.Join(parts, ", ")
}

func (calc *EventlogPCRCalculator) bankError(eventLog *attest.EventLog, indices []int, eventlogPath string) error {
	var present []string
	for _, candidate := range []struct {
		name string
		alg  attest.HashAlg
	}{{"SHA-1", attest.HashSHA1}, {"SHA-256", attest.HashSHA256}} {
		for _, event := range eventLog.Events(candidate.alg) {
			if slices.Contains(indices, int(event.Index)) && len(event.Digest) > 0 {
				present = append(present, candidate.name)
				break
			}
		}
	}
	return &EventlogBankError{
		PCRIndices:   indices,
		Requested:    calc.HashAlgo,
		Present:      present,
		EventlogPath: eventlogPath,
	}
}

// pcrIndicesToEventlogString formats PCR indices with 'e' suffix for error messages
func pcrIndicesToEventlogString(indices []int) string {
	result := ""
	for i, idx := range indices {
		if i > 0 {
			result += ","
		}
		result += fmt.Sprintf("%de", idx)
	}
	return result
}

// readRawEventLogFromPath reads the raw binary eventlog from a specific path
func readRawEventLogFromPath(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open eventlog file %s: %w", path, err)
	}
	defer file.Close()

	return io.ReadAll(file)
}

// replayEventLog replays the eventlog to calculate PCR values.
// The returned map counts how many events actually extended each PCR, which
// distinguishes "left at its reset value" from "no digests in this bank".
func (calc *EventlogPCRCalculator) replayEventLog(events []attest.Event) (map[int][]byte, map[int]int, int, int, error) {
	digestSize := calc.HashAlgo.DigestSize()

	// Initialize PCR banks
	pcrs := make(map[int][]byte)

	// Initialize PCRs to zero (except PCR0 which may have locality)
	for _, pcrIndex := range calc.PCRIndices {
		if pcrIndex == 0 {
			// PCR0 starts with locality value only if StartupLocality event exists
			pcr0 := make([]byte, digestSize)
			// Look for StartupLocality event to determine initial value
			locality, found := calc.findStartupLocality(events)
			if found {
				pcr0[digestSize-1] = locality
				if calc.Debug {
					fmt.Printf("Found StartupLocality event: locality = 0x%02x\n", locality)
					fmt.Printf("Initial PCR0 value (%d zeros + locality): %x\n", digestSize-1, pcr0)
				}
			} else {
				if calc.Debug {
					fmt.Printf("No StartupLocality event found - PCR0 starts with all zeros\n")
					fmt.Printf("Initial PCR0 value (%d zeros): %x\n", digestSize, pcr0)
				}
			}
			pcrs[pcrIndex] = pcr0
		} else {
			// Other PCRs start with all zeros
			pcrs[pcrIndex] = make([]byte, digestSize)
			if calc.Debug {
				fmt.Printf("Initial PCR%d value (%d zeros): %x\n", pcrIndex, digestSize, pcrs[pcrIndex])
			}
		}
	}

	totalEvents := len(events)
	processedEvents := 0
	extendsPerPCR := make(map[int]int, len(calc.PCRIndices))

	// Replay events
	for _, event := range events {
		// Skip informational events that don't extend PCRs
		if event.Type == 0x03 { // EV_NO_ACTION
			if calc.Debug && event.Index < 10 { // Only show debug for first few PCRs
				fmt.Printf("  Skipping EV_NO_ACTION event for PCR%d (informational only)\n", event.Index)
			}
			continue
		}

		// Only process events for PCRs we're interested in
		pcrIndex := int(event.Index)
		if _, interested := pcrs[pcrIndex]; !interested {
			continue
		}

		// Get digest from the event
		digest := event.Digest

		if len(digest) == 0 {
			if calc.Debug {
				fmt.Printf("  No digest found for event on PCR%d\n", pcrIndex)
			}
			continue
		}

		// Extend PCR: PCR = Hash(current_pcr || event_digest)
		pcrs[pcrIndex] = ExtendDigest(calc.HashAlgo, pcrs[pcrIndex], digest)

		processedEvents++
		extendsPerPCR[pcrIndex]++

		if calc.Debug && pcrIndex < 10 { // Limit debug output
			fmt.Printf("  Extended PCR%d with digest %x -> PCR now: %x\n", pcrIndex, digest[:min(8, len(digest))], pcrs[pcrIndex][:min(8, len(pcrs[pcrIndex]))])
		}
	}

	return pcrs, extendsPerPCR, totalEvents, processedEvents, nil
}

// findStartupLocality looks for the StartupLocality event to determine PCR0 initial value
// Returns (locality_value, found) where found indicates if the event was actually present
func (calc *EventlogPCRCalculator) findStartupLocality(events []attest.Event) (byte, bool) {
	if calc.Debug {
		fmt.Printf("Searching for StartupLocality event in %d events...\n", len(events))
	}

	for i, event := range events {
		if event.Index == 0 && event.Type == 0x03 { // EV_NO_ACTION
			if calc.Debug {
				fmt.Printf("  Event %d: PCR0 EV_NO_ACTION, data length: %d\n", i, len(event.Data))
			}
			// Look for StartupLocality signature in event data
			if len(event.Data) >= 17 {
				// Check if data starts with "StartupLocality" (hex: 537461727475704c6f63616c697479)
				expectedSig := []byte("StartupLocality")
				if len(event.Data) >= len(expectedSig) && string(event.Data[:len(expectedSig)]) == string(expectedSig) {
					locality := event.Data[16]
					if calc.Debug {
						fmt.Printf("  Found StartupLocality event! Data: %x, Locality: 0x%02x\n", event.Data, locality)
					}
					return locality, true
				} else if calc.Debug {
					fmt.Printf("  Data does not match StartupLocality signature: %x\n", event.Data[:min(len(event.Data), 32)])
				}
			}
		}
	}
	if calc.Debug {
		fmt.Printf("  No StartupLocality event found\n")
	}
	// Return 0 and false if not found - PCR0 should start with all zeros
	return 0, false
}

// ComputePolicyDigestFromPCRValues creates a policy digest from specific PCR values
func ComputePolicyDigestFromPCRValues(tpmDev transport.TPM, pcrIndices []int, pcrValues map[int][]byte, hashAlgo PCRHashAlgo) (tpm2.TPM2BDigest, error) {
	// Create trial policy session using the correct go-tpm API
	// Policy session always uses SHA256 for the policy digest computation
	sess, cleanup, err := tpm2.PolicySession(tpmDev, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to create trial session: %w", err)
	}
	defer cleanup()

	// Build PCR digest from provided values according to TPM 2.0 spec
	pcrDigest, err := buildPCRDigest(pcrIndices, pcrValues, hashAlgo)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to build PCR digest: %w", err)
	}

	// Apply PCR policy with specific PCR digest values in trial session
	// The PCR bank selection uses the hash algo (SHA1 or SHA256)
	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest:     pcrDigest,
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
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to apply PCR policy: %w", err)
	}

	// Get policy digest from trial session
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(tpmDev)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to get policy digest: %w", err)
	}

	return pgd.PolicyDigest, nil
}

// buildPCRDigest creates a TPM PCR digest from individual PCR values
// According to TPM 2.0 specification Part 3, section 23.7 (PolicyPCR):
// The digest is the hash of the concatenated PCR values in the order specified.
// The hash used here matches the policy session hash (always SHA256), not the PCR bank hash.
func buildPCRDigest(pcrIndices []int, pcrValues map[int][]byte, hashAlgo PCRHashAlgo) (tpm2.TPM2BDigest, error) {
	expectedLen := hashAlgo.DigestSize()

	// Concatenate PCR values in order
	var concatenated []byte
	for _, pcrIndex := range pcrIndices {
		pcrValue, exists := pcrValues[pcrIndex]
		if !exists {
			return tpm2.TPM2BDigest{}, fmt.Errorf("PCR %d value not provided", pcrIndex)
		}
		if len(pcrValue) != expectedLen {
			return tpm2.TPM2BDigest{}, fmt.Errorf("PCR %d has invalid length %d (expected %d for %s)", pcrIndex, len(pcrValue), expectedLen, hashAlgo.DisplayString())
		}
		concatenated = append(concatenated, pcrValue...)
	}

	// Hash the concatenated values using SHA256 (matches policy session hash)
	hash := sha256.Sum256(concatenated)

	return tpm2.TPM2BDigest{
		Buffer: hash[:],
	}, nil
}
