package cmd

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
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
	Debug      bool
}

// NewEventlogPCRCalculator creates a new eventlog PCR calculator
func NewEventlogPCRCalculator(tpmDev transport.TPM, pcrIndices []int, debug bool) *EventlogPCRCalculator {
	return &EventlogPCRCalculator{
		TPMDevice:  tpmDev,
		PCRIndices: pcrIndices,
		Debug:      debug,
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

	events := eventLog.Events(attest.HashSHA256)
	if len(events) == 0 {
		return nil, nil, fmt.Errorf("eventlog contains no events")
	}

	// Calculate eventlog hash for verification
	eventlogHash := sha256.Sum256(rawEventlog)

	// Calculate PCR values by replaying the eventlog
	pcrValues, totalEvents, processedEvents, err := calc.replayEventLog(events)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to replay eventlog: %w", err)
	}

	// Filter to only requested PCRs
	filteredPCRs := make(map[int][]byte)
	for _, pcrIndex := range calc.PCRIndices {
		if pcrValue, exists := pcrValues[pcrIndex]; exists {
			filteredPCRs[pcrIndex] = pcrValue
		} else {
			return nil, nil, fmt.Errorf("PCR %d not found in eventlog calculations", pcrIndex)
		}
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

// readRawEventLog reads the raw binary eventlog from the default path
func readRawEventLog() ([]byte, error) {
	return readRawEventLogFromPath(DefaultEventlogPath)
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

// replayEventLog replays the eventlog to calculate PCR values
func (calc *EventlogPCRCalculator) replayEventLog(events []attest.Event) (map[int][]byte, int, int, error) {
	// Initialize PCR banks (assuming SHA256)
	pcrs := make(map[int][]byte)

	// Initialize PCRs to zero (except PCR0 which may have locality)
	for _, pcrIndex := range calc.PCRIndices {
		if pcrIndex == 0 {
			// PCR0 starts with locality value only if StartupLocality event exists
			// This follows the same logic as calculate.py
			pcr0 := make([]byte, 32)
			// Look for StartupLocality event to determine initial value
			locality, found := calc.findStartupLocality(events)
			if found {
				pcr0[31] = locality
				if calc.Debug {
					fmt.Printf("Found StartupLocality event: locality = 0x%02x\n", locality)
					fmt.Printf("Initial PCR0 value (31 zeros + locality): %x\n", pcr0)
				}
			} else {
				if calc.Debug {
					fmt.Printf("No StartupLocality event found - PCR0 starts with all zeros\n")
					fmt.Printf("Initial PCR0 value (32 zeros): %x\n", pcr0)
				}
			}
			pcrs[pcrIndex] = pcr0
		} else {
			// Other PCRs start with all zeros
			pcrs[pcrIndex] = make([]byte, 32)
			if calc.Debug {
				fmt.Printf("Initial PCR%d value (32 zeros): %x\n", pcrIndex, pcrs[pcrIndex])
			}
		}
	}

	totalEvents := len(events)
	processedEvents := 0

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

		// Get SHA256 digest from the event
		digest := event.Digest

		if len(digest) == 0 {
			if calc.Debug {
				fmt.Printf("  No digest found for event on PCR%d\n", pcrIndex)
			}
			continue
		}

		// Extend PCR: PCR = SHA256(current_pcr || event_digest)
		hasher := sha256.New()
		hasher.Write(pcrs[pcrIndex])
		hasher.Write(digest)
		pcrs[pcrIndex] = hasher.Sum(nil)

		processedEvents++

		if calc.Debug && pcrIndex < 10 { // Limit debug output
			fmt.Printf("  Extended PCR%d with digest %x -> PCR now: %x\n", pcrIndex, digest[:8], pcrs[pcrIndex][:8])
		}
	}

	return pcrs, totalEvents, processedEvents, nil
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

// ValidateEventlogAccess checks if the eventlog can be accessed using go-attestation
func ValidateEventlogAccess(tpmDev transport.TPM) error {
	// Try to read and parse eventlog
	rawEventlog, err := readRawEventLog()
	if err != nil {
		return fmt.Errorf("failed to read TPM eventlog: %w", err)
	}

	eventLog, err := attest.ParseEventLog(rawEventlog)
	if err != nil {
		return fmt.Errorf("failed to parse TPM eventlog: %w", err)
	}

	events := eventLog.Events(attest.HashSHA256)
	if len(events) == 0 {
		return fmt.Errorf("TPM eventlog appears to be empty")
	}

	return nil
}

// ComputePolicyDigestFromPCRValues creates a policy digest from specific PCR values
func ComputePolicyDigestFromPCRValues(tpmDev transport.TPM, pcrIndices []int, pcrValues map[int][]byte) (tpm2.TPM2BDigest, error) {
	// Create trial policy session using the correct go-tpm API
	sess, cleanup, err := tpm2.PolicySession(tpmDev, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to create trial session: %w", err)
	}
	defer cleanup()

	// Build PCR digest from provided values according to TPM 2.0 spec
	pcrDigest, err := buildPCRDigest(pcrIndices, pcrValues)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to build PCR digest: %w", err)
	}

	// Apply PCR policy with specific PCR digest values in trial session
	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest:     pcrDigest,
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
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
// The digest is the hash of the concatenated PCR values in the order specified
func buildPCRDigest(pcrIndices []int, pcrValues map[int][]byte) (tpm2.TPM2BDigest, error) {
	// Concatenate PCR values in order
	var concatenated []byte
	for _, pcrIndex := range pcrIndices {
		pcrValue, exists := pcrValues[pcrIndex]
		if !exists {
			return tpm2.TPM2BDigest{}, fmt.Errorf("PCR %d value not provided", pcrIndex)
		}
		if len(pcrValue) != 32 {
			return tpm2.TPM2BDigest{}, fmt.Errorf("PCR %d has invalid length %d (expected 32)", pcrIndex, len(pcrValue))
		}
		concatenated = append(concatenated, pcrValue...)
	}

	// Hash the concatenated values
	hash := sha256.Sum256(concatenated)

	return tpm2.TPM2BDigest{
		Buffer: hash[:],
	}, nil
}
