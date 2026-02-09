package cmd

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
)

// RunPredictCommand executes an external command that is expected to print
// a single hex-encoded PCR digest to stdout (e.g. a SHA-256 hash).
//
// The command is run without arguments. It must exit 0 and print exactly
// one line of hex on stdout. Leading/trailing whitespace and an optional
// trailing newline are stripped before decoding.
//
// Example valid output:
//
//	89361c0ba4ecd44f03323759d5fd339f6c93582100ac9b748e74d5583106d8f3
func RunPredictCommand(command string, expectedDigestSize int, debug bool) ([]byte, error) {
	if command == "" {
		return nil, fmt.Errorf("predict command is empty")
	}

	if debug {
		fmt.Printf("Running predict command: %s\n", command)
	}

	cmd := exec.Command(command)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("predict command %q exited with code %d: %s",
				command, exitErr.ExitCode(), strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("failed to execute predict command %q: %w", command, err)
	}

	hexStr := strings.TrimSpace(string(output))

	if debug {
		fmt.Printf("Predict command output: %s\n", hexStr)
	}

	if hexStr == "" {
		return nil, fmt.Errorf("predict command %q produced no output", command)
	}

	// Reject multi-line output — only the first line is meaningful but we
	// require exactly one line to avoid ambiguity.
	if strings.ContainsAny(hexStr, "\n\r") {
		return nil, fmt.Errorf("predict command %q produced multi-line output; expected a single hex digest line", command)
	}

	digest, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("predict command %q produced invalid hex %q: %w", command, hexStr, err)
	}

	if len(digest) != expectedDigestSize {
		return nil, fmt.Errorf("predict command %q returned %d-byte digest, expected %d bytes for the selected hash algorithm",
			command, len(digest), expectedDigestSize)
	}

	if debug {
		fmt.Printf("Predicted digest (%d bytes): %x\n", len(digest), digest)
	}

	return digest, nil
}
