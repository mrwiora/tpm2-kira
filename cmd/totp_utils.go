package cmd

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ANSI color codes for KIRA output
const (
	KIRASuccess = "\033[1;33mKIRA\033[0m" // Yellow KIRA for success
	KIRAError   = "\033[0;31mKIRA\033[0m" // Red KIRA for errors
	KIRANormal  = "KIRA"                  // Plain KIRA for no color
)

// FormatKIRAOutput formats output with colored KIRA prefix and timestamp
func FormatKIRAOutput(code string) string {
	now := time.Now().UTC()
	timestamp := now.Format("15:04:05")
	return fmt.Sprintf("[ %s ] %s: %s", KIRASuccess, timestamp, code)
}

// FormatKIRAError formats error output with red KIRA prefix and timestamp
func FormatKIRAError(err error) string {
	now := time.Now().UTC()
	timestamp := now.Format("15:04:05")
	return fmt.Sprintf("[ %s ] %s ERROR: %v", KIRAError, timestamp, err)
}

// PrintKIRAOutput prints a TOTP code with colored KIRA formatting
func PrintKIRAOutput(code string) {
	fmt.Println(FormatKIRAOutput(code))
}

// PrintKIRAError prints an error with colored KIRA formatting
// If the error is a PCRMismatchError, it includes detailed PCR information.
// On the unseal path CurrentDigests always holds TPM register values; no
// eventlog or predict output is shown.
func PrintKIRAError(err error) {
	// Check if it's a PCR mismatch error for special formatting
	if pcrErr, ok := err.(*PCRMismatchError); ok {
		// Print KIRA error line first
		fmt.Println(FormatKIRAError(pcrErr))
		fmt.Println()

		// Print detailed PCR mismatch information
		fmt.Println("=== PCR Mismatch Detected ===")
		fmt.Printf("PCRs used for sealing: %v\n", pcrErr.PCRIndices)
		fmt.Println()

		for i, pcrIndex := range pcrErr.PCRIndices {
			if i >= len(pcrErr.ExpectedDigests) || i >= len(pcrErr.CurrentDigests) {
				break
			}

			expected := pcrErr.ExpectedDigests[i]
			current := pcrErr.CurrentDigests[i]

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

			source := ""
			if i < len(pcrErr.PCRSources) {
				source = pcrErr.PCRSources[i].String()
			}

			fmt.Printf("  PCR%-2d (%s): %s - %s\n", pcrIndex, source, GetPCRDescription(pcrIndex), status)
			fmt.Printf("    Expected (blob):    %x\n", expected)
			fmt.Printf("    Current (register): %x\n", current)
		}

		fmt.Println()
		fmt.Println("To fix this, run: tpm2-kira reseal")
	} else if IsTPMPolicyFailure(err) {
		// Handle TPM policy failures with helpful guidance
		fmt.Println(FormatKIRAError(err))
		fmt.Println()
		fmt.Println("=== TPM Policy Failure ===")
		fmt.Println("The TPM policy verification failed. This typically happens when:")
		fmt.Println("- PCR values changed between checking and using them")
		fmt.Println("- The system state has changed since sealing")
		fmt.Println()

		fmt.Println("To see detailed PCR values and fix this, run: tpm2-kira reseal")
		fmt.Println("(Make sure you have the password that was set during initial sealing)")
	} else {
		fmt.Println(FormatKIRAError(err))
	}
}

// PCRMismatchError represents a PCR mismatch error with detailed information.
// CurrentDigests always contains values read from TPM registers (the unseal
// path never uses eventlog or predict tools).
type PCRMismatchError struct {
	Message         string
	PCRIndices      []int
	ExpectedDigests [][]byte // Digest values stored in the sealed blob
	CurrentDigests  [][]byte // Current TPM register values
	PCRSources      []PCRSource // Original source used at seal time (informational)
}

func (e *PCRMismatchError) Error() string {
	return e.Message
}

// isTOTPSecret checks if a string looks like a Base32-encoded TOTP secret
func isTOTPSecret(s string) bool {
	// Remove spaces and convert to uppercase
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))

	// TOTP secrets are typically 16-64 characters in Base32
	if len(s) < 16 || len(s) > 128 {
		return false
	}

	// Try to decode as Base32
	_, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	return err == nil
}

// generateQRCode generates a QR code using the system's qrencode command
// Returns an error if qrencode is not installed or execution fails
func generateQRCode(data string) error {
	// Check if qrencode is available
	qrencodePath, err := exec.LookPath("qrencode")
	if err != nil {
		return fmt.Errorf("qrencode not found in PATH")
	}

	// Run qrencode with ANSI UTF-8 output for terminal display
	cmd := exec.Command(qrencodePath, "-t", "ANSIUTF8", data)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to execute qrencode: %w", err)
	}

	// Print the QR code
	fmt.Print(string(output))

	return nil
}

// generateTOTPURI creates an otpauth URI for TOTP
func generateTOTPURI(secret, label, issuer string) string {
	if label == "" {
		label = "TPM2-KIRA"
	}
	if issuer == "" {
		issuer = "TPM2-KIRA"
	}
	// URL encode the label for proper formatting
	encodedLabel := url.PathEscape(label)
	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s", encodedLabel, secret, issuer)
}

// displayTOTPQRCode generates and displays a QR code for a TOTP secret with slot and PCR info
// If qrencode is not available, displays installation instructions
func displayTOTPQRCode(secret string, nvramIndex uint32, pcrsStr string) {
	// Get hostname
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}

	// Calculate slot number from NVRAM index
	slotNumber := int(nvramIndex - 0x01803010)

	// Create label with slot number and PCRs
	label := fmt.Sprintf("TPM2-KIRA: %s, PCRs %s (#%d)", hostname, pcrsStr, slotNumber)
	totpURI := generateTOTPURI(secret, label, "TPM2-KIRA")

	// Try to generate and display QR code
	if err := generateQRCode(totpURI); err != nil {
		fmt.Printf("   QR code could not be generated: %v\n", err)
		fmt.Println("   Install 'qrencode' package to enable QR code display")
		fmt.Println("   Example: apt install qrencode  # Debian/Ubuntu")
		fmt.Println("           dnf install qrencode  # Fedora")
		fmt.Println("           pacman -S qrencode    # Arch Linux")
	}

	// Always display the URI for manual entry or backup
	fmt.Println()
	fmt.Println("TOTP URI (for manual entry):")
	fmt.Printf("   %s\n", totpURI)
}

// generateTOTPCode generates a TOTP code from a Base32-encoded secret
// Returns the 6-digit code and seconds remaining until expiry
func generateTOTPCode(secret string) (string, int64, error) {
	// Remove spaces and convert to uppercase (standard Base32)
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))

	// Decode Base32 secret
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", 0, fmt.Errorf("invalid Base32 secret: %w", err)
	}

	// Get current Unix timestamp
	now := time.Now().Unix()

	// TOTP uses 30-second time steps
	timeStep := int64(30)
	counter := now / timeStep

	// Calculate time remaining in current window
	timeRemaining := timeStep - (now % timeStep)

	// Generate HOTP code using HMAC-SHA1
	code := generateHOTP(key, counter)

	return code, timeRemaining, nil
}

// generateHOTP generates an HOTP code using HMAC-SHA1
func generateHOTP(key []byte, counter int64) string {
	// Convert counter to 8-byte big-endian
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	// HMAC-SHA1
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	// Dynamic truncation (RFC 4226)
	offset := hash[len(hash)-1] & 0x0F
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF

	// Generate 6-digit code
	code := truncated % 1000000

	return fmt.Sprintf("%06d", code)
}
