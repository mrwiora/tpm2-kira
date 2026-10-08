package cmd

import (
	"encoding/binary"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"rsc.io/qr"
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

// PrintKIRAError prints an error with colored KIRA formatting
// If the error is a PCRMismatchError, it includes detailed PCR information.
// On the unseal path CurrentDigests always holds TPM register values; no
// eventlog or UKI reconstruction is shown.
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

			status := PCRStatus(expected, current)

			source := ""
			if i < len(pcrErr.PCRSources) {
				source = pcrErr.PCRSources[i].String()
			}

			fmt.Printf("  PCR%-2d (%s): %s - %s\n", pcrIndex, source, GetPCRDescription(pcrIndex), status)
			fmt.Printf("    Expected (blob):    %x\n", expected)
			fmt.Printf("    Current (register): %x\n", current)
		}

		fmt.Println()
		fmt.Println("To fix this, run: tpm2-kira reseal --privkey /path/to/private.key")
	} else if IsTPMPolicyFailure(err) {
		// Handle TPM policy failures with helpful guidance
		fmt.Println(FormatKIRAError(err))
		fmt.Println()
		fmt.Println("=== TPM Policy Failure ===")
		fmt.Println("The TPM policy verification failed. This typically happens when:")
		fmt.Println("- PCR values changed between checking and using them")
		fmt.Println("- The system state has changed since sealing")
		fmt.Println()

		fmt.Println("To see detailed PCR values and fix this, run: tpm2-kira reseal --privkey /path/to/private.key")
		fmt.Println("(Provide the signing private key that corresponds to the public key used during sealing)")
	} else {
		fmt.Println(FormatKIRAError(err))
	}
}

// PCRMismatchError represents a PCR mismatch error with detailed information.
// CurrentDigests always contains values read from TPM registers (the unseal
// path never uses eventlog or UKI reconstruction).
type PCRMismatchError struct {
	Message         string
	PCRIndices      []int
	ExpectedDigests [][]byte    // Digest values stored in the sealed blob
	CurrentDigests  [][]byte    // Current TPM register values
	PCRSources      []PCRSource // Original source used at seal time (informational)
}

func (e *PCRMismatchError) Error() string {
	return e.Message
}

// renderQRCode renders data as a QR code for a terminal.
//
// The encoder is built in: an external qrencode would receive the TOTP
// secret on its command line, which every local user can read from
// /proc/<pid>/cmdline while it runs. Two module rows share one text line
// (half blocks), drawn black on white with ANSI colours so the code scans on
// dark terminal themes too, and surrounded by the quiet zone scanners need.
func renderQRCode(data string) (string, error) {
	code, err := qr.Encode(data, qr.M)
	if err != nil {
		return "", fmt.Errorf("failed to encode QR code: %w", err)
	}
	const quiet = 4
	var b strings.Builder
	for y := -quiet; y < code.Size+quiet; y += 2 {
		b.WriteString("\033[30;47m")
		for x := -quiet; x < code.Size+quiet; x++ {
			top, bottom := code.Black(x, y), code.Black(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\033[0m\n")
	}
	return b.String(), nil
}

// generateTOTPURI creates an otpauth URI for TOTP
//
// The algorithm parameter is only added for SHA-256: SHA-1 is the default
// every authenticator assumes, and some apps reject the parameter.
func generateTOTPURI(secret, label, issuer string, alg tpm2.TPMAlgID) string {
	if label == "" {
		label = "TPM2-KIRA"
	}
	if issuer == "" {
		issuer = "TPM2-KIRA"
	}
	// URL encode the label for proper formatting
	encodedLabel := url.PathEscape(label)
	uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s", encodedLabel, secret, issuer)
	if alg == tpm2.TPMAlgSHA256 {
		uri += "&algorithm=SHA256"
	}
	return uri
}

// displayTOTPQRCode displays a QR code for a TOTP secret with slot and PCR info
func displayTOTPQRCode(secret string, nvramIndex uint32, pcrsStr string, alg tpm2.TPMAlgID) {
	// Get hostname
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}

	slotNumber := SlotNumber(nvramIndex)

	// Create label with slot number and PCRs
	label := fmt.Sprintf("TPM2-KIRA: %s, PCRs %s (#%d)", hostname, pcrsStr, slotNumber)
	totpURI := generateTOTPURI(secret, label, "TPM2-KIRA", alg)

	if qrText, err := renderQRCode(totpURI); err != nil {
		fmt.Printf("   QR code could not be generated: %v\n", err)
	} else {
		fmt.Print(qrText)
	}

	// Always display the URI for manual entry or backup
	fmt.Println()
	fmt.Println("TOTP URI (for manual entry):")
	fmt.Printf("   %s\n", totpURI)
}

// hotpTruncate turns an HMAC into the six-digit code (RFC 4226 dynamic
// truncation). It works for any HMAC of at least 20 bytes, so for the
// SHA-256 keys used on TPMs without SHA-1 too (RFC 6238).
func hotpTruncate(mac []byte) string {
	offset := mac[len(mac)-1] & 0x0F
	truncated := binary.BigEndian.Uint32(mac[offset:offset+4]) & 0x7FFFFFFF
	return fmt.Sprintf("%06d", truncated%1000000)
}
