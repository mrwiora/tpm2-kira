package cmd

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

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
	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s", label, secret, issuer)
}

// displayTOTPQRCode generates and displays a QR code for a TOTP secret
// If qrencode is not available, displays installation instructions
func displayTOTPQRCode(secret string) {
	// Get hostname
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}

	label := fmt.Sprintf("TPM2-KIRA: %s", hostname)
	totpURI := generateTOTPURI(secret, label, "TPM2-KIRA")

	if err := generateQRCode(totpURI); err != nil {
		fmt.Printf("   QR code could not be generated: %v\n", err)
		fmt.Println("   Install 'qrencode' package to enable QR code display")
		fmt.Println("   Example: apt install qrencode  # Debian/Ubuntu")
		fmt.Println("           dnf install qrencode  # Fedora")
		fmt.Println("           pacman -S qrencode    # Arch Linux")
		fmt.Printf("   Or manually generate from: %s\n", totpURI)
	}
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
