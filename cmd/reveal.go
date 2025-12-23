package cmd

import (
	"fmt"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
)

// Reveal unseals the TOTP secret from TPM NVRAM and generates a TOTP code
func Reveal(tpmPath, pcrsStr string, nvramIndex uint32, password string, debug bool) error {
	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	// Cleanup TPM memory
	CleanupTPM(tpmDev, debug)

	// Perform unsealing workflow
	result, err := UnsealWorkflow(tpmDev, nvramIndex, password, debug)
	if err != nil {
		return err
	}

	// Get the unsealed TOTP secret
	secret := string(result.UnsealedData)

	// Generate TOTP code
	code, _, err := generateTOTPCode(secret)
	if err != nil {
		return fmt.Errorf("failed to generate TOTP code (invalid TOTP secret): %w", err)
	}

	// Get current time in UTC and display with colored KIRA format
	now := time.Now().UTC()
	timestamp := now.Format("15:04:05")

	// Print in the format: KIRA HH:MM:SS XXXXXX
	fmt.Printf("[ \033[1;33mKIRA\033[0m ] %s: %s\n", timestamp, code)

	return nil
}

// RevealPlain unseals the TOTP secret from TPM NVRAM and generates a plain TOTP code
func RevealPlain(tpmPath, pcrsStr string, nvramIndex uint32, password string, debug bool) error {
	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	// Cleanup TPM memory
	CleanupTPM(tpmDev, debug)

	// Perform unsealing workflow
	result, err := UnsealWorkflow(tpmDev, nvramIndex, password, debug)
	if err != nil {
		return err
	}

	// Get the unsealed TOTP secret
	secret := string(result.UnsealedData)

	// Generate TOTP code
	code, _, err := generateTOTPCode(secret)
	if err != nil {
		return fmt.Errorf("failed to generate TOTP code (invalid TOTP secret): %w", err)
	}

	// Display only the 6-digit TOTP code
	fmt.Println(code)

	return nil
}
