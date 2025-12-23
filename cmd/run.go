package cmd

import (
	"fmt"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
)

// Run unseals the TOTP secret from TPM NVRAM and continuously generates TOTP codes
// In case of errors, it retries every 30 seconds and displays error messages
func Run(tpmPath, pcrsStr string, nvramIndex uint32, debug bool) error {
	var secret string
	var lastCode string
	var lastError error
	var lastErrorTime time.Time

	for {
		// If we don't have a valid secret, try to unseal it
		if secret == "" {
			// Open TPM
			tpmDev, err := transport.OpenTPM(tpmPath)
			if err != nil {
				currentTime := time.Now()
				newError := fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)

				// Show error message if it's new or 30 seconds have passed
				if lastError == nil || lastError.Error() != newError.Error() || currentTime.Sub(lastErrorTime) >= 30*time.Second {
					PrintKIRAError(newError)
					lastError = newError
					lastErrorTime = currentTime
				}

				// Wait 30 seconds before retrying
				time.Sleep(30 * time.Second)
				continue
			}

			// Cleanup TPM memory
			CleanupTPM(tpmDev, debug)

			// Perform unsealing workflow
			result, err := UnsealWorkflow(tpmDev, nvramIndex, debug)
			tpmDev.Close()

			if err != nil {
				currentTime := time.Now()

				// Show error message if it's new or 30 seconds have passed
				if lastError == nil || lastError.Error() != err.Error() || currentTime.Sub(lastErrorTime) >= 30*time.Second {
					PrintKIRAError(err)
					lastError = err
					lastErrorTime = currentTime
				}

				// Wait 30 seconds before retrying
				time.Sleep(30 * time.Second)
				continue
			}

			// Get the unsealed TOTP secret
			candidateSecret := string(result.UnsealedData)

			// Verify secret is valid
			_, _, err = generateTOTPCode(candidateSecret)
			if err != nil {
				currentTime := time.Now()
				newError := fmt.Errorf("failed to generate TOTP code (invalid TOTP secret): %w", err)

				// Show error message if it's new or 30 seconds have passed
				if lastError == nil || lastError.Error() != newError.Error() || currentTime.Sub(lastErrorTime) >= 30*time.Second {
					PrintKIRAError(newError)
					lastError = newError
					lastErrorTime = currentTime
				}

				// Wait 30 seconds before retrying
				time.Sleep(30 * time.Second)
				continue
			}

			// Successfully unsealed and validated secret
			secret = candidateSecret
			lastError = nil // Clear any previous error
		}

		// Generate TOTP code
		code, timeRemaining, err := generateTOTPCode(secret)
		if err != nil {
			currentTime := time.Now()
			newError := fmt.Errorf("failed to generate TOTP code: %w", err)

			// Show error message if it's new or 30 seconds have passed
			if lastError == nil || lastError.Error() != newError.Error() || currentTime.Sub(lastErrorTime) >= 30*time.Second {
				PrintKIRAError(newError)
				lastError = newError
				lastErrorTime = currentTime
			}

			// Clear the secret to force re-unsealing
			secret = ""

			// Wait 30 seconds before retrying
			time.Sleep(30 * time.Second)
			continue
		}

		// Only print if the code has changed (new time window)
		if code != lastCode {
			// Display with colored KIRA format
			PrintKIRAOutput(code)
			lastCode = code
			lastError = nil // Clear any previous error since we're successful
		}

		// Sleep until the next time window
		// Add a small buffer to ensure we don't miss the transition
		time.Sleep(time.Duration(timeRemaining) * time.Second)
	}
}
