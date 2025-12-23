package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// ReadPasswordFromStdin securely reads a password from stdin without echoing it to the terminal.
// It prompts the user with the provided message and returns the password string.
func ReadPasswordFromStdin(prompt string) (string, error) {
	// Check if we're running in a terminal
	if !term.IsTerminal(int(syscall.Stdin)) {
		// Not a terminal, read from stdin normally (for scripts/pipes)
		fmt.Fprint(os.Stderr, prompt)
		reader := bufio.NewReader(os.Stdin)
		password, err := reader.ReadString('\n')
		if err != nil {
			// Handle EOF as empty input
			if err == io.EOF {
				return "", nil
			}
			return "", fmt.Errorf("failed to read password from stdin: %w", err)
		}
		return strings.TrimSpace(password), nil
	}

	// Terminal mode - read password securely without echoing
	fmt.Fprint(os.Stderr, prompt)
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Fprintln(os.Stderr) // Print newline after password input

	return string(passwordBytes), nil
}

// ReadOptionalPasswordFromStdin reads a password from stdin.
// If the user presses enter without typing anything, it returns an empty string (no password).
// Otherwise, it prompts for confirmation.
func ReadOptionalPasswordFromStdin(purpose string) (string, error) {
	// Read password
	password, err := ReadPasswordFromStdin(fmt.Sprintf("Enter password for %s (press enter for no password): ", purpose))
	if err != nil {
		return "", err
	}

	// If empty password, that means no password
	if password == "" {
		return "", nil
	}

	// Confirm password
	confirmPassword, err := ReadPasswordFromStdin("Confirm password: ")
	if err != nil {
		return "", err
	}

	if password != confirmPassword {
		return "", fmt.Errorf("passwords do not match")
	}

	return password, nil
}

// ReadRequiredPasswordFromStdin reads a required password from stdin with confirmation.
// This is used for operations where a password is mandatory.
func ReadRequiredPasswordFromStdin(purpose string) (string, error) {
	fmt.Fprintf(os.Stderr, "A password is required for %s.\n", purpose)

	// Read password
	password, err := ReadPasswordFromStdin("Enter password: ")
	if err != nil {
		return "", err
	}

	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	return password, nil
}

// ReadExistingPasswordFromStdin reads an existing password from stdin for authentication.
// This is used when accessing already sealed data.
func ReadExistingPasswordFromStdin() (string, error) {
	password, err := ReadPasswordFromStdin("Enter password: ")
	if err != nil {
		return "", err
	}

	// If password is empty (EOF or just enter), treat as authentication failure
	if password == "" {
		return "", fmt.Errorf("password required but none provided")
	}

	return password, nil
}
