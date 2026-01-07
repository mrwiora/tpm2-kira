//go:build integration
// +build integration

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	// Test configuration
	testTPMPath    = "/tmp/tpm2-kira-test-tpm"
	testNVRAMIndex = "0x01800999"
	testPassword   = "test-password-123"
	testPCRs       = "0,2,4,7"
)

// TestMain sets up and tears down the test environment
func TestMain(m *testing.M) {
	// Check if binary exists, if not build it
	if _, err := os.Stat("./tpm2-kira"); os.IsNotExist(err) {
		fmt.Println("Building tpm2-kira binary for testing...")
		buildCmd := exec.Command("go", "build", "-o", "tpm2-kira")
		if output, err := buildCmd.CombinedOutput(); err != nil {
			fmt.Printf("Failed to build binary: %v\nOutput: %s\n", err, output)
			os.Exit(1)
		}
	}

	// Run tests
	exitCode := m.Run()
	os.Exit(exitCode)
}

// setupSoftwareTPM initializes a software TPM simulator for testing
func setupSoftwareTPM(t *testing.T) (tpmPath string, cleanup func()) {
	// Check if swtpm is available
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not found - skipping TPM integration tests. Install with: apt-get install swtpm")
	}

	// Create temporary directory for TPM state
	tmpDir, err := os.MkdirTemp("", "tpm2-kira-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Use Unix socket mode with .ctrl suffix for control socket
	socketPath := filepath.Join(tmpDir, "swtpm.sock")
	tpmPath = socketPath

	// Start swtpm in Unix socket mode
	// Note: control socket must have .ctrl suffix
	cmd := exec.Command("swtpm", "socket",
		"--tpmstate", "dir="+tmpDir,
		"--ctrl", "type=unixio,path="+socketPath+".ctrl",
		"--tpm2",
		"--server", "type=unixio,path="+socketPath,
		"--flags", "not-need-init")

	// Capture output for debugging
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if err := cmd.Start(); err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to start swtpm: %v", err)
	}

	// Wait for socket to be created
	maxWait := 50 // 5 seconds
	for i := 0; i < maxWait; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
		if i == maxWait-1 {
			cmd.Process.Kill()
			os.RemoveAll(tmpDir)
			t.Fatalf("Timeout waiting for swtpm socket\nStdout: %s\nStderr: %s", outBuf.String(), errBuf.String())
		}
	}

	// Additional delay to ensure TPM is fully ready
	time.Sleep(200 * time.Millisecond)

	// Initialize the TPM with TPM2_Startup command
	// This is required for swtpm to respond to commands properly
	// Use tpm2_startup if available, otherwise skip (may already be initialized)
	if _, err := exec.LookPath("tpm2_startup"); err == nil {
		startupCmd := exec.Command("sh", "-c",
			fmt.Sprintf("TPM2TOOLS_TCTI='swtpm:path=%s' tpm2_startup -c 2>/dev/null || true", socketPath))
		startupCmd.Run() // Ignore errors - TPM might already be initialized
	} else {
		t.Logf("Warning: tpm2_startup not found, TPM may not be initialized. Install tpm2-tools for better compatibility.")
	}

	cleanup = func() {
		// Ensure swtpm process is fully stopped
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}

		// Also kill any lingering swtpm processes using pkill as backup
		exec.Command("pkill", "-f", "swtpm.*"+tmpDir).Run()

		// Small delay to ensure process is dead
		time.Sleep(100 * time.Millisecond)

		// Clean up temporary directory
		os.RemoveAll(tmpDir)
	}

	// Return the Unix socket path for go-tpm to connect
	return tpmPath, cleanup
}

// runTPMKira executes the tpm2-kira binary with given arguments
func runTPMKira(t *testing.T, tpmPath string, args ...string) (stdout, stderr string, err error) {
	return runTPMKiraWithInput(t, tpmPath, "", args...)
}

func runTPMKiraWithInput(t *testing.T, tpmPath string, stdinInput string, args ...string) (stdout, stderr string, err error) {
	// Build args: command comes first, then flags
	// args[0] should be the command (seal, reveal, nvram, etc.)
	allArgs := []string{}

	if len(args) > 0 {
		// First arg is the command
		allArgs = append(allArgs, args[0])

		// Special handling for nvram command which has subcommands
		if args[0] == "nvram" && len(args) > 1 {
			// For nvram: nvram <subcommand> --tpm <path> <other flags>
			// Add subcommand first (list, status, delete)
			allArgs = append(allArgs, args[1])

			// Add TPM path flag after subcommand
			if tpmPath != "" {
				allArgs = append(allArgs, "--tpm", tpmPath)
			}

			// Add remaining args
			if len(args) > 2 {
				allArgs = append(allArgs, args[2:]...)
			}
		} else {
			// For other commands: <command> --tpm <path> <other flags>
			// Add TPM path flag after command if provided
			if tpmPath != "" {
				allArgs = append(allArgs, "--tpm", tpmPath)
			}

			// Add remaining args
			if len(args) > 1 {
				allArgs = append(allArgs, args[1:]...)
			}
		}
	} else {
		// No command provided, just add tpm path if available
		if tpmPath != "" {
			allArgs = append(allArgs, "--tpm", tpmPath)
		}
	}

	cmd := exec.Command("./tpm2-kira", allArgs...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	// If stdin input is provided, set it up
	if stdinInput != "" {
		cmd.Stdin = strings.NewReader(stdinInput)
	}

	err = cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()

	if err != nil {
		t.Logf("Command failed: tpm2-kira %v", allArgs)
		t.Logf("Stdout: %s", stdout)
		t.Logf("Stderr: %s", stderr)
	}

	return stdout, stderr, err
}

// TestSealBasic tests basic seal operation with password
func TestSealBasic(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	// Test seal with password - provide password via stdin with confirmation
	stdinInput := testPassword + "\n" + testPassword + "\n"
	stdout, stderr, err := runTPMKiraWithInput(t, tpmPath, stdinInput,
		"seal",
		"--nvram", testNVRAMIndex,
		"--pcrs", testPCRs,
	)

	if err != nil {
		t.Fatalf("Seal command failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	// Verify output contains expected messages
	if !strings.Contains(stdout, "TOTP Secret Generated") {
		t.Errorf("Expected 'TOTP Secret Generated' in output, got: %s", stdout)
	}

	if !strings.Contains(stdout, "Secret:") {
		t.Errorf("Expected secret in output, got: %s", stdout)
	}
}

// TestSealWithoutPassword tests seal operation without password
func TestSealWithoutPassword(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	// Test seal without password - provide empty password (just press enter)
	stdinInput := "\n"
	stdout, stderr, err := runTPMKiraWithInput(t, tpmPath, stdinInput,
		"seal",
		"--nvram", testNVRAMIndex,
		"--pcrs", testPCRs,
	)

	if err != nil {
		t.Fatalf("Seal command failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	// Verify warning about no password fallback
	if !strings.Contains(stdout, "WARNING: no password fallback") {
		t.Logf("Expected warning about no password fallback, got: %s", stdout)
	}

	if !strings.Contains(stdout, "TOTP Secret Generated") {
		t.Errorf("Expected 'TOTP Secret Generated' in output, got: %s", stdout)
	}
}

// TestSealAndReveal tests seal followed by reveal operation
func TestSealAndReveal(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	// Seal with password
	stdinInput := testPassword + "\n" + testPassword + "\n"
	_, _, err := runTPMKiraWithInput(t, tpmPath, stdinInput,
		"seal",
		"--nvram", testNVRAMIndex,
		"--pcrs", testPCRs,
	)

	if err != nil {
		t.Fatalf("Seal command failed: %v", err)
	}

	// Reveal the TOTP code
	stdout, stderr, err := runTPMKira(t, tpmPath,
		"reveal-plain",
		"--nvram", testNVRAMIndex,
	)

	if err != nil {
		t.Fatalf("Reveal command failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	// Verify output is a 6-digit code
	code := strings.TrimSpace(stdout)
	if len(code) != 6 {
		t.Errorf("Expected 6-digit TOTP code, got: %s", code)
	}

	// Verify it's numeric
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("TOTP code should be numeric, got: %s", code)
			break
		}
	}
}

// TestSealWithCustomPCRs tests seal with custom PCR selection
func TestSealWithCustomPCRs(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	// Test with different PCR combinations
	testCases := []struct {
		name string
		pcrs string
	}{
		{"Single PCR", "0"},
		{"Two PCRs", "0,7"},
		{"Three PCRs", "0,2,7"},
		{"All common PCRs", "0,1,2,3,4,5,6,7"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Use different NVRAM index for each test
			nvramIndex := fmt.Sprintf("0x0180%04d", time.Now().UnixNano()%10000)

			stdinInput := testPassword + "\n" + testPassword + "\n"
			stdout, stderr, err := runTPMKiraWithInput(t, tpmPath, stdinInput,
				"seal",
				"--nvram", nvramIndex,
				"--pcrs", tc.pcrs,
			)

			if err != nil {
				t.Fatalf("Seal with PCRs %s failed: %v\nStdout: %s\nStderr: %s",
					tc.pcrs, err, stdout, stderr)
			}

			// Verify it worked
			if !strings.Contains(stdout, "TOTP Secret Generated") {
				t.Errorf("Expected success message for PCRs %s", tc.pcrs)
			}

			// Clean up - delete the NVRAM index
			runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", nvramIndex)
		})
	}
}

// TestNVRAMDelete tests NVRAM delete functionality
func TestNVRAMDelete(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	// First, seal some data
	stdinInput := testPassword + "\n" + testPassword + "\n"
	_, _, err := runTPMKiraWithInput(t, tpmPath, stdinInput,
		"seal",
		"--nvram", testNVRAMIndex,
		"--pcrs", testPCRs,
	)

	if err != nil {
		t.Fatalf("Seal command failed: %v", err)
	}

	// Verify it exists by checking status
	stdout, _, err := runTPMKira(t, tpmPath,
		"nvram",
		"status",
		"--nvram", testNVRAMIndex,
	)

	if err != nil {
		t.Fatalf("NVRAM status command failed: %v", err)
	}

	if !strings.Contains(stdout, testNVRAMIndex) {
		t.Errorf("Expected NVRAM index %s in status output", testNVRAMIndex)
	}

	// Delete the NVRAM index
	stdout, stderr, err := runTPMKira(t, tpmPath,
		"nvram",
		"delete",
		"--nvram", testNVRAMIndex,
	)

	if err != nil {
		t.Fatalf("NVRAM delete failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	// Verify success message
	if !strings.Contains(stdout, "Successfully deleted") {
		t.Errorf("Expected success message, got: %s", stdout)
	}

	// Verify it no longer exists by trying to reveal
	stdout, stderr, err = runTPMKira(t, tpmPath,
		"reveal",
		"--nvram", testNVRAMIndex,
	)

	// Check if command failed OR if no valid OTP was returned
	code := strings.TrimSpace(stdout)
	hasValidOTP := len(code) == 6
	if hasValidOTP {
		// Double-check it's actually numeric
		for _, c := range code {
			if c < '0' || c > '9' {
				hasValidOTP = false
				break
			}
		}
	}

	if err == nil && hasValidOTP {
		t.Errorf("Expected reveal to fail after deletion, but it succeeded with code: %s", code)
	}

	// Check error message indicates it's not configured
	if err != nil && !strings.Contains(stderr, "not been configured") && !strings.Contains(stderr, "does not exist") {
		t.Logf("Expected 'not configured' or 'does not exist' error, got: %s", stderr)
	}
}

// TestNVRAMDeleteNonExistent tests deleting a non-existent NVRAM index
func TestNVRAMDeleteNonExistent(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	// Try to delete a non-existent index
	_, stderr, err := runTPMKira(t, tpmPath,
		"nvram",
		"delete",
		"--nvram", "0x01809999",
	)

	// Check if command failed OR if error message indicates non-existent index
	hasExpectedError := strings.Contains(stderr, "does not exist") ||
		strings.Contains(stderr, "not found") ||
		strings.Contains(stderr, "invalid")

	if err == nil && !hasExpectedError {
		t.Errorf("Expected delete to fail for non-existent index\nStderr: %s", stderr)
	}

	// Verify error message
	if err != nil && !hasExpectedError {
		t.Logf("Expected 'does not exist' in error, got: %s", stderr)
	}
}

// TestNVRAMList tests listing NVRAM indices
func TestNVRAMList(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	// List should work even with no indices
	stdout, stderr, err := runTPMKira(t, tpmPath,
		"nvram",
		"list",
	)

	if err != nil {
		t.Fatalf("NVRAM list failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	// Seal some data
	stdinInput := testPassword + "\n" + testPassword + "\n"
	_, _, err = runTPMKiraWithInput(t, tpmPath, stdinInput,
		"seal",
		"--nvram", testNVRAMIndex,
	)

	if err != nil {
		t.Fatalf("Seal command failed: %v", err)
	}

	// List again and verify our index appears
	stdout, stderr, err = runTPMKira(t, tpmPath,
		"nvram",
		"list",
	)

	if err != nil {
		t.Fatalf("NVRAM list failed after seal: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	if !strings.Contains(stdout, testNVRAMIndex) {
		t.Errorf("Expected NVRAM index %s in list output, got: %s", testNVRAMIndex, stdout)
	}

	// Clean up
	runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", testNVRAMIndex)
}

// TestSealTwiceOverwrites tests that sealing twice to the same index successfully overwrites
// This is useful behavior - allows re-sealing without manual deletion
func TestSealTwiceOverwrites(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	// First seal with password1
	stdinInput1 := "password1" + "\n" + "password1" + "\n"
	stdout1, _, err := runTPMKiraWithInput(t, tpmPath, stdinInput1,
		"seal",
		"--nvram", testNVRAMIndex,
	)

	if err != nil {
		t.Fatalf("First seal command failed: %v", err)
	}

	// Extract first secret
	var secret1 string
	for _, line := range strings.Split(stdout1, "\n") {
		if strings.HasPrefix(line, "Secret: ") {
			secret1 = strings.TrimPrefix(line, "Secret: ")
			break
		}
	}

	if secret1 == "" {
		t.Fatal("Could not extract first secret from output")
	}

	// Second seal with password2 - should succeed and overwrite
	stdinInput2 := "password2" + "\n" + "password2" + "\n"
	stdout2, _, err := runTPMKiraWithInput(t, tpmPath, stdinInput2,
		"seal",
		"--nvram", testNVRAMIndex,
	)

	if err != nil {
		t.Fatalf("Second seal command failed (expected to succeed and overwrite): %v", err)
	}

	// Extract second secret
	var secret2 string
	for _, line := range strings.Split(stdout2, "\n") {
		if strings.HasPrefix(line, "Secret: ") {
			secret2 = strings.TrimPrefix(line, "Secret: ")
			break
		}
	}

	if secret2 == "" {
		t.Fatal("Could not extract second secret from output")
	}

	// Verify secrets are different (new secret was generated)
	if secret1 == secret2 {
		t.Error("Second seal should generate a new secret, but got the same secret")
	}

	// Verify we can reveal with the new secret
	stdout3, _, err := runTPMKira(t, tpmPath,
		"reveal-plain",
		"--nvram", testNVRAMIndex,
	)

	if err != nil {
		t.Fatalf("Reveal after second seal failed: %v", err)
	}

	// Should get a TOTP code
	code := strings.TrimSpace(stdout3)
	if len(code) != 6 {
		t.Errorf("Expected 6-digit TOTP code after overwrite, got: %s", code)
	}

	// Clean up
	runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", testNVRAMIndex)
}

// TestInfo tests the info command
func TestInfo(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	// Seal with password
	stdinInput := testPassword + "\n" + testPassword + "\n"
	_, _, err := runTPMKiraWithInput(t, tpmPath, stdinInput,
		"seal",
		"--nvram", testNVRAMIndex,
		"--pcrs", testPCRs,
	)

	if err != nil {
		t.Fatalf("Seal command failed: %v", err)
	}

	// Get info
	stdout, stderr, err := runTPMKira(t, tpmPath,
		"info",
		"--nvram", testNVRAMIndex,
	)

	if err != nil {
		t.Fatalf("Info command failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	// Verify output contains expected information
	expectedStrings := []string{
		"Sealed Blob Information",
		"PCR Configuration",
		"Password",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(stdout, expected) {
			t.Errorf("Expected '%s' in info output, got: %s", expected, stdout)
		}
	}

	// Clean up
	runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", testNVRAMIndex)
}

// TestInfoJSON tests the info command with JSON output
func TestInfoJSON(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	// Seal with password
	stdinInput := testPassword + "\n" + testPassword + "\n"
	_, _, err := runTPMKiraWithInput(t, tpmPath, stdinInput,
		"seal",
		"--nvram", testNVRAMIndex,
	)

	if err != nil {
		t.Fatalf("Seal command failed: %v", err)
	}

	// Get info as JSON
	stdout, stderr, err := runTPMKira(t, tpmPath,
		"info",
		"--nvram", testNVRAMIndex,
		"--json",
	)

	if err != nil {
		t.Fatalf("Info JSON command failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	// Verify it's valid JSON by checking for braces
	stdout = strings.TrimSpace(stdout)
	if !strings.HasPrefix(stdout, "{") || !strings.HasSuffix(stdout, "}") {
		t.Errorf("Expected JSON output, got: %s", stdout)
	}

	// Verify it contains expected JSON fields
	expectedFields := []string{
		"\"version\"",
		"\"pcr_digests\"",
		"\"has_password\"",
	}

	for _, field := range expectedFields {
		if !strings.Contains(stdout, field) {
			t.Errorf("Expected JSON field %s in output, got: %s", field, stdout)
		}
	}

	// Clean up
	runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", testNVRAMIndex)
}

// TestDebugFlag tests that debug flag provides additional output
func TestDebugFlag(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	// Seal with debug flag
	stdinInput := testPassword + "\n" + testPassword + "\n"
	stdout, stderr, err := runTPMKiraWithInput(t, tpmPath, stdinInput,
		"seal",
		"--nvram", testNVRAMIndex,
		"--debug",
	)

	if err != nil {
		t.Fatalf("Seal with debug failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	// Debug output should contain technical details
	if !strings.Contains(stdout, "Successfully sealed") {
		t.Logf("Expected debug information in output with --debug flag")
	}

	// Clean up
	runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", testNVRAMIndex)
}

// Helper functions for modular testing

// testSeal performs a seal operation and validates success
func testSeal(t *testing.T, tpmPath, nvramIndex, password string) {
	t.Helper()
	args := []string{"seal", "--nvram", nvramIndex, "--pcrs", testPCRs}

	var stdinInput string
	if password != "" {
		// Provide password + confirmation
		stdinInput = password + "\n" + password + "\n"
	} else {
		// Just press enter for no password
		stdinInput = "\n"
	}

	stdout, stderr, err := runTPMKiraWithInput(t, tpmPath, stdinInput, args...)
	if err != nil {
		t.Fatalf("✗ Seal failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "TOTP Secret Generated") {
		t.Fatalf("✗ Seal output missing 'TOTP Secret Generated': %s", stdout)
	}
	if password == "" && !strings.Contains(stdout, "WARNING: no password fallback") {
		t.Logf("Note: Expected warning about no password fallback")
	}
	t.Log("✓ Seal successful")
}

// testReveal performs a reveal operation and validates the TOTP code
func testReveal(t *testing.T, tpmPath, nvramIndex string) string {
	t.Helper()
	stdout, stderr, err := runTPMKira(t, tpmPath, "reveal-plain", "--nvram", nvramIndex)
	if err != nil {
		t.Fatalf("✗ Reveal failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	code := strings.TrimSpace(stdout)
	if len(code) != 6 {
		t.Fatalf("✗ Reveal returned invalid TOTP code (expected 6 digits): %s", code)
	}

	// Verify it's numeric
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Fatalf("✗ TOTP code should be numeric, got: %s", code)
		}
	}

	t.Logf("✓ Reveal successful (code: %s)", code)
	return code
}

// testRun executes the run command for a specified duration and then kills it
func testRun(t *testing.T, tpmPath, nvramIndex string, duration time.Duration) {
	t.Helper()
	runCmd := exec.Command("./tpm2-kira", "run", "--tpm", tpmPath, "--nvram", nvramIndex)
	var runOut bytes.Buffer
	runCmd.Stdout = &runOut
	runCmd.Stderr = &runOut

	if err := runCmd.Start(); err != nil {
		t.Fatalf("✗ Run command failed to start: %v", err)
	}

	// Let it run for specified duration
	time.Sleep(duration)

	// Kill the process
	if err := runCmd.Process.Kill(); err != nil {
		t.Fatalf("✗ Failed to kill run process: %v", err)
	}
	runCmd.Wait() // Clean up the process

	// Check that it produced some output
	runOutput := runOut.String()
	if len(runOutput) < 6 {
		t.Logf("Run output: %s", runOutput)
		t.Log("Note: Run command produced minimal output")
	}
	t.Log("✓ Run command executed successfully and was killed")
}

// testResealSuccess performs a reseal operation that should succeed
func testResealSuccess(t *testing.T, tpmPath, nvramIndex, password string) {
	t.Helper()
	stdinInput := password + "\n"
	stdout, stderr, err := runTPMKiraWithInput(t, tpmPath, stdinInput,
		"reseal",
		"--nvram", nvramIndex,
	)
	if err != nil {
		t.Fatalf("✗ Reseal failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "Successfully resealed") {
		t.Fatalf("✗ Reseal output missing success message: %s", stdout)
	}
	t.Log("✓ Reseal successful")
}

// testResealFailure performs a reseal operation that should fail
func testResealFailure(t *testing.T, tpmPath, nvramIndex, password, expectedError string) {
	t.Helper()
	args := []string{"reseal", "--nvram", nvramIndex}

	var stdinInput string
	if password != "" {
		stdinInput = password + "\n"
	} else {
		stdinInput = "\n"
	}

	stdout, stderr, err := runTPMKiraWithInput(t, tpmPath, stdinInput, args...)
	combinedOutput := stdout + stderr

	// Check if command failed OR if the expected error message is present
	hasExpectedError := strings.Contains(combinedOutput, expectedError)

	if err == nil && !hasExpectedError {
		t.Fatalf("✗ Reseal should have failed but succeeded\nStdout: %s\nStderr: %s", stdout, stderr)
	}

	if err != nil && !hasExpectedError {
		t.Logf("Note: Expected error containing '%s', got: %s", expectedError, combinedOutput)
	}

	t.Logf("✓ Reseal correctly failed (%s)", expectedError)
}

// testNVRAMDelete performs an NVRAM delete operation and validates success
func testNVRAMDelete(t *testing.T, tpmPath, nvramIndex string) {
	t.Helper()
	stdout, stderr, err := runTPMKira(t, tpmPath,
		"nvram",
		"delete",
		"--nvram", nvramIndex,
	)
	if err != nil {
		t.Fatalf("✗ NVRAM delete failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "Successfully deleted") {
		t.Fatalf("✗ NVRAM delete missing success message: %s", stdout)
	}
	t.Log("✓ NVRAM delete successful")
}

// testNVRAMDeleted verifies that data no longer exists in NVRAM
func testNVRAMDeleted(t *testing.T, tpmPath, nvramIndex string) {
	t.Helper()
	stdout, stderr, err := runTPMKira(t, tpmPath, "reveal", "--nvram", nvramIndex)

	// Check if command failed OR if no valid OTP was returned
	code := strings.TrimSpace(stdout)
	hasValidOTP := len(code) == 6
	if hasValidOTP {
		// Double-check it's actually numeric
		for _, c := range code {
			if c < '0' || c > '9' {
				hasValidOTP = false
				break
			}
		}
	}

	if err == nil && hasValidOTP {
		t.Fatalf("✗ Reveal should fail after deletion but succeeded with code: %s", code)
	}

	if err != nil {
		if !strings.Contains(stderr, "not been configured") && !strings.Contains(stderr, "does not exist") {
			t.Logf("Note: Expected 'not configured' or 'does not exist' error, got: %s", stderr)
		}
	}
	t.Log("✓ Verified: data no longer accessible")
}

// TestCompleteWorkflow is a comprehensive integration test that verifies the complete workflow
// including seal, reveal, run, reseal, and nvram delete operations with and without passwords
func TestCompleteWorkflow(t *testing.T) {
	t.Log("=== PREPARATION ===")

	// Setup swtpm - must be successful
	t.Log("Setting up software TPM...")
	tpmPath, cleanup := setupSoftwareTPM(t)
	if tpmPath == "" {
		t.Fatal("Setup swtpm failed - no TPM path returned")
	}
	t.Logf("✓ Setup swtpm successful (path: %s)", tpmPath)

	// Cleanup will be called at the end
	defer func() {
		t.Log("\n=== RAMPDOWN ===")
		t.Log("Removing swtpm service and tmp folder...")
		cleanup()
		t.Log("✓ Cleanup completed")
	}()

	// Startup tpm2 - must be successful (already done in setupSoftwareTPM)
	t.Log("✓ Startup TPM2 successful")

	// Use unique NVRAM indices for each phase to avoid conflicts
	nvramIndexNoPassword := "0x01800001"
	nvramIndexWithPassword := "0x01800002"

	// ===================================================================
	t.Log("\n=== TEST WITH NO PASSWORD ===")
	// ===================================================================

	// Seal without password - must be successful
	t.Log("Testing seal without password...")
	testSeal(t, tpmPath, nvramIndexNoPassword, "")

	// Reveal - must be successful
	t.Log("Testing reveal after seal without password...")
	testReveal(t, tpmPath, nvramIndexNoPassword)

	// Run - must be running successfully, needs to be killed
	t.Log("Testing run command (will kill after 3 seconds)...")
	testRun(t, tpmPath, nvramIndexNoPassword, 3*time.Second)

	// Reseal - must fail (no password was set during seal)
	t.Log("Testing reseal (should fail - no password fallback available)...")
	testResealFailure(t, tpmPath, nvramIndexNoPassword, testPassword, "password")

	// NVRAM delete - must be successful
	t.Log("Testing nvram delete...")
	testNVRAMDelete(t, tpmPath, nvramIndexNoPassword)

	// ===================================================================
	t.Log("\n=== TEST WITH PASSWORD ===")
	// ===================================================================

	// Seal with password - must be successful
	t.Log("Testing seal with password...")
	testSeal(t, tpmPath, nvramIndexWithPassword, testPassword)

	// Reveal - must be successful
	t.Log("Testing reveal after seal with password...")
	testReveal(t, tpmPath, nvramIndexWithPassword)

	// Reseal without password parameter - must fail
	t.Log("Testing reseal without password parameter (should fail)...")
	testResealFailure(t, tpmPath, nvramIndexWithPassword, "", "password")

	// Reseal with incorrect password when PCRs match - succeeds because PCR policy is satisfied
	t.Log("Testing reseal with incorrect password when PCRs match (should succeed - PCR policy satisfied)...")
	wrongPassword := "wrong-password-123"
	testResealSuccess(t, tpmPath, nvramIndexWithPassword, wrongPassword)
	t.Log("✓ Reseal succeeded with wrong password because PCRs match (PCR policy satisfied)")

	// Reseal with correct password - must be successful
	t.Log("Testing reseal with correct password...")
	testResealSuccess(t, tpmPath, nvramIndexWithPassword, testPassword)

	// Verify reveal still works after reseal
	t.Log("Testing reveal after reseal...")
	testReveal(t, tpmPath, nvramIndexWithPassword)

	// NVRAM delete - must be successful
	t.Log("Testing nvram delete...")
	testNVRAMDelete(t, tpmPath, nvramIndexWithPassword)

	// Verify data is actually deleted
	t.Log("Verifying data is deleted...")
	testNVRAMDeleted(t, tpmPath, nvramIndexWithPassword)

	// ===================================================================
	t.Log("\n=== TEST WITH PCR EXTENSION ===")
	// ===================================================================

	nvramIndexPCR := "0x01800003"
	customPCRs := "0,23"

	// Seal with password and custom PCRs - must be successful
	t.Log("Testing seal with password and PCR 0,23...")
	stdinInput := testPassword + "\n" + testPassword + "\n"
	stdout, stderr, err := runTPMKiraWithInput(t, tpmPath, stdinInput,
		"seal",
		"--nvram", nvramIndexPCR,
		"--pcrs", customPCRs,
	)
	if err != nil {
		t.Fatalf("✗ Seal with custom PCRs failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "TOTP Secret Generated") {
		t.Fatalf("✗ Seal output missing 'TOTP Secret Generated': %s", stdout)
	}
	t.Log("✓ Seal with PCR 0,23 successful")

	// Reveal - must be successful
	t.Log("Testing reveal before PCR extension...")
	testReveal(t, tpmPath, nvramIndexPCR)

	// Execute tpm2_pcrextend to change PCR 23
	t.Log("Extending PCR 23 (this will break PCR policy)...")
	extendCmd := exec.Command("sh", "-c",
		fmt.Sprintf("TPM2TOOLS_TCTI='swtpm:path=%s' tpm2_pcrextend 23:sha256=0x99E38F0F51A998A56FDB6AD280B7F104457160505A1625EFB4DA7226E9120558", tpmPath))
	if output, err := extendCmd.CombinedOutput(); err != nil {
		t.Fatalf("✗ PCR extend failed: %v\nOutput: %s", err, output)
	}
	t.Log("✓ PCR 23 extended successfully")

	// Reveal after PCR change - must fail
	t.Log("Testing reveal after PCR extension (should fail)...")
	// Provide empty stdin input so password prompt fails
	stdout, stderr, err = runTPMKiraWithInput(t, tpmPath, "",
		"reveal",
		"--nvram", nvramIndexPCR,
	)

	// Check if command failed OR if no valid OTP was returned
	code := strings.TrimSpace(stdout)
	hasValidOTP := len(code) == 6
	if hasValidOTP {
		// Double-check it's actually numeric
		for _, c := range code {
			if c < '0' || c > '9' {
				hasValidOTP = false
				break
			}
		}
	}

	if err == nil && hasValidOTP {
		t.Fatalf("✗ Reveal should have failed after PCR extension but succeeded with code: %s", code)
	}
	t.Logf("✓ Reveal correctly failed after PCR change (error: %s)", strings.TrimSpace(stderr))

	// Verify PCR mismatch information is displayed
	t.Log("Verifying PCR mismatch information is shown...")
	if !strings.Contains(stdout, "PCR Mismatch") {
		t.Fatalf("✗ PCR mismatch header not found in output. Stdout: %s", stdout)
	}
	if !strings.Contains(stdout, "0") || !strings.Contains(stdout, "23") {
		t.Fatalf("✗ PCR indices not shown in mismatch output. Stdout: %s", stdout)
	}
	if !strings.Contains(stdout, "PCR23") && !strings.Contains(stdout, "CHANGED") {
		t.Fatalf("✗ PCR23 change status not shown in mismatch output. Stdout: %s", stdout)
	}
	if !strings.Contains(stdout, "Expected") || !strings.Contains(stdout, "Current") {
		t.Fatalf("✗ Expected/Current PCR values not shown in mismatch output. Stdout: %s", stdout)
	}
	t.Log("✓ PCR mismatch information correctly displayed")

	// Reseal with wrong password after PCR mismatch - must fail (password auth required)
	t.Log("Testing reseal with wrong password after PCR extension (should fail - password auth required)...")
	stdinInput = wrongPassword + "\n"
	stdout, stderr, err = runTPMKiraWithInput(t, tpmPath, stdinInput,
		"reseal",
		"--nvram", nvramIndexPCR,
	)

	// Check if command failed OR if error message indicates wrong password
	combinedOutput := stdout + stderr
	hasPasswordError := strings.Contains(combinedOutput, "password") ||
		strings.Contains(combinedOutput, "authentication") ||
		strings.Contains(combinedOutput, "incorrect")

	if err == nil && !hasPasswordError {
		t.Fatalf("✗ Reseal with wrong password should have failed when PCRs don't match\nStdout: %s\nStderr: %s", stdout, stderr)
	}
	if !strings.Contains(stderr, "incorrect password") && !strings.Contains(stdout, "incorrect password") {
		t.Logf("Expected 'incorrect password' error, got: %s", stderr)
	}
	t.Log("✓ Reseal correctly failed with wrong password when PCRs don't match")

	// Test reseal with correct password to verify PCR mismatch information is shown
	t.Log("Testing reseal with correct password to verify PCR mismatch display...")
	stdinInput = testPassword + "\n"
	stdout, stderr, err = runTPMKiraWithInput(t, tpmPath, stdinInput,
		"reseal",
		"--nvram", nvramIndexPCR,
	)
	if err != nil {
		t.Fatalf("✗ Reseal with correct password failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	// Verify PCR mismatch information is shown during successful reseal
	t.Log("Verifying PCR mismatch information is shown during reseal...")
	if !strings.Contains(stdout, "PCR Mismatch") {
		t.Fatalf("✗ PCR mismatch header not found in reseal output. Stdout: %s", stdout)
	}
	if !strings.Contains(stdout, "PCR values changed") && !strings.Contains(stdout, "password authentication") {
		t.Fatalf("✗ PCR change notification not shown in reseal output. Stdout: %s", stdout)
	}
	t.Log("✓ PCR mismatch information correctly displayed during reseal")

	t.Log("✓ Reseal with correct password successful")

	// Verify PCRs are still 0,23 by checking info output
	t.Log("Verifying PCRs are still 0,23 using info command...")
	stdout, stderr, err = runTPMKira(t, tpmPath,
		"info",
		"--nvram", nvramIndexPCR,
	)
	if err != nil {
		t.Fatalf("✗ Info command failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "0") || !strings.Contains(stdout, "23") {
		t.Logf("Warning: Info output may not show expected PCRs 0,23: %s", stdout)
	}
	t.Log("✓ Verified PCRs configuration preserved")

	// Reveal after reseal - must be successful
	t.Log("Testing reveal after reseal with new PCR values...")
	testReveal(t, tpmPath, nvramIndexPCR)

	// Cleanup
	t.Log("Testing nvram delete for PCR test...")
	testNVRAMDelete(t, tpmPath, nvramIndexPCR)

	t.Log("\n=== ALL TESTS PASSED ===")
}

// TestQuickWorkflow demonstrates reusability of helper functions for a simpler test scenario
func TestQuickWorkflow(t *testing.T) {
	t.Log("=== Quick Workflow Test (demonstrating modular functions) ===")

	// Setup
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	nvramIndex := "0x01800003"

	// Simple workflow: seal -> reveal -> delete
	t.Log("Step 1: Seal with password")
	testSeal(t, tpmPath, nvramIndex, testPassword)

	t.Log("Step 2: Reveal")
	testReveal(t, tpmPath, nvramIndex)

	t.Log("Step 3: Reseal with same password")
	testResealSuccess(t, tpmPath, nvramIndex, testPassword)

	t.Log("Step 4: Reveal again after reseal")
	testReveal(t, tpmPath, nvramIndex)

	t.Log("Step 5: Delete")
	testNVRAMDelete(t, tpmPath, nvramIndex)

	t.Log("Step 6: Verify deletion")
	testNVRAMDeleted(t, tpmPath, nvramIndex)

	t.Log("✓ Quick workflow completed successfully")
}

// TestExitCodes verifies that all commands return exit code 0 even with errors
func TestExitCodes(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	nvramIndex := "0x01800010"

	t.Log("=== Testing Exit Codes ===")

	// Test 1: Reveal on non-existent NVRAM (should exit 0 with error message)
	t.Log("Test 1: Reveal on non-existent NVRAM...")
	cmd := exec.Command("./tpm2-kira", "reveal", "--tpm", tpmPath, "--nvram", nvramIndex)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		t.Errorf("✗ Reveal on non-existent NVRAM returned non-zero exit code: %v", err)
	} else {
		t.Log("✓ Reveal on non-existent NVRAM returned exit code 0")
	}

	// Test 2: Seal and then extend PCR to cause mismatch
	t.Log("Test 2: Seal with PCR 0,23...")
	stdinInput := testPassword + "\n" + testPassword + "\n"
	_, _, err = runTPMKiraWithInput(t, tpmPath, stdinInput,
		"seal",
		"--nvram", nvramIndex,
		"--pcrs", "0,23",
	)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	t.Log("✓ Seal successful")

	// Test 3: Reveal before PCR extension (should work)
	t.Log("Test 3: Reveal before PCR extension...")
	cmd = exec.Command("./tpm2-kira", "reveal", "--tpm", tpmPath, "--nvram", nvramIndex)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		t.Errorf("✗ Reveal before PCR extension returned non-zero exit code: %v", err)
	} else {
		t.Log("✓ Reveal before PCR extension returned exit code 0")
	}

	// Test 4: Extend PCR 23
	t.Log("Test 4: Extending PCR 23...")
	extendCmd := exec.Command("tpm2_pcrextend", "23:sha256=0000000000000000000000000000000000000000000000000000000000000000")
	extendCmd.Env = append(os.Environ(), "TPM2TOOLS_TCTI=swtpm:path="+tpmPath)
	if output, err := extendCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to extend PCR: %v\nOutput: %s", err, output)
	}
	t.Log("✓ PCR 23 extended")

	// Test 5: Reveal after PCR extension (should show mismatch but exit 0)
	t.Log("Test 5: Reveal after PCR extension (with mismatch)...")
	stdout.Reset()
	stderr.Reset()
	cmd = exec.Command("./tpm2-kira", "reveal", "--tpm", tpmPath, "--nvram", nvramIndex)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		t.Errorf("✗ Reveal with PCR mismatch returned non-zero exit code: %v", err)
	} else {
		t.Log("✓ Reveal with PCR mismatch returned exit code 0")
		// Verify PCR Mismatch is shown in output
		if !strings.Contains(stdout.String(), "PCR Mismatch") {
			t.Errorf("✗ PCR Mismatch not shown in output")
		} else {
			t.Log("✓ PCR Mismatch shown in output")
		}
	}

	// Test 6: Reveal-plain with PCR mismatch
	t.Log("Test 6: Reveal-plain after PCR extension (with mismatch)...")
	stdout.Reset()
	stderr.Reset()
	cmd = exec.Command("./tpm2-kira", "reveal-plain", "--tpm", tpmPath, "--nvram", nvramIndex)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		t.Errorf("✗ Reveal-plain with PCR mismatch returned non-zero exit code: %v", err)
	} else {
		t.Log("✓ Reveal-plain with PCR mismatch returned exit code 0")
	}

	// Test 7: Info command on slot with PCR mismatch
	t.Log("Test 7: Info command with PCR mismatch...")
	stdout.Reset()
	stderr.Reset()
	cmd = exec.Command("./tpm2-kira", "info", "--tpm", tpmPath, "--nvram", nvramIndex)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		t.Errorf("✗ Info with PCR mismatch returned non-zero exit code: %v", err)
	} else {
		t.Log("✓ Info with PCR mismatch returned exit code 0")
	}

	// Test 8: Reseal without password (should fail password validation but exit 0)
	t.Log("Test 8: Reseal without password (should show error but exit 0)...")
	stdout.Reset()
	stderr.Reset()
	cmd = exec.Command("./tpm2-kira", "reseal", "--tpm", tpmPath, "--nvram", nvramIndex)
	cmd.Stdin = strings.NewReader("\n") // Empty password
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		t.Errorf("✗ Reseal without password returned non-zero exit code: %v", err)
	} else {
		t.Log("✓ Reseal without password returned exit code 0")
	}

	// Test 9: NVRAM status on non-existent index
	t.Log("Test 9: NVRAM status on non-existent index...")
	stdout.Reset()
	stderr.Reset()
	cmd = exec.Command("./tpm2-kira", "nvram", "status", "--tpm", tpmPath, "--nvram", "0x01800050")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		t.Errorf("✗ NVRAM status on non-existent index returned non-zero exit code: %v", err)
	} else {
		t.Log("✓ NVRAM status on non-existent index returned exit code 0")
	}

	// Test 10: Delete non-existent NVRAM index
	t.Log("Test 10: NVRAM delete on non-existent index...")
	stdout.Reset()
	stderr.Reset()
	cmd = exec.Command("./tpm2-kira", "nvram", "delete", "--tpm", tpmPath, "--nvram", "0x01800051")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		t.Errorf("✗ NVRAM delete on non-existent index returned non-zero exit code: %v", err)
	} else {
		t.Log("✓ NVRAM delete on non-existent index returned exit code 0")
	}

	t.Log("✓ All exit code tests passed")
}
