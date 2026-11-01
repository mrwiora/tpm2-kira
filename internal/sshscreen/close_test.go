package sshscreen

import (
	"strings"
	"testing"
	"time"
)

// A TPM that does not come: Close fails after its wait, so that the resume
// from hibernation, or the boot, stops.
func TestCloseWithoutTPM(t *testing.T) {
	defer func(w time.Duration) { closeTPMWait = w }(closeTPMWait)
	closeTPMWait = 100 * time.Millisecond
	start := time.Now()
	err := Close("/dev/tpm2-kira-test-none")
	if err == nil || !strings.Contains(err.Error(), "did not appear") {
		t.Fatalf("without a TPM: %v", err)
	}
	if time.Since(start) < closeTPMWait {
		t.Fatal("did not wait for the TPM")
	}
}
