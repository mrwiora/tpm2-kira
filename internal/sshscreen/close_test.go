package sshscreen

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A TPM that does not come: Close fails after its wait, so that the resume
// from hibernation stops.
func TestCloseWithoutTPM(t *testing.T) {
	defer func(w time.Duration) { closeTPMWait = w }(closeTPMWait)
	closeTPMWait = 100 * time.Millisecond
	dir := t.TempDir()
	start := time.Now()
	err := Close("/dev/tpm2-kira-test-none", filepath.Join(dir, "assh.conf"))
	if err == nil || !strings.Contains(err.Error(), "did not appear") {
		t.Fatalf("without a TPM: %v", err)
	}
	if time.Since(start) < closeTPMWait {
		t.Fatal("did not wait for the TPM")
	}
}
