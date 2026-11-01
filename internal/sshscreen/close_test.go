package sshscreen

import (
	"errors"
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

// A close that fails is tried once more, and only once: a passing fault does
// not power the machine off, a lasting one does.
func TestCloseRetried(t *testing.T) {
	for _, tc := range []struct {
		fails, calls int
		wantErr      bool
	}{{0, 1, false}, {1, 2, false}, {2, 2, true}, {5, 2, true}} {
		calls := 0
		err := closeRetried(func() error {
			calls++
			if calls <= tc.fails {
				return errors.New("the TPM said no")
			}
			return nil
		})
		if calls != tc.calls || (err != nil) != tc.wantErr {
			t.Errorf("%d failures: %d calls, %v", tc.fails, calls, err)
		}
	}
}
