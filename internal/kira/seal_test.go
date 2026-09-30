//go:build unit || !integration
// +build unit !integration

package kira

import (
	"crypto"
	"strings"
	"testing"
)

func TestSealDataWithSpecsValidation(t *testing.T) {
	// Create a dummy public key for tests that need to reach later validations
	// (we use a non-nil interface value to pass the nil-check)
	type dummyPubKey struct{}
	var dummyKey crypto.PublicKey = &dummyPubKey{}

	t.Run("Rejects empty PCR specs", func(t *testing.T) {
		err := sealDataWithSpecs("/dev/null", []PCRSpec{}, 0x01803010, []byte("data"), nil, "", "", false, PCRHashAlgoSHA256, false, nil)
		if err == nil {
			t.Error("sealDataWithSpecs() expected error for empty specs, got nil")
		}
		if !strings.Contains(err.Error(), "no PCRs specified") {
			t.Errorf("sealDataWithSpecs() error = %q, want to contain 'no PCRs specified'", err.Error())
		}
	})

	t.Run("Rejects empty data", func(t *testing.T) {
		specs := []PCRSpec{{Index: 0, Source: PCRSourceRegister}}
		err := sealDataWithSpecs("/dev/null", specs, 0x01803010, []byte{}, dummyKey, "", "", false, PCRHashAlgoSHA256, false, nil)
		if err == nil {
			t.Error("sealDataWithSpecs() expected error for empty data, got nil")
		}
		if !strings.Contains(err.Error(), "no data to seal") {
			t.Errorf("sealDataWithSpecs() error = %q, want to contain 'no data to seal'", err.Error())
		}
	})

	t.Run("Rejects nil data", func(t *testing.T) {
		specs := []PCRSpec{{Index: 0, Source: PCRSourceRegister}}
		err := sealDataWithSpecs("/dev/null", specs, 0x01803010, nil, dummyKey, "", "", false, PCRHashAlgoSHA256, false, nil)
		if err == nil {
			t.Error("sealDataWithSpecs() expected error for nil data, got nil")
		}
		if !strings.Contains(err.Error(), "no data to seal") {
			t.Errorf("sealDataWithSpecs() error = %q, want to contain 'no data to seal'", err.Error())
		}
	})

	t.Run("Rejects nil signing public key", func(t *testing.T) {
		specs := []PCRSpec{{Index: 0, Source: PCRSourceRegister}}
		err := sealDataWithSpecs("/dev/null", specs, 0x01803010, []byte("test-data"), nil, "", "", false, PCRHashAlgoSHA256, false, nil)
		if err == nil {
			t.Error("sealDataWithSpecs() expected error for nil signing key, got nil")
		}
		if !strings.Contains(err.Error(), "no signing public key provided") {
			t.Errorf("sealDataWithSpecs() error = %q, want to contain 'no signing public key provided'", err.Error())
		}
	})

	t.Run("Empty private key path falls back to default", func(t *testing.T) {
		specs := []PCRSpec{{Index: 0, Source: PCRSourceRegister}}
		err := sealDataWithSpecs("/dev/null", specs, 0x01803010, []byte("test-data"), dummyKey, "", "", false, PCRHashAlgoSHA256, false, nil)
		if err == nil {
			t.Error("sealDataWithSpecs() expected error (TPM or key load), got nil")
		}
		// Empty privKeyPath should fall back to DefaultPrivateKeyPath and proceed
		// past the empty-path check, failing later on TPM open or key load.
		if strings.Contains(err.Error(), "signing private key path is required") {
			t.Errorf("sealDataWithSpecs() should not reject empty privkey path (should fall back to default), got: %q", err.Error())
		}
	})

	t.Run("Fails on invalid TPM path", func(t *testing.T) {
		specs := []PCRSpec{{Index: 0, Source: PCRSourceRegister}}
		err := sealDataWithSpecs("/nonexistent/tpm/path", specs, 0x01803010, []byte("test-data"), dummyKey, "", "/dummy/privkey.pem", false, PCRHashAlgoSHA256, false, nil)
		if err == nil {
			t.Error("sealDataWithSpecs() expected error for invalid TPM path, got nil")
		}
		// The message says what is wrong and how to look, rather than
		// relaying a syscall error.
		if !strings.Contains(err.Error(), "no TPM device at /nonexistent/tpm/path") {
			t.Errorf("sealDataWithSpecs() error = %q, want it to name the missing device", err.Error())
		}
	})
}
