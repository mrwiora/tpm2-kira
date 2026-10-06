package cmd

import (
	"strings"
	"testing"

	"github.com/matthias/tpm2-kira/attest"
)

func TestCheckSamePCRs(t *testing.T) {
	blob := &Attestation{PCRAlg: attest.AlgSHA1, PCRSelection: []uint8{0, 2, 7, 11}}
	for _, ok := range []string{"0,2,7,11", "11, 7,2,0"} {
		if err := checkSamePCRs(blob, ok, 0); err != nil {
			t.Errorf("--pcrs %q: %v", ok, err)
		}
	}
	err := checkSamePCRs(blob, "0,2,4,7,11", 0)
	if err == nil || !strings.Contains(err.Error(), "already enrolled with PCRs sha1:[0 2 7 11]") {
		t.Fatalf("differing --pcrs: %v", err)
	}
}
