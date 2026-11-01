package attest

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// The slot's policy, computed by hand from TPM 2.0 Part 3 (PolicyPCR):
// H(PolicyAuthorizeDigest ‖ TPM_CC_PolicyPCR ‖ TPML_PCR_SELECTION{1:
// bank, 3, 00 80 00} ‖ H(zero register)). The integration tests check the
// same against a real policy session (internal/nvslot).
func TestSlotPolicyDigest(t *testing.T) {
	name, ref := bytes.Repeat([]byte{1}, 34), bytes.Repeat([]byte{2}, 32)
	for _, c := range []struct {
		bank tpm2.TPMIAlgHash
		size int
	}{{tpm2.TPMAlgSHA256, 32}, {tpm2.TPMAlgSHA1, 20}} {
		zero := sha256.Sum256(make([]byte, c.size))
		h := sha256.New()
		h.Write(PolicyAuthorizeDigest(name, ref))
		h.Write([]byte{0, 0, 0x01, 0x7f})
		h.Write([]byte{0, 0, 0, 1, byte(c.bank >> 8), byte(c.bank), 3, 0x00, 0x80, 0x00})
		h.Write(zero[:])
		got, err := SlotPolicyDigest(name, ref, c.bank)
		if err != nil || !bytes.Equal(got, h.Sum(nil)) {
			t.Fatalf("bank %v: %x %v", c.bank, got, err)
		}
		if bank, ok := IsSlotPolicy(got, name, ref); !ok || bank != c.bank {
			t.Fatalf("bank %v not recognised: %v %v", c.bank, bank, ok)
		}
	}
	a, _ := SlotPolicyDigest(name, ref, tpm2.TPMAlgSHA256)
	b, _ := SlotPolicyDigest(name, ref, tpm2.TPMAlgSHA1)
	if bytes.Equal(a, b) {
		t.Fatal("the two banks give the same policy")
	}
	// Without the close, or for another slot: not the slot's policy.
	if _, ok := IsSlotPolicy(PolicyAuthorizeDigest(name, ref), name, ref); ok {
		t.Fatal("a policy without PCR 15 taken for the slot's")
	}
	if _, ok := IsSlotPolicy(a, name, bytes.Repeat([]byte{3}, 32)); ok {
		t.Fatal("another slot's policy taken for this one's")
	}
	if _, err := SlotPolicyDigest(name, ref, tpm2.TPMAlgSHA384); err == nil {
		t.Fatal("a bank no slot uses")
	}
}
