package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// The slot's policy: what every key and sealed object of a slot is
// created under - the TOTP key, the sealed machine-id, the boot key, the
// release key (which adds PolicyCommandCode, ReleaseKeyPolicy).
//
//	PolicyAuthorize(signing key, policyRef) ; PolicyPCR(15 == zero)
//
// PolicyAuthorize accepts whatever the slot's signing key approved for
// this policyRef (PCR values and the generation). The PolicyPCR after it
// is the object's own, fixed when it is created: no approval can leave it
// out. PCR 15 is zero from the TPM's start until the boot image closes it
// (PCR_Event, aSSH's hostkey.Close, which also closes the SSH CA): from
// then on no slot object can be used until the next boot.

// ClosePCR is the PCR whose extension closes every slot object and the
// SSH CA until the next boot.
const ClosePCR = 15

// closePCRSelect is ClosePCR's bit in a three-byte pcrSelect.
var closePCRSelect = []byte{0x00, 0x80, 0x00}

// ClosePCRSelection is PolicyPCR's selection of ClosePCR in bank (SHA-256,
// or SHA-1 for a slot sealed to the SHA-1 bank): the selection the policy
// session sends, byte for byte, as SlotPolicyDigest computes it.
func ClosePCRSelection(bank tpm2.TPMIAlgHash) tpm2.TPMLPCRSelection {
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash:      bank,
		PCRSelect: append([]byte(nil), closePCRSelect...),
	}}}
}

// bankSize is the size of a PCR of bank, for the banks a slot may use.
func bankSize(bank tpm2.TPMIAlgHash) (int, error) {
	switch bank {
	case tpm2.TPMAlgSHA256:
		return sha256.Size, nil
	case tpm2.TPMAlgSHA1:
		return 20, nil
	}
	return 0, fmt.Errorf("PCR bank 0x%04x is not one a slot uses", uint16(bank))
}

// OpenPCRDigest is PolicyPCR's pcrDigest for ClosePCR at zero in bank: the
// SHA-256 (the session's hash) of a zero register of the bank's size.
func OpenPCRDigest(bank tpm2.TPMIAlgHash) ([]byte, error) {
	n, err := bankSize(bank)
	if err != nil {
		return nil, err
	}
	d := sha256.Sum256(make([]byte, n))
	return d[:], nil
}

// SlotPolicyDigest is the slot's policy as the TPM computes it, for the
// signing key named keyName, policyRef and the bank ClosePCR is read in:
// PolicyAuthorizeDigest, then H(that ‖ TPM_CC_PolicyPCR ‖
// TPML_PCR_SELECTION ‖ OpenPCRDigest(bank)).
func SlotPolicyDigest(keyName, policyRef []byte, bank tpm2.TPMIAlgHash) ([]byte, error) {
	open, err := OpenPCRDigest(bank)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(PolicyAuthorizeDigest(keyName, policyRef))
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(tpm2.TPMCCPolicyPCR)))
	h.Write(tpm2.Marshal(ClosePCRSelection(bank)))
	h.Write(open)
	return h.Sum(nil), nil
}

// slotBanks are the banks a slot's ClosePCR may be read in. A verifier
// that sees an object's policy does not know the slot's bank; it accepts
// either, since an extension of ClosePCR changes every bank.
var slotBanks = []tpm2.TPMIAlgHash{tpm2.TPMAlgSHA256, tpm2.TPMAlgSHA1}

// IsSlotPolicy reports whether policy is the slot's policy of keyName and
// policyRef, in either bank, and returns that bank.
func IsSlotPolicy(policy, keyName, policyRef []byte) (tpm2.TPMIAlgHash, bool) {
	for _, bank := range slotBanks {
		if want, err := SlotPolicyDigest(keyName, policyRef, bank); err == nil && bytes.Equal(policy, want) {
			return bank, true
		}
	}
	return 0, false
}
