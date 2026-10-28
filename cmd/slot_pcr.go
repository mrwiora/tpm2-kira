package cmd

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/mrwiora/tpm2-kira/internal/measure"
)

// GetCurrentPCRValuesFromRegisters reads current PCR values directly from TPM
// registers, regardless of the original PCR source stored in the blob. This is
// used on the unseal/reveal/run path so that neither the eventlog file nor
// the unified kernel image are required (critical for early-boot).
// Results are returned in the same order as the blob's PCR digests.
func GetCurrentPCRValuesFromRegisters(tpmDev transport.TPM, sealedBlob *SealedBlob, debug bool) ([]tpm2.TPM2BDigest, error) {
	hashAlgo := sealedBlob.GetHashAlgo()
	pcrIndices := sealedBlob.GetPCRIndices()

	regValues, err := measure.ReadPCRRegisters(tpmDev, pcrIndices, hashAlgo, debug)
	if err != nil {
		return nil, err
	}

	// Map results back to blob PCR digest order
	currentPCRValues := make([]tpm2.TPM2BDigest, len(sealedBlob.Payload.PCRDigests))
	for i, pair := range sealedBlob.Payload.PCRDigests {
		if val, ok := regValues[pair.Index]; ok {
			currentPCRValues[i] = tpm2.TPM2BDigest{Buffer: val}
		}
	}

	return currentPCRValues, nil
}
