package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// ErrPhoneSlot: the slot is attested by its phones and has no TOTP code.
var ErrPhoneSlot = errors.New("the slot is attested by its phone and has no TOTP code")

// SlotCode reads the blob at nvramIndex and computes its current TOTP code.
//
// Before asking the TPM it compares the blob with the live state, purely to
// explain a failure: a PCRMismatchError when the registers differ from the
// sealed values, ErrSeparatorLocked when they differ only by the OS
// separator that ran after the measure point, a GenerationMismatchError
// when a later reseal revoked this blob's approval, ErrCodesLocked after
// 'tpm2-kira cap'. None of these checks is the gate; the TPM is.
func SlotCode(tpmDev transport.TPM, nvramIndex uint32, t time.Time, debug bool) (string, *SealedBlob, error) {
	sealedData, err := tpmdev.ReadFromNVRAM(tpmDev, nvramIndex)
	if err != nil {
		return "", nil, tpmdev.HandleNVRAMNotFoundError(err, debug)
	}
	sealedBlob, err := UnmarshalSealedBlob(sealedData)
	if err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal sealed data: %w", err)
	}
	if !sealedBlob.HasTOTPKey() {
		return "", sealedBlob, ErrPhoneSlot
	}

	gen, err := ReadGeneration(tpmDev, GenerationIndex(nvramIndex))
	switch {
	case errors.Is(err, ErrCodesLocked):
		return "", sealedBlob, ErrCodesLocked
	case err != nil:
		return "", sealedBlob, &GenerationMismatchError{BlobGeneration: sealedBlob.Payload.Generation, IndexMissing: true}
	case gen != sealedBlob.Payload.Generation:
		return "", sealedBlob, &GenerationMismatchError{BlobGeneration: sealedBlob.Payload.Generation, IndexGeneration: gen}
	}

	currentPCRValues, err := GetCurrentPCRValuesFromRegisters(tpmDev, sealedBlob, debug)
	if err != nil {
		return "", sealedBlob, err
	}
	if !measure.VerifyPCRValues(sealedBlob.GetPCRDigestValues(), currentPCRValues) {
		mismatch := newPCRMismatchError(sealedBlob, currentPCRValues)
		if mismatch.SeparatorLocked() {
			return "", sealedBlob, measure.ErrSeparatorLocked
		}
		return "", sealedBlob, mismatch
	}

	code, err := TOTPCode(tpmDev, sealedBlob, nvramIndex, t)
	return code, sealedBlob, err
}

func newPCRMismatchError(sealedBlob *SealedBlob, current []tpm2.TPM2BDigest) *measure.PCRMismatchError {
	expectedDigests := make([][]byte, len(sealedBlob.Payload.PCRDigests))
	pcrSources := make([]measure.PCRSource, len(sealedBlob.Payload.PCRDigests))
	for i, d := range sealedBlob.Payload.PCRDigests {
		expectedDigests[i] = d.Digest.Buffer
		pcrSources[i] = d.Source
	}
	currentDigests := make([][]byte, len(current))
	for i, d := range current {
		currentDigests[i] = d.Buffer
	}
	return &measure.PCRMismatchError{
		Message:         "PCR values have changed. Use 'slot approve' with the signing key to approve the new values",
		PCRIndices:      sealedBlob.GetPCRIndices(),
		ExpectedDigests: expectedDigests,
		CurrentDigests:  currentDigests,
		PCRSources:      pcrSources,
	}
}

// LoadSealedObjectResponse contains the result of loading a sealed object
type LoadSealedObjectResponse struct {
	ObjectHandle tpm2.TPMHandle
	Name         tpm2.TPM2BName
}

// LoadSealedObject loads the blob's key object into the TPM
func LoadSealedObject(tpmDev transport.TPM, primaryKey *tpmdev.PrimaryKeyResponse, sealedBlob *SealedBlob) (*LoadSealedObjectResponse, error) {
	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](sealedBlob.Payload.Public),
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: sealedBlob.Payload.Private,
		},
	}

	loadRsp, err := loadCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to load sealed object: %w", err)
	}

	return &LoadSealedObjectResponse{
		ObjectHandle: loadRsp.ObjectHandle,
		Name:         loadRsp.Name,
	}, nil
}
