package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPM device, session and object primitives.

// DefaultTPMPath is the kernel's resource-managed TPM device. Through it each
// process sees only its own handles, and the kernel flushes them when the
// device is closed.
const DefaultTPMPath = "/dev/tpmrm0"

// rawTPMPath is used only when the kernel provides no resource manager.
const rawTPMPath = "/dev/tpm0"

// openedTPM remembers whether the TPM was opened through a resource manager.
type openedTPM struct {
	transport.TPMCloser
	managed bool
}

// OpenTPM opens the TPM at path. The default path falls back to the raw
// device when the kernel has no resource manager node.
func OpenTPM(path string) (transport.TPMCloser, error) {
	if path == DefaultTPMPath {
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			if _, rawErr := os.Stat(rawTPMPath); rawErr == nil {
				path = rawTPMPath
			}
		}
	}
	tpm, err := transport.OpenTPM(path)
	if err != nil {
		return nil, err
	}
	return &openedTPM{TPMCloser: tpm, managed: strings.HasPrefix(filepath.Base(path), "tpmrm")}, nil
}

// CleanupTPM flushes leftover transient handles and sessions to free TPM
// memory.
//
// It does nothing on a resource-managed device: there the process only sees
// its own handles, which it flushes itself, and the kernel flushes the rest
// on close. Flushing globally on the raw device or a simulator socket is
// safe, because the raw device admits one opener at a time, so whatever is
// loaded was left behind by a process that is gone.
func CleanupTPM(tpmDev transport.TPM, debug bool) {
	if t, ok := tpmDev.(*openedTPM); ok && t.managed {
		return
	}
	if err := flushAllTransientHandles(tpmDev); err != nil {
		if debug {
			fmt.Printf("Warning: failed to flush transient handles: %v\n", err)
		}
	}
	if err := flushAllSessions(tpmDev); err != nil {
		if debug {
			fmt.Printf("Warning: failed to flush sessions: %v\n", err)
		}
	}
}

// flushAllTransientHandles flushes all transient object handles to free TPM memory
func flushAllTransientHandles(tpmDev transport.TPM) error {
	getCap := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTTransient) << 24,
		PropertyCount: 128,
	}

	capResp, err := getCap.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to get transient handles: %w", err)
	}

	handleList, err := capResp.CapabilityData.Data.Handles()
	if err != nil {
		return fmt.Errorf("failed to parse handle list: %w", err)
	}

	for _, handle := range handleList.Handle {
		flushCmd := tpm2.FlushContext{FlushHandle: handle}
		_, _ = flushCmd.Execute(tpmDev) // Ignore errors, some handles might not be flushable
	}

	return nil
}

// flushAllSessions flushes all loaded sessions to free TPM session memory
func flushAllSessions(tpmDev transport.TPM) error {
	getCap := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTLoadedSession) << 24,
		PropertyCount: 128,
	}

	capResp, err := getCap.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to get session handles: %w", err)
	}

	handleList, err := capResp.CapabilityData.Data.Handles()
	if err != nil {
		return fmt.Errorf("failed to parse session handle list: %w", err)
	}

	for _, handle := range handleList.Handle {
		flushCmd := tpm2.FlushContext{FlushHandle: handle}
		_, _ = flushCmd.Execute(tpmDev) // Ignore errors
	}

	return nil
}

// IsTPMPolicyFailure checks if an error is a TPM policy failure: the TPM refused
// to compute a code because the session did not satisfy the key's policy.
func IsTPMPolicyFailure(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	return strings.Contains(errStr, "TPM_RC_POLICY_FAIL") ||
		strings.Contains(errStr, "TPM_RC_POLICY_CC") ||
		strings.Contains(errStr, "policy check failed") ||
		strings.Contains(errStr, "failed to create PCR policy session") ||
		strings.Contains(errStr, "session 1): a policy check failed")
}

// SlotCode reads the blob at nvramIndex and computes its current TOTP code.
//
// Before asking the TPM it compares the blob with the live state, purely to
// explain a failure: a PCRMismatchError when the registers differ from the
// sealed values, a GenerationMismatchError when a later reseal revoked this
// blob's approval, ErrCodesLocked after 'tpm2-kira cap'. None of these checks
// is the gate; the TPM is.
func SlotCode(tpmDev transport.TPM, nvramIndex uint32, t time.Time, debug bool) (string, *SealedBlob, error) {
	sealedData, err := ReadFromNVRAM(tpmDev, nvramIndex)
	if err != nil {
		return "", nil, HandleNVRAMNotFoundError(err, debug)
	}
	sealedBlob, err := UnmarshalSealedBlob(sealedData)
	if err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal sealed data: %w", err)
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
	if !VerifyPCRValues(sealedBlob.GetPCRDigestValues(), currentPCRValues) {
		return "", sealedBlob, newPCRMismatchError(sealedBlob, currentPCRValues)
	}

	code, err := TOTPCode(tpmDev, sealedBlob, nvramIndex, t)
	return code, sealedBlob, err
}

func newPCRMismatchError(sealedBlob *SealedBlob, current []tpm2.TPM2BDigest) *PCRMismatchError {
	expectedDigests := make([][]byte, len(sealedBlob.Payload.PCRDigests))
	pcrSources := make([]PCRSource, len(sealedBlob.Payload.PCRDigests))
	for i, d := range sealedBlob.Payload.PCRDigests {
		expectedDigests[i] = d.Digest.Buffer
		pcrSources[i] = d.Source
	}
	currentDigests := make([][]byte, len(current))
	for i, d := range current {
		currentDigests[i] = d.Buffer
	}
	return &PCRMismatchError{
		Message:         "PCR values have changed. Use 'reseal' with the signing key to approve the new values",
		PCRIndices:      sealedBlob.GetPCRIndices(),
		ExpectedDigests: expectedDigests,
		CurrentDigests:  currentDigests,
		PCRSources:      pcrSources,
	}
}

// PrimaryKeyResponse contains the result of creating a primary key
type PrimaryKeyResponse struct {
	ObjectHandle tpm2.TPMHandle
	Name         tpm2.TPM2BName
	Public       tpm2.TPMTPublic // used to salt sessions
}

// CreatePrimaryKey creates a primary key in the owner hierarchy
func CreatePrimaryKey(tpmDev transport.TPM) (*PrimaryKeyResponse, error) {
	createPrimaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Restricted:          true,
				Decrypt:             true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					Symmetric: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgAES,
						KeyBits: tpm2.NewTPMUSymKeyBits(
							tpm2.TPMAlgAES,
							tpm2.TPMKeyBits(128),
						),
						Mode: tpm2.NewTPMUSymMode(
							tpm2.TPMAlgAES,
							tpm2.TPMAlgCFB,
						),
					},
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgNull,
					},
					CurveID: tpm2.TPMECCNistP256,
				},
			),
		}),
	}

	createPrimaryRsp, err := createPrimaryCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to create primary key: %w", err)
	}

	pub, err := createPrimaryRsp.OutPublic.Contents()
	if err != nil {
		FlushHandle(tpmDev, createPrimaryRsp.ObjectHandle)
		return nil, fmt.Errorf("failed to parse primary key: %w", err)
	}
	return &PrimaryKeyResponse{
		ObjectHandle: createPrimaryRsp.ObjectHandle,
		Name:         createPrimaryRsp.Name,
		Public:       *pub,
	}, nil
}

// CreateSealedObjectResponse contains the result of creating a sealed object
type CreateSealedObjectResponse struct {
	Public  []byte
	Private []byte
}

// LoadSealedObjectResponse contains the result of loading a sealed object
type LoadSealedObjectResponse struct {
	ObjectHandle tpm2.TPMHandle
	Name         tpm2.TPM2BName
}

// LoadSealedObject loads the blob's key object into the TPM
func LoadSealedObject(tpmDev transport.TPM, primaryKey *PrimaryKeyResponse, sealedBlob *SealedBlob) (*LoadSealedObjectResponse, error) {
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

// FlushHandle flushes a TPM handle
func FlushHandle(tpmDev transport.TPM, handle tpm2.TPMHandle) {
	flushCmd := tpm2.FlushContext{FlushHandle: handle}
	_, _ = flushCmd.Execute(tpmDev)
}
