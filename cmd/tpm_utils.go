package cmd

import (
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPM device, session and object primitives.

// CleanupTPM flushes all transient handles and sessions to free TPM memory
func CleanupTPM(tpmDev transport.TPM, debug bool) {
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

// IsTPMPolicyFailure checks if an error is a TPM policy failure that can be recovered with password authentication
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

// UnsealWorkflowResult contains the results of the unseal workflow
type UnsealWorkflowResult struct {
	UnsealedData []byte
	SealedBlob   *SealedBlob
}

// UnsealWorkflow performs the complete unsealing workflow using PolicyOR PCR branch.
// This consolidates the common pattern used in run, reveal, and reseal commands.
// When PCRs don't match, returns a PCRMismatchError so the caller can fall back
// to the PolicySigned branch if a private key is available.
func UnsealWorkflow(tpmDev transport.TPM, nvramIndex uint32, debug bool) (*UnsealWorkflowResult, error) {
	// Read sealed blob from NVRAM
	sealedData, err := ReadFromNVRAM(tpmDev, nvramIndex)
	if err != nil {
		return nil, HandleNVRAMNotFoundError(err, debug)
	}

	// Unmarshal sealed blob
	sealedBlob, err := UnmarshalSealedBlob(sealedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sealed data: %w", err)
	}

	// Read current PCR values directly from TPM registers. This avoids any
	// dependency on the eventlog file or the unified kernel image, which may
	// not be available during early boot.
	currentPCRValues, err := GetCurrentPCRValuesFromRegisters(tpmDev, sealedBlob, debug)
	if err != nil {
		return nil, err
	}

	// Check if PCR values match
	pcrMatch := VerifyPCRValues(sealedBlob.GetPCRDigestValues(), currentPCRValues)

	if !pcrMatch {
		// Create structured PCR mismatch error with detailed information
		expectedDigests := make([][]byte, len(sealedBlob.GetPCRDigestValues()))
		for i, digest := range sealedBlob.GetPCRDigestValues() {
			expectedDigests[i] = digest.Buffer
		}

		currentDigests := make([][]byte, len(currentPCRValues))
		for i, digest := range currentPCRValues {
			currentDigests[i] = digest.Buffer
		}

		pcrSources := make([]PCRSource, len(sealedBlob.Payload.PCRDigests))
		for i, pcrDigest := range sealedBlob.Payload.PCRDigests {
			pcrSources[i] = pcrDigest.Source
		}

		pcrErr := &PCRMismatchError{
			Message:         "PCR values have changed. Use 'reseal' command with signing key to update",
			PCRIndices:      sealedBlob.GetPCRIndices(),
			ExpectedDigests: expectedDigests,
			CurrentDigests:  currentDigests,
			PCRSources:      pcrSources,
		}
		return nil, pcrErr
	}

	// Create primary key
	primaryKey, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, primaryKey.ObjectHandle)

	// Load sealed object
	loadedObject, err := LoadSealedObject(tpmDev, primaryKey, sealedBlob)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, loadedObject.ObjectHandle)

	// Unseal the data using PolicyOR PCR branch
	unsealedData, err := UnsealWithPCRBranch(tpmDev, loadedObject, sealedBlob, debug)
	if err != nil {
		return nil, err
	}

	return &UnsealWorkflowResult{
		UnsealedData: unsealedData,
		SealedBlob:   sealedBlob,
	}, nil
}

// PrimaryKeyResponse contains the result of creating a primary key
type PrimaryKeyResponse struct {
	ObjectHandle tpm2.TPMHandle
	Name         tpm2.TPM2BName
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

	return &PrimaryKeyResponse{
		ObjectHandle: createPrimaryRsp.ObjectHandle,
		Name:         createPrimaryRsp.Name,
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

// LoadSealedObject loads a sealed object into the TPM
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
