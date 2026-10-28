// Package tpmdev opens the TPM and does what needs no slot: the storage
// primary, flushing, reading and undefining NV indices.
package tpmdev

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPM device, session and object primitives.

// DefaultPath is the kernel's resource-managed TPM device. Through it each
// process sees only its own handles, and the kernel flushes them when the
// device is closed.
const DefaultPath = "/dev/tpmrm0"

// rawTPMPath is used only when the kernel provides no resource manager.
const rawTPMPath = "/dev/tpm0"

// Opened remembers whether the TPM was opened through a resource manager.
type Opened struct {
	transport.TPMCloser
	Managed bool
}

// Open opens the TPM at path. The default path falls back to the raw
// device when the kernel has no resource manager node.
func Open(path string) (transport.TPMCloser, error) {
	if path == DefaultPath {
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
	return &Opened{TPMCloser: tpm, Managed: strings.HasPrefix(filepath.Base(path), "tpmrm")}, nil
}

// Cleanup flushes leftover transient handles and sessions to free TPM
// memory.
//
// It does nothing on a resource-managed device: there the process only sees
// its own handles, which it flushes itself, and the kernel flushes the rest
// on close. Flushing globally on the raw device or a simulator socket is
// safe, because the raw device admits one opener at a time, so whatever is
// loaded was left behind by a process that is gone.
func Cleanup(tpmDev transport.TPM, debug bool) {
	if t, ok := tpmDev.(*Opened); ok && t.Managed {
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

// PrimaryKeyResponse contains the result of creating a primary key
type PrimaryKeyResponse struct {
	ObjectHandle tpm2.TPMHandle
	Name         tpm2.TPM2BName
	Public       tpm2.TPMTPublic // used to salt sessions
}

// StoragePrimaryTemplate is the deterministic ECC P-256 storage key that
// parents tpm2-kira's objects. Re-created on every use, never persisted.
func StoragePrimaryTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
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
	}
}

// CreatePrimaryKey creates a primary key in the owner hierarchy
func CreatePrimaryKey(tpmDev transport.TPM) (*PrimaryKeyResponse, error) {
	createPrimaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(StoragePrimaryTemplate()),
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

// FlushHandle flushes a TPM handle
func FlushHandle(tpmDev transport.TPM, handle tpm2.TPMHandle) {
	flushCmd := tpm2.FlushContext{FlushHandle: handle}
	_, _ = flushCmd.Execute(tpmDev)
}

// HandleNVRAMNotFoundError converts NVRAM errors to user-friendly messages
func HandleNVRAMNotFoundError(err error, debug bool) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()
	if strings.Contains(errStr, "TPM_RC_HANDLE") ||
		strings.Contains(errStr, "does not exist") ||
		strings.Contains(errStr, "TPM_RC_NV_UNINITIALIZED") {
		if debug {
			return fmt.Errorf("tpm2-kira has not been configured yet. Run 'tpm2-kira slot add' to set it up (debug: %w)", err)
		}
		return fmt.Errorf("tpm2-kira has not been configured yet. Run 'tpm2-kira slot add' to set it up")
	}
	return err
}

// ReadFromNVRAM reads data from a TPM NVRAM index
func ReadFromNVRAM(tpmDev transport.TPM, index uint32) ([]byte, error) {
	nvIndex := tpm2.TPMHandle(index)

	// Read public area to get size
	readPublic := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}

	readPublicResp, err := readPublic.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to read NVRAM public area (index may not exist): %w", err)
	}

	nvPublic, err := readPublicResp.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to parse NVRAM public area: %w", err)
	}

	dataSize := nvPublic.DataSize
	data := make([]byte, dataSize)

	// Read data from NVRAM in chunks
	maxChunkSize := uint16(1024)
	offset := uint16(0)

	for offset < dataSize {
		chunkSize := maxChunkSize
		if offset+chunkSize > dataSize {
			chunkSize = dataSize - offset
		}

		read := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: nvIndex,
				Name:   readPublicResp.NVName,
				Auth:   tpm2.PasswordAuth(nil),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: nvIndex,
				Name:   readPublicResp.NVName,
			},
			Size:   chunkSize,
			Offset: offset,
		}

		readResp, err := read.Execute(tpmDev)
		if err != nil {
			return nil, fmt.Errorf("failed to read from NVRAM at offset %d: %w", offset, err)
		}

		copy(data[offset:], readResp.Data.Buffer)
		offset += chunkSize
	}

	return data, nil
}

func UndefineIndex(tpmDev transport.TPM, index uint32) error {
	h := tpm2.TPMHandle(index)
	pub, err := (tpm2.NVReadPublic{NVIndex: h}).Execute(tpmDev)
	if err != nil {
		return err
	}
	_, err = (tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex:    tpm2.NamedHandle{Handle: h, Name: pub.NVName},
	}).Execute(tpmDev)
	return err
}

// NVRAMIndexExists performs a lightweight check whether the given NVRAM index
// is defined and contains data.  It only reads the NV public area — no
// unsealing or authorization is attempted.
func NVRAMIndexExists(tpmDev transport.TPM, index uint32) bool {
	readPublic := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(index),
	}
	resp, err := readPublic.Execute(tpmDev)
	if err != nil {
		return false
	}
	nvPub, err := resp.NVPublic.Contents()
	if err != nil {
		return false
	}
	return nvPub.DataSize > 0
}
