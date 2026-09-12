package cmd

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPM NVRAM index definition, access and management.

const (
	// AppNVRAMStart is the start of the safe NVRAM index range for application use
	AppNVRAMStart = 0x01803000
	// AppNVRAMEnd is the end of the safe NVRAM index range for application use
	AppNVRAMEnd = 0x01803FFF
)

// ValidateNVRAMIndex checks that the given NVRAM index is within the safe application range.
// Indices outside this range may belong to platform firmware, other applications, or
// reserved TPM hierarchy ranges and must not be accessed to prevent data destruction.
func ValidateNVRAMIndex(index uint32) error {
	if index < AppNVRAMStart || index > AppNVRAMEnd {
		return fmt.Errorf("NVRAM index 0x%08X is outside the safe application range (0x%08X-0x%08X)", index, AppNVRAMStart, AppNVRAMEnd)
	}
	return nil
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
			return fmt.Errorf("tpm2-kira has not been configured yet. Run 'tpm2-kira seal' to set it up (debug: %w)", err)
		}
		return fmt.Errorf("tpm2-kira has not been configured yet. Run 'tpm2-kira seal' to set it up")
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

// WriteToNVRAM writes data to a TPM NVRAM index
func WriteToNVRAM(tpmDev transport.TPM, index uint32, data []byte, pubKey crypto.PublicKey, privKey crypto.Signer) error {
	// Validate index is within the safe application range
	if err := ValidateNVRAMIndex(index); err != nil {
		return fmt.Errorf("invalid NVRAM index: %w", err)
	}

	if pubKey == nil {
		return fmt.Errorf("signing public key is required for NV write authorization")
	}
	if privKey == nil {
		return fmt.Errorf("signing private key is required for NV write authorization")
	}

	nvIndex := tpm2.TPMHandle(index)

	// Try to undefine existing NVRAM space (if it exists)
	// NVUndefineSpace is an owner-hierarchy operation and works regardless
	// of the NV index's read/write attributes.
	readPub := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}
	if readPubResp, checkErr := readPub.Execute(tpmDev); checkErr == nil {
		// Index exists, undefine it
		undefine := tpm2.NVUndefineSpace{
			AuthHandle: tpm2.TPMRHOwner,
			NVIndex: tpm2.NamedHandle{
				Handle: nvIndex,
				Name:   readPubResp.NVName,
			},
		}
		if _, err := undefine.Execute(tpmDev); err != nil {
			return fmt.Errorf("failed to undefine existing NVRAM index 0x%08X: %w", index, err)
		}
	}
	// If checkErr != nil, index doesn't exist, which is fine

	// Load the signing public key into the TPM once — the handle is reused
	// for both the policy digest computation and the per-chunk PolicySigned
	// sessions, avoiding redundant LoadExternal round-trips.
	loadRsp, err := LoadExternalPublicKey(tpmDev, pubKey)
	if err != nil {
		return fmt.Errorf("failed to load signing key for NV write policy: %w", err)
	}
	defer FlushHandle(tpmDev, loadRsp.ObjectHandle)

	keyHandle := loadRsp.ObjectHandle
	keyName := loadRsp.Name

	// Compute the PolicySigned digest that will be the AuthPolicy on this
	// NV index.  Any future NVWrite must satisfy a PolicySigned session
	// proving possession of the corresponding private key.
	nvWritePolicy, err := ComputeNVWritePolicyDigestWithHandle(tpmDev, keyHandle, keyName, pubKey)
	if err != nil {
		return fmt.Errorf("failed to compute NV write policy digest: %w", err)
	}

	// Define NVRAM space with PolicySigned-protected writes: no owner or
	// unauthenticated write path, so only a holder of the signing key can
	// replace the blob. Reads stay open — the secret itself is protected by the
	// sealed object's own policy, not by NV read control.
	define := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth: tpm2.TPM2BAuth{
			Buffer: []byte{},
		},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: nvIndex,
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				OwnerWrite:  false,
				OwnerRead:   true,
				PolicyWrite: true,
				AuthRead:    true,
			},
			AuthPolicy: nvWritePolicy,
			DataSize:   uint16(len(data)),
		}),
	}

	_, err = define.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to define NVRAM space: %w", err)
	}

	// Write data to NVRAM in chunks using PolicySigned sessions.
	//
	// Each chunk gets its own policy session because:
	//   1. The TPM nonce changes per session, requiring a fresh signature.
	//   2. After the first NVWrite the TPM sets TPMA_NV_WRITTEN which
	//      changes the NV public area and therefore the NV Name.  We
	//      re-read NVReadPublic before each chunk to pick up the new Name.
	maxChunkSize := 1024
	offset := 0

	for offset < len(data) {
		chunkSize := maxChunkSize
		if offset+chunkSize > len(data) {
			chunkSize = len(data) - offset
		}

		// Re-read NV public area to get the current Name.
		// The Name changes after the first write (TPMA_NV_WRITTEN is set).
		nvReadPub := tpm2.NVReadPublic{
			NVIndex: nvIndex,
		}
		nvReadPubRsp, err := nvReadPub.Execute(tpmDev)
		if err != nil {
			return fmt.Errorf("failed to read NV public: %w", err)
		}

		// Build a PolicySigned session for this chunk.  The callback is
		// invoked by the go-tpm library when the session is first used as
		// authorization; it signs the TPM-provided nonce to prove
		// possession of the private key.
		policySession := tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
			// aHash = SHA-256(nonceTPM || expiration(0))
			// expiration is a 4-byte big-endian int32 = 0
			// cpHashA and policyRef are empty (omitted per spec)
			aHashInput := make([]byte, 0, len(nonceTPM.Buffer)+4)
			aHashInput = append(aHashInput, nonceTPM.Buffer...)
			expirationBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(expirationBytes, 0)
			aHashInput = append(aHashInput, expirationBytes...)

			aHash := sha256.Sum256(aHashInput)

			// Sign the aHash with the private key
			tpmSig, signErr := signForTPM(privKey, aHash[:])
			if signErr != nil {
				return fmt.Errorf("failed to sign NV write policy nonce: %w", signErr)
			}

			// Execute PolicySigned — the TPM verifies the signature
			// against the loaded public key and extends the session
			// digest with the key Name.
			_, signedErr := tpm2.PolicySigned{
				AuthObject: tpm2.NamedHandle{
					Handle: keyHandle,
					Name:   keyName,
				},
				PolicySession: handle,
				NonceTPM:      nonceTPM,
				Expiration:    0,
				Auth:          tpmSig,
			}.Execute(tpm)
			if signedErr != nil {
				return fmt.Errorf("failed to execute PolicySigned for NV write: %w", signedErr)
			}

			return nil
		})

		// Write the chunk using the satisfied policy session as authorization
		write := tpm2.NVWrite{
			AuthHandle: tpm2.AuthHandle{
				Handle: nvIndex,
				Name:   nvReadPubRsp.NVName,
				Auth:   policySession,
			},
			NVIndex: tpm2.NamedHandle{
				Handle: nvIndex,
				Name:   nvReadPubRsp.NVName,
			},
			Data: tpm2.TPM2BMaxNVBuffer{
				Buffer: data[offset : offset+chunkSize],
			},
			Offset: uint16(offset),
		}

		_, err = write.Execute(tpmDev)
		if err != nil {
			return fmt.Errorf("failed to write to NVRAM at offset %d: %w", offset, err)
		}

		offset += chunkSize
	}

	return nil
}

// NVRAMList lists all defined NVRAM indices in the TPM
func NVRAMList(tpmPath string, nvramIndex uint32, debug bool) error {
	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	// Get capability to list NVRAM indices
	getCap := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTNVIndex) << 24,
		PropertyCount: 128,
	}

	capResp, err := getCap.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to get NVRAM capabilities: %w", err)
	}

	handles, err := capResp.CapabilityData.Data.Handles()
	if err != nil {
		return fmt.Errorf("failed to parse capability data: %w", err)
	}

	if debug {
		// The query caps at 128 handles, so a full result may be truncated.
		fmt.Printf("TPM %s returned %d NV handle(s) (query limit 128)\n\n", tpmPath, len(handles.Handle))
	}

	if len(handles.Handle) == 0 {
		fmt.Println("No NVRAM indices defined in TPM")
		return nil
	}

	fmt.Printf("Defined NVRAM Indices:\n")
	fmt.Printf("======================\n\n")

	for _, handle := range handles.Handle {
		// Read public area for each index
		readPublic := tpm2.NVReadPublic{
			NVIndex: handle,
		}

		readPublicResp, err := readPublic.Execute(tpmDev)
		if err != nil {
			fmt.Printf("Index: 0x%08X - Error reading details: %v\n", handle, err)
			continue
		}

		nvPublic, err := readPublicResp.NVPublic.Contents()
		if err != nil {
			fmt.Printf("Index: 0x%08X - Error parsing details\n", handle)
			continue
		}

		fmt.Printf("Index: 0x%08X\n", handle)
		fmt.Printf("  Size: %d bytes\n", nvPublic.DataSize)
		fmt.Printf("  Name Algorithm: %v\n", nvPublic.NameAlg)

		// Show key attributes
		attrs := []string{}
		if nvPublic.Attributes.OwnerWrite {
			attrs = append(attrs, "OwnerWrite")
		}
		if nvPublic.Attributes.OwnerRead {
			attrs = append(attrs, "OwnerRead")
		}
		if nvPublic.Attributes.AuthWrite {
			attrs = append(attrs, "AuthWrite")
		}
		if nvPublic.Attributes.AuthRead {
			attrs = append(attrs, "AuthRead")
		}
		if nvPublic.Attributes.Written {
			attrs = append(attrs, "Written")
		}
		if nvPublic.Attributes.WriteDefine {
			attrs = append(attrs, "WriteDefine")
		}
		if nvPublic.Attributes.ReadSTClear {
			attrs = append(attrs, "ReadSTClear")
		}

		fmt.Printf("  Attributes: %v\n", attrs)

		// Check if this is our configured index
		if handle == tpm2.TPMHandle(nvramIndex) {
			fmt.Printf("  ** Current configured index **\n")
		}

		fmt.Println()
	}

	return nil
}

// NVRAMDelete deletes the specified NVRAM index
func NVRAMDelete(tpmPath string, nvramIndex uint32, debug bool) error {
	// Validate index is within the safe application range
	if err := ValidateNVRAMIndex(nvramIndex); err != nil {
		return fmt.Errorf("invalid NVRAM index: %w", err)
	}

	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	nvIndex := tpm2.TPMHandle(nvramIndex)

	// Check if index exists
	readPublic := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}

	readPublicResp, err := readPublic.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("NVRAM index 0x%08X does not exist: %w", nvramIndex, err)
	}

	if debug {
		fmt.Printf("NV name: %x\n", readPublicResp.NVName.Buffer)
		if nvPublic, pubErr := readPublicResp.NVPublic.Contents(); pubErr == nil {
			fmt.Printf("Deleting 0x%08X: %d bytes, written=%v\n", nvramIndex, nvPublic.DataSize, nvPublic.Attributes.Written)
		}
	}

	// Undefine NVRAM space
	undefine := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex: tpm2.NamedHandle{
			Handle: nvIndex,
			Name:   readPublicResp.NVName,
		},
	}

	_, err = undefine.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to delete NVRAM index 0x%08X: %w", nvramIndex, err)
	}

	fmt.Printf("Successfully deleted NVRAM index 0x%08X\n", nvramIndex)

	return nil
}

// NVRAMDeleteCommand is the top-level entry point for the nvram delete CLI
// command.  When nvramIndex is 0 it scans every default slot and deletes
// each populated one; otherwise it deletes only the requested index.
func NVRAMDeleteCommand(tpmPath string, nvramIndex uint32, debug bool) error {
	if nvramIndex != 0 {
		return NVRAMDelete(tpmPath, nvramIndex, debug)
	}

	// Multi-slot mode – discover populated slots, then delete each one.
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	slots := FindPopulatedSlots(tpmDev, debug)
	tpmDev.Close()

	if len(slots) == 0 {
		return fmt.Errorf("no sealed secrets found in NVRAM slots 0x%08X – 0x%08X", NVRAMSlotStart, NVRAMSlotEnd)
	}

	fmt.Printf("Found %d sealed slot(s) to delete\n\n", len(slots))

	var failed []uint32
	for _, slotIdx := range slots {
		slotNum := SlotNumber(slotIdx)
		fmt.Printf("Deleting slot #%d (0x%08X)... ", slotNum, slotIdx)

		if err := NVRAMDelete(tpmPath, slotIdx, debug); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			failed = append(failed, slotIdx)
		}
	}

	fmt.Println()
	if len(failed) > 0 {
		return fmt.Errorf("%d of %d slot(s) failed to delete", len(failed), len(slots))
	}
	fmt.Printf("All %d slot(s) deleted successfully\n", len(slots))
	return nil
}

// NVRAMStatus shows detailed status of the specified NVRAM index
func NVRAMStatus(tpmPath string, nvramIndex uint32, debug bool) error {
	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	nvIndex := tpm2.TPMHandle(nvramIndex)

	// Read public area
	readPublic := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}

	readPublicResp, err := readPublic.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("NVRAM index 0x%08X does not exist: %w", nvramIndex, err)
	}

	nvPublic, err := readPublicResp.NVPublic.Contents()
	if err != nil {
		return fmt.Errorf("failed to parse NVRAM public area: %w", err)
	}

	fmt.Printf("NVRAM Index Status:\n")
	fmt.Printf("===================\n")
	fmt.Printf("Index: 0x%08X\n", nvramIndex)
	fmt.Printf("Data Size: %d bytes\n", nvPublic.DataSize)
	fmt.Printf("Name Algorithm: %v\n", nvPublic.NameAlg)
	fmt.Printf("\n")

	fmt.Printf("Attributes:\n")
	fmt.Printf("  PPWRITE: %v\n", nvPublic.Attributes.PPWrite)
	fmt.Printf("  OWNERWRITE: %v\n", nvPublic.Attributes.OwnerWrite)
	fmt.Printf("  AUTHWRITE: %v\n", nvPublic.Attributes.AuthWrite)
	fmt.Printf("  POLICYWRITE: %v\n", nvPublic.Attributes.PolicyWrite)
	fmt.Printf("  PPREAD: %v\n", nvPublic.Attributes.PPRead)
	fmt.Printf("  OWNERREAD: %v\n", nvPublic.Attributes.OwnerRead)
	fmt.Printf("  AUTHREAD: %v\n", nvPublic.Attributes.AuthRead)
	fmt.Printf("  POLICYREAD: %v\n", nvPublic.Attributes.PolicyRead)
	fmt.Printf("  WRITTEN: %v\n", nvPublic.Attributes.Written)
	fmt.Printf("  WRITELOCKED: %v\n", nvPublic.Attributes.WriteLocked)
	fmt.Printf("  WRITEDEFINE: %v\n", nvPublic.Attributes.WriteDefine)
	fmt.Printf("  READLOCKED: %v\n", nvPublic.Attributes.ReadLocked)
	fmt.Printf("  READ_STCLEAR: %v\n", nvPublic.Attributes.ReadSTClear)
	fmt.Printf("  WRITE_STCLEAR: %v\n", nvPublic.Attributes.WriteSTClear)
	fmt.Printf("\n")

	// Try to determine if it contains sealed data
	if nvPublic.Attributes.Written {
		data, readErr := ReadFromNVRAM(tpmDev, nvramIndex)
		switch {
		case readErr != nil:
			fmt.Printf("Contents: unreadable (%v)\n", readErr)
		default:
			blob, unmarshalErr := UnmarshalSealedBlob(data)
			if unmarshalErr == nil {
				fmt.Printf("Contains Sealed Data:\n")
				fmt.Printf("  PCR Indices: %v\n", blob.GetPCRIndices())
				fmt.Printf("  Number of PCRs: %d\n", len(blob.Payload.PCRDigests))
				fmt.Printf("  Public Blob Size: %d bytes\n", len(blob.Payload.Public))
				fmt.Printf("  Private Blob Size: %d bytes\n", len(blob.Payload.Private))
				break
			}
			fmt.Printf("Data Format: Unknown (not a sealed blob)\n")
			if debug {
				peek := PeekBlobVersion(data)
				fmt.Printf("  Raw size: %d bytes\n", peek.DataSize)
				fmt.Printf("  Version field: %d (supported: %d)\n", peek.Version, CurrentBlobVersion)
				if peek.AppVersion != "" {
					fmt.Printf("  App version: %s\n", peek.AppVersion)
				}
				fmt.Printf("  Parse error: %v\n", unmarshalErr)
				fmt.Printf("  First bytes: %x\n", data[:min(32, len(data))])
			}
		}
	} else {
		fmt.Printf("Status: Not yet written\n")
	}

	return nil
}
