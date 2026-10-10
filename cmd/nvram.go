package cmd

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

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

// ValidateBlobIndex checks that a blob may be stored at index: inside the
// application range, and below the generation indices (GenerationIndex).
func ValidateBlobIndex(index uint32) error {
	if err := ValidateNVRAMIndex(index); err != nil {
		return err
	}
	if g := GenerationIndex(index); g >= AttestCounterIndex(NVRAMSlotStart) && g <= AttestCounterIndex(NVRAMSlotEnd) {
		return fmt.Errorf("NVRAM index 0x%08X cannot hold a blob: its generation index 0x%08X is the record counter of slot %d",
			index, g, g-attestCounterStart)
	}
	if index >= GenerationIndex(AppNVRAMStart) {
		return fmt.Errorf("NVRAM index 0x%08X is reserved for generation indices; blobs go at 0x%08X-0x%08X",
			index, AppNVRAMStart, GenerationIndex(AppNVRAMStart)-1)
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

// MaxNVRAMBlobSize is the largest blob an NV index can hold: TPMS_NV_PUBLIC
// stores the size as a uint16, so anything larger would be silently truncated
// by the conversion rather than rejected.
const MaxNVRAMBlobSize = 65535

// BlobTooLargeError is a blob that this TPM cannot store in one NV index.
// It is found before the index is touched: the slot stays as it was.
type BlobTooLargeError struct {
	Index uint32
	Size  int // the blob, signed
	Limit int // TPM2_PT_NV_INDEX_MAX of this TPM
}

func (e *BlobTooLargeError) Error() string {
	return fmt.Sprintf("the blob for NV index 0x%08X would be %d bytes, %d more than this TPM stores in one NV index (%d); nothing was written",
		e.Index, e.Size, e.Size-e.Limit, e.Limit)
}

// NVRAMRecoveryDir holds a blob that could not be written back after the index
// had already been undefined.  See stashUnwrittenBlob. A variable so the
// tests can point it elsewhere.
var NVRAMRecoveryDir = "/etc/tpm2-kira/recovery"

// WriteToNVRAM writes data to a TPM NVRAM index.
//
// Replacing an index means undefining it first, and there is no atomic
// replace in TPM 2.0: between the undefine and the last chunk being written,
// the slot holds no secret at all.  Everything that can fail without touching
// the TPM state is therefore done *before* the undefine — the key is loaded,
// the write policy is computed, and the signer is exercised on a dummy digest
// — so that an unusable key, an absent hardware token or a refused PIN is
// discovered while the old blob is still intact.
//
// If a step after the undefine fails anyway, the blob is written to
// NVRAMRecoveryDir: it carries the sealed object's public and private areas,
// which the TPM can still load, so the secret is not lost with the index.
func WriteToNVRAM(tpmDev transport.TPM, index uint32, data []byte, pubKey crypto.PublicKey, privKey crypto.Signer) error {
	if err := ValidateBlobIndex(index); err != nil {
		return fmt.Errorf("invalid NVRAM index: %w", err)
	}

	if len(data) == 0 {
		return fmt.Errorf("refusing to write an empty blob to NVRAM index 0x%08X", index)
	}
	if len(data) > MaxNVRAMBlobSize {
		return fmt.Errorf("blob is %d bytes, which exceeds the %d-byte maximum for an NV index", len(data), MaxNVRAMBlobSize)
	}
	// The TPM's own limit decides, for the blob as it is: what fits
	// depends on the signing key, the phones and the PCRs together.
	if limit := nvIndexLimit(tpmDev); limit > 0 && len(data) > limit {
		return &BlobTooLargeError{Index: index, Size: len(data), Limit: limit}
	}

	if pubKey == nil {
		return fmt.Errorf("signing public key is required for NV write authorization")
	}
	if privKey == nil {
		return fmt.Errorf("signing private key is required for NV write authorization")
	}

	nvIndex := tpm2.TPMHandle(index)

	// ── Pre-flight: everything that can fail non-destructively ──

	// Load the signing public key into the TPM once — the handle is reused
	// for both the policy digest computation and the per-chunk PolicySigned
	// sessions, avoiding redundant LoadExternal round-trips.  Some TPMs
	// reject key sizes here (RSA-4096 in particular), and that must be
	// found out before the existing index is destroyed.
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

	// Exercise the signer before anything is destroyed.  Every chunk below
	// needs a signature, and for a key held on a hardware token that means a
	// present device, an unlocked PIN and — depending on the slot's touch
	// policy — a user.  A failure here costs nothing; the same failure after
	// the undefine costs the sealed secret.
	if _, err := signForTPM(privKey, make([]byte, 32)); err != nil {
		return fmt.Errorf("signing key is not usable for NV write authorization: %w", err)
	}

	// ── Point of no return: the index is replaced from here on ──

	// Try to undefine existing NVRAM space (if it exists).
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

	if _, err = define.Execute(tpmDev); err != nil {
		return stashUnwrittenBlob(index, data, fmt.Errorf("failed to define NVRAM space: %w", err))
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

		if err := policySignedNVWrite(tpmDev, nvIndex, uint16(offset), data[offset:offset+chunkSize], keyHandle, keyName, privKey); err != nil {
			return stashUnwrittenBlob(index, data, fmt.Errorf("failed to write to NVRAM at offset %d: %w", offset, err))
		}

		offset += chunkSize
	}

	// Read the blob back and compare. The write is split across chunks and
	// sized by a uint16 in the NV public area, so a size or offset mistake
	// would otherwise surface as an unreadable blob at the next boot rather
	// than here, where the bytes are still in hand.
	written, err := ReadFromNVRAM(tpmDev, index)
	if err != nil {
		return stashUnwrittenBlob(index, data, fmt.Errorf("wrote the blob but could not read it back: %w", err))
	}
	if !bytes.Equal(written, data) {
		return stashUnwrittenBlob(index, data, fmt.Errorf("blob read back from NVRAM index 0x%08X differs from what was written (%d bytes written, %d read)", index, len(data), len(written)))
	}

	return nil
}

// policySignedNVWrite writes one chunk of at most 1024 bytes to an NV index
// whose write policy is PolicySigned by the signing key loaded at keyHandle.
//
// Each chunk gets its own policy session: the TPM nonce changes per session
// and needs a fresh signature, and after the first write the TPM sets
// TPMA_NV_WRITTEN, which changes the index's Name, so the Name is re-read
// before every write.
func policySignedNVWrite(tpmDev transport.TPM, nvIndex tpm2.TPMHandle, offset uint16, chunk []byte, keyHandle tpm2.TPMHandle, keyName tpm2.TPM2BName, privKey crypto.Signer) error {
	nvReadPubRsp, err := tpm2.NVReadPublic{NVIndex: nvIndex}.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to read NV public: %w", err)
	}

	// The callback runs when the session is first used: it signs the
	// TPM-provided nonce to prove possession of the private key.
	policySession := tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
		// aHash = SHA-256(nonceTPM || expiration(0)); cpHashA and
		// policyRef are empty.
		aHash := sha256.Sum256(append(append([]byte(nil), nonceTPM.Buffer...), 0, 0, 0, 0))
		tpmSig, signErr := signForTPM(privKey, aHash[:])
		if signErr != nil {
			return fmt.Errorf("failed to sign NV write policy nonce: %w", signErr)
		}
		// The TPM verifies the signature against the loaded public key.
		if _, err := (tpm2.PolicySigned{
			AuthObject:    tpm2.NamedHandle{Handle: keyHandle, Name: keyName},
			PolicySession: handle,
			NonceTPM:      nonceTPM,
			Expiration:    0,
			Auth:          tpmSig,
		}).Execute(tpm); err != nil {
			return fmt.Errorf("failed to execute PolicySigned for NV write: %w", err)
		}
		return nil
	})

	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: nvIndex, Name: nvReadPubRsp.NVName, Auth: policySession},
		NVIndex:    tpm2.NamedHandle{Handle: nvIndex, Name: nvReadPubRsp.NVName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: chunk},
		Offset:     offset,
	}.Execute(tpmDev)
	return err
}

// stashUnwrittenBlob saves a blob that could not be committed to NVRAM and
// wraps err with where it went.
//
// It is only ever reached after the index has been undefined, so the slot is
// empty at this point. The blob carries the sealed object's public and private
// areas, and the private area is wrapped by this TPM's storage hierarchy, whose
// primary key is re-derived deterministically — so the secret is recoverable
// from this file even though the index is gone. Without it, the secret is lost
// and the authenticator has to be re-enrolled.
//
// A failure to write the file is reported alongside the original error rather
// than replacing it: the original is what the user has to act on.
// ErrNVIndexReplaced marks an error that happened after an NVRAM index was
// undefined for rewriting: the old blob is gone from the TPM. Callers must
// never present such an error as harmless.
var ErrNVIndexReplaced = errors.New("NVRAM index was replaced")

type nvReplacedError struct{ err error }

func (e *nvReplacedError) Error() string   { return e.err.Error() }
func (e *nvReplacedError) Unwrap() []error { return []error{e.err, ErrNVIndexReplaced} }

func stashUnwrittenBlob(index uint32, data []byte, cause error) error {
	return &nvReplacedError{err: stashUnwrittenBlobFile(index, data, cause)}
}

func stashUnwrittenBlobFile(index uint32, data []byte, cause error) error {
	if mkErr := os.MkdirAll(NVRAMRecoveryDir, 0700); mkErr != nil {
		return fmt.Errorf("%w\n  NVRAM index 0x%08X is now EMPTY and the blob could not be saved either (%v).\n  The sealed secret is lost; run 'tpm2-kira seal' and re-enrol your authenticator", cause, index, mkErr)
	}

	path := fmt.Sprintf("%s/slot-0x%08X-%d.blob", NVRAMRecoveryDir, index, time.Now().Unix())
	if wrErr := os.WriteFile(path, data, 0600); wrErr != nil {
		return fmt.Errorf("%w\n  NVRAM index 0x%08X is now EMPTY and the blob could not be saved either (%v).\n  The sealed secret is lost; run 'tpm2-kira seal' and re-enrol your authenticator", cause, index, wrErr)
	}

	return fmt.Errorf("%w\n  NVRAM index 0x%08X is now EMPTY. The blob that was about to be written has been saved to:\n      %s\n  Keep this file: it holds the sealed object and is the only remaining copy of the secret.\n  Fix the cause above, then put it back:\n      tpm2-kira nvram restore %s\n  If you discard it, the secret is gone and you must run 'tpm2-kira seal' and re-enrol\n  your authenticator", cause, index, path, path)
}

// NVRAMList lists all defined NVRAM indices in the TPM
func NVRAMList(tpmPath string, nvramIndex uint32, debug bool) error {
	// Open TPM
	tpmDev, err := OpenTPM(tpmPath)
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
		if role := kiraIndexRole(uint32(handle)); role != "" {
			fmt.Printf("  tpm2-kira: %s\n", role)
		}
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
	tpmDev, err := OpenTPM(tpmPath)
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

	// A slot is deleted whole: its record counter goes with it. (Without its counter no blob of
	// the slot is accepted by the gate again, and a new counter starts
	// above every value this one had.)
	if nvramIndex >= NVRAMSlotStart && nvramIndex <= NVRAMSlotEnd {
		if counter := AttestCounterIndex(nvramIndex); NVRAMIndexExists(tpmDev, counter) {
			if err := undefineIndex(tpmDev, counter); err != nil {
				return fmt.Errorf("deleted the slot, but not its record counter 0x%08X: %w", counter, err)
			}
		}
	}

	// A slot's generation index goes with it.
	if ValidateBlobIndex(nvramIndex) == nil {
		genIndex := tpm2.TPMHandle(GenerationIndex(nvramIndex))
		if genPub, err := (tpm2.NVReadPublic{NVIndex: genIndex}).Execute(tpmDev); err == nil {
			if _, err := (tpm2.NVUndefineSpace{
				AuthHandle: tpm2.TPMRHOwner,
				NVIndex:    tpm2.NamedHandle{Handle: genIndex, Name: genPub.NVName},
			}).Execute(tpmDev); err != nil {
				return fmt.Errorf("deleted the blob, but not its generation index 0x%08X: %w", uint32(genIndex), err)
			}
		}
	}

	return nil
}

// kiraIndexRole says what tpm2-kira keeps at an NV index, or "" for an
// index that is not one of its own.
func kiraIndexRole(index uint32) string {
	switch {
	case index >= NVRAMSlotStart && index <= NVRAMSlotEnd:
		return fmt.Sprintf("slot #%d: its TOTP key and, if set up, its attestation part", SlotNumber(index))
	case index >= GenerationIndex(NVRAMSlotStart) && index <= GenerationIndex(NVRAMSlotEnd):
		return fmt.Sprintf("generation index of slot #%d", SlotNumber(index-GenerationIndexOffset))
	case index >= AttestCounterIndex(NVRAMSlotStart) && index <= AttestCounterIndex(NVRAMSlotEnd):
		return fmt.Sprintf("record counter of slot #%d's attestation part", index-attestCounterStart)
	}
	return ""
}

// kiraLeftovers returns the companion indices (generation index, record
// counter) whose slot is gone, as an interrupted command leaves them.
func kiraLeftovers(tpmDev transport.TPM, debug bool) []uint32 {
	var out []uint32
	for idx := uint32(NVRAMSlotStart); idx <= NVRAMSlotEnd; idx++ {
		if NVRAMIndexExists(tpmDev, idx) {
			continue
		}
		for _, companion := range []uint32{GenerationIndex(idx), AttestCounterIndex(idx)} {
			if NVRAMIndexExists(tpmDev, companion) {
				out = append(out, companion)
			}
		}
	}
	return out
}

func undefineIndex(tpmDev transport.TPM, index uint32) error {
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

// NVRAMDeleteCommand implements 'nvram delete'. A slot is one thing: its
// blob holds the TOTP key and the phone enrolment, and its generation index
// and record counter go with it. With an index that slot is deleted;
// without one, every slot and whatever an interrupted command left behind.
func NVRAMDeleteCommand(tpmPath string, nvramIndex uint32, yes bool, debug bool) error {
	if nvramIndex != 0 {
		if err := NVRAMDelete(tpmPath, nvramIndex, debug); err != nil {
			return err
		}
		// What outlives the blob by design of this command - a LUKS keyslot
		// bound to the slot, a recovery blob - makes the slot dirty; say so.
		fmt.Print(slotKeyslotAdvice(tpmPath))
		return nil
	}

	// Everything mode - discover what there is, then delete each.
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	slots := FindPopulatedSlots(tpmDev, debug)
	enrolled := 0
	for _, idx := range slots {
		if _, err := loadAttestBlob(tpmDev, idx); err == nil {
			enrolled++
		}
	}
	leftovers := kiraLeftovers(tpmDev, debug)
	tpmDev.Close()

	total := len(slots) + len(leftovers)
	if total == 0 {
		return fmt.Errorf("nothing of tpm2-kira found in the TPM: no sealed secrets in NVRAM slots 0x%08X – 0x%08X and no leftover indices",
			NVRAMSlotStart, NVRAMSlotEnd)
	}

	if len(slots) > 0 {
		fmt.Printf("Found %d sealed slot(s) to delete:", len(slots))
		for _, slotIdx := range slots {
			fmt.Printf(" #%d", SlotNumber(slotIdx))
		}
		if enrolled > 0 {
			fmt.Printf(" (%d with phones enrolled)", enrolled)
		}
		fmt.Println()
	}
	if len(leftovers) > 0 {
		fmt.Printf("Found %d leftover index(es) that belong to no slot:\n", len(leftovers))
		for _, idx := range leftovers {
			fmt.Printf("  0x%08X  %s\n", idx, kiraIndexRole(idx))
		}
	}
	if err := confirmDeleteAll(len(slots), enrolled, len(leftovers), yes); err != nil {
		return err
	}
	fmt.Println()

	failed := 0
	for _, slotIdx := range slots {
		fmt.Printf("Deleting slot #%d (0x%08X)... ", SlotNumber(slotIdx), slotIdx)
		if err := NVRAMDelete(tpmPath, slotIdx, debug); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			failed++
		}
	}
	if len(leftovers) > 0 {
		tpmDev, err := OpenTPM(tpmPath)
		if err != nil {
			return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
		}
		for _, idx := range leftovers {
			if !NVRAMIndexExists(tpmDev, idx) {
				continue // went with its slot
			}
			fmt.Printf("Deleting leftover 0x%08X... ", idx)
			if err := undefineIndex(tpmDev, idx); err != nil {
				fmt.Printf("FAILED: %v\n", err)
				failed++
				continue
			}
			fmt.Println("done")
		}
		tpmDev.Close()
	}

	fmt.Println()
	if failed > 0 {
		return fmt.Errorf("%d of %d item(s) failed to delete", failed, total)
	}
	fmt.Printf("All %d item(s) deleted successfully\n", total)
	if enrolled > 0 {
		fmt.Println("The phones still list this machine; remove it there too.")
		fmt.Println("The initramfs may still carry the Bluetooth gate: rebuild it (mkinitcpio -P / update-initramfs -u).")
	}
	fmt.Print(slotKeyslotAdvice(tpmPath))
	return nil
}

func confirmDeleteAll(slots, enrolled, leftovers int, yes bool) error {
	if yes {
		return nil
	}
	total := slots + leftovers
	tty := setupTerminal()
	if tty == nil {
		return fmt.Errorf("refusing to delete all %d item(s) without confirmation; nothing was deleted.\n"+
			"  Each deleted slot means re-enrolling its authenticator and its phones.\n"+
			"  To go ahead, run:\n"+
			"      tpm2-kira nvram delete --yes\n"+
			"  or delete one slot with --nvram <slot>", total)
	}
	if slots > 0 {
		fmt.Println("This deletes the sealed secret of every slot listed; each authenticator must then be re-enrolled.")
	}
	if enrolled > 0 {
		fmt.Println("The phones enrolled for those slots go with them; each must then be enrolled again.")
	}
	fmt.Printf("Type 'yes' to delete all %d item(s): ", total)
	answer, _ := tty.ReadString('\n')
	if strings.TrimSpace(answer) != "yes" {
		return fmt.Errorf("not confirmed; nothing was deleted")
	}
	return nil
}

// NVRAMStatus shows detailed status of the specified NVRAM index
func NVRAMStatus(tpmPath string, nvramIndex uint32, debug bool) error {
	// Open TPM
	tpmDev, err := OpenTPM(tpmPath)
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
				if blob.HasTOTPKey() {
					fmt.Printf("  TOTP key: public %d bytes, private %d bytes\n", len(blob.Payload.Public), len(blob.Payload.Private))
				} else {
					fmt.Printf("  TOTP key: none (attested by its phones)\n")
				}
				break
			}
			fmt.Printf("Data Format: Unknown (not a sealed blob)\n")
			if debug {
				peek := PeekBlobVersion(data)
				fmt.Printf("  Raw size: %d bytes\n", peek.DataSize)
				fmt.Printf("  Version field: %d (supported: %d)\n", peek.Version, CurrentBlobVersion)
				fmt.Printf("  Parse error: %v\n", unmarshalErr)
				fmt.Printf("  First bytes: %x\n", data[:min(32, len(data))])
			}
		}
	} else {
		fmt.Printf("Status: Not yet written\n")
	}

	return nil
}
