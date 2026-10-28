package nvslot

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"

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
			index, g, g-AttestCounterStart)
	}
	if index >= GenerationIndex(AppNVRAMStart) {
		return fmt.Errorf("NVRAM index 0x%08X is reserved for generation indices; blobs go at 0x%08X-0x%08X",
			index, AppNVRAMStart, GenerationIndex(AppNVRAMStart)-1)
	}
	return nil
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
	if limit := NvIndexLimit(tpmDev); limit > 0 && len(data) > limit {
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
	loadRsp, err := signing.LoadExternalPublicKey(tpmDev, pubKey)
	if err != nil {
		return fmt.Errorf("failed to load signing key for NV write policy: %w", err)
	}
	defer tpmdev.FlushHandle(tpmDev, loadRsp.ObjectHandle)

	keyHandle := loadRsp.ObjectHandle
	keyName := loadRsp.Name

	// Compute the PolicySigned digest that will be the AuthPolicy on this
	// NV index.  Any future NVWrite must satisfy a PolicySigned session
	// proving possession of the corresponding private key.
	nvWritePolicy, err := signing.ComputeNVWritePolicyDigestWithHandle(tpmDev, keyHandle, keyName, pubKey)
	if err != nil {
		return fmt.Errorf("failed to compute NV write policy digest: %w", err)
	}

	// Exercise the signer before anything is destroyed.  Every chunk below
	// needs a signature, and for a key held on a hardware token that means a
	// present device, an unlocked PIN and — depending on the slot's touch
	// policy — a user.  A failure here costs nothing; the same failure after
	// the undefine costs the sealed secret.
	if _, err := signing.SignForTPM(privKey, make([]byte, 32)); err != nil {
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
	written, err := tpmdev.ReadFromNVRAM(tpmDev, index)
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
		tpmSig, signErr := signing.SignForTPM(privKey, aHash[:])
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

type NvReplacedError struct{ Err error }

func (e *NvReplacedError) Error() string   { return e.Err.Error() }
func (e *NvReplacedError) Unwrap() []error { return []error{e.Err, ErrNVIndexReplaced} }

func stashUnwrittenBlob(index uint32, data []byte, cause error) error {
	return &NvReplacedError{Err: stashUnwrittenBlobFile(index, data, cause)}
}

func stashUnwrittenBlobFile(index uint32, data []byte, cause error) error {
	if mkErr := os.MkdirAll(NVRAMRecoveryDir, 0700); mkErr != nil {
		return fmt.Errorf("%w\n  NVRAM index 0x%08X is now EMPTY and the blob could not be saved either (%v).\n  The sealed secret is lost; run 'tpm2-kira slot add' and re-enrol your authenticator", cause, index, mkErr)
	}

	path := fmt.Sprintf("%s/slot-0x%08X-%d.blob", NVRAMRecoveryDir, index, time.Now().Unix())
	if wrErr := os.WriteFile(path, data, 0600); wrErr != nil {
		return fmt.Errorf("%w\n  NVRAM index 0x%08X is now EMPTY and the blob could not be saved either (%v).\n  The sealed secret is lost; run 'tpm2-kira slot add' and re-enrol your authenticator", cause, index, wrErr)
	}

	return fmt.Errorf("%w\n  NVRAM index 0x%08X is now EMPTY. The blob that was about to be written has been saved to:\n      %s\n  Keep this file: it holds the sealed object and is the only remaining copy of the secret.\n  Fix the cause above, then put it back:\n      tpm2-kira slot restore %s\n  If you discard it, the secret is gone and you must run 'tpm2-kira slot add' and re-enrol\n  your authenticator", cause, index, path, path)
}

// nvIndexLimit is the largest NV index this TPM stores, or 0 if it does
// not say.
func NvIndexLimit(tpmDev transport.TPM) int {
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVIndexMax),
		PropertyCount: 1,
	}.Execute(tpmDev)
	if err != nil {
		return 0
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0
	}
	for _, p := range props.TPMProperty {
		if p.Property == tpm2.TPMPTNVIndexMax {
			return int(p.Value)
		}
	}
	return 0
}
