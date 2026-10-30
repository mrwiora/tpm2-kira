package nvslot

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"fmt"

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

// blobPublic is the boot settings' index: written
// only under the signing key's PolicySigned, no owner or unauthenticated
// write path, so only a holder of that key can replace it. Reads stay open:
// the secret is protected by the sealed object's own policy.
func blobPublic(index uint32, writePolicy tpm2.TPM2BDigest, size uint16) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: tpm2.TPMHandle(index),
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerRead:   true,
			PolicyWrite: true,
			AuthRead:    true,
		},
		AuthPolicy: writePolicy,
		DataSize:   size,
	}
}

// ValidateNVRAMIndex checks that the given NVRAM index is within the safe application range.
// Indices outside this range may belong to platform firmware, other applications, or
// reserved TPM hierarchy ranges and must not be accessed to prevent data destruction.
func ValidateNVRAMIndex(index uint32) error {
	if index < AppNVRAMStart || index > AppNVRAMEnd {
		return fmt.Errorf("NVRAM index 0x%08X is outside the safe application range (0x%08X-0x%08X)", index, AppNVRAMStart, AppNVRAMEnd)
	}
	return nil
}

// ValidateBlobIndex checks that index names one of the 16 slots: the
// slot's number is its record's (KIRAslotN), its index the base of its
// generation index and record counter.
func ValidateBlobIndex(index uint32) error {
	if err := ValidateNVRAMIndex(index); err != nil {
		return err
	}
	if index < NVRAMSlotStart || index > NVRAMSlotEnd {
		return fmt.Errorf("0x%08X is not a slot: slots are 0-%d (0x%08X-0x%08X)", index, MaxSlotNumber, NVRAMSlotStart, NVRAMSlotEnd)
	}
	return nil
}

// WriteToNVRAM writes data to one of tpm2-kira's NV indices below the
// slots - the boot settings (bootsettings.go) - writable with the signing
// key alone (PolicySigned). A slot's record is not in NV: record.go.
//
// Replacing an index means undefining it first, and there is no atomic
// replace in TPM 2.0. Everything that can fail without touching the TPM
// state is therefore done before the undefine - the key is loaded, the
// write policy is computed, and the signer is exercised on a dummy digest -
// so that an unusable key, an absent hardware token or a refused PIN is
// discovered while the old contents are still intact.
func WriteToNVRAM(tpmDev transport.TPM, index uint32, data []byte, pubKey crypto.PublicKey, privKey crypto.Signer) error {
	if err := ValidateNVRAMIndex(index); err != nil {
		return fmt.Errorf("invalid NVRAM index: %w", err)
	}
	if index >= NVRAMSlotStart {
		return fmt.Errorf("invalid NVRAM index: 0x%08X is a slot's or above (a slot's record is its EFI variable)", index)
	}

	if len(data) == 0 {
		return fmt.Errorf("refusing to write an empty blob to NVRAM index 0x%08X", index)
	}
	if limit := NvIndexLimit(tpmDev); len(data) > 0xFFFF || limit > 0 && len(data) > limit {
		return fmt.Errorf("%d bytes are more than this TPM stores in one NV index", len(data))
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

	// What is at the index goes, whatever it is: the index is tpm2-kira's
	// own place (replace, remove.go). NVUndefineSpace is the owner's and
	// works whatever the index's read/write attributes.
	if err := replaceAt(tpmDev, index); err != nil {
		return err
	}

	// define NVRAM space with PolicySigned-protected writes: no owner or
	// unauthenticated write path, so only a holder of the signing key can
	// replace the blob. Reads stay open — the secret itself is protected by the
	// sealed object's own policy, not by NV read control.
	define := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth: tpm2.TPM2BAuth{
			Buffer: []byte{},
		},
		PublicInfo: tpm2.New2B(blobPublic(index, nvWritePolicy, uint16(len(data)))),
	}

	if _, err = define.Execute(tpmDev); err != nil {
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

		if err := policySignedNVWrite(tpmDev, nvIndex, uint16(offset), data[offset:offset+chunkSize], keyHandle, keyName, privKey); err != nil {
			return fmt.Errorf("failed to write to NVRAM at offset %d: %w", offset, err)
		}

		offset += chunkSize
	}

	// Read the blob back and compare. The write is split across chunks and
	// sized by a uint16 in the NV public area, so a size or offset mistake
	// would otherwise surface as an unreadable blob at the next boot rather
	// than here, where the bytes are still in hand.
	written, err := tpmdev.ReadFromNVRAM(tpmDev, index)
	if err != nil {
		return fmt.Errorf("wrote the blob but could not read it back: %w", err)
	}
	if !bytes.Equal(written, data) {
		return fmt.Errorf("blob read back from NVRAM index 0x%08X differs from what was written (%d bytes written, %d read)", index, len(data), len(written))
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

// NvIndexLimit is the largest NV index this TPM stores, or 0 if it does
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
