package nvslot

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/core/vaultproto"
	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// The TOTP key is an HMAC key inside the TPM. tpm2-kira never gets it back:
// it sends the TOTP counter and receives the HMAC, which it truncates to the
// six-digit code. The key leaves the process exactly once, at seal time, for
// the enrolment QR code.
//
// The key object's policy - every slot object's: the TOTP key, the sealed
// machine-id, the boot key, the release key - is the slot's policy
// (attest.SlotPolicyDigest):
//
//	PolicyAuthorize(signing key, policyRef) ; PolicyPCR(15 == zero)
//
// The signing key approves one policy at a time:
//
//	approvedPolicy = PolicyNV(PolicyPCR(selection, values), generation index == G)
//
// and where the slot has signed PCRs - PCR 11 of a unified kernel image, by the
// PCR key - those first (attest.PCRKeyPublic), so that a new image needs no
// approval for them:
//
//	PolicyPCR(11) ; PolicyAuthorize(PCR key) ; PolicyPCR(the others) ; PolicyNV(G)
//
// G lives in a per-slot NV index (GenerationIndex) that only the signing key
// can write. reseal raises G, which revokes every earlier approval, and signs
// a new approvedPolicy for the new PCR values; it never needs the key.
//
// The PolicyPCR after PolicyAuthorize is the object's own, fixed at its
// creation, beyond any approval: PCR 15 is zero until the boot image closes
// the boot (tpm2-kira-boot close, at the end of the code screen and before
// a resume from hibernation), and from then on nothing - not the running
// system, not root - can use a slot object until the next boot. The same
// extension closes the SSH CA (aSSH's hostkey.Close).

// GenerationIndexOffset separates a slot's generation index from its blob
// index. Blob indices live below AppNVRAMStart+GenerationIndexOffset, their
// generation indices at the same offset above it.
const GenerationIndexOffset = 0x800

// GenerationIndex returns the NV index that holds the generation of the slot
// whose blob is at blobIndex.
func GenerationIndex(blobIndex uint32) uint32 {
	return blobIndex + GenerationIndexOffset
}

// ErrClosed marks a slot whose objects cannot be used in this boot any
// more: PCR 15 is extended (the boot image's close), which every slot
// object's policy requires to be zero.
var ErrClosed = errors.New("closed until the next boot (PCR 15 extended: the code screen is over)")

// CheckOpen returns ErrClosed when PCR 15 is no longer zero in bank, the
// bank the slot's policy reads it in. The TPM decides all the same; this
// only names why it would refuse.
func CheckOpen(tpmDev transport.TPM, bank measure.PCRHashAlgo) error {
	values, err := measure.ReadPCRRegisters(tpmDev, []int{attest.ClosePCR}, bank, false)
	if err != nil {
		return fmt.Errorf("reading PCR %d: %w", attest.ClosePCR, err)
	}
	if v := values[attest.ClosePCR]; len(v) != bank.DigestSize() || !bytes.Equal(v, make([]byte, bank.DigestSize())) {
		return ErrClosed
	}
	return nil
}

// GenerationMismatchError is returned when the slot's generation index does
// not hold the generation the blob's approval requires: the blob was
// replaced by a later reseal, or the index was deleted.
type GenerationMismatchError struct {
	BlobGeneration  uint64
	IndexGeneration uint64
	IndexMissing    bool
}

func (e *GenerationMismatchError) Error() string {
	if e.IndexMissing {
		return fmt.Sprintf("the slot's generation index is missing, so the approval in the blob (generation %d) cannot be used; approve to recreate it", e.BlobGeneration)
	}
	return fmt.Sprintf("the approval in the blob is for generation %d, but the slot is at generation %d: it was revoked by a later approval", e.BlobGeneration, e.IndexGeneration)
}

func TOTPAlgorithmName(alg tpm2.TPMAlgID) string {
	switch alg {
	case tpm2.TPMAlgSHA1:
		return "SHA1"
	case tpm2.TPMAlgSHA256:
		return "SHA256"
	}
	return fmt.Sprintf("unknown (0x%04x)", uint16(alg))
}

// Closed reports whether this boot is closed: PCR 15 is not zero in the
// SHA-256 bank, or, on a TPM without one, in the SHA-1 bank.
func Closed(tpmDev transport.TPM) bool {
	err := CheckOpen(tpmDev, measure.PCRHashAlgoSHA256)
	if err != nil && !errors.Is(err, ErrClosed) {
		err = CheckOpen(tpmDev, measure.PCRHashAlgoSHA1)
	}
	return errors.Is(err, ErrClosed)
}

// signedPCRs is what a policy session needs for a slot's signed PCRs: the PCR
// key's Name, the policy of their values as they are now, and the TPM's ticket
// for the signature. The key is gone again by then: a TPM holds few objects at
// once (three transient ones), and the session's user loads two of its own.
type signedPCRs struct {
	name   tpm2.TPM2BName
	policy []byte
	ticket tpm2.TPMTTKVerified
}

// ErrNotSigned is a boot whose PCR 11 the PCR key has not signed: an image
// without its signature, or none from the image at all.
var ErrNotSigned = errors.New("no signature by the PCR key of this boot's PCR 11")

// checkSignedPCRs finds the PCR key's signature of the signed PCRs' values.
func checkSignedPCRs(tpmDev transport.TPM, blob *SealedBlob) (*signedPCRs, error) {
	pcrs := blob.SignedPCRIndices()
	if len(pcrs) != 1 {
		return nil, fmt.Errorf("the slot signs PCRs %v: only one is supported", pcrs)
	}
	bank := blob.GetHashAlgo()
	values, err := measure.ReadPCRRegisters(tpmDev, pcrs, bank, false)
	if err != nil {
		return nil, err
	}
	sigs, err := measure.ReadBootPCRSignatures()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotSigned, err)
	}
	pol := measure.SignedPolicy(pcrs[0], values[pcrs[0]], bank)
	sig := sigs.Find(blob.Payload.PCRKey, bank, pcrs, pol)
	if sig == nil {
		return nil, ErrNotSigned
	}
	pub, err := attest.PCRKeyPublic(blob.Payload.PCRKey)
	if err != nil {
		return nil, err
	}
	key, err := tpm2.LoadExternal{InPublic: tpm2.New2B(pub), Hierarchy: tpm2.TPMRHOwner}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to load the PCR key: %w", err)
	}
	defer tpmdev.FlushHandle(tpmDev, key.ObjectHandle)
	digest := sha256.Sum256(pol)
	ticket, err := tpm2.VerifySignature{
		KeyHandle: key.ObjectHandle,
		Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
		Signature: attest.PCRSignatureForTPM(sig),
	}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("the PCR key's signature: %w", err)
	}
	return &signedPCRs{name: key.Name, policy: pol, ticket: ticket.Validation}, nil
}

// ── policy digests ──────────────────────────────────────────────────────────
//
// Computed in software, so they can be computed in the running OS after the
// close. The integration tests check them against real policy sessions.

// approvalDigest is what the signing key signs to approve a policy.
func approvalDigest(approvedPolicy, policyRef []byte) []byte {
	return vaultproto.ApprovalDigest(approvedPolicy, policyRef)
}

func generationOperand(gen uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, gen)
}

// ApprovedPolicy is the policy the signing key approves: the PCR values in
// pcrPolicy (a PolicyPCR digest), and the slot's generation index holding gen.
// The vault checks a quote against the same computation (vaultproto).
func ApprovedPolicy(pcrPolicy []byte, genIndexName []byte, gen uint64) []byte {
	return vaultproto.ApprovedPolicy(pcrPolicy, genIndexName, gen)
}

// ── generation index ────────────────────────────────────────────────────────

func generationIndexPublic(index uint32, writePolicy tpm2.TPM2BDigest) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: tpm2.TPMHandle(index),
		NameAlg: tpm2.TPMAlgSHA256,
		// noDA: PolicyNV reads it with an empty password, and a lockout
		// (wrong PINs elsewhere) must not stop the codes at boot. Only a
		// PIN is counted (aSSH's rule).
		Attributes: tpm2.TPMANV{
			OwnerRead:   true,
			AuthRead:    true,
			PolicyWrite: true,
			NoDA:        true,
			NT:          tpm2.TPMNTOrdinary,
		},
		AuthPolicy: writePolicy,
		DataSize:   8,
	}
}

// GenerationIndexName returns the Name of the written index: the Name
// PolicyNV checks.
func GenerationIndexName(tpmDev transport.TPM, index uint32) ([]byte, error) {
	rsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to read generation index 0x%08X: %w", index, err)
	}
	return rsp.NVName.Buffer, nil
}

// ReadGeneration returns the value of a generation index.
func ReadGeneration(tpmDev transport.TPM, index uint32) (uint64, error) {
	data, err := tpmdev.ReadFromNVRAM(tpmDev, index)
	if err != nil {
		return 0, err
	}
	if len(data) != 8 {
		return 0, fmt.Errorf("generation index 0x%08X holds %d bytes, want 8", index, len(data))
	}
	return binary.BigEndian.Uint64(data), nil
}

// WriteGeneration sets the slot's generation index to gen, defining it first
// when it is missing or was defined differently, and returns its Name for
// PolicyNV. The write is authorized by the signing key, like the blob's.
func WriteGeneration(tpmDev transport.TPM, index uint32, gen uint64, pubKey crypto.PublicKey, signer crypto.Signer) ([]byte, error) {
	loadRsp, err := signing.LoadExternalPublicKey(tpmDev, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing key for the generation index: %w", err)
	}
	defer tpmdev.FlushHandle(tpmDev, loadRsp.ObjectHandle)
	writePolicy, err := signing.ComputeNVWritePolicyDigestWithHandle(tpmDev, loadRsp.ObjectHandle, loadRsp.Name, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute the generation index write policy: %w", err)
	}
	want := generationIndexPublic(index, writePolicy)

	nvIndex := tpm2.TPMHandle(index)
	if rsp, err := (tpm2.NVReadPublic{NVIndex: nvIndex}).Execute(tpmDev); err == nil {
		have, perr := rsp.NVPublic.Contents()
		if perr != nil || !sameGenerationIndex(have, &want) {
			if err := replaceAt(tpmDev, index); err != nil {
				return nil, err
			}
		}
	}
	if _, err := (tpm2.NVReadPublic{NVIndex: nvIndex}).Execute(tpmDev); err != nil {
		if _, err := (tpm2.NVDefineSpace{
			AuthHandle: tpm2.TPMRHOwner,
			Auth:       tpm2.TPM2BAuth{Buffer: []byte{}},
			PublicInfo: tpm2.New2B(want),
		}).Execute(tpmDev); err != nil {
			return nil, fmt.Errorf("failed to define generation index 0x%08X: %w", index, err)
		}
	}

	if err := policySignedNVWrite(tpmDev, nvIndex, 0, generationOperand(gen), loadRsp.ObjectHandle, loadRsp.Name, signer); err != nil {
		return nil, fmt.Errorf("failed to write generation index 0x%08X: %w", index, err)
	}
	return GenerationIndexName(tpmDev, index)
}

// sameGenerationIndex reports whether an existing index was defined as want,
// ignoring the state bits (written, locked) that change at run time.
func sameGenerationIndex(have, want *tpm2.TPMSNVPublic) bool {
	h, w := have.Attributes, want.Attributes
	h.Written, h.ReadLocked, h.WriteLocked = false, false, false
	return h == w && have.NameAlg == want.NameAlg && have.DataSize == want.DataSize &&
		bytes.Equal(have.AuthPolicy.Buffer, want.AuthPolicy.Buffer)
}

// ── key object ──────────────────────────────────────────────────────────────

// NewPolicyRef returns a random policyRef for a new key object, so that its
// approvals fit no other object, even one made with the same signing key.
func NewPolicyRef() ([]byte, error) {
	ref := make([]byte, sha256.Size)
	if _, err := rand.Read(ref); err != nil {
		return nil, fmt.Errorf("failed to generate policy reference: %w", err)
	}
	return ref, nil
}

// SignApproval signs approvedPolicy for policyRef and returns the
// TPMT_SIGNATURE that VerifySignature takes.
func SignApproval(signer crypto.Signer, approvedPolicy, policyRef []byte) ([]byte, error) {
	sig, err := signing.SignForTPM(signer, approvalDigest(approvedPolicy, policyRef))
	if err != nil {
		return nil, fmt.Errorf("failed to sign the approved policy: %w", err)
	}
	return tpm2.Marshal(sig), nil
}

// ── computing a code ────────────────────────────────────────────────────────

// ApprovedSession returns a policy session that satisfies the slot's policy
// if the PCRs and the generation are what the signing key approved and the
// boot is not closed (PCR 15 zero): the one authorization for everything
// bound to the slot (the TOTP key, the machine-id, the boot key). The
// session runs its policy when a command uses it. The caller calls done
// once that command has been executed. ErrClosed after the close.
func ApprovedSession(tpmDev transport.TPM, blob *SealedBlob, blobIndex uint32) (tpm2.Session, func(), error) {
	return ApprovedSessionThen(tpmDev, blob, blobIndex, nil)
}

// ApprovedSessionThen is ApprovedSession with one more policy command run
// after the slot's policy, for an object whose policy extends it (the
// release key: PolicyCommandCode, attest.ReleaseKeyPolicy).
func ApprovedSessionThen(tpmDev transport.TPM, blob *SealedBlob, blobIndex uint32, then func(transport.TPM, tpm2.TPMISHPolicy) error) (tpm2.Session, func(), error) {
	p := &blob.Payload
	signingPublic, err := tpm2.Unmarshal[tpm2.TPMTPublic](p.SigningPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("blob holds no valid signing public key: %w", err)
	}
	approval, err := tpm2.Unmarshal[tpm2.TPMTSignature](p.ApprovalSignature)
	if err != nil {
		return nil, nil, fmt.Errorf("blob holds no valid approval signature: %w", err)
	}

	hashAlgo := blob.GetHashAlgo()
	if err := CheckOpen(tpmDev, hashAlgo); err != nil {
		return nil, nil, err
	}
	openDigest, err := attest.OpenPCRDigest(hashAlgo.TPMAlg())
	if err != nil {
		return nil, nil, err
	}

	genIndex := GenerationIndex(blobIndex)
	genPub, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(genIndex)}.Execute(tpmDev)
	if err != nil {
		return nil, nil, &GenerationMismatchError{BlobGeneration: p.Generation, IndexMissing: true}
	}

	// The PCR key is loaded and flushed before the signing key: a TPM holds
	// three objects, and a caller may hold two (a primary and its object).
	var signed *signedPCRs
	if len(blob.SignedPCRIndices()) > 0 {
		if signed, err = checkSignedPCRs(tpmDev, blob); err != nil {
			return nil, nil, err
		}
	}

	// The ticket must come from a key in a real hierarchy: PolicyAuthorize
	// refuses the NULL ticket a NULL-hierarchy key produces.
	signKey, err := tpm2.LoadExternal{InPublic: tpm2.New2B(*signingPublic), Hierarchy: tpm2.TPMRHOwner}.Execute(tpmDev)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load the signing public key: %w", err)
	}
	done := func() { tpmdev.FlushHandle(tpmDev, signKey.ObjectHandle) }

	session := tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
		if signed != nil {
			// The signed PCRs first: PolicyAuthorize by the PCR key resets
			// the session's digest to its Name.
			if _, err := (tpm2.PolicyPCR{
				PolicySession: handle,
				Pcrs:          measure.CreatePCRSelection(blob.SignedPCRIndices(), hashAlgo),
			}).Execute(tpm); err != nil {
				return fmt.Errorf("PolicyPCR(%v): %w", blob.SignedPCRIndices(), err)
			}
			if _, err := (tpm2.PolicyAuthorize{
				PolicySession:  handle,
				ApprovedPolicy: tpm2.TPM2BDigest{Buffer: signed.policy},
				KeySign:        signed.name,
				CheckTicket:    signed.ticket,
			}).Execute(tpm); err != nil {
				return fmt.Errorf("PolicyAuthorize(PCR key): %w", err)
			}
		}
		if _, err := (tpm2.PolicyPCR{
			PolicySession: handle,
			Pcrs: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      hashAlgo.TPMAlg(),
				PCRSelect: measure.PcrsToBitmapBytes(blob.PlainPCRIndices()),
			}}},
		}).Execute(tpm); err != nil {
			return fmt.Errorf("PolicyPCR: %w", err)
		}
		if _, err := (tpm2.PolicyNV{
			AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMHandle(genIndex), Name: genPub.NVName, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:       tpm2.NamedHandle{Handle: tpm2.TPMHandle(genIndex), Name: genPub.NVName},
			PolicySession: handle,
			OperandB:      tpm2.TPM2BOperand{Buffer: generationOperand(p.Generation)},
			Offset:        0,
			Operation:     tpm2.TPMEOEq,
		}).Execute(tpm); err != nil {
			return fmt.Errorf("PolicyNV: %w", err)
		}
		// The session digest is now the approved policy, if the PCRs and
		// the generation match; the signature is checked against it.
		pgd, err := tpm2.PolicyGetDigest{PolicySession: handle}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("PolicyGetDigest: %w", err)
		}
		ticket, err := tpm2.VerifySignature{
			KeyHandle: signKey.ObjectHandle,
			Digest:    tpm2.TPM2BDigest{Buffer: approvalDigest(pgd.PolicyDigest.Buffer, p.PolicyRef)},
			Signature: *approval,
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("the approval signature does not verify for the current PCR values and generation: %w", err)
		}
		if _, err := (tpm2.PolicyAuthorize{
			PolicySession:  handle,
			ApprovedPolicy: pgd.PolicyDigest,
			PolicyRef:      tpm2.TPM2BDigest{Buffer: p.PolicyRef},
			KeySign:        signKey.Name,
			CheckTicket:    ticket.Validation,
		}).Execute(tpm); err != nil {
			return fmt.Errorf("PolicyAuthorize: %w", err)
		}
		// The object's own part of the slot's policy: PCR 15 still zero.
		// With the digest given, the TPM compares at once: TPM_RC_VALUE
		// once the boot is closed.
		if _, err := (tpm2.PolicyPCR{
			PolicySession: handle,
			PcrDigest:     tpm2.TPM2BDigest{Buffer: openDigest},
			Pcrs:          attest.ClosePCRSelection(hashAlgo.TPMAlg()),
		}).Execute(tpm); err != nil {
			if errors.Is(err, tpm2.TPMRCValue) {
				return ErrClosed
			}
			return fmt.Errorf("PolicyPCR(%d): %w", attest.ClosePCR, err)
		}
		if then != nil {
			return then(tpm, handle)
		}
		return nil
	})
	return session, done, nil
}
