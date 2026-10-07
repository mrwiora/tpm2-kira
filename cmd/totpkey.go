package cmd

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/matthias/tpm2-kira/attest"
)

// The TOTP key is an HMAC key inside the TPM. tpm2-kira never gets it back:
// it sends the TOTP counter and receives the HMAC, which it truncates to the
// six-digit code. The key leaves the process exactly once, at seal time, for
// the enrolment QR code.
//
// The key object's policy is PolicyAuthorize by the signing key, qualified by
// a per-object policyRef. The signing key approves one policy at a time:
//
//	approvedPolicy = PolicyNV(PolicyPCR(selection, values), generation index == G)
//
// G lives in a per-slot NV index (GenerationIndex) that only the signing key
// can write. reseal raises G, which revokes every earlier approval, and signs
// a new approvedPolicy for the new PCR values; it never needs the key.
//
// The generation index is defined with TPMA_NV_READ_STCLEAR. 'tpm2-kira cap',
// run when leaving the initrd, read-locks it; PolicyNV then fails until the
// next TPM reset (reboot), so nothing in the running OS can compute codes.

// GenerationIndexOffset separates a slot's generation index from its blob
// index. Blob indices live below AppNVRAMStart+GenerationIndexOffset, their
// generation indices at the same offset above it.
const GenerationIndexOffset = 0x800

// GenerationIndex returns the NV index that holds the generation of the slot
// whose blob is at blobIndex.
func GenerationIndex(blobIndex uint32) uint32 {
	return blobIndex + GenerationIndexOffset
}

// ErrCodesLocked marks a slot whose generation index is read-locked: 'tpm2-kira
// cap' ran in this boot, so no code can be computed until the next reboot.
var ErrCodesLocked = errors.New("codes are locked until the next reboot ('tpm2-kira cap' ran when the initrd was left)")

// ErrNoTOTPKeyAlgorithm means the TPM supports neither SHA-1 nor SHA-256 HMAC.
var ErrNoTOTPKeyAlgorithm = errors.New("the TPM supports neither SHA-1 nor SHA-256 for HMAC")

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
		return fmt.Sprintf("the slot's generation index is missing, so the approval in the blob (generation %d) cannot be used; reseal to recreate it", e.BlobGeneration)
	}
	return fmt.Sprintf("the approval in the blob is for generation %d, but the slot is at generation %d: it was revoked by a later reseal", e.BlobGeneration, e.IndexGeneration)
}

func totpAlgorithmName(alg tpm2.TPMAlgID) string {
	switch alg {
	case tpm2.TPMAlgSHA1:
		return "SHA1"
	case tpm2.TPMAlgSHA256:
		return "SHA256"
	}
	return fmt.Sprintf("unknown (0x%04x)", uint16(alg))
}

// totpKeySize is the size of a fresh TOTP key: the output size of the HMAC
// hash, as RFC 4226 recommends for SHA-1.
func totpKeySize(alg tpm2.TPMAlgID) int {
	if alg == tpm2.TPMAlgSHA256 {
		return sha256.Size
	}
	return 20
}

// ChooseTOTPAlgorithm returns HMAC-SHA1, the TOTP default every authenticator
// supports, or HMAC-SHA256 when the TPM has no SHA-1.
func ChooseTOTPAlgorithm(tpmDev transport.TPM) (tpm2.TPMAlgID, error) {
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapAlgs,
		Property:      uint32(tpm2.TPMAlgSHA1),
		PropertyCount: 64,
	}.Execute(tpmDev)
	if err != nil {
		return 0, fmt.Errorf("failed to read the TPM's algorithms: %w", err)
	}
	algs, err := rsp.CapabilityData.Data.Algorithms()
	if err != nil {
		return 0, fmt.Errorf("failed to parse the TPM's algorithms: %w", err)
	}
	has := map[tpm2.TPMAlgID]bool{}
	for _, a := range algs.AlgProperties {
		has[a.Alg] = true
	}
	switch {
	case has[tpm2.TPMAlgSHA1]:
		return tpm2.TPMAlgSHA1, nil
	case has[tpm2.TPMAlgSHA256]:
		return tpm2.TPMAlgSHA256, nil
	}
	return 0, ErrNoTOTPKeyAlgorithm
}

// ── policy digests ──────────────────────────────────────────────────────────
//
// Computed in software, so they can be computed in the running OS after the
// generation index has been read-locked. The integration tests check them
// against real policy sessions.

func policyHash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func commandCode(cc tpm2.TPMCC) []byte {
	return binary.BigEndian.AppendUint32(nil, uint32(cc))
}

// policyNVDigest extends a policy digest with
// PolicyNV(index == operandB at offset 0).
func policyNVDigest(prev []byte, indexName []byte, operandB []byte) []byte {
	args := policyHash(operandB, []byte{0, 0}, binary.BigEndian.AppendUint16(nil, uint16(tpm2.TPMEOEq)))
	return policyHash(prev, commandCode(tpm2.TPMCCPolicyNV), args, indexName)
}

// policyAuthorizeDigest is the policy of a key object that accepts any
// policy approved by the key named keyName for policyRef.
func policyAuthorizeDigest(keyName []byte, policyRef []byte) []byte {
	return attest.PolicyAuthorizeDigest(keyName, policyRef)
}

// approvalDigest is what the signing key signs to approve a policy.
func approvalDigest(approvedPolicy, policyRef []byte) []byte {
	return policyHash(approvedPolicy, policyRef)
}

func generationOperand(gen uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, gen)
}

// ApprovedPolicy is the policy the signing key approves: the PCR values in
// pcrPolicy (a PolicyPCR digest), and the slot's generation index holding gen.
func ApprovedPolicy(pcrPolicy []byte, genIndexName []byte, gen uint64) []byte {
	return policyNVDigest(pcrPolicy, genIndexName, generationOperand(gen))
}

// ── generation index ────────────────────────────────────────────────────────

func generationIndexPublic(index uint32, writePolicy tpm2.TPM2BDigest) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: tpm2.TPMHandle(index),
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerRead:   true,
			AuthRead:    true,
			PolicyWrite: true,
			ReadSTClear: true,
			NT:          tpm2.TPMNTOrdinary,
		},
		AuthPolicy: writePolicy,
		DataSize:   8,
	}
}

// generationIndexName returns the Name the index has while it is written and
// not read-locked: the Name PolicyNV checks in the initrd. Read-locking sets
// TPMA_NV_READLOCKED, which changes the current Name, so it is cleared here.
func generationIndexName(tpmDev transport.TPM, index uint32) ([]byte, error) {
	rsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to read generation index 0x%08X: %w", index, err)
	}
	pub, err := rsp.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to parse generation index 0x%08X: %w", index, err)
	}
	pub.Attributes.ReadLocked = false
	name, err := tpm2.NVName(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute the Name of generation index 0x%08X: %w", index, err)
	}
	return name.Buffer, nil
}

// ReadGeneration returns the value of a generation index. It returns
// ErrCodesLocked when the index is read-locked.
func ReadGeneration(tpmDev transport.TPM, index uint32) (uint64, error) {
	data, err := ReadFromNVRAM(tpmDev, index)
	if err != nil {
		if strings.Contains(err.Error(), "TPM_RC_NV_LOCKED") {
			return 0, ErrCodesLocked
		}
		return 0, err
	}
	if len(data) != 8 {
		return 0, fmt.Errorf("generation index 0x%08X holds %d bytes, want 8", index, len(data))
	}
	return binary.BigEndian.Uint64(data), nil
}

// writeGeneration sets the slot's generation index to gen, defining it first
// when it is missing or was defined differently, and returns its Name for
// PolicyNV. The write is authorized by the signing key, like the blob's.
func writeGeneration(tpmDev transport.TPM, index uint32, gen uint64, pubKey crypto.PublicKey, signer crypto.Signer) ([]byte, error) {
	loadRsp, err := LoadExternalPublicKey(tpmDev, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing key for the generation index: %w", err)
	}
	defer FlushHandle(tpmDev, loadRsp.ObjectHandle)
	writePolicy, err := ComputeNVWritePolicyDigestWithHandle(tpmDev, loadRsp.ObjectHandle, loadRsp.Name, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute the generation index write policy: %w", err)
	}
	want := generationIndexPublic(index, writePolicy)

	nvIndex := tpm2.TPMHandle(index)
	if rsp, err := (tpm2.NVReadPublic{NVIndex: nvIndex}).Execute(tpmDev); err == nil {
		have, perr := rsp.NVPublic.Contents()
		if perr != nil || !sameGenerationIndex(have, &want) {
			if _, err := (tpm2.NVUndefineSpace{
				AuthHandle: tpm2.TPMRHOwner,
				NVIndex:    tpm2.NamedHandle{Handle: nvIndex, Name: rsp.NVName},
			}).Execute(tpmDev); err != nil {
				return nil, fmt.Errorf("failed to replace generation index 0x%08X: %w", index, err)
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
	return generationIndexName(tpmDev, index)
}

// sameGenerationIndex reports whether an existing index was defined as want,
// ignoring the state bits (written, read-locked) that change at run time.
func sameGenerationIndex(have, want *tpm2.TPMSNVPublic) bool {
	h, w := have.Attributes, want.Attributes
	h.Written, h.ReadLocked, h.WriteLocked = false, false, false
	return h == w && have.NameAlg == want.NameAlg && have.DataSize == want.DataSize &&
		bytes.Equal(have.AuthPolicy.Buffer, want.AuthPolicy.Buffer)
}

// CapCodes read-locks every generation index, so that no code can be
// computed until the next reboot. It returns how many it locked.
func CapCodes(tpmDev transport.TPM) (int, error) {
	start, end := GenerationIndex(AppNVRAMStart), uint32(AppNVRAMEnd)
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      start,
		PropertyCount: end - start + 1,
	}.Execute(tpmDev)
	if err != nil {
		return 0, fmt.Errorf("failed to list NV indices: %w", err)
	}
	handles, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		return 0, fmt.Errorf("failed to parse NV indices: %w", err)
	}
	locked := 0
	var errs []error
	for _, h := range handles.Handle {
		if uint32(h) < start || uint32(h) > end {
			continue
		}
		pubRsp, err := tpm2.NVReadPublic{NVIndex: h}.Execute(tpmDev)
		if err != nil {
			errs = append(errs, fmt.Errorf("0x%08X: %w", uint32(h), err))
			continue
		}
		pub, err := pubRsp.NVPublic.Contents()
		if err != nil || !pub.Attributes.ReadSTClear {
			continue
		}
		if pub.Attributes.ReadLocked {
			locked++
			continue
		}
		if _, err := (tpm2.NVReadLock{
			AuthHandle: tpm2.AuthHandle{Handle: h, Name: pubRsp.NVName, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: h, Name: pubRsp.NVName},
		}).Execute(tpmDev); err != nil {
			errs = append(errs, fmt.Errorf("0x%08X: %w", uint32(h), err))
			continue
		}
		locked++
	}
	return locked, errors.Join(errs...)
}

// ── key object ──────────────────────────────────────────────────────────────

// newPolicyRef returns a random policyRef for a new key object, so that its
// approvals fit no other object, even one made with the same signing key.
func newPolicyRef() ([]byte, error) {
	ref := make([]byte, sha256.Size)
	if _, err := rand.Read(ref); err != nil {
		return nil, fmt.Errorf("failed to generate policy reference: %w", err)
	}
	return ref, nil
}

// CreateTOTPKey creates the HMAC key object for key under the primary key.
// The key is sent to the TPM in a salted, parameter-encrypted session, so it
// does not cross the bus in the clear.
func CreateTOTPKey(tpmDev transport.TPM, primary *PrimaryKeyResponse, key []byte, alg tpm2.TPMAlgID, authPolicy []byte) (*CreateSealedObjectResponse, error) {
	session := tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
		tpm2.Salted(primary.ObjectHandle, primary.Public),
		tpm2.AESEncryption(128, tpm2.EncryptIn))
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: session},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: key}),
			},
		},
		InPublic: tpm2.New2B(totpKeyTemplate(alg, authPolicy)),
	}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to create the TOTP key in the TPM: %w", err)
	}
	return &CreateSealedObjectResponse{Public: rsp.OutPublic.Bytes(), Private: rsp.OutPrivate.Buffer}, nil
}

func totpKeyTemplate(alg tpm2.TPMAlgID, authPolicy []byte) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:    true,
			FixedParent: true,
			SignEncrypt: true,
			// UserWithAuth deliberately NOT set: policy only.
			// SensitiveDataOrigin is clear because tpm2-kira supplies the
			// key, which it must show once for enrolment.
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{
				Scheme:  tpm2.TPMAlgHMAC,
				Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{HashAlg: alg}),
			},
		}),
	}
}

// signApproval signs approvedPolicy for policyRef and returns the
// TPMT_SIGNATURE that VerifySignature takes.
func signApproval(signer crypto.Signer, approvedPolicy, policyRef []byte) ([]byte, error) {
	sig, err := signForTPM(signer, approvalDigest(approvedPolicy, policyRef))
	if err != nil {
		return nil, fmt.Errorf("failed to sign the approved policy: %w", err)
	}
	return tpm2.Marshal(sig), nil
}

// ── computing a code ────────────────────────────────────────────────────────

// TOTPCode computes the TOTP code of the slot whose blob is at blobIndex, for
// time t, inside the TPM.
//
// The policy session satisfies the approved policy (PolicyPCR against the
// live registers, PolicyNV against the generation index), then PolicyAuthorize
// with a ticket for the approval signature in the blob. The TPM decides; the
// blob is not trusted for anything it could not also have done itself:
// PolicyAuthorize only accepts the signing key whose Name the key object's
// policy binds.
func TOTPCode(tpmDev transport.TPM, blob *SealedBlob, blobIndex uint32, t time.Time) (string, error) {
	p := &blob.Payload
	if p.TOTPAlgorithm != tpm2.TPMAlgSHA1 && p.TOTPAlgorithm != tpm2.TPMAlgSHA256 {
		return "", fmt.Errorf("blob has unknown TOTP algorithm 0x%04x", uint16(p.TOTPAlgorithm))
	}
	session, done, err := approvedSession(tpmDev, blob, blobIndex)
	if err != nil {
		return "", err
	}
	defer done()
	primary, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return "", err
	}
	defer FlushHandle(tpmDev, primary.ObjectHandle)
	key, err := LoadSealedObject(tpmDev, primary, blob)
	if err != nil {
		return "", err
	}
	defer FlushHandle(tpmDev, key.ObjectHandle)

	counter := binary.BigEndian.AppendUint64(nil, uint64(t.Unix()/30))
	rsp, err := tpm2.Hmac{
		Handle:  tpm2.AuthHandle{Handle: key.ObjectHandle, Name: key.Name, Auth: session},
		Buffer:  tpm2.TPM2BMaxBuffer{Buffer: counter},
		HashAlg: p.TOTPAlgorithm,
	}.Execute(tpmDev)
	if err != nil {
		if errors.Is(err, ErrCodesLocked) {
			return "", ErrCodesLocked
		}
		return "", fmt.Errorf("failed to compute the code in the TPM: %w", err)
	}
	return hotpTruncate(rsp.OutHMAC.Buffer), nil
}

// approvedSession returns a policy session that satisfies the slot's policy
// if the PCRs and the generation are what the signing key approved: the one
// authorization for everything bound to the slot (the TOTP key, the boot
// key). The session runs its policy when a command uses it. The caller calls
// done once that command has been executed.
func approvedSession(tpmDev transport.TPM, blob *SealedBlob, blobIndex uint32) (tpm2.Session, func(), error) {
	return approvedSessionThen(tpmDev, blob, blobIndex, nil)
}

// approvedSessionThen is approvedSession with one more policy command run
// after PolicyAuthorize, for an object whose policy extends the slot's
// (the release key: PolicyCommandCode, attest.ReleaseKeyPolicy).
func approvedSessionThen(tpmDev transport.TPM, blob *SealedBlob, blobIndex uint32, then func(transport.TPM, tpm2.TPMISHPolicy) error) (tpm2.Session, func(), error) {
	p := &blob.Payload
	signingPublic, err := tpm2.Unmarshal[tpm2.TPMTPublic](p.SigningPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("blob holds no valid signing public key: %w", err)
	}
	approval, err := tpm2.Unmarshal[tpm2.TPMTSignature](p.ApprovalSignature)
	if err != nil {
		return nil, nil, fmt.Errorf("blob holds no valid approval signature: %w", err)
	}

	genIndex := GenerationIndex(blobIndex)
	genPub, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(genIndex)}.Execute(tpmDev)
	if err != nil {
		return nil, nil, &GenerationMismatchError{BlobGeneration: p.Generation, IndexMissing: true}
	}

	// The ticket must come from a key in a real hierarchy: PolicyAuthorize
	// refuses the NULL ticket a NULL-hierarchy key produces.
	signKey, err := tpm2.LoadExternal{InPublic: tpm2.New2B(*signingPublic), Hierarchy: tpm2.TPMRHOwner}.Execute(tpmDev)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load the signing public key: %w", err)
	}
	done := func() { FlushHandle(tpmDev, signKey.ObjectHandle) }

	hashAlgo := blob.GetHashAlgo()
	session := tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
		if _, err := (tpm2.PolicyPCR{
			PolicySession: handle,
			Pcrs: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      hashAlgo.TPMAlg(),
				PCRSelect: PcrsToBitmapBytes(blob.GetPCRIndices()),
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
			if strings.Contains(err.Error(), "TPM_RC_NV_LOCKED") {
				return ErrCodesLocked
			}
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
		if then != nil {
			return then(tpm, handle)
		}
		return nil
	})
	return session, done, nil
}

// CapCommand implements 'tpm2-kira cap': it read-locks every generation
// index, so that no TOTP code can be computed until the next reboot. Run it
// when leaving the initrd; the systemd unit and the initramfs-tools script do.
func CapCommand(tpmPath string) error {
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	n, err := CapCodes(tpmDev)
	if err != nil {
		return fmt.Errorf("locked %d generation index(es), but not all: %w", n, err)
	}
	fmt.Printf("tpm2-kira: locked %d generation index(es); no codes until the next reboot\n", n)
	return nil
}
