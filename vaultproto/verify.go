package vaultproto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"

	"github.com/mrwiora/tpm2-kira/attest"
)

// Device is what the vault pins of a machine at enrolment and checks
// every release against.
type Device struct {
	DeviceID            []byte
	AKPublic            []byte
	SigningPublic       []byte
	PolicyRef           []byte
	GenerationIndexName []byte
	Selection           Selection
}

// DeviceOf is the pinned part of an enrolment request.
func DeviceOf(r *EnrolRequest) *Device {
	return &Device{
		DeviceID:            r.DeviceID,
		AKPublic:            r.AKPublic,
		SigningPublic:       r.SigningPublic,
		PolicyRef:           r.PolicyRef,
		GenerationIndexName: r.GenerationIndexName,
		Selection:           r.Selection,
	}
}

// Check checks an enrolment request's form, before the vault keeps it.
func (r *EnrolRequest) Check() error {
	if len(r.DeviceID) != DeviceIDSize {
		return fmt.Errorf("device ID: %d bytes, want %d", len(r.DeviceID), DeviceIDSize)
	}
	if err := attest.ValidateEKPublic(r.EKPublic); err != nil {
		return err
	}
	if _, err := attest.ParseAKPublic(r.AKPublic, nil); err != nil {
		return err
	}
	if _, err := signingKey(r.SigningPublic); err != nil {
		return err
	}
	if len(r.PolicyRef) == 0 || len(r.PolicyRef) > 64 {
		return fmt.Errorf("policy reference: %d bytes", len(r.PolicyRef))
	}
	if len(r.GenerationIndexName) != 2+sha256.Size {
		return fmt.Errorf("generation index name: %d bytes", len(r.GenerationIndexName))
	}
	if err := r.Selection.check(); err != nil {
		return err
	}
	if len(r.Remote.Credential) == 0 || len(r.Remote.EncryptedSecret) == 0 {
		return errors.New("no wrapped remote part")
	}
	return nil
}

// Checked is what a verified release request says about the boot.
type Checked struct {
	Generation   uint64
	PCRValues    []PCRValue
	ResetCount   uint32 // TPM resets (boots) since the TPM was cleared
	RestartCount uint32
	Firmware     uint64
}

// VerifyRelease is the vault's check of one release request, against the
// device it pinned, the nonce it issued for req.RequestID, and the highest
// generation it has seen for the device:
//
//  1. the quote is signed by the device's attestation key, is a TPM quote
//     (TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE), and its qualifying data
//     is QualifyingData(device, request, nonce): fresh, for this request;
//  2. it covers exactly the pinned selection, and the values reproduce
//     its PCR digest;
//  3. the generation is not lower than minGeneration (no rollback to an
//     approval a reseal revoked);
//  4. the signing key's approval verifies over the policy those values
//     and that generation make (docs/SECURITY-BACKGROUND.md §4.2): the
//     quoted state is one the machine's own signing key approved.
//
// The machine's TPM checks 3 and 4 again, against its own registers and
// generation index, when it opens the remote part.
func VerifyRelease(dev *Device, nonce []byte, req *ReleaseRequest, minGeneration uint64) (*Checked, error) {
	if dev == nil || req == nil {
		return nil, errors.New("nothing to verify")
	}
	if !bytes.Equal(req.DeviceID, dev.DeviceID) {
		return nil, errors.New("the request is for another device")
	}
	if len(nonce) != NonceSize || req.RequestID == "" {
		return nil, errors.New("no challenge for the request")
	}
	if err := dev.Selection.check(); err != nil {
		return nil, err
	}

	ak, err := attest.ParseAKPublic(dev.AKPublic, nil)
	if err != nil {
		return nil, err
	}
	if err := attest.VerifyTPMSignature(ak, req.Quoted, req.QuoteSignature); err != nil {
		return nil, fmt.Errorf("the quote: %w", err)
	}
	att, err := tpm2.Unmarshal[tpm2.TPMSAttest](req.Quoted)
	if err != nil {
		return nil, fmt.Errorf("the quote does not parse: %w", err)
	}
	if att.Magic != tpm2.TPMGeneratedValue || att.Type != tpm2.TPMSTAttestQuote {
		return nil, errors.New("the signed structure is not a TPM quote")
	}
	if !bytes.Equal(att.ExtraData.Buffer, QualifyingData(req.DeviceID, req.RequestID, nonce)) {
		return nil, errors.New("the quote is not for this challenge")
	}
	info, err := att.Attested.Quote()
	if err != nil {
		return nil, fmt.Errorf("the quote: %w", err)
	}
	if !bytes.Equal(tpm2.Marshal(info.PCRSelect), tpm2.Marshal(dev.Selection.tpm())) {
		return nil, errors.New("the quote covers another PCR selection than the slot's")
	}
	if err := dev.Selection.checkValues(req.PCRValues); err != nil {
		return nil, err
	}
	if !bytes.Equal(info.PCRDigest.Buffer, compositeDigest(req.PCRValues)) {
		return nil, errors.New("the PCR values do not reproduce the quoted digest")
	}

	if req.Generation < minGeneration {
		return nil, fmt.Errorf("generation %d is older than %d: an approval a later one revoked", req.Generation, minGeneration)
	}
	signer, err := signingKey(dev.SigningPublic)
	if err != nil {
		return nil, err
	}
	approved := ApprovedPolicy(PolicyPCRDigest(dev.Selection, req.PCRValues), dev.GenerationIndexName, req.Generation)
	if err := verifyDigestSignature(signer, ApprovalDigest(approved, dev.PolicyRef), req.ApprovalSignature); err != nil {
		return nil, fmt.Errorf("the slot's approval does not cover this boot state: %w", err)
	}
	return &Checked{
		Generation:   req.Generation,
		PCRValues:    req.PCRValues,
		ResetCount:   att.ClockInfo.ResetCount,
		RestartCount: att.ClockInfo.RestartCount,
		Firmware:     att.FirmwareVersion,
	}, nil
}

// ── policy digests, as the TPM computes them (SHA-256 sessions) ───────────

func policyHash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func cc(c tpm2.TPMCC) []byte { return binary.BigEndian.AppendUint32(nil, uint32(c)) }

// PolicyPCRDigest is a fresh session's digest after PolicyPCR over sel with
// these values: H(0…0 ‖ TPM_CC_PolicyPCR ‖ TPML_PCR_SELECTION ‖ H(values)).
func PolicyPCRDigest(sel Selection, vals []PCRValue) []byte {
	return policyHash(make([]byte, sha256.Size), cc(tpm2.TPMCCPolicyPCR), tpm2.Marshal(sel.tpm()), compositeDigest(vals))
}

// ApprovedPolicy extends a PolicyPCR digest by PolicyNV(generation index ==
// gen at offset 0): the policy the slot's signing key approves.
func ApprovedPolicy(pcrPolicy, genIndexName []byte, gen uint64) []byte {
	operand := binary.BigEndian.AppendUint64(nil, gen)
	args := policyHash(operand, []byte{0, 0}, binary.BigEndian.AppendUint16(nil, uint16(tpm2.TPMEOEq)))
	return policyHash(pcrPolicy, cc(tpm2.TPMCCPolicyNV), args, genIndexName)
}

// ApprovalDigest is what the signing key signs to approve a policy for
// policyRef.
func ApprovalDigest(approvedPolicy, policyRef []byte) []byte {
	return policyHash(approvedPolicy, policyRef)
}

// compositeDigest is SHA-256 over the values in order: PolicyPCR's digest
// in a SHA-256 session, and a quote's pcrDigest under a SHA-256 scheme.
func compositeDigest(vals []PCRValue) []byte {
	h := sha256.New()
	for _, v := range vals {
		h.Write(v.Value)
	}
	return h.Sum(nil)
}

// ── selections ─────────────────────────────────────────────────────────────

func (s Selection) digestSize() int {
	switch tpm2.TPMAlgID(s.Alg) {
	case tpm2.TPMAlgSHA256:
		return sha256.Size
	case tpm2.TPMAlgSHA1:
		return sha1.Size
	}
	return 0
}

func (s Selection) check() error {
	if s.digestSize() == 0 {
		return fmt.Errorf("PCR bank 0x%04x is neither SHA-256 nor SHA-1", s.Alg)
	}
	if len(s.Indices) == 0 {
		return errors.New("an empty PCR selection")
	}
	for i, idx := range s.Indices {
		if idx >= attest.MaxPCRIndex || (i > 0 && idx <= s.Indices[i-1]) {
			return errors.New("PCR indices must be ascending and below 24")
		}
	}
	return nil
}

func (s Selection) checkValues(vals []PCRValue) error {
	if len(vals) != len(s.Indices) {
		return fmt.Errorf("%d PCR values for %d selected PCRs", len(vals), len(s.Indices))
	}
	for i, v := range vals {
		if v.Index != s.Indices[i] || len(v.Value) != s.digestSize() {
			return fmt.Errorf("PCR value %d is not PCR %d of the selection's bank", i, s.Indices[i])
		}
	}
	return nil
}

func (s Selection) tpm() tpm2.TPMLPCRSelection {
	bitmap := make([]byte, 3)
	for _, idx := range s.Indices {
		bitmap[idx/8] |= 1 << (idx % 8)
	}
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgID(s.Alg), PCRSelect: bitmap}}}
}

// ── the signing key ────────────────────────────────────────────────────────

func signingKey(public []byte) (crypto.PublicKey, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](public)
	if err != nil {
		return nil, fmt.Errorf("the signing key's public area does not parse: %w", err)
	}
	return tpm2.Pub(*pub)
}

// verifyDigestSignature checks a TPMT_SIGNATURE over digest itself, as
// TPM2_VerifySignature does (the digest is not hashed again).
func verifyDigestSignature(pub crypto.PublicKey, digest, sigBytes []byte) error {
	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](sigBytes)
	if err != nil {
		return fmt.Errorf("signature does not parse: %w", err)
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		s, err := sig.Signature.ECDSA()
		if err != nil || sig.SigAlg != tpm2.TPMAlgECDSA || s.Hash != tpm2.TPMAlgSHA256 {
			return errors.New("not an ECDSA SHA-256 signature")
		}
		if !ecdsa.Verify(k, digest, new(big.Int).SetBytes(s.SignatureR.Buffer), new(big.Int).SetBytes(s.SignatureS.Buffer)) {
			return errors.New("signature does not verify")
		}
		return nil
	case *rsa.PublicKey:
		s, err := sig.Signature.RSASSA()
		if err != nil || sig.SigAlg != tpm2.TPMAlgRSASSA || s.Hash != tpm2.TPMAlgSHA256 {
			return errors.New("not an RSASSA SHA-256 signature")
		}
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, s.Sig.Buffer)
	}
	return fmt.Errorf("signing key of type %T", pub)
}
