// Package vaultproto is the contract between tpm2-kira and tpm2-kira-vault
// (docs/VAULT.md): the messages of the vault's REST interface, and the
// check the vault makes before it releases a machine's remote part.
//
// The disk's key of a keyslot with the vault's salt is made of two parts. The
// local part L stays in the machine's TPM (in the slot's blob, wrapped for
// the TPM's endorsement key and the slot's release key). The remote part R
// is kept by the vault, wrapped the same way: a credential only this
// machine's TPM opens, and only in a boot state the slot's signing key
// approved, before the boot is capped. The vault never sees R in the clear.
//
// The vault releases R only to a quote from the machine's attestation key
// over a fresh challenge, whose PCR values are a state the machine's
// signing key approved (the slot's approval signature, pinned at
// enrolment) at a generation not lower than the highest the vault has
// seen. The machine's TPM enforces the same once more when it opens R.
//
// The package is pure: no TPM, no network, no clock. JSON carries []byte
// as standard base64.
package vaultproto

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// The machine-facing paths. The vault serves them over HTTPS; the machine
// pins the vault's public key (PinOf) instead of checking a certificate
// chain, because the initrd has no clock to check one with.
const (
	PathEnrol        = "/v1/enrol"         // EnrolRequest → EnrolChallenge
	PathEnrolConfirm = "/v1/enrol/confirm" // EnrolConfirm → EnrolResult
	PathChallenge    = "/v1/challenge"     // ChallengeRequest → ChallengeResponse
	PathRelease      = "/v1/release"       // ReleaseRequest → ReleaseResponse
)

// DeviceIDSize is the size of a device ID: the slot's attestation device ID.
const DeviceIDSize = 16

// NonceSize is the size of the vault's challenge.
const NonceSize = 32

// SecretSize is the size of L and R, and of the enrolment's activation
// secret: what TPM2_MakeCredential carries directly.
const SecretSize = 32

// Wrapped is a TPM2_MakeCredential output: a secret only one TPM opens,
// with one object (named at wrapping) loaded and authorised.
type Wrapped struct {
	Credential      []byte `json:"credential"`       // TPM2B_ID_OBJECT contents
	EncryptedSecret []byte `json:"encrypted_secret"` // TPM2B_ENCRYPTED_SECRET contents
}

// Selection is a PCR selection: one bank, ascending indices.
type Selection struct {
	Alg     uint16  `json:"alg"` // TPM_ALG_SHA256 (0x000B) or TPM_ALG_SHA1 (0x0004)
	Indices []uint8 `json:"indices"`
}

// PCRValue is one register's value in the selection's bank.
type PCRValue struct {
	Index uint8  `json:"index"`
	Value []byte `json:"value"`
}

// EnrolRequest is sent once, from the booted machine, with a one-time
// token an operator created on the vault. Everything in it except
// Remote is pinned by the vault and checked at every release; Remote is
// opaque to the vault.
type EnrolRequest struct {
	Token    string `json:"token"`
	DeviceID []byte `json:"device_id"`
	Name     string `json:"name"` // the machine's name, for the operator

	EKPublic []byte `json:"ek_public"`         // TPMT_PUBLIC of the endorsement key
	EKCert   []byte `json:"ek_cert,omitempty"` // DER, when the TPM has one
	AKPublic []byte `json:"ak_public"`         // TPMT_PUBLIC of the attestation key

	// The slot's approval: what the vault verifies a quote's PCR values
	// against (docs/SECURITY-BACKGROUND.md §4).
	SigningPublic       []byte    `json:"signing_public"`        // TPMT_PUBLIC of the slot's signing key
	PolicyRef           []byte    `json:"policy_ref"`            // the slot's policyRef
	GenerationIndexName []byte    `json:"generation_index_name"` // Name of the generation index, written and not read-locked
	Generation          uint64    `json:"generation"`            // the slot's generation now
	Selection           Selection `json:"selection"`             // the slot's PCR selection

	Remote Wrapped `json:"remote"` // R, wrapped for EK and the slot's release key
	Label  string  `json:"label"`  // the keyslot's label, for the operator

	// ReleaseKeyPublic is the TPMT_PUBLIC of the slot's release key, the
	// key R is wrapped for. The vault checks it is the slot's
	// (attest.ReleaseKeyName) and wraps a pepper for its Name.
	ReleaseKeyPublic []byte `json:"release_key_public"`

	// Pepper says the key is derived with an operator's pepper as well:
	// the vault then releases only on an approval that carries it, and
	// passes it on once, wrapped for the TPM (ReleaseResponse.Pepper). The
	// pepper itself is never sent at enrolment; the vault never keeps it.
	Pepper bool `json:"pepper,omitempty"`
}

// EnrolChallenge proves the attestation key lives in the TPM holding the
// endorsement key: the vault wraps a random secret for (EK, name of AK),
// and only that TPM returns it.
type EnrolChallenge struct {
	EnrolID   string  `json:"enrol_id"`
	Challenge Wrapped `json:"challenge"`
}

// EnrolConfirm returns the opened secret.
type EnrolConfirm struct {
	EnrolID string `json:"enrol_id"`
	Secret  []byte `json:"secret"`
}

// EnrolResult ends an enrolment. Mode is how the vault releases R for
// this device: ModeAuto or ModeApprove.
type EnrolResult struct {
	DeviceID []byte      `json:"device_id"`
	Mode     ReleaseMode `json:"mode"`
}

// MaxPepper bounds a pepper's length in bytes.
const MaxPepper = 256

// ReleaseMode is how the vault releases a device's part, by number; the
// words are for people (String, ParseReleaseMode).
type ReleaseMode uint8

// The release modes.
const (
	ModeAuto    ReleaseMode = 0x01 // a release whose checks pass is released at once
	ModeApprove ReleaseMode = 0x02 // it waits for an operator's approval
)

// Check says why m is not a release mode, or nil.
func (m ReleaseMode) Check() error {
	if m != ModeAuto && m != ModeApprove {
		return fmt.Errorf("release mode %#02x: 0x01 (auto) or 0x02 (approve)", uint8(m))
	}
	return nil
}

// String is the mode's word: auto, approve.
func (m ReleaseMode) String() string {
	switch m {
	case ModeAuto:
		return "auto"
	case ModeApprove:
		return "approve"
	}
	return fmt.Sprintf("%#02x", uint8(m))
}

// ParseReleaseMode reads the mode's word, as the command line takes it.
func ParseReleaseMode(word string) (ReleaseMode, error) {
	switch word {
	case "auto":
		return ModeAuto, nil
	case "approve":
		return ModeApprove, nil
	}
	return 0, fmt.Errorf("the release mode is auto or approve, not %q", word)
}

// ChallengeRequest starts a release.
type ChallengeRequest struct {
	DeviceID []byte `json:"device_id"`
}

// ChallengeResponse is the vault's fresh challenge, valid for ExpiresIn
// seconds by the vault's clock and for one release.
type ChallengeResponse struct {
	RequestID string `json:"request_id"`
	Nonce     []byte `json:"nonce"`
	ExpiresIn int    `json:"expires_in"`
}

// ReleaseRequest is the machine's evidence: a quote of the slot's
// selection with QualifyingData(device, request, nonce), the values that
// reproduce it, and the slot's approval. A machine whose request is
// pending sends the same request again; the vault answers it by its
// RequestID.
type ReleaseRequest struct {
	RequestID         string     `json:"request_id"`
	DeviceID          []byte     `json:"device_id"`
	Quoted            []byte     `json:"quoted"`          // TPMS_ATTEST
	QuoteSignature    []byte     `json:"quote_signature"` // TPMT_SIGNATURE by the AK
	PCRValues         []PCRValue `json:"pcr_values"`
	Generation        uint64     `json:"generation"`
	ApprovalSignature []byte     `json:"approval_signature"` // TPMT_SIGNATURE by the signing key
}

// Release states.
const (
	StatusReleased = "released"
	StatusPending  = "pending"
	StatusDenied   = "denied"
)

// ReleaseResponse is the vault's answer. Released carries Remote, and
// Pepper - the operator's, as given with the approval, once, wrapped for
// the machine's TPM - for a device enrolled with one; Pending says when to
// ask again; Denied says why, for the console and the log.
type ReleaseResponse struct {
	Status     string         `json:"status"`
	Remote     *Wrapped       `json:"remote,omitempty"`
	Pepper     *WrappedPepper `json:"pepper,omitempty"`
	RetryAfter int            `json:"retry_after,omitempty"`
	Reason     string         `json:"reason,omitempty"`
}

// ErrorResponse is the body of every non-2xx answer.
type ErrorResponse struct {
	Error string `json:"error"`
}

// QualifyingData is what the machine quotes with: it binds the quote to
// one device, one request and the vault's nonce.
func QualifyingData(deviceID []byte, requestID string, nonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte("tpm2-kira/vault/release/v1"))
	for _, p := range [][]byte{deviceID, []byte(requestID), nonce} {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(p))))
		h.Write(p)
	}
	return h.Sum(nil)
}

// PinOf is the pin of a vault's key: SHA-256 over the DER
// SubjectPublicKeyInfo of its TLS certificate, written "sha256:" and hex.
func PinOf(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, 7+64)
	out = append(out, "sha256:"...)
	for _, b := range sum {
		out = append(out, hexdigits[b>>4], hexdigits[b&15])
	}
	return string(out)
}
