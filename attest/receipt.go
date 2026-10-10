package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
)

// ParseAnchor parses a pinned anchor: a PKIX DER ECDSA P-256 public key, the
// format both Android (KeyStore getPublicKey().getEncoded()) and iOS
// (SecKeyCopyExternalRepresentation plus the fixed SPKI header) produce.
func ParseAnchor(der []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("attest: anchor is not a PKIX public key: %w", err)
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("attest: anchor must be an ECDSA P-256 key")
	}
	return ec, nil
}

// VerifyAnchorSignature checks a DER ECDSA signature over SHA-256(tbs).
func VerifyAnchorSignature(anchor *ecdsa.PublicKey, tbs, sig []byte) bool {
	d := sha256.Sum256(tbs)
	return ecdsa.VerifyASN1(anchor, d[:], sig)
}

// ReceiptExpectation is what the attester knows about its own session, and
// what a receipt must match to count.
type ReceiptExpectation struct {
	DeviceID    []byte
	AKName      []byte
	QD          []byte
	QuoteDigest []byte
	VerifierID  string
}

// ReceiptCheck is the attester's reading of a receipt.
type ReceiptCheck struct {
	Verdict VerdictCode
	// Authentic: signed by the pinned anchor and bound to this session.
	Authentic bool
	Ack       uint8
	Detail    string
}

// CheckReceipt validates a receipt against the pinned anchor and this
// session. It never consults a clock (PLAN-REMOTEATTESTATION.md §11.4):
// freshness comes from qd, which covers nonce_a, chosen by the attester this
// boot.
func CheckReceipt(r *Receipt, anchor *ecdsa.PublicKey, exp ReceiptExpectation) ReceiptCheck {
	out := ReceiptCheck{Verdict: r.Verdict}
	if !bytes.Equal(r.DeviceID, exp.DeviceID) || !bytes.Equal(r.AKName, exp.AKName) ||
		!bytes.Equal(r.QD, exp.QD) || !bytes.Equal(r.QuoteDigest, exp.QuoteDigest) {
		out.Ack = AckBindingMismatch
		out.Detail = "receipt is not bound to this session's quote"
		return out
	}
	if r.VerifierID != exp.VerifierID {
		out.Ack = AckBindingMismatch
		out.Detail = "receipt names a different verifier"
		return out
	}
	if len(r.Signature) == 0 {
		if r.Verdict == VerdictReject {
			out.Ack = AckRejectNoted
			out.Detail = "unsigned reject"
			return out
		}
		out.Ack = AckBadSignature
		out.Detail = "receipt is not signed"
		return out
	}
	if anchor == nil || !VerifyAnchorSignature(anchor, ReceiptTBS(r), r.Signature) {
		out.Ack = AckBadSignature
		out.Detail = "anchor mismatch: receipt not signed by the enrolled phone"
		return out
	}
	out.Authentic = true
	if r.Verdict == VerdictReject {
		out.Ack = AckRejectNoted
		out.Detail = "signed reject"
		return out
	}
	if !r.Verdict.Trusted() {
		out.Authentic = false
		out.Ack = AckMalformed
		out.Detail = fmt.Sprintf("unsupported verdict %s", r.Verdict)
		return out
	}
	out.Ack = AckAccepted
	return out
}

// MakeCredential runs TPM2_MakeCredential in software: it encrypts secret to
// the EK so that only a TPM holding that EK *and* a loaded object with Name
// objectName can recover it with TPM2_ActivateCredential.
//
// Used at enrolment (objectName = the AK, proving the AK lives in that TPM)
// and for factor release (objectName = the release key).
func MakeCredential(rng io.Reader, ekPub []byte, objectName []byte, secret []byte) (credentialBlob, encryptedSecret []byte, err error) {
	if rng == nil {
		rng = rand.Reader
	}
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](ekPub)
	if err != nil {
		return nil, nil, fmt.Errorf("attest: EK public area does not parse: %w", err)
	}
	if err := checkEKPublic(pub); err != nil {
		return nil, nil, err
	}
	key, err := tpm2.ImportEncapsulationKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("attest: EK is not usable for MakeCredential: %w", err)
	}
	return tpm2.CreateCredential(rng, key, objectName, secret)
}

// checkEKPublic requires the attributes of a TCG EK: a restricted decryption
// key that cannot leave the TPM.
func checkEKPublic(pub *tpm2.TPMTPublic) error {
	a := pub.ObjectAttributes
	if !a.Restricted || !a.Decrypt || a.SignEncrypt || !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin {
		return fmt.Errorf("attest: EK attributes are not those of a restricted, non-duplicable decryption key")
	}
	return nil
}

// ValidateEKPublic parses and checks a marshalled EK public area.
func ValidateEKPublic(ekPub []byte) error {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](ekPub)
	if err != nil {
		return fmt.Errorf("attest: EK public area does not parse: %w", err)
	}
	return checkEKPublic(pub)
}
