package attest

// The boot key: a key in the machine's TPM that works only while the boot is
// in a state the machine's signing key has approved - the same policy that
// lets the TPM compute the TOTP code.
//
// At every attestation the phone makes up a short code, encrypts it to that
// key and sends it along with its request. Only the TPM, in an approved boot
// state, can recover it. The machine shows the code on its screen and proves
// with a MAC that it could; the phone shows the code too, and the person
// compares the two before answering.
//
// This gives the session what a quote does not:
//
//   - the screen in front of the person belongs to the machine whose TPM
//     answered. A look-alike machine that forwards the Bluetooth session to
//     the real one cannot show the code;
//   - the TPM's own statement that this boot state is an approved one. A
//     quote lists the registers and leaves the judging to the phone.
//
// It deliberately does not replace the quote: when the key is refused, the
// quote still says what changed.
//
// Key agreement is ECDH on P-256 between a key the phone makes for one
// session and the boot key (TPM2_ECDH_ZGen on the machine). From the shared
// secret, HKDF-SHA256 derives a key that seals the code (AES-256-GCM) and a
// key for the proof (HMAC-SHA256). Both are bound to the session's
// qualifying data, as the quote is.
//
// The same key also signs (ECDSA, TPM2_Sign) the session's qualifying data
// and the digest of the quote: a signature anyone holding the pinned public
// key can verify, now or later, that says "this quote describes a boot state
// the machine's signing key approved". The key agreement is what ties the
// session to the screen; the signature is what can be shown to others.

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

const (
	// BootCodeLen is the number of characters of the code.
	BootCodeLen = 8
	// bootCodeAlphabet has 32 symbols that are hard to confuse on a screen
	// (no I, O, 0, 1), so a code carries 40 bits.
	bootCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

	bootPointSize  = 65 // uncompressed P-256 point
	bootSealedSize = BootCodeLen + 16
	bootProofSize  = sha256.Size

	labelBootKey   = "tpm2-kira/boot-key/v1"
	labelBootProof = "tpm2-kira/boot-proof/v1"
	labelBootSig   = "tpm2-kira/boot-signature/v1"
)

// Boot key states in Evidence.
const (
	BootKeyUnused  uint8 = 0 // the machine did not try (it was not asked)
	BootKeyProved  uint8 = 1 // the TPM released the key; the proof is attached
	BootKeyRefused uint8 = 2 // the TPM refused: this boot state is not an approved one
	BootKeyFailed  uint8 = 3 // the machine could not try (TPM or data error)
)

// BootKeyTemplate is the boot key's public area: a P-256 key that signs and
// agrees on keys (an unrestricted key with no fixed scheme may do both),
// cannot leave its TPM, and can be used under authPolicy only, never with
// a password.
func BootKeyTemplate(authPolicy []byte) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			Decrypt:             true,
			SignEncrypt:         true,
			NoDA:                true,
			// UserWithAuth deliberately not set: policy only.
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			CurveID:   tpm2.TPMECCNistP256,
			KDF:       tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}
}

// BootChallenge is what the phone sends: its key for this session and the
// sealed code.
type BootChallenge struct {
	EphemeralPub []byte // uncompressed P-256 point
	Sealed       []byte // AES-256-GCM(code)
}

// BootSecret is what the phone keeps to check the answer.
type BootSecret struct {
	Code string
	kMac []byte
	ctx  []byte
}

func bootKeys(z, ephemeralPub, bootKeyPub, context []byte) (kEnc, kMac []byte, err error) {
	info := append(append([]byte(labelBootKey), ephemeralPub...), bootKeyPub...)
	okm, err := hkdf.Key(sha256.New, z, context, string(info), 64)
	if err != nil {
		return nil, nil, err
	}
	return okm[:32], okm[32:], nil
}

func bootAEAD(kEnc []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(kEnc)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func bootProof(kMac, context []byte) []byte {
	m := hmac.New(sha256.New, kMac)
	m.Write([]byte(labelBootProof))
	m.Write(context)
	return m.Sum(nil)
}

// NewBootChallenge makes the phone's challenge for one session. bootKeyPub
// is the pinned boot key (uncompressed point), context the session's
// qualifying data.
func NewBootChallenge(rng io.Reader, bootKeyPub, context []byte) (*BootChallenge, *BootSecret, error) {
	pub, err := ecdh.P256().NewPublicKey(bootKeyPub)
	if err != nil {
		return nil, nil, fmt.Errorf("attest: pinned boot key is not a P-256 point: %w", err)
	}
	eph, err := ecdh.P256().GenerateKey(rng)
	if err != nil {
		return nil, nil, err
	}
	z, err := eph.ECDH(pub)
	if err != nil {
		return nil, nil, err
	}
	ephPub := eph.PublicKey().Bytes()
	kEnc, kMac, err := bootKeys(z, ephPub, bootKeyPub, context)
	if err != nil {
		return nil, nil, err
	}
	raw := make([]byte, BootCodeLen)
	if _, err := io.ReadFull(rng, raw); err != nil {
		return nil, nil, err
	}
	code := make([]byte, BootCodeLen)
	for i, b := range raw {
		code[i] = bootCodeAlphabet[int(b)%len(bootCodeAlphabet)] // 256 is a multiple of 32: no bias
	}
	aead, err := bootAEAD(kEnc)
	if err != nil {
		return nil, nil, err
	}
	// The key is used for this one message: a fixed nonce is safe.
	sealed := aead.Seal(nil, make([]byte, aead.NonceSize()), code, context)
	return &BootChallenge{EphemeralPub: ephPub, Sealed: sealed},
		&BootSecret{Code: string(code), kMac: kMac, ctx: append([]byte(nil), context...)}, nil
}

// OpenBootChallenge is the machine's side once its TPM has produced the
// shared secret z (the x coordinate from TPM2_ECDH_ZGen): it recovers the
// code and computes the proof.
func OpenBootChallenge(z, ephemeralPub, bootKeyPub, context, sealed []byte) (code string, proof []byte, err error) {
	if len(ephemeralPub) != bootPointSize || len(bootKeyPub) != bootPointSize || len(sealed) != bootSealedSize {
		return "", nil, fmt.Errorf("attest: boot challenge has the wrong shape")
	}
	kEnc, kMac, err := bootKeys(z, ephemeralPub, bootKeyPub, context)
	if err != nil {
		return "", nil, err
	}
	aead, err := bootAEAD(kEnc)
	if err != nil {
		return "", nil, err
	}
	plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), sealed, context)
	if err != nil {
		return "", nil, fmt.Errorf("attest: the boot challenge was not made for this key and session")
	}
	for _, c := range plain {
		if bytes.IndexByte([]byte(bootCodeAlphabet), c) < 0 {
			return "", nil, fmt.Errorf("attest: the boot challenge holds no code")
		}
	}
	return string(plain), bootProof(kMac, context), nil
}

// Check reports whether proof shows that the machine recovered the code.
func (s *BootSecret) Check(proof []byte) bool {
	return len(proof) == bootProofSize && hmac.Equal(proof, bootProof(s.kMac, s.ctx))
}

// BootAnswer is the machine's answer to a boot challenge: the proof that it
// recovered the code, and its signature over the session and the quote.
type BootAnswer struct {
	Proof     []byte
	Signature []byte // marshalled TPMT_SIGNATURE
}

// BootSignatureMessage is what the boot key signs: the session's qualifying
// data and the quote it goes with. TPM2_Sign receives its SHA-256.
func BootSignatureMessage(qd, quoteDigest []byte) []byte {
	return append(append([]byte(labelBootSig), qd...), quoteDigest...)
}

// BootKeyPublicKey turns the pinned point into a key for verifying.
func BootKeyPublicKey(point []byte) (*ecdsa.PublicKey, error) {
	if len(point) != bootPointSize || point[0] != 4 {
		return nil, fmt.Errorf("attest: boot key point has the wrong shape")
	}
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return nil, fmt.Errorf("attest: boot key point is not on the curve: %w", err)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(point[1:33]), Y: new(big.Int).SetBytes(point[33:])}, nil
}

// VerifyBootSignature checks the boot key's signature over this session and
// quote with the pinned point.
func VerifyBootSignature(point, qd, quoteDigest, sig []byte) error {
	pub, err := BootKeyPublicKey(point)
	if err != nil {
		return err
	}
	return VerifyTPMSignature(pub, BootSignatureMessage(qd, quoteDigest), sig)
}

// FormatBootCode groups a code for reading: "ABCD-EFGH".
func FormatBootCode(code string) string {
	if len(code) != BootCodeLen {
		return code
	}
	return code[:4] + "-" + code[4:]
}

// PolicyAuthorizeDigest is the policy digest of a key that is usable
// exactly when keyName has approved a policy for policyRef:
// H(H(0 ‖ TPM_CC_PolicyAuthorize ‖ keyName) ‖ policyRef) (TPM 2.0 Part 3,
// PolicyAuthorize). It is what the machine's TOTP key and boot key carry.
func PolicyAuthorizeDigest(keyName, policyRef []byte) []byte {
	cc := []byte{0, 0, 0x01, 0x6a} // TPM_CC_PolicyAuthorize
	inner := sha256.New()
	inner.Write(make([]byte, sha256.Size))
	inner.Write(cc)
	inner.Write(keyName)
	outer := sha256.New()
	outer.Write(inner.Sum(nil))
	outer.Write(policyRef)
	return outer.Sum(nil)
}

// BootKeyOffer is what the machine presents for its boot key at enrolment.
type BootKeyOffer struct {
	PubArea     []byte // TPMT_PUBLIC of the boot key
	CertifyInfo []byte // TPMS_ATTEST of TPM2_Certify by the AK
	CertifySig  []byte // TPMT_SIGNATURE over it
	SigningPub  []byte // TPMT_PUBLIC of the machine's signing key
	PolicyRef   []byte // the slot's policy reference
}

// CheckBootKey is the phone's check of the boot key at enrolment. The key
// must be what a relying party needs it to be - made inside this TPM, not
// exportable, for signing and key agreement, and only under a policy (never
// by a password); that policy must be "whatever the machine's signing key
// approves for this slot" (PolicyAuthorizeDigest); and the attestation key,
// which the phone has already tied to the TPM's endorsement key, must
// certify exactly that public area for this session. It returns the key's
// public point and the signing key's Name for pinning.
func CheckBootKey(akPub crypto.PublicKey, o *BootKeyOffer, qd []byte) (point, signingKeyName []byte, err error) {
	if o == nil {
		return nil, nil, fmt.Errorf("no boot key offered")
	}
	bootPubArea, certifyInfo, certifySig := o.PubArea, o.CertifyInfo, o.CertifySig
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](bootPubArea)
	if err != nil {
		return nil, nil, fmt.Errorf("boot key public area does not parse: %w", err)
	}
	a := pub.ObjectAttributes
	if !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || !a.Decrypt || !a.SignEncrypt || a.Restricted {
		return nil, nil, fmt.Errorf("boot key is not a non-duplicable signing and key-agreement key made inside the TPM")
	}
	if a.UserWithAuth {
		return nil, nil, fmt.Errorf("boot key can be used with a password instead of its policy")
	}
	if pub.NameAlg != tpm2.TPMAlgSHA256 || len(pub.AuthPolicy.Buffer) != sha256.Size {
		return nil, nil, fmt.Errorf("boot key carries no SHA-256 policy")
	}
	if pub.Type != tpm2.TPMAlgECC {
		return nil, nil, fmt.Errorf("boot key is not an ECC key")
	}
	parms, err := pub.Parameters.ECCDetail()
	if err != nil || parms.CurveID != tpm2.TPMECCNistP256 {
		return nil, nil, fmt.Errorf("boot key is not on P-256")
	}
	unique, err := pub.Unique.ECC()
	if err != nil || len(unique.X.Buffer) > 32 || len(unique.Y.Buffer) > 32 {
		return nil, nil, fmt.Errorf("boot key has no P-256 point")
	}
	point = make([]byte, bootPointSize)
	point[0] = 4
	copy(point[1+32-len(unique.X.Buffer):33], unique.X.Buffer)
	copy(point[33+32-len(unique.Y.Buffer):], unique.Y.Buffer)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return nil, nil, fmt.Errorf("boot key point is not on the curve: %w", err)
	}

	// The policy: nothing but the signing key's approvals for this slot.
	signingPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](o.SigningPub)
	if err != nil {
		return nil, nil, fmt.Errorf("signing key public area does not parse: %w", err)
	}
	signingName, err := tpm2.ObjectName(signingPub)
	if err != nil {
		return nil, nil, err
	}
	if len(o.PolicyRef) == 0 || len(o.PolicyRef) > 64 {
		return nil, nil, fmt.Errorf("the slot's policy reference has an invalid size")
	}
	if !bytes.Equal(pub.AuthPolicy.Buffer, PolicyAuthorizeDigest(signingName.Buffer, o.PolicyRef)) {
		return nil, nil, fmt.Errorf("the boot key's policy is not \"approved by the machine's signing key for this slot\"")
	}

	if err := VerifyTPMSignature(akPub, certifyInfo, certifySig); err != nil {
		return nil, nil, fmt.Errorf("boot key certification: %w", err)
	}
	att, err := tpm2.Unmarshal[tpm2.TPMSAttest](certifyInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("boot key certification does not parse: %w", err)
	}
	if att.Magic != tpm2.TPMGeneratedValue || att.Type != tpm2.TPMSTAttestCertify {
		return nil, nil, fmt.Errorf("boot key certification is not a TPM2_Certify statement")
	}
	if !bytes.Equal(att.ExtraData.Buffer, qd) {
		return nil, nil, fmt.Errorf("boot key certification is not bound to this session")
	}
	info, err := att.Attested.Certify()
	if err != nil {
		return nil, nil, fmt.Errorf("boot key certification: %w", err)
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(info.Name.Buffer, name.Buffer) {
		return nil, nil, fmt.Errorf("the attestation key certified another key than the boot key offered")
	}
	return point, signingName.Buffer, nil
}
