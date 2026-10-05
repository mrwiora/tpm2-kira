package attest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
)

// Canonical, domain-separated byte strings that are hashed or signed.
// PLAN-REMOTEATTESTATION.md §6.3: nothing is ever signed via its transport
// encoding. Every string here starts with a label that names its purpose and
// version, and every variable-length part is length-prefixed with lp().

const (
	labelQD           = "tpm2-kira/qd/v1"
	labelEnrolQD      = "tpm2-kira/enrol-qd/v1"
	labelOfflineQD    = "tpm2-kira/offline-qd/v1"
	labelReceipt      = "tpm2-kira/receipt/v1"
	labelEnrolAccept  = "tpm2-kira/enrol-accept/v1"
	labelSASCommit    = "tpm2-kira/sas-commit/v1"
	labelSAS          = "tpm2-kira/sas/v1"
	labelAdvertising  = "tpm2-kira/adv/v1"
	labelFactor       = "tpm2-kira/factor/v1"
	labelAnchorDigest = "tpm2-kira/anchor/v1"
)

// NonceSize is the size of every protocol nonce.
const NonceSize = 32

// DeviceIDSize is the size of a device identifier.
const DeviceIDSize = 16

// lp is u32le(len(x)) ‖ x, as in cmd/blob.go.
func lp(x []byte) []byte {
	out := make([]byte, 4+len(x))
	binary.LittleEndian.PutUint32(out, uint32(len(x)))
	copy(out[4:], x)
	return out
}

func u64le(v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b[:]
}

// PCRSelection is one bank and a set of PCR indices.
type PCRSelection struct {
	Alg     uint16  // TPM_ALG_SHA256 (0x000B) or TPM_ALG_SHA1 (0x0004)
	Indices []uint8 // strictly ascending, each < MaxPCRIndex
}

// MaxPCRIndex bounds PCR indices; a PC-client TPM has 24 PCRs.
const MaxPCRIndex = 24

// TPM algorithm identifiers used by the protocol.
const (
	AlgSHA1   uint16 = 0x0004
	AlgSHA256 uint16 = 0x000B
)

// DigestSize returns the digest size of a PCR bank algorithm, or 0 if unsupported.
func DigestSize(alg uint16) int {
	switch alg {
	case AlgSHA1:
		return 20
	case AlgSHA256:
		return 32
	}
	return 0
}

// NewPCRSelection builds a validated selection from arbitrary-order indices.
func NewPCRSelection(alg uint16, indices []int) (PCRSelection, error) {
	if DigestSize(alg) == 0 {
		return PCRSelection{}, fmt.Errorf("attest: unsupported PCR bank 0x%04x", alg)
	}
	seen := map[int]bool{}
	var out []uint8
	for _, i := range indices {
		if i < 0 || i >= MaxPCRIndex {
			return PCRSelection{}, fmt.Errorf("attest: PCR index %d out of range", i)
		}
		if !seen[i] {
			seen[i] = true
			out = append(out, uint8(i))
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	if len(out) == 0 {
		return PCRSelection{}, fmt.Errorf("attest: empty PCR selection")
	}
	return PCRSelection{Alg: alg, Indices: out}, nil
}

// Validate checks bank, range and strict ordering.
func (s PCRSelection) Validate() error {
	if DigestSize(s.Alg) == 0 {
		return fmt.Errorf("attest: unsupported PCR bank 0x%04x", s.Alg)
	}
	if len(s.Indices) == 0 {
		return fmt.Errorf("attest: empty PCR selection")
	}
	for i, idx := range s.Indices {
		if idx >= MaxPCRIndex {
			return fmt.Errorf("attest: PCR index %d out of range", idx)
		}
		if i > 0 && idx <= s.Indices[i-1] {
			return fmt.Errorf("attest: PCR selection not strictly ascending")
		}
	}
	return nil
}

// Equal compares two selections.
func (s PCRSelection) Equal(o PCRSelection) bool {
	if s.Alg != o.Alg || len(s.Indices) != len(o.Indices) {
		return false
	}
	for i := range s.Indices {
		if s.Indices[i] != o.Indices[i] {
			return false
		}
	}
	return true
}

// canonical is u16le(alg) ‖ u8(n) ‖ indices.
func (s PCRSelection) canonical() []byte {
	out := make([]byte, 3, 3+len(s.Indices))
	binary.LittleEndian.PutUint16(out, s.Alg)
	out[2] = uint8(len(s.Indices))
	return append(out, s.Indices...)
}

// QualifyingData computes the value passed as TPM2_Quote's qualifyingData:
//
//	qd := SHA-256("tpm2-kira/qd/v1" ‖ nonce_a ‖ nonce_v ‖ cb ‖ u16le(alg) ‖ u8(n) ‖ indices)
//
// nonce_a, nonce_v and cb are fixed at 32 bytes each.
func QualifyingData(nonceA, nonceV, cb []byte, sel PCRSelection) ([]byte, error) {
	if len(nonceA) != NonceSize || len(nonceV) != NonceSize || len(cb) != NoiseKeySize {
		return nil, fmt.Errorf("attest: qualifying data inputs have wrong sizes")
	}
	h := sha256.New()
	h.Write([]byte(labelQD))
	h.Write(nonceA)
	h.Write(nonceV)
	h.Write(cb)
	h.Write(sel.canonical())
	return h.Sum(nil), nil
}

// EnrolQualifyingData is the qualifying data of the quote carried in
// EnrolOffer: SHA-256("tpm2-kira/enrol-qd/v1" ‖ cb). It binds the baseline
// quote to the enrolment session.
func EnrolQualifyingData(cb []byte) []byte {
	h := sha256.New()
	h.Write([]byte(labelEnrolQD))
	h.Write(cb)
	return h.Sum(nil)
}

// OfflineQualifyingData is used by `attest quote` / `attest verify`, where
// evidence is carried on a stick instead of a session:
// SHA-256("tpm2-kira/offline-qd/v1" ‖ nonce). The nonce is chosen by whoever
// will verify, so the quote is fresh for them; there is no channel to bind.
func OfflineQualifyingData(nonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte(labelOfflineQD))
	h.Write(nonce)
	return h.Sum(nil)
}

// Verdict codes carried in a receipt.
type VerdictCode uint8

const (
	// VerdictOK: the evidence matched a known-good profile.
	VerdictOK VerdictCode = 1
	// VerdictApproved: the evidence did not match, a human reviewed the
	// difference on the phone and approved this boot.
	VerdictApproved VerdictCode = 2
	// VerdictReject: the verifier does not trust this boot. A reject may be
	// sent unsigned; believing a false "no" costs a check, never trust.
	VerdictReject VerdictCode = 3
	// VerdictBypass is reserved for the break-glass token of PLAN-BLE.md §7.6.
	VerdictBypass VerdictCode = 0x10
)

func (v VerdictCode) String() string {
	switch v {
	case VerdictOK:
		return "ok"
	case VerdictApproved:
		return "approved"
	case VerdictReject:
		return "reject"
	case VerdictBypass:
		return "bypass"
	}
	return fmt.Sprintf("verdict(%d)", uint8(v))
}

// Trusted reports whether the verdict lets the boot count as attested.
func (v VerdictCode) Trusted() bool { return v == VerdictOK || v == VerdictApproved }

// ReceiptTBS is the byte string a receipt signature covers:
//
//	"tpm2-kira/receipt/v1" ‖ u8(verdict) ‖ lp(device_id) ‖ lp(ak_name) ‖ lp(qd) ‖
//	lp(sha256(quoted)) ‖ lp(policy_id) ‖ u64le(issued_at) ‖ u64le(expires_at) ‖ lp(verifier_id)
//
// The signature is ECDSA P-256 over SHA-256(ReceiptTBS), DER-encoded: what
// Android's "SHA256withECDSA" and iOS's ecdsaSignatureMessageX962SHA256 produce
// when given these bytes.
func ReceiptTBS(r *Receipt) []byte {
	var b []byte
	b = append(b, labelReceipt...)
	b = append(b, byte(r.Verdict))
	b = append(b, lp(r.DeviceID)...)
	b = append(b, lp(r.AKName)...)
	b = append(b, lp(r.QD)...)
	b = append(b, lp(r.QuoteDigest)...)
	b = append(b, lp([]byte(r.PolicyID))...)
	b = append(b, u64le(r.IssuedAt)...)
	b = append(b, u64le(r.ExpiresAt)...)
	b = append(b, lp([]byte(r.VerifierID))...)
	return b
}

// EnrolAcceptTBS is what the anchor signature in EnrolAccept covers. It proves
// that the phone holds the anchor's private key and binds the anchor to this
// enrolment session:
//
//	"tpm2-kira/enrol-accept/v1" ‖ lp(device_id) ‖ lp(cb) ‖ lp(ak_name) ‖
//	lp(anchor_pub) ‖ lp(verifier_id) ‖ lp(policy_id)
func EnrolAcceptTBS(deviceID, cb, akName, anchorPub []byte, verifierID, policyID string) []byte {
	var b []byte
	b = append(b, labelEnrolAccept...)
	b = append(b, lp(deviceID)...)
	b = append(b, lp(cb)...)
	b = append(b, lp(akName)...)
	b = append(b, lp(anchorPub)...)
	b = append(b, lp([]byte(verifierID))...)
	b = append(b, lp([]byte(policyID))...)
	return b
}

// AnchorDigest identifies a pinned anchor: SHA-256("tpm2-kira/anchor/v1" ‖ anchor_pub).
func AnchorDigest(anchorPub []byte) []byte {
	h := sha256.New()
	h.Write([]byte(labelAnchorDigest))
	h.Write(anchorPub)
	return h.Sum(nil)
}

// SASCommitment is the machine's commitment to its SAS nonce:
// SHA-256("tpm2-kira/sas-commit/v1" ‖ cb ‖ nonce_m).
func SASCommitment(cb, nonceM []byte) []byte {
	h := sha256.New()
	h.Write([]byte(labelSASCommit))
	h.Write(cb)
	h.Write(nonceM)
	return h.Sum(nil)
}

// ShortAuthString derives the six-digit enrolment confirmation code:
//
//	d   := SHA-256("tpm2-kira/sas/v1" ‖ cb ‖ nonce_p ‖ nonce_m)
//	SAS := u32be(d[0:4]) mod 1_000_000, as six decimal digits with leading zeros
//
// Why the commit/reveal: an attacker in the middle runs two handshakes and so
// holds two different cb values. Without a commitment it could grind its
// ephemeral keys until both codes collide (10^6 X25519 operations take about
// a second). The machine commits to nonce_m before it sees nonce_p, and the
// phone sends nonce_p before it learns nonce_m, so in at least one of the two
// sessions the attacker must fix its inputs before seeing the other side's.
// Its chance of a matching pair is then 10^-6 per attempt, and every attempt
// needs the user to confirm.
func ShortAuthString(cb, nonceP, nonceM []byte) string {
	h := sha256.New()
	h.Write([]byte(labelSAS))
	h.Write(cb)
	h.Write(nonceP)
	h.Write(nonceM)
	d := h.Sum(nil)
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(d[:4])%1000000)
}

// Advertising: the machine's scan response carries 13 bytes of service data
// for the tpm2-kira service UUID:
//
//	u8 flags ‖ prand[4] ‖ tag[8]
//	tag := HMAC-SHA256(adv_key, "tpm2-kira/adv/v1" ‖ prand)[0:8]
//
// prand is random per boot. Without adv_key the bytes are indistinguishable
// from random, so an observer learns that some tpm2-kira machine is booting,
// not which. An enrolled phone recomputes the tag for each machine it holds
// and knows which one is asking, before connecting.

// AdvFlag bits.
const (
	AdvFlagEnrol  uint8 = 0x01 // waiting for an enrolment; tag is all zero
	AdvFlagAttest uint8 = 0x02 // serving attestation requests
)

// AdvServiceDataSize is the size of the service data payload.
const AdvServiceDataSize = 13

// AdvertisingTag computes the 8-byte tag for prand.
func AdvertisingTag(advKey, prand []byte) []byte {
	return hmacSHA256(advKey, []byte(labelAdvertising), prand)[:8]
}

// BuildServiceData assembles the service data payload.
func BuildServiceData(flags uint8, prand, advKey []byte) []byte {
	out := make([]byte, AdvServiceDataSize)
	out[0] = flags
	copy(out[1:5], prand)
	if advKey != nil {
		copy(out[5:], AdvertisingTag(advKey, prand))
	}
	return out
}

// MatchServiceData reports whether service data was produced with advKey.
func MatchServiceData(sd, advKey []byte) bool {
	if len(sd) != AdvServiceDataSize || len(advKey) == 0 {
		return false
	}
	return hmac.Equal(sd[5:], AdvertisingTag(advKey, sd[1:5]))
}

// FactorFromSecret derives the factor line of PLAN-FACTORRELEASE.md §3 from F:
// HKDF-SHA256(ikm = F, salt = "", info = "tpm2-kira/factor/v1" ‖ lp(label), 32).
// Defined here so the derivation string is fixed in one place; the release
// path itself is not implemented yet.
func FactorFromSecret(f []byte, label string) []byte {
	// HKDF-Extract with an empty salt uses a zero key of hash length.
	prk := hmacSHA256(make([]byte, sha256.Size), f)
	info := append([]byte(labelFactor), lp([]byte(label))...)
	return hmacSHA256(prk, info, []byte{0x01})
}
