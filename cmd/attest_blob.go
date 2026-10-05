package cmd

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/matthias/tpm2-kira/attest"
)

// The attestation blob: a second NV object per slot, separate from the sealed
// blob because it has a different lifecycle — enrolment changes it, sealing
// does not (PLAN-REMOTEATTESTATION.md §10.1).
//
// It reuses the sealed blob's conventions: little-endian length prefixes, an
// explicit maximum on every variable-length field, a detached signature by the
// signing key over [version ‖ payloadLen ‖ payload], NV writes authorised by
// PolicySigned with the same key, and no migration between versions.
//
// Nothing in it is secret in the sense the sealed blob's seed is:
//
//   - the AK private area is wrapped by this TPM's storage hierarchy and
//     useless anywhere else;
//   - the Noise static key and the advertising key identify the machine's
//     *transport* endpoint. Someone who reads them (root, or anyone booting
//     another OS on this machine) can impersonate the BLE endpoint, but cannot
//     produce a quote: quotes come from the TPM and are bound to the session by
//     the channel binding, and a TPM in a tampered state reports tampered PCRs.
//     The phone's verdict therefore never rests on these keys.

const (
	// AttestNVRAMStart is slot 0's attestation blob; slot N is at +N.
	AttestNVRAMStart = 0x01803020
	// AttestNVRAMEnd is slot 15's attestation blob.
	AttestNVRAMEnd = 0x0180302F

	// AttestBlobVersion is the only supported attestation blob format.
	AttestBlobVersion = 1

	// MaxVerifiers bounds the pinned verifier list. The format holds a list
	// from day one so a second phone needs no format change
	// (PLAN-REMOTEATTESTATION.md §15.5).
	MaxVerifiers = 8
)

var attestBlobMagic = []byte("KATT")

// AttestBlob is the attester's per-slot enrolment state.
type AttestBlob struct {
	AppVersion   string
	DeviceID     []byte // 16 bytes, random, assigned at first enrolment
	FriendlyName string
	AKPublic     []byte // marshalled TPMT_PUBLIC
	AKPrivate    []byte // TPM2B_PRIVATE contents, wrapped by the storage primary
	AKName       []byte
	EKAlg        uint16 // TPM_ALG_ECC or TPM_ALG_RSA: which EK template enrolment used
	NoisePrivate []byte // 32 bytes
	AdvKey       []byte // 32 bytes
	PCRAlg       uint16
	PCRSelection []uint8
	Verifiers    []attest.EnrolledVerifier
	Signature    []byte
}

// AttestIndexForSlot maps a sealed-blob index (or slot number) to the
// attestation index of the same slot.
func AttestIndexForSlot(sealIndex uint32) (uint32, error) {
	idx := ResolveNVRAMIndex(sealIndex)
	if idx < NVRAMSlotStart || idx > NVRAMSlotEnd {
		return 0, fmt.Errorf("attestation needs a slot in the default range (0-15), got 0x%08X", idx)
	}
	return AttestNVRAMStart + (idx - NVRAMSlotStart), nil
}

type blobWriter struct{ b bytes.Buffer }

func (w *blobWriter) u8(v uint8)   { w.b.WriteByte(v) }
func (w *blobWriter) u16(v uint16) { binary.Write(&w.b, binary.LittleEndian, v) }
func (w *blobWriter) raw(v []byte) { w.b.Write(v) }
func (w *blobWriter) lp16(v []byte) {
	w.u16(uint16(len(v)))
	w.b.Write(v)
}
func (w *blobWriter) lp32(v []byte) {
	binary.Write(&w.b, binary.LittleEndian, uint32(len(v)))
	w.b.Write(v)
}

type blobReader struct {
	b   []byte
	off int
	err error
}

func (r *blobReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b)-r.off < n {
		r.err = fmt.Errorf("attestation blob truncated at offset %d", r.off)
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return append([]byte(nil), v...)
}

func (r *blobReader) u8() uint8 {
	v := r.take(1)
	if v == nil {
		return 0
	}
	return v[0]
}

func (r *blobReader) u16() uint16 {
	v := r.take(2)
	if v == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(v)
}

func (r *blobReader) lp16(max int) []byte {
	n := int(r.u16())
	if r.err == nil && n > max {
		r.err = fmt.Errorf("attestation blob field of %d bytes exceeds %d", n, max)
		return nil
	}
	return r.take(n)
}

func (r *blobReader) lp32(max int) []byte {
	v := r.take(4)
	if v == nil {
		return nil
	}
	n := binary.LittleEndian.Uint32(v)
	if uint64(n) > uint64(max) {
		r.err = fmt.Errorf("attestation blob field of %d bytes exceeds %d", n, max)
		return nil
	}
	return r.take(int(n))
}

func (b *AttestBlob) marshalPayload() ([]byte, error) {
	if len(b.DeviceID) != attest.DeviceIDSize || len(b.NoisePrivate) != 32 || len(b.AdvKey) != 32 {
		return nil, fmt.Errorf("attestation blob is incomplete")
	}
	if len(b.Verifiers) > MaxVerifiers {
		return nil, fmt.Errorf("at most %d verifiers can be enrolled per slot", MaxVerifiers)
	}
	w := &blobWriter{}
	w.raw(attestBlobMagic)
	w.lp16([]byte(b.AppVersion))
	w.raw(b.DeviceID)
	w.lp16([]byte(b.FriendlyName))
	w.lp32(b.AKPublic)
	w.lp32(b.AKPrivate)
	w.lp16(b.AKName)
	w.u16(b.EKAlg)
	w.raw(b.NoisePrivate)
	w.raw(b.AdvKey)
	w.u16(b.PCRAlg)
	w.lp16(b.PCRSelection)
	w.u8(uint8(len(b.Verifiers)))
	for _, v := range b.Verifiers {
		if len(v.NoisePub) != 32 {
			return nil, fmt.Errorf("verifier %q has an invalid Noise key", v.ID)
		}
		w.lp16([]byte(v.ID))
		w.lp16([]byte(v.Name))
		w.lp16(v.AnchorPub)
		w.raw(v.NoisePub)
		w.lp16([]byte(v.PolicyID))
	}
	return w.b.Bytes(), nil
}

// Marshal returns the unsigned envelope [version ‖ payloadLen ‖ payload],
// ready for SignBlobPayload.
func (b *AttestBlob) Marshal() ([]byte, error) {
	p, err := b.marshalPayload()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8, 8+len(p))
	binary.LittleEndian.PutUint32(out, AttestBlobVersion)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(p)))
	return append(out, p...), nil
}

// UnmarshalAttestBlob parses a signed attestation blob. The signature is
// read but not verified here: the initrd has no copy of the signing key.
func UnmarshalAttestBlob(data []byte) (*AttestBlob, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("attestation blob too short")
	}
	if v := binary.LittleEndian.Uint32(data); v != AttestBlobVersion {
		return nil, fmt.Errorf("attestation blob version %d is not supported (requires %d); enrol again with: tpm2-kira attest enrol", v, AttestBlobVersion)
	}
	plen := binary.LittleEndian.Uint32(data[4:])
	if uint64(plen)+8 > uint64(len(data)) {
		return nil, fmt.Errorf("attestation blob payload truncated")
	}
	r := &blobReader{b: data[8 : 8+plen]}
	if m := r.take(4); !bytes.Equal(m, attestBlobMagic) {
		return nil, fmt.Errorf("NV index does not hold an attestation blob")
	}
	b := &AttestBlob{}
	b.AppVersion = string(r.lp16(MaxAppVersionLen))
	b.DeviceID = r.take(attest.DeviceIDSize)
	b.FriendlyName = string(r.lp16(64))
	b.AKPublic = r.lp32(4096)
	b.AKPrivate = r.lp32(4096)
	b.AKName = r.lp16(68)
	b.EKAlg = r.u16()
	b.NoisePrivate = r.take(32)
	b.AdvKey = r.take(32)
	b.PCRAlg = r.u16()
	b.PCRSelection = r.lp16(attest.MaxPCRIndex)
	n := int(r.u8())
	if r.err == nil && n > MaxVerifiers {
		return nil, fmt.Errorf("attestation blob lists %d verifiers, maximum %d", n, MaxVerifiers)
	}
	for i := 0; i < n && r.err == nil; i++ {
		v := attest.EnrolledVerifier{
			ID:        string(r.lp16(64)),
			Name:      string(r.lp16(64)),
			AnchorPub: r.lp16(256),
			NoisePub:  r.take(32),
			PolicyID:  string(r.lp16(64)),
		}
		b.Verifiers = append(b.Verifiers, v)
	}
	if r.err != nil {
		return nil, r.err
	}
	if r.off != len(r.b) {
		return nil, fmt.Errorf("attestation blob has %d trailing bytes", len(r.b)-r.off)
	}
	tr := &blobReader{b: data[8+plen:]}
	b.Signature = tr.lp16(MaxBlobSignatureLen)
	if tr.err != nil || len(b.Signature) == 0 {
		return nil, fmt.Errorf("attestation blob is not signed")
	}
	return b, nil
}

// Selection returns the PCR selection the slot was enrolled with.
func (b *AttestBlob) Selection() (attest.PCRSelection, error) {
	s := attest.PCRSelection{Alg: b.PCRAlg, Indices: b.PCRSelection}
	return s, s.Validate()
}

// UpsertVerifier adds v, replacing an existing entry with the same ID.
func (b *AttestBlob) UpsertVerifier(v attest.EnrolledVerifier) error {
	for i := range b.Verifiers {
		if b.Verifiers[i].ID == v.ID {
			b.Verifiers[i] = v
			return nil
		}
	}
	if len(b.Verifiers) >= MaxVerifiers {
		return fmt.Errorf("slot already has %d verifiers enrolled", MaxVerifiers)
	}
	b.Verifiers = append(b.Verifiers, v)
	return nil
}
