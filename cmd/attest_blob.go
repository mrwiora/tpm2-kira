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

	// attestSectionVersion is the format of the enrolment section inside a
	// slot's blob. (Versions 1 and 2 were NV indices of their own, at
	// AttestNVRAMStart + slot; those are no longer read.)
	attestSectionVersion = 3

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
	// Count is the value of the slot's TPM counter when the enrolment was
	// last changed (attest_counter.go). It is signed with the rest of the
	// slot's blob: an enrolment is current only while it equals the
	// counter, which nobody can turn back.
	Count uint64
}

// AttestIndexForSlot resolves a slot number or index to the NV index of the
// slot's blob, where its phone enrolment lives. Attestation needs one of
// the sixteen default slots: the record counter is found by slot number.
func AttestIndexForSlot(sealIndex uint32) (uint32, error) {
	idx := ResolveNVRAMIndex(sealIndex)
	if idx < NVRAMSlotStart || idx > NVRAMSlotEnd {
		return 0, fmt.Errorf("attestation needs a slot in the default range (0-15), got 0x%08X", idx)
	}
	return idx, nil
}

// attestSlot is the slot number of a slot's blob index.
func attestSlot(idx uint32) uint32 { return idx - NVRAMSlotStart }

// legacyAttestIndex is where earlier versions kept a slot's enrolment as an
// NV index of its own. Nothing reads those any more; they are only found
// to be reported and removed.
func legacyAttestIndex(idx uint32) uint32 { return AttestNVRAMStart + attestSlot(idx) }

type blobWriter struct{ b bytes.Buffer }

func (w *blobWriter) u8(v uint8)   { w.b.WriteByte(v) }
func (w *blobWriter) u16(v uint16) { binary.Write(&w.b, binary.LittleEndian, v) }
func (w *blobWriter) u64(v uint64) { binary.Write(&w.b, binary.LittleEndian, v) }
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

func (r *blobReader) u64() uint64 {
	v := r.take(8)
	if v == nil {
		return 0
	}
	return binary.LittleEndian.Uint64(v)
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

// marshalSection encodes the enrolment as the section of a slot's blob.
func (b *AttestBlob) marshalSection() ([]byte, error) {
	if len(b.DeviceID) != attest.DeviceIDSize || len(b.NoisePrivate) != 32 || len(b.AdvKey) != 32 {
		return nil, fmt.Errorf("attestation blob is incomplete")
	}
	if len(b.Verifiers) > MaxVerifiers {
		return nil, fmt.Errorf("at most %d verifiers can be enrolled per slot", MaxVerifiers)
	}
	w := &blobWriter{}
	w.raw(attestBlobMagic)
	w.u8(attestSectionVersion)
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
	w.u64(b.Count)
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

// unmarshalAttestSection parses the enrolment section of a slot's blob. It
// carries no signature of its own: the blob's covers it.
func unmarshalAttestSection(data []byte) (*AttestBlob, error) {
	r := &blobReader{b: data}
	if m := r.take(4); !bytes.Equal(m, attestBlobMagic) {
		return nil, fmt.Errorf("the slot's blob does not carry a phone enrolment where one is announced")
	}
	if v := r.u8(); r.err == nil && v != attestSectionVersion {
		return nil, fmt.Errorf("phone enrolment format %d is not supported (requires %d); enrol again with: tpm2-kira attest enrol", v, attestSectionVersion)
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
	b.Count = r.u64()
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
		return nil, fmt.Errorf("phone enrolment has %d trailing bytes", len(r.b)-r.off)
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
