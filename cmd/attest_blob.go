package cmd

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/matthias/tpm2-kira/attest"
)

// The remote-attestation part of a slot's blob.
//
// A slot's blob (blob.go) always holds a TOTP key. Remote attestation is
// optional, and how a verifier reaches the machine is a choice within it:
//
//	Attestation      the machine as an attester: its identity for verifiers,
//	                 the attestation key in the TPM, the PCRs that are
//	                 quoted, and the count that says the part is current
//	  methods        who may ask for a quote, and over what. Each method is
//	                 a typed, length-prefixed block of its own:
//	    1  phone     phones over Bluetooth LE (the Kira app)
//
// A further method - a verification server reached over the network, say -
// is another type next to the phone, with its own data, and uses the same
// attestation key, selection and count. The layout is documented in
// docs/SECURITY-BACKGROUND.md §10 and follows the blob's conventions:
// little-endian length prefixes and an explicit maximum on every
// variable-length field.

const (
	// attestCounterStart is slot 0's record counter; slot N is at +N
	// (attest_counter.go).
	attestCounterStart = 0x01803820

	// MaxVerifiers bounds the phones of one slot.
	MaxVerifiers = 8

	// MaxAttestationLen bounds the attestation part of a slot's blob.
	MaxAttestationLen = 16 * 1024

	// Attestation methods, as they are numbered in the blob.
	attestMethodPhone = 1
)

// Attestation is the optional remote-attestation part of a slot's blob.
type Attestation struct {
	AppVersion   string
	DeviceID     []byte // 16 bytes, random, assigned at first enrolment
	FriendlyName string // the machine's name as verifiers show it
	AKPublic     []byte // marshalled TPMT_PUBLIC
	AKPrivate    []byte // TPM2B_PRIVATE contents, wrapped by the storage primary
	AKName       []byte
	EKAlg        uint16 // TPM_ALG_ECC or TPM_ALG_RSA: which EK template enrolment used
	// The boot key (bootkey.go): usable only under the slot's policy.
	BootKeyPublic  []byte // marshalled TPMT_PUBLIC
	BootKeyPrivate []byte // TPM2B_PRIVATE contents, wrapped by the storage primary
	// The release key (factor.go): the object a wrapped factor is made
	// for, under the slot's policy plus PolicyCommandCode(ActivateCredential).
	ReleaseKeyPublic  []byte // marshalled TPMT_PUBLIC
	ReleaseKeyPrivate []byte // TPM2B_PRIVATE contents, wrapped by the storage primary
	PCRAlg            uint16
	PCRSelection      []uint8
	// Count is the revision of the attestation part: the value of the
	// slot's TPM counter when the part was last changed (attest_counter.go).
	// It does not count attestations; it moves when verifiers are added or
	// removed. It is signed with the rest of the blob: the part is current
	// only while it equals the counter, which nobody can turn back.
	Count uint64

	// The methods. Only one kind exists so far.
	Phone PhoneAttestation
}

// PhoneAttestation is the method "phones over Bluetooth LE": the keys of
// the channel and the phones that may use it. The zero value is "not set up".
type PhoneAttestation struct {
	NoisePrivate []byte // 32 bytes: the machine's static key of the encrypted channel
	AdvKey       []byte // 32 bytes: lets an enrolled phone recognise the advertising
	Verifiers    []attest.EnrolledVerifier
}

// Enabled reports whether the method is set up.
func (p *PhoneAttestation) Enabled() bool { return len(p.NoisePrivate) != 0 }

// AttestIndexForSlot resolves a slot number or index to the NV index of the
// slot's blob, where its attestation part lives. Attestation needs one of
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
		r.err = fmt.Errorf("attestation data truncated at offset %d", r.off)
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
		r.err = fmt.Errorf("attestation field of %d bytes exceeds %d", n, max)
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
		r.err = fmt.Errorf("attestation field of %d bytes exceeds %d", n, max)
		return nil
	}
	return r.take(int(n))
}

// marshal encodes the attestation part of a slot's blob.
func (b *Attestation) marshal() ([]byte, error) {
	if len(b.DeviceID) != attest.DeviceIDSize {
		return nil, fmt.Errorf("attestation data is incomplete")
	}
	w := &blobWriter{}
	w.lp16([]byte(b.AppVersion))
	w.raw(b.DeviceID)
	w.lp16([]byte(b.FriendlyName))
	w.lp32(b.AKPublic)
	w.lp32(b.AKPrivate)
	w.lp16(b.AKName)
	w.u16(b.EKAlg)
	w.lp32(b.BootKeyPublic)
	w.lp32(b.BootKeyPrivate)
	w.lp32(b.ReleaseKeyPublic)
	w.lp32(b.ReleaseKeyPrivate)
	w.u16(b.PCRAlg)
	w.lp16(b.PCRSelection)
	w.u64(b.Count)

	// The methods: [count:1] then per method [type:1][len:4][data].
	var methods [][2][]byte
	if b.Phone.Enabled() {
		data, err := b.Phone.marshal()
		if err != nil {
			return nil, err
		}
		methods = append(methods, [2][]byte{{attestMethodPhone}, data})
	}
	w.u8(uint8(len(methods)))
	for _, m := range methods {
		w.u8(m[0][0])
		w.lp32(m[1])
	}
	return w.b.Bytes(), nil
}

func (p *PhoneAttestation) marshal() ([]byte, error) {
	if len(p.NoisePrivate) != 32 || len(p.AdvKey) != 32 {
		return nil, fmt.Errorf("the phone method's keys are incomplete")
	}
	if len(p.Verifiers) > MaxVerifiers {
		return nil, fmt.Errorf("at most %d phones can be enrolled per slot", MaxVerifiers)
	}
	w := &blobWriter{}
	w.raw(p.NoisePrivate)
	w.raw(p.AdvKey)
	w.u8(uint8(len(p.Verifiers)))
	for _, v := range p.Verifiers {
		if len(v.NoisePub) != 32 {
			return nil, fmt.Errorf("phone %q has an invalid Noise key", v.ID)
		}
		w.lp16([]byte(v.ID))
		w.lp16([]byte(v.Name))
		w.lp16(v.AnchorPub)
		w.raw(v.NoisePub)
		w.lp16([]byte(v.PolicyID))
	}
	return w.b.Bytes(), nil
}

// unmarshalAttestation parses the attestation part of a slot's blob. It
// carries no signature of its own: the blob's covers it.
func unmarshalAttestation(data []byte) (*Attestation, error) {
	r := &blobReader{b: data}
	b := &Attestation{}
	b.AppVersion = string(r.lp16(MaxAppVersionLen))
	b.DeviceID = r.take(attest.DeviceIDSize)
	b.FriendlyName = string(r.lp16(64))
	b.AKPublic = r.lp32(4096)
	b.AKPrivate = r.lp32(4096)
	b.AKName = r.lp16(68)
	b.EKAlg = r.u16()
	b.BootKeyPublic = r.lp32(4096)
	b.BootKeyPrivate = r.lp32(4096)
	b.ReleaseKeyPublic = r.lp32(4096)
	b.ReleaseKeyPrivate = r.lp32(4096)
	b.PCRAlg = r.u16()
	b.PCRSelection = r.lp16(attest.MaxPCRIndex)
	b.Count = r.u64()
	n := int(r.u8())
	seen := map[uint8]bool{}
	for i := 0; i < n && r.err == nil; i++ {
		kind := r.u8()
		body := r.lp32(MaxAttestationLen)
		if r.err != nil {
			break
		}
		if seen[kind] {
			return nil, fmt.Errorf("attestation method %d appears twice", kind)
		}
		seen[kind] = true
		switch kind {
		case attestMethodPhone:
			if err := b.Phone.unmarshal(body); err != nil {
				return nil, err
			}
		default:
			// Carrying over a method this build cannot read would mean
			// signing it again unseen on the next reseal.
			return nil, fmt.Errorf("attestation method %d is not known to this version of tpm2-kira", kind)
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	if r.off != len(r.b) {
		return nil, fmt.Errorf("attestation data has %d trailing bytes", len(r.b)-r.off)
	}
	return b, nil
}

func (p *PhoneAttestation) unmarshal(data []byte) error {
	r := &blobReader{b: data}
	p.NoisePrivate = r.take(32)
	p.AdvKey = r.take(32)
	n := int(r.u8())
	if r.err == nil && n > MaxVerifiers {
		return fmt.Errorf("the blob lists %d phones, maximum %d", n, MaxVerifiers)
	}
	for i := 0; i < n && r.err == nil; i++ {
		p.Verifiers = append(p.Verifiers, attest.EnrolledVerifier{
			ID:        string(r.lp16(64)),
			Name:      string(r.lp16(64)),
			AnchorPub: r.lp16(256),
			NoisePub:  r.take(32),
			PolicyID:  string(r.lp16(64)),
		})
	}
	if r.err != nil {
		return r.err
	}
	if r.off != len(r.b) {
		return fmt.Errorf("the phone method has %d trailing bytes", len(r.b)-r.off)
	}
	return nil
}

// Selection returns the PCR selection the slot was enrolled with.
func (b *Attestation) Selection() (attest.PCRSelection, error) {
	s := attest.PCRSelection{Alg: b.PCRAlg, Indices: b.PCRSelection}
	return s, s.Validate()
}

// UpsertVerifier adds the phone v, replacing an entry with the same ID.
func (b *Attestation) UpsertVerifier(v attest.EnrolledVerifier) error {
	for i := range b.Phone.Verifiers {
		if b.Phone.Verifiers[i].ID == v.ID {
			b.Phone.Verifiers[i] = v
			return nil
		}
	}
	if len(b.Phone.Verifiers) >= MaxVerifiers {
		return fmt.Errorf("slot already has %d phones enrolled", MaxVerifiers)
	}
	b.Phone.Verifiers = append(b.Phone.Verifiers, v)
	return nil
}

// attestationJSON is the attestation part as 'info --json' shows it: what
// identifies the machine and its verifiers. The channel and advertising
// keys and the attestation key's private area are left out.
type attestationJSON struct {
	AppVersion   string             `json:"app_version"`
	DeviceID     string             `json:"device_id"`
	FriendlyName string             `json:"friendly_name"`
	AKName       string             `json:"ak_name"`
	AKPublic     string             `json:"ak_public_hex"`
	EKAlg        string             `json:"ek_alg"`
	BootKey      string             `json:"boot_key_public_hex"`
	PCRSelection string             `json:"pcr_selection"`
	Revision     uint64             `json:"revision"` // changes with the verifiers, not with attestations
	Methods      attestationMethods `json:"methods"`
}

type attestationMethods struct {
	Phone *phoneMethodJSON `json:"phone,omitempty"`
}

type phoneMethodJSON struct {
	Transport string           `json:"transport"`
	Verifiers []phoneEntryJSON `json:"verifiers"`
}

type phoneEntryJSON struct {
	ID           string `json:"id"`
	Name         string `json:"name,omitempty"`
	PolicyID     string `json:"policy_id,omitempty"`
	AnchorDigest string `json:"anchor_digest"`
	NoisePublic  string `json:"noise_public_hex"`
}

func (b *Attestation) json() *attestationJSON {
	if b == nil {
		return nil
	}
	sel, _ := b.Selection()
	out := &attestationJSON{
		AppVersion:   b.AppVersion,
		DeviceID:     hex.EncodeToString(b.DeviceID),
		FriendlyName: b.FriendlyName,
		AKName:       hex.EncodeToString(b.AKName),
		AKPublic:     hex.EncodeToString(b.AKPublic),
		EKAlg:        ekAlgName(b.EKAlg),
		BootKey:      hex.EncodeToString(b.BootKeyPublic),
		PCRSelection: sel.String(),
		Revision:     b.Count,
	}
	if b.Phone.Enabled() {
		m := &phoneMethodJSON{Transport: "bluetooth-le", Verifiers: []phoneEntryJSON{}}
		for _, v := range b.Phone.Verifiers {
			m.Verifiers = append(m.Verifiers, phoneEntryJSON{
				ID: v.ID, Name: v.Name, PolicyID: v.PolicyID,
				AnchorDigest: hex.EncodeToString(attest.AnchorDigest(v.AnchorPub)),
				NoisePublic:  hex.EncodeToString(v.NoisePub),
			})
		}
		out.Methods.Phone = m
	}
	return out
}
