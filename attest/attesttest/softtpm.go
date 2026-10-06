package attesttest

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/google/go-tpm/tpm2"

	"github.com/matthias/tpm2-kira/attest"
)

// SoftTPM is a software double of the TPM operations an attester needs: a
// restricted ECDSA AK producing real TPMS_ATTEST quotes, and an ECC EK whose
// ActivateCredential is reimplemented from TPM 2.0 Part 1 §24. It lets the
// whole protocol run without hardware; swtpm covers the real thing in the
// integration tests.
type SoftTPM struct {
	AKPriv     *ecdsa.PrivateKey
	AKPub      []byte
	AKName     []byte
	EKPriv     *ecdh.PrivateKey
	EKPub      []byte
	PCRs       map[uint8][]byte
	ResetCount uint32
	Firmware   uint64
	Safe       bool
	Evlog      []byte

	// TamperQuote, if set, edits each quote before it is signed.
	TamperQuote func(att *tpm2.TPMSAttest)
}

// NewSoftTPM creates a TPM double with fresh keys and distinct PCR values.
func NewSoftTPM() (*SoftTPM, error) {
	ak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := attest.AKTemplateECC()
	tmpl.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: ak.PublicKey.X.FillBytes(make([]byte, 32))},
		Y: tpm2.TPM2BECCParameter{Buffer: ak.PublicKey.Y.FillBytes(make([]byte, 32))},
	})
	name, err := tpm2.ObjectName(&tmpl)
	if err != nil {
		return nil, err
	}
	ek, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	raw := ek.PublicKey().Bytes() // 0x04 ‖ X ‖ Y
	ekT := attest.EKTemplateECC
	ekT.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: raw[1:33]},
		Y: tpm2.TPM2BECCParameter{Buffer: raw[33:65]},
	})
	s := &SoftTPM{
		AKPriv:     ak,
		AKPub:      tpm2.Marshal(tmpl),
		AKName:     name.Buffer,
		EKPriv:     ek,
		EKPub:      tpm2.Marshal(ekT),
		PCRs:       map[uint8][]byte{},
		ResetCount: 7,
		Firmware:   0x0001000200030004,
		Safe:       true,
		Evlog:      bytes.Repeat([]byte("event log "), 5000),
	}
	for i := uint8(0); i < attest.MaxPCRIndex; i++ {
		s.PCRs[i] = bytes.Repeat([]byte{i}, 32)
	}
	return s, nil
}

// Extend extends a PCR with the SHA-256 of data.
func (s *SoftTPM) Extend(idx uint8, data string) {
	h := sha256.New()
	h.Write(s.PCRs[idx])
	d := sha256.Sum256([]byte(data))
	h.Write(d[:])
	s.PCRs[idx] = h.Sum(nil)
}

// Quote implements attest.AttesterBackend.
func (s *SoftTPM) Quote(qd []byte, sel attest.PCRSelection) (*attest.QuoteResult, error) {
	var vals []attest.PCRValue
	for _, i := range sel.Indices {
		vals = append(vals, attest.PCRValue{Index: i, Digest: append([]byte(nil), s.PCRs[i]...)})
	}
	att := tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: s.AKName},
		ExtraData:       tpm2.TPM2BData{Buffer: qd},
		ClockInfo:       tpm2.TPMSClockInfo{Clock: 1234, ResetCount: s.ResetCount, Safe: tpm2.TPMIYesNo(s.Safe)},
		FirmwareVersion: s.Firmware,
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: sel.ToTPM(),
			PCRDigest: tpm2.TPM2BDigest{Buffer: attest.CompositeDigest(sel, vals)},
		}),
	}
	if s.TamperQuote != nil {
		s.TamperQuote(&att)
	}
	quoted := tpm2.Marshal(att)
	sig, err := s.sign(quoted)
	if err != nil {
		return nil, err
	}
	return &attest.QuoteResult{Quoted: quoted, Signature: sig, Values: vals}, nil
}

func (s *SoftTPM) sign(msg []byte) ([]byte, error) {
	d := sha256.Sum256(msg)
	r, ss, err := ecdsa.Sign(rand.Reader, s.AKPriv, d[:])
	if err != nil {
		return nil, err
	}
	return tpm2.Marshal(tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpm2.TPMAlgSHA256,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: r.FillBytes(make([]byte, 32))},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: ss.FillBytes(make([]byte, 32))},
		}),
	}), nil
}

// BootContext implements attest.AttesterBackend.
func (s *SoftTPM) BootContext() attest.BootContext {
	return attest.BootContext{BlobVersion: 8, NVRAMIndex: 0x01803010, SecureBootState: attest.SecureBootEnabled, SealPCRSelection: []uint8{0, 7}, UptimeMS: 4200}
}

// Eventlog implements attest.AttesterBackend.
func (s *SoftTPM) Eventlog() ([]byte, error) { return s.Evlog, nil }

// EKPublic implements attest.EnrolBackend.
func (s *SoftTPM) EKPublic() ([]byte, []byte, error) { return s.EKPub, nil, nil }

// ActivateCredential reverses tpm2.CreateCredential with the EK private key.
func (s *SoftTPM) ActivateCredential(idObject, encSecret []byte) ([]byte, error) {
	pt, err := tpm2.Unmarshal[tpm2.TPMSECCPoint](encSecret)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.P256().NewPublicKey(append([]byte{0x04}, append(pt.X.Buffer, pt.Y.Buffer...)...))
	if err != nil {
		return nil, err
	}
	z, err := s.EKPriv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	ekX := s.EKPriv.PublicKey().Bytes()[1:33]
	seed := tpm2.KDFe(crypto.SHA256, z, "IDENTITY", pt.X.Buffer, ekX, 256)

	if len(idObject) < 2 {
		return nil, errors.New("short id object")
	}
	hl := int(binary.BigEndian.Uint16(idObject))
	if len(idObject) < 2+hl {
		return nil, errors.New("short id object")
	}
	integrity, encIdentity := idObject[2:2+hl], idObject[2+hl:]
	mac := hmac.New(sha256.New, tpm2.KDFa(crypto.SHA256, seed, "INTEGRITY", nil, nil, 256))
	mac.Write(encIdentity)
	mac.Write(s.AKName)
	if !hmac.Equal(mac.Sum(nil), integrity) {
		return nil, errors.New("TPM_RC_INTEGRITY: credential not for this AK/EK")
	}
	block, err := aes.NewCipher(tpm2.KDFa(crypto.SHA256, seed, "STORAGE", s.AKName, nil, 128))
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(encIdentity))
	cipher.NewCFBDecrypter(block, make([]byte, 16)).XORKeyStream(plain, encIdentity)
	if len(plain) < 2 {
		return nil, errors.New("short credential")
	}
	n := int(binary.BigEndian.Uint16(plain))
	if len(plain) != 2+n {
		return nil, errors.New("bad credential length")
	}
	return plain[2:], nil
}

// SoftEnrol wraps SoftTPM into an attest.EnrolBackend with a scripted
// console and a commit sink.
type SoftEnrol struct {
	*SoftTPM
	SASAnswer    bool
	SASSeen      string
	Committed    *attest.EnrolledVerifier
	MeasurePoint []attest.PCRValue // boot-check values to offer; nil: none
}

// MeasurePointValues implements attest.MeasurePointProvider.
func (b *SoftEnrol) MeasurePointValues(attest.PCRSelection) ([]attest.PCRValue, error) {
	return b.MeasurePoint, nil
}

// ConfirmSAS implements attest.EnrolBackend.
func (b *SoftEnrol) ConfirmSAS(code string) (bool, error) {
	b.SASSeen = code
	return b.SASAnswer, nil
}

// Commit implements attest.EnrolBackend.
func (b *SoftEnrol) Commit(v attest.EnrolledVerifier) error {
	b.Committed = &v
	return nil
}

// EnrolBackendFunc lets a test wrap SoftEnrol in a modified backend.
type EnrolBackendFunc func(*SoftEnrol) attest.EnrolBackend

// Machine bundles a SoftTPM with the attester's identity, for tests that
// need a whole machine.
type Machine struct {
	TPM      *SoftTPM
	DeviceID []byte
	Noise    *attest.NoiseKeypair
	AdvKey   []byte
	Sel      attest.PCRSelection
	// MeasurePoint, when set, is offered as the values at the boot check.
	MeasurePoint []attest.PCRValue
	Verifier     *attest.EnrolledVerifier
}

// NewMachine creates a machine quoting PCRs 0, 2, 4 and 7.
func NewMachine() (*Machine, error) {
	tpm, err := NewSoftTPM()
	if err != nil {
		return nil, err
	}
	kp, err := attest.GenerateNoiseKeypair(nil)
	if err != nil {
		return nil, err
	}
	sel, _ := attest.NewPCRSelection(attest.AlgSHA256, []int{0, 2, 4, 7})
	id := make([]byte, attest.DeviceIDSize)
	adv := make([]byte, 32)
	rand.Read(id)
	rand.Read(adv)
	return &Machine{TPM: tpm, DeviceID: id, Noise: kp, AdvKey: adv, Sel: sel}, nil
}

// EnrolIdentity returns the identity offered at enrolment.
func (m *Machine) EnrolIdentity() *attest.EnrolIdentity {
	return &attest.EnrolIdentity{
		DeviceID: m.DeviceID, FriendlyName: "Thinkpad-X1", AKPub: m.TPM.AKPub, AKName: m.TPM.AKName,
		NoiseStatic: m.Noise, AdvKey: m.AdvKey, Selection: m.Sel, AppVersion: "test",
	}
}

// AttestIdentity returns the identity used after enrolment.
func (m *Machine) AttestIdentity() *attest.AttestIdentity {
	var vs []attest.EnrolledVerifier
	if m.Verifier != nil {
		vs = []attest.EnrolledVerifier{*m.Verifier}
	}
	return &attest.AttestIdentity{
		DeviceID: m.DeviceID, AKName: m.TPM.AKName, NoiseStatic: m.Noise,
		Verifiers: vs, AppVersion: "test", Capabilities: attest.CapEventlog,
	}
}

// ServeEnrolment runs the machine side of an enrolment on conn and records
// the pinned verifier.
func (m *Machine) ServeEnrolment(conn attest.Conn, sasAnswer bool) (*SoftEnrol, error) {
	be := &SoftEnrol{SoftTPM: m.TPM, SASAnswer: sasAnswer, MeasurePoint: m.MeasurePoint}
	v, err := attest.ServeEnrolment(conn, m.EnrolIdentity(), be, nil)
	if err == nil {
		m.Verifier = v
	}
	return be, err
}
