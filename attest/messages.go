package attest

import (
	"fmt"
)

// Protocol messages. Field tags are part of the protocol definition
// (docs/PROTOCOL-BLE.md) and must never be renumbered.

// SchemaVersion is the protocol schema carried in Hello, Evidence and EnrolOffer.
const SchemaVersion = 2

// Size limits for variable-length fields.
const (
	maxName        = 68   // TPM2B_NAME: 2-byte alg + 64-byte digest, with headroom
	maxTPMPublic   = 1024 // marshalled TPMT_PUBLIC (RSA-2048 EK ~ 310 bytes)
	maxQuoted      = 1024 // TPMS_ATTEST of a quote
	maxTPMSig      = 600  // TPMT_SIGNATURE, RSA-4096 at most
	maxDERSig      = 128  // ECDSA P-256 DER signature
	maxEKCert      = 4096 // DER certificate
	maxShortString = 64
	maxMessageText = 256
	maxAnchorPub   = 256 // PKIX DER of an ECDSA P-256 key is 91 bytes
	maxCredential  = 1024
	maxPCRValues   = MaxPCRIndex
	// MaxEventlogChunk is the payload of one EventlogChunk.
	MaxEventlogChunk = 32768
	// MaxEventlogSize bounds a transferred event log.
	MaxEventlogSize = 1 << 20
)

// Capability bits in Hello.
const (
	CapEventlog          uint32 = 1 << 0
	CapReleaseFactor     uint32 = 1 << 1
	CapReleasePassphrase uint32 = 1 << 2
)

// Error codes carried in Error messages.
const (
	ErrCodeProtocol         uint16 = 1
	ErrCodeUnknownDevice    uint16 = 2
	ErrCodeNotEnrolled      uint16 = 3
	ErrCodeSASRejected      uint16 = 4
	ErrCodeTPM              uint16 = 5
	ErrCodeActivationFailed uint16 = 6
	ErrCodeStorage          uint16 = 7
	ErrCodePolicy           uint16 = 8
	ErrCodeTimeout          uint16 = 9
	ErrCodeUserAborted      uint16 = 10
	ErrCodeUnsupported      uint16 = 11
)

// SecureBootState values in BootContext.
const (
	SecureBootUnknown   uint8 = 0
	SecureBootEnabled   uint8 = 1
	SecureBootDisabled  uint8 = 2
	SecureBootSetupMode uint8 = 3
)

func checkNonce(name string, b []byte) error {
	if len(b) != NonceSize {
		return fmt.Errorf("attest: %s must be %d bytes", name, NonceSize)
	}
	return nil
}

func decodeSelection(d *Decoder, algTag, idxTag uint16) PCRSelection {
	alg := d.U16(algTag, true)
	idx := d.Bytes(idxTag, MaxPCRIndex, true)
	return PCRSelection{Alg: alg, Indices: idx}
}

// PCRValue is one PCR and its digest.
type PCRValue struct {
	Index  uint8
	Digest []byte
}

func encodePCRValues(vals []PCRValue) []byte {
	entries := make([][]byte, len(vals))
	for i, v := range vals {
		entries[i] = append([]byte{v.Index}, v.Digest...)
	}
	return EncodeList(entries)
}

func decodePCRValues(v []byte) ([]PCRValue, error) {
	entries, err := DecodeList(v, maxPCRValues, 1+64)
	if err != nil {
		return nil, err
	}
	out := make([]PCRValue, len(entries))
	for i, e := range entries {
		if len(e) < 2 {
			return nil, fmt.Errorf("attest: PCR value entry %d too short", i)
		}
		out[i] = PCRValue{Index: e[0], Digest: e[1:]}
	}
	return out, nil
}

// BootContext describes how the attester is configured. It is informational:
// nothing in it is covered by the TPM's signature, and the verifier never
// trusts it over the quote.
type BootContext struct {
	BlobVersion      uint32
	NVRAMIndex       uint32
	MeasurePoint     string
	SecureBootState  uint8
	SealPCRSelection []uint8
	UptimeMS         uint64
	// Where this boot measured the initrd, read from the attester's event
	// log: InitrdUnknown (field absent), InitrdMeasured with the PCRs, or
	// InitrdNone for a boot without an initrd.
	InitrdState uint8
	InitrdPCRs  []uint8
}

// InitrdState values in BootContext.
const (
	InitrdUnknown  = 0
	InitrdMeasured = 1
	InitrdNone     = 2
)

func (b *BootContext) encode() *Encoder {
	e := SubEncoder()
	e.U32(1, b.BlobVersion)
	e.U32(2, b.NVRAMIndex)
	e.String(3, b.MeasurePoint)
	e.U8(4, b.SecureBootState)
	e.Bytes(5, b.SealPCRSelection)
	e.U64(6, b.UptimeMS)
	if b.InitrdState != InitrdUnknown {
		e.U8(7, b.InitrdState)
		e.OptBytes(8, b.InitrdPCRs)
	}
	return e
}

func decodeBootContext(d *Decoder) BootContext {
	if d == nil {
		return BootContext{}
	}
	return BootContext{
		BlobVersion:      d.U32(1, false),
		NVRAMIndex:       d.U32(2, false),
		MeasurePoint:     d.String(3, 512, false),
		SecureBootState:  d.U8(4, false),
		SealPCRSelection: d.Bytes(5, MaxPCRIndex, false),
		UptimeMS:         d.U64(6, false),
		InitrdState:      d.U8(7, false),
		InitrdPCRs:       d.Bytes(8, MaxPCRIndex, false),
	}
}

// Hello opens an attestation session (attester -> verifier).
type Hello struct {
	Schema       uint16
	DeviceID     []byte
	NonceA       []byte
	Capabilities uint32
	AppVersion   string
}

// Encode serialises the message.
func (m *Hello) Encode() ([]byte, error) {
	e := NewEncoder(MsgHello)
	e.U16(1, m.Schema)
	e.Bytes(2, m.DeviceID)
	e.Bytes(3, m.NonceA)
	e.U32(4, m.Capabilities)
	e.String(5, m.AppVersion)
	return e.Finish()
}

// DecodeHello parses a Hello.
func DecodeHello(d *Decoder) (*Hello, error) {
	if err := d.Expect(MsgHello); err != nil {
		return nil, err
	}
	m := &Hello{
		Schema:       d.U16(1, true),
		DeviceID:     d.Fixed(2, DeviceIDSize, true),
		NonceA:       d.Fixed(3, NonceSize, true),
		Capabilities: d.U32(4, false),
		AppVersion:   d.String(5, maxShortString, false),
	}
	return m, d.Err()
}

// Request asks for a quote (verifier -> attester).
type Request struct {
	NonceV       []byte
	Selection    PCRSelection
	WantEventlog bool
	PolicyID     string
	// The boot challenge (bootkey.go): the phone's key for this session
	// and the code sealed to the machine's boot key.
	EphemeralPub []byte
	Sealed       []byte
}

// Encode serialises the message.
func (m *Request) Encode() ([]byte, error) {
	e := NewEncoder(MsgRequest)
	e.Bytes(1, m.NonceV)
	e.U16(2, m.Selection.Alg)
	e.Bytes(3, m.Selection.Indices)
	e.Bool(4, m.WantEventlog)
	e.String(5, m.PolicyID)
	e.Bytes(6, m.EphemeralPub)
	e.Bytes(7, m.Sealed)
	return e.Finish()
}

// DecodeRequest parses a Request.
func DecodeRequest(d *Decoder) (*Request, error) {
	if err := d.Expect(MsgRequest); err != nil {
		return nil, err
	}
	m := &Request{
		NonceV:       d.Fixed(1, NonceSize, true),
		Selection:    decodeSelection(d, 2, 3),
		WantEventlog: d.Bool(4, false),
		PolicyID:     d.String(5, maxShortString, false),
		EphemeralPub: d.Fixed(6, bootPointSize, true),
		Sealed:       d.Fixed(7, bootSealedSize, true),
	}
	if err := d.Err(); err != nil {
		return nil, err
	}
	return m, m.Selection.Validate()
}

// Evidence is the attester's answer to a Request (PLAN-REMOTEATTESTATION.md §5).
type Evidence struct {
	Schema         uint16
	DeviceID       []byte
	AKName         []byte
	Quoted         []byte // TPM2B_ATTEST contents: a marshalled TPMS_ATTEST
	Signature      []byte // marshalled TPMT_SIGNATURE
	PCRAlg         uint16
	PCRValues      []PCRValue
	EventlogSHA256 []byte // optional
	EventlogSize   uint32 // optional, 0 when unknown
	BootContext    BootContext
	AppVersion     string
	// BootKeyState says what the machine's TPM made of the boot challenge
	// (BootKey* constants); BootProof is present when it released the key.
	BootKeyState uint8
	BootProof    []byte
}

// Encode serialises the message.
func (m *Evidence) Encode() ([]byte, error) {
	e := NewEncoder(MsgEvidence)
	e.U16(1, m.Schema)
	e.Bytes(2, m.DeviceID)
	e.Bytes(3, m.AKName)
	e.Bytes(4, m.Quoted)
	e.Bytes(5, m.Signature)
	e.U16(6, m.PCRAlg)
	e.Bytes(7, encodePCRValues(m.PCRValues))
	e.OptBytes(8, m.EventlogSHA256)
	e.Sub(9, m.BootContext.encode())
	e.String(10, m.AppVersion)
	if m.EventlogSize > 0 {
		e.U32(11, m.EventlogSize)
	}
	e.U8(12, m.BootKeyState)
	e.OptBytes(13, m.BootProof)
	return e.Finish()
}

// DecodeEvidence parses an Evidence message.
func DecodeEvidence(d *Decoder) (*Evidence, error) {
	if err := d.Expect(MsgEvidence); err != nil {
		return nil, err
	}
	m := &Evidence{
		Schema:         d.U16(1, true),
		DeviceID:       d.Fixed(2, DeviceIDSize, true),
		AKName:         d.Bytes(3, maxName, true),
		Quoted:         d.Bytes(4, maxQuoted, true),
		Signature:      d.Bytes(5, maxTPMSig, true),
		PCRAlg:         d.U16(6, true),
		EventlogSHA256: d.Fixed(8, 32, false),
		BootContext:    decodeBootContext(d.Sub(9, 2048, false)),
		AppVersion:     d.String(10, maxShortString, false),
		EventlogSize:   d.U32(11, false),
		BootKeyState:   d.U8(12, false),
		BootProof:      d.Fixed(13, bootProofSize, false),
	}
	vals := d.Bytes(7, 2+maxPCRValues*(5+65), true)
	if err := d.Err(); err != nil {
		return nil, err
	}
	pv, err := decodePCRValues(vals)
	if err != nil {
		return nil, err
	}
	m.PCRValues = pv
	return m, nil
}

// EventlogRequest asks for the event log body (verifier -> attester).
type EventlogRequest struct {
	SHA256 []byte
	Offset uint32
}

// Encode serialises the message.
func (m *EventlogRequest) Encode() ([]byte, error) {
	e := NewEncoder(MsgEventlogRequest)
	e.Bytes(1, m.SHA256)
	e.U32(2, m.Offset)
	return e.Finish()
}

// DecodeEventlogRequest parses an EventlogRequest.
func DecodeEventlogRequest(d *Decoder) (*EventlogRequest, error) {
	if err := d.Expect(MsgEventlogRequest); err != nil {
		return nil, err
	}
	m := &EventlogRequest{SHA256: d.Fixed(1, 32, true), Offset: d.U32(2, false)}
	return m, d.Err()
}

// EventlogChunk carries part of the event log (attester -> verifier).
type EventlogChunk struct {
	SHA256 []byte
	Offset uint32
	Total  uint32
	Data   []byte
}

// Encode serialises the message.
func (m *EventlogChunk) Encode() ([]byte, error) {
	e := NewEncoder(MsgEventlogChunk)
	e.Bytes(1, m.SHA256)
	e.U32(2, m.Offset)
	e.U32(3, m.Total)
	e.Bytes(4, m.Data)
	return e.Finish()
}

// DecodeEventlogChunk parses an EventlogChunk.
func DecodeEventlogChunk(d *Decoder) (*EventlogChunk, error) {
	if err := d.Expect(MsgEventlogChunk); err != nil {
		return nil, err
	}
	m := &EventlogChunk{
		SHA256: d.Fixed(1, 32, true),
		Offset: d.U32(2, true),
		Total:  d.U32(3, true),
		Data:   d.Bytes(4, MaxEventlogChunk, true),
	}
	if err := d.Err(); err != nil {
		return nil, err
	}
	if m.Total > MaxEventlogSize || uint64(m.Offset)+uint64(len(m.Data)) > uint64(m.Total) {
		return nil, fmt.Errorf("attest: event log chunk out of bounds")
	}
	return m, nil
}

// Receipt is the verifier's signed verdict (verifier -> attester).
type Receipt struct {
	Verdict     VerdictCode
	DeviceID    []byte
	AKName      []byte
	QD          []byte
	QuoteDigest []byte
	PolicyID    string
	IssuedAt    uint64
	ExpiresAt   uint64
	VerifierID  string
	Signature   []byte // DER ECDSA P-256 over SHA-256(ReceiptTBS); may be empty for VerdictReject
}

// Encode serialises the message.
func (m *Receipt) Encode() ([]byte, error) {
	e := NewEncoder(MsgReceipt)
	e.U8(1, uint8(m.Verdict))
	e.Bytes(2, m.DeviceID)
	e.Bytes(3, m.AKName)
	e.Bytes(4, m.QD)
	e.Bytes(5, m.QuoteDigest)
	e.String(6, m.PolicyID)
	e.U64(7, m.IssuedAt)
	e.U64(8, m.ExpiresAt)
	e.String(9, m.VerifierID)
	e.OptBytes(10, m.Signature)
	return e.Finish()
}

// DecodeReceipt parses a Receipt.
func DecodeReceipt(d *Decoder) (*Receipt, error) {
	if err := d.Expect(MsgReceipt); err != nil {
		return nil, err
	}
	m := &Receipt{
		Verdict:     VerdictCode(d.U8(1, true)),
		DeviceID:    d.Fixed(2, DeviceIDSize, true),
		AKName:      d.Bytes(3, maxName, true),
		QD:          d.Fixed(4, 32, true),
		QuoteDigest: d.Fixed(5, 32, true),
		PolicyID:    d.String(6, maxShortString, false),
		IssuedAt:    d.U64(7, true),
		ExpiresAt:   d.U64(8, true),
		VerifierID:  d.String(9, maxShortString, true),
		Signature:   d.Bytes(10, maxDERSig, false),
	}
	return m, d.Err()
}

// Release kinds (PLAN-FACTORRELEASE.md §4).
const (
	ReleaseKindPassphrase uint8 = 1
	ReleaseKindFactor     uint8 = 2
)

// Release hands the attester a TPM-bound secret after a trusted receipt
// (verifier -> attester). Defined once for remote unlocking and factor release.
type Release struct {
	Kind            uint8
	Slot            uint8
	CredentialBlob  []byte // TPM2_MakeCredential credentialBlob (TPM2B_ID_OBJECT contents)
	EncryptedSecret []byte // TPM2_MakeCredential secret (TPM2B_ENCRYPTED_SECRET contents)
	Ciphertext      []byte // kind 1 only
	Approval        []byte // optional: signature for the release key's PolicySigned branch
	Label           string // optional: factor label, default "luks"
}

// Encode serialises the message.
func (m *Release) Encode() ([]byte, error) {
	e := NewEncoder(MsgRelease)
	e.U8(1, m.Kind)
	e.U8(2, m.Slot)
	e.Bytes(3, m.CredentialBlob)
	e.Bytes(4, m.EncryptedSecret)
	e.OptBytes(5, m.Ciphertext)
	e.OptBytes(6, m.Approval)
	if m.Label != "" {
		e.String(7, m.Label)
	}
	return e.Finish()
}

// DecodeRelease parses a Release.
func DecodeRelease(d *Decoder) (*Release, error) {
	if err := d.Expect(MsgRelease); err != nil {
		return nil, err
	}
	m := &Release{
		Kind:            d.U8(1, true),
		Slot:            d.U8(2, true),
		CredentialBlob:  d.Bytes(3, maxCredential, true),
		EncryptedSecret: d.Bytes(4, maxCredential, true),
		Ciphertext:      d.Bytes(5, 4096, false),
		Approval:        d.Bytes(6, maxTPMSig, false),
		Label:           d.String(7, maxShortString, false),
	}
	return m, d.Err()
}

// ReceiptAck results.
const (
	AckAccepted        uint8 = 1 // signature valid, bound to this session
	AckBadSignature    uint8 = 2 // not signed by the pinned anchor
	AckBindingMismatch uint8 = 3 // qd, device id, AK name or quote digest differ
	AckRejectNoted     uint8 = 4 // verdict was reject; displayed
	AckMalformed       uint8 = 5
)

// ReceiptAck tells the verifier what the attester made of the receipt.
type ReceiptAck struct {
	Result  uint8
	Message string
}

// Encode serialises the message.
func (m *ReceiptAck) Encode() ([]byte, error) {
	e := NewEncoder(MsgReceiptAck)
	e.U8(1, m.Result)
	e.String(2, m.Message)
	return e.Finish()
}

// DecodeReceiptAck parses a ReceiptAck.
func DecodeReceiptAck(d *Decoder) (*ReceiptAck, error) {
	if err := d.Expect(MsgReceiptAck); err != nil {
		return nil, err
	}
	m := &ReceiptAck{Result: d.U8(1, true), Message: d.String(2, maxMessageText, false)}
	return m, d.Err()
}

// ReleaseAck statuses.
const (
	ReleaseOK          uint8 = 1
	ReleaseUnsupported uint8 = 2
	ReleaseTPMRefused  uint8 = 3
	ReleaseNoReceipt   uint8 = 4
)

// ReleaseAck reports the outcome of a Release (attester -> verifier). It never
// carries the released secret or anything derived from it.
type ReleaseAck struct {
	Status  uint8
	Message string
}

// Encode serialises the message.
func (m *ReleaseAck) Encode() ([]byte, error) {
	e := NewEncoder(MsgReleaseAck)
	e.U8(1, m.Status)
	e.String(2, m.Message)
	return e.Finish()
}

// DecodeReleaseAck parses a ReleaseAck.
func DecodeReleaseAck(d *Decoder) (*ReleaseAck, error) {
	if err := d.Expect(MsgReleaseAck); err != nil {
		return nil, err
	}
	m := &ReleaseAck{Status: d.U8(1, true), Message: d.String(2, maxMessageText, false)}
	return m, d.Err()
}

// encodeNonceMsg / decodeNonceMsg serve the three SAS messages, which all
// carry a single 32-byte value in field 1.
func encodeNonceMsg(t MsgType, v []byte) ([]byte, error) {
	if err := checkNonce(t.String(), v); err != nil {
		return nil, err
	}
	e := NewEncoder(t)
	e.Bytes(1, v)
	return e.Finish()
}

func decodeNonceMsg(d *Decoder, t MsgType) ([]byte, error) {
	if err := d.Expect(t); err != nil {
		return nil, err
	}
	v := d.Fixed(1, NonceSize, true)
	return v, d.Err()
}

// EncodeSASCommit, EncodeSASNonce and EncodeSASReveal build the SAS messages.
func EncodeSASCommit(commit []byte) ([]byte, error) { return encodeNonceMsg(MsgSASCommit, commit) }

// EncodeSASNonce builds a SASNonce message.
func EncodeSASNonce(nonce []byte) ([]byte, error) { return encodeNonceMsg(MsgSASNonce, nonce) }

// EncodeSASReveal builds a SASReveal message.
func EncodeSASReveal(nonce []byte) ([]byte, error) { return encodeNonceMsg(MsgSASReveal, nonce) }

// EncodeEmpty builds a message without fields (SASConfirm, Bye).
func EncodeEmpty(t MsgType) ([]byte, error) { return NewEncoder(t).Finish() }

// EnrolOffer carries the attester's identity and baseline (attester -> verifier).
type EnrolOffer struct {
	Schema         uint16
	DeviceID       []byte
	FriendlyName   string
	EKPub          []byte // marshalled TPMT_PUBLIC
	EKCert         []byte // optional DER
	AKPub          []byte // marshalled TPMT_PUBLIC
	AKName         []byte
	Selection      PCRSelection
	PCRValues      []PCRValue
	Quoted         []byte // baseline quote, qualifying data = EnrolQualifyingData(cb)
	Signature      []byte
	EventlogSHA256 []byte // optional
	BootContext    BootContext
	AppVersion     string
	AdvKey         []byte // 32 bytes: lets the phone recognise this machine's advertisements
	EKCertChain    []byte // optional: the TPM's intermediates for EKCert, concatenated DER
	// MeasurePointValues are the PCR values the machine expects at the boot
	// check, where the gate quotes inside the initramfs. They differ from
	// PCRValues, the running system's registers, for PCRs systemd extends
	// after the initramfs (PCR 11 phases, PCR 9). Optional: the verifier
	// pins them as the baseline when present, the quote's values otherwise.
	MeasurePointValues []PCRValue
	// The boot key (bootkey.go): its public area, and the attestation
	// key's TPM2_Certify statement over it for this session.
	BootKeyPub        []byte
	BootKeyCertify    []byte
	BootKeyCertifySig []byte
}

// BaselineValues are the PCR values the verifier pins at enrolment: the
// boot-check values when the machine predicted them, else the live quote's.
func (m *EnrolOffer) BaselineValues() []PCRValue {
	if len(m.MeasurePointValues) > 0 {
		return m.MeasurePointValues
	}
	return m.PCRValues
}

// BaselineAddedBy names the baseline's origin in the record's profile.
func (m *EnrolOffer) BaselineAddedBy() string {
	if len(m.MeasurePointValues) > 0 {
		return BaselineMeasurePoint
	}
	return BaselineLive
}

// Profile AddedBy values for the enrolment baseline.
const (
	BaselineLive         = "enrolment"
	BaselineMeasurePoint = "enrolment (values at the boot check)"
)

// Encode serialises the message.
func (m *EnrolOffer) Encode() ([]byte, error) {
	e := NewEncoder(MsgEnrolOffer)
	e.U16(1, m.Schema)
	e.Bytes(2, m.DeviceID)
	e.String(3, m.FriendlyName)
	e.Bytes(4, m.EKPub)
	e.OptBytes(5, m.EKCert)
	e.Bytes(6, m.AKPub)
	e.Bytes(7, m.AKName)
	e.U16(8, m.Selection.Alg)
	e.Bytes(9, m.Selection.Indices)
	e.Bytes(10, encodePCRValues(m.PCRValues))
	e.Bytes(11, m.Quoted)
	e.Bytes(12, m.Signature)
	e.OptBytes(13, m.EventlogSHA256)
	e.Sub(14, m.BootContext.encode())
	e.String(15, m.AppVersion)
	e.Bytes(16, m.AdvKey)
	e.OptBytes(17, m.EKCertChain)
	if len(m.MeasurePointValues) > 0 {
		e.Bytes(18, encodePCRValues(m.MeasurePointValues))
	}
	e.Bytes(19, m.BootKeyPub)
	e.Bytes(20, m.BootKeyCertify)
	e.Bytes(21, m.BootKeyCertifySig)
	return e.Finish()
}

// DecodeEnrolOffer parses an EnrolOffer.
func DecodeEnrolOffer(d *Decoder) (*EnrolOffer, error) {
	if err := d.Expect(MsgEnrolOffer); err != nil {
		return nil, err
	}
	m := &EnrolOffer{
		Schema:         d.U16(1, true),
		DeviceID:       d.Fixed(2, DeviceIDSize, true),
		FriendlyName:   d.String(3, maxShortString, true),
		EKPub:          d.Bytes(4, maxTPMPublic, true),
		EKCert:         d.Bytes(5, maxEKCert, false),
		AKPub:          d.Bytes(6, maxTPMPublic, true),
		AKName:         d.Bytes(7, maxName, true),
		Selection:      decodeSelection(d, 8, 9),
		Quoted:         d.Bytes(11, maxQuoted, true),
		Signature:      d.Bytes(12, maxTPMSig, true),
		EventlogSHA256: d.Fixed(13, 32, false),
		BootContext:    decodeBootContext(d.Sub(14, 2048, false)),
		AppVersion:     d.String(15, maxShortString, false),
		AdvKey:         d.Fixed(16, 32, true),
		EKCertChain:    d.Bytes(17, MaxEKCertChain, false),

		BootKeyPub:        d.Bytes(19, maxTPMPublic, true),
		BootKeyCertify:    d.Bytes(20, maxQuoted, true),
		BootKeyCertifySig: d.Bytes(21, maxTPMSig, true),
	}
	vals := d.Bytes(10, 2+maxPCRValues*(5+65), true)
	mpv := d.Bytes(18, 2+maxPCRValues*(5+65), false)
	if err := d.Err(); err != nil {
		return nil, err
	}
	if err := m.Selection.Validate(); err != nil {
		return nil, err
	}
	pv, err := decodePCRValues(vals)
	if err != nil {
		return nil, err
	}
	m.PCRValues = pv
	if len(mpv) > 0 {
		if m.MeasurePointValues, err = decodePCRValues(mpv); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Challenge is the credential activation challenge (verifier -> attester).
type Challenge struct {
	CredentialBlob  []byte
	EncryptedSecret []byte
}

// Encode serialises the message.
func (m *Challenge) Encode() ([]byte, error) {
	e := NewEncoder(MsgChallenge)
	e.Bytes(1, m.CredentialBlob)
	e.Bytes(2, m.EncryptedSecret)
	return e.Finish()
}

// DecodeChallenge parses a Challenge.
func DecodeChallenge(d *Decoder) (*Challenge, error) {
	if err := d.Expect(MsgChallenge); err != nil {
		return nil, err
	}
	m := &Challenge{
		CredentialBlob:  d.Bytes(1, maxCredential, true),
		EncryptedSecret: d.Bytes(2, maxCredential, true),
	}
	return m, d.Err()
}

// ChallengeResponse returns the activated secret (attester -> verifier).
type ChallengeResponse struct {
	Secret []byte
}

// Encode serialises the message.
func (m *ChallengeResponse) Encode() ([]byte, error) {
	e := NewEncoder(MsgChallengeResponse)
	e.Bytes(1, m.Secret)
	return e.Finish()
}

// DecodeChallengeResponse parses a ChallengeResponse.
func DecodeChallengeResponse(d *Decoder) (*ChallengeResponse, error) {
	if err := d.Expect(MsgChallengeResponse); err != nil {
		return nil, err
	}
	m := &ChallengeResponse{Secret: d.Bytes(1, 64, true)}
	return m, d.Err()
}

// EnrolAccept pins the verifier's anchor on the attester (verifier -> attester).
type EnrolAccept struct {
	VerifierID   string
	VerifierName string
	AnchorPub    []byte // PKIX DER, ECDSA P-256
	PolicyID     string
	ReceiptTTL   uint32 // seconds
	AnchorSig    []byte // DER ECDSA over SHA-256(EnrolAcceptTBS)
	// AnchorAttestation is the anchor key's attestation certificate chain
	// (Android Key Attestation), concatenated DER, leaf first; optional.
	AnchorAttestation []byte
}

// Encode serialises the message.
func (m *EnrolAccept) Encode() ([]byte, error) {
	e := NewEncoder(MsgEnrolAccept)
	e.String(1, m.VerifierID)
	e.String(2, m.VerifierName)
	e.Bytes(3, m.AnchorPub)
	e.String(4, m.PolicyID)
	e.U32(5, m.ReceiptTTL)
	e.Bytes(6, m.AnchorSig)
	e.OptBytes(7, m.AnchorAttestation)
	return e.Finish()
}

// DecodeEnrolAccept parses an EnrolAccept.
func DecodeEnrolAccept(d *Decoder) (*EnrolAccept, error) {
	if err := d.Expect(MsgEnrolAccept); err != nil {
		return nil, err
	}
	m := &EnrolAccept{
		VerifierID:   d.String(1, maxShortString, true),
		VerifierName: d.String(2, maxShortString, false),
		AnchorPub:    d.Bytes(3, maxAnchorPub, true),
		PolicyID:     d.String(4, maxShortString, false),
		ReceiptTTL:   d.U32(5, false),
		AnchorSig:    d.Bytes(6, maxDERSig, true),

		AnchorAttestation: d.Bytes(7, MaxAnchorAttestation, false),
	}
	if err := d.Err(); err != nil {
		return nil, err
	}
	if m.VerifierID == "" {
		return nil, fmt.Errorf("attest: EnrolAccept: empty verifier id")
	}
	return m, nil
}

// EnrolConfirm reports that the attester stored the anchor (attester -> verifier).
type EnrolConfirm struct {
	AnchorDigest []byte
	Slot         uint8
}

// Encode serialises the message.
func (m *EnrolConfirm) Encode() ([]byte, error) {
	e := NewEncoder(MsgEnrolConfirm)
	e.Bytes(1, m.AnchorDigest)
	e.U8(2, m.Slot)
	return e.Finish()
}

// DecodeEnrolConfirm parses an EnrolConfirm.
func DecodeEnrolConfirm(d *Decoder) (*EnrolConfirm, error) {
	if err := d.Expect(MsgEnrolConfirm); err != nil {
		return nil, err
	}
	m := &EnrolConfirm{AnchorDigest: d.Fixed(1, 32, true), Slot: d.U8(2, false)}
	return m, d.Err()
}

// ErrorMsg aborts a session.
type ErrorMsg struct {
	Code    uint16
	Message string
}

// Encode serialises the message.
func (m *ErrorMsg) Encode() ([]byte, error) {
	e := NewEncoder(MsgError)
	e.U16(1, m.Code)
	e.String(2, truncate(m.Message, maxMessageText))
	return e.Finish()
}

// DecodeErrorMsg parses an Error message.
func DecodeErrorMsg(d *Decoder) (*ErrorMsg, error) {
	if err := d.Expect(MsgError); err != nil {
		return nil, err
	}
	m := &ErrorMsg{Code: d.U16(1, true), Message: d.String(2, maxMessageText, false)}
	return m, d.Err()
}

func (m *ErrorMsg) Error() string {
	return fmt.Sprintf("peer aborted (code %d): %s", m.Code, m.Message)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
