package attest

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

// The verifier side of both exchanges, as an event-driven state machine.
//
// It is built for the phone: every input (a received record, a button press,
// a signature from the platform keystore) is a method call that returns an
// Output — records to send and events to show. Nothing blocks, nothing calls
// back into the app, and nothing needs a thread. The app moves bytes and
// pixels; every decision is made here.

// MachineRecordVersion is the version of the stored machine record format.
const MachineRecordVersion = 1

// MachineRecord is everything a verifier keeps about one enrolled machine.
// The phone stores it (encrypted at rest by the platform) as opaque JSON
// and hands it back for every attestation.
type MachineRecord struct {
	Version         int    `json:"version"`
	DeviceID        HexStr `json:"device_id"`
	FriendlyName    string `json:"friendly_name"`
	EKPub           HexStr `json:"ek_pub"`
	EKCert          HexStr `json:"ek_cert,omitempty"`
	AKPub           HexStr `json:"ak_pub"`
	AKName          HexStr `json:"ak_name"`
	MachineNoisePub HexStr `json:"machine_noise_pub"`
	AdvKey          HexStr `json:"adv_key"`
	AnchorPub       HexStr `json:"anchor_pub"`
	VerifierID      string `json:"verifier_id"`
	Slot            uint8  `json:"slot"`
	Policy          Policy `json:"policy"`
	ResetCount      uint32 `json:"reset_count"`
	FirmwareVersion uint64 `json:"firmware_version"`
	ReceiptTTL      uint32 `json:"receipt_ttl"`
	BaselineEvlog   HexStr `json:"baseline_eventlog_sha256,omitempty"`
	// EKVerifiedBy names the TPM vendor whose certificate chain vouched for
	// the EK at enrolment; empty when it could not be verified (ekcert.go).
	EKVerifiedBy string     `json:"ek_verified_by,omitempty"`
	EnrolledAt   time.Time  `json:"enrolled_at"`
	LastAttested *time.Time `json:"last_attested,omitempty"`
}

func (r *MachineRecord) pinned() *PinnedIdentity {
	return &PinnedIdentity{
		DeviceID:        r.DeviceID,
		EKPub:           r.EKPub,
		AKPub:           r.AKPub,
		AKName:          r.AKName,
		ResetCount:      r.ResetCount,
		FirmwareVersion: r.FirmwareVersion,
	}
}

// Validate checks a record handed back by the app before it is used.
func (r *MachineRecord) Validate() error {
	if r.Version != MachineRecordVersion {
		return fmt.Errorf("attest: machine record version %d, expected %d", r.Version, MachineRecordVersion)
	}
	if len(r.DeviceID) != DeviceIDSize || len(r.MachineNoisePub) != NoiseKeySize || len(r.AdvKey) != 32 {
		return errors.New("attest: machine record is incomplete")
	}
	if _, err := ParseAKPublic(r.AKPub, r.AKName); err != nil {
		return err
	}
	if _, err := r.Policy.PCRSelection(); err != nil {
		return err
	}
	return nil
}

// Event is one thing the app must show or act on. Type selects which fields
// are set; docs/PROTOCOL-BLE.md §7 lists them.
type Event struct {
	Type string `json:"type"`

	SAS           string         `json:"sas,omitempty"`
	Purpose       string         `json:"purpose,omitempty"`
	TBS           []byte         `json:"tbs,omitempty"`
	VerdictCode   uint8          `json:"verdict_code,omitempty"`
	Verdict       *Verdict       `json:"verdict,omitempty"`
	NeedsDecision bool           `json:"needs_decision,omitempty"`
	EventlogAvail bool           `json:"eventlog_available,omitempty"`
	Record        *MachineRecord `json:"record,omitempty"`
	DeviceID      HexStr         `json:"device_id,omitempty"`
	FriendlyName  string         `json:"friendly_name,omitempty"`
	Received      uint32         `json:"received,omitempty"`
	Total         uint32         `json:"total,omitempty"`
	Complete      bool           `json:"complete,omitempty"`
	Code          uint16         `json:"code,omitempty"`
	Result        uint8          `json:"result,omitempty"`
	Message       string         `json:"message,omitempty"`
	Warnings      []string       `json:"warnings,omitempty"`

	// need_anchor_key: what the phone learnt about the machine before the
	// user binds it.
	EKVerifiedBy string `json:"ek_verified_by,omitempty"`
	// AttestationChallenge goes into the anchor key's attestation, binding it
	// to this enrolment (AnchorAttestationChallenge).
	AttestationChallenge HexStr `json:"attestation_challenge,omitempty"`
	EKNote               string `json:"ek_note,omitempty"`
	InitrdCoverage       string `json:"initrd_coverage,omitempty"` // covered | not_covered | no_initrd | unknown
	InitrdPCRs           []int  `json:"initrd_pcrs,omitempty"`
}

// InitrdCoverage values in need_anchor_key events.
const (
	InitrdCovered    = "covered"
	InitrdNotCovered = "not_covered"
	InitrdNoInitrd   = "no_initrd"
	InitrdUnknownMsg = "unknown"
)

// Event types.
const (
	EvSAS           = "sas"             // show SAS; call ConfirmSAS
	EvNeedAnchorKey = "need_anchor_key" // create the keystore key; call ProvideAnchorKey
	EvNeedSignature = "need_signature"  // sign TBS with the anchor key; call ProvideSignature
	EvEnrolled      = "enrolled"        // persist Record
	EvHello         = "hello"           // the machine identified itself
	EvVerdict       = "verdict"         // show Verdict; if NeedsDecision call Decide
	EvEventlog      = "eventlog"        // event log transfer progress
	EvReceiptAck    = "receipt_ack"     // what the machine made of the receipt
	EvRecordUpdated = "record_updated"  // persist Record (replaces the stored one)
	EvDone          = "done"            // session finished normally; disconnect
	EvError         = "error"           // session failed; disconnect
)

// Signing purposes in need_signature events.
const (
	PurposeEnrolAccept = "enrol_accept"
	PurposeReceipt     = "receipt"
)

// Decision is the human's answer to a verdict that needs one.
type Decision int

const (
	DecisionApproveOnce     Decision = 1
	DecisionApproveRemember Decision = 2
	DecisionReject          Decision = 3
)

// Output is the result of one input to the verifier.
type Output struct {
	Records [][]byte
	Events  []Event
}

// VerifierConfig is the phone's own identity.
type VerifierConfig struct {
	NoiseStatic  *NoiseKeypair
	VerifierID   string
	VerifierName string
	PolicyID     string        // default "default"
	ReceiptTTL   time.Duration // default 5 minutes
	Now          func() time.Time
	Rand         io.Reader
}

type vstate int

const (
	vsInit vstate = iota
	vsHandshake
	// enrolment
	vsWaitSASCommit
	vsWaitSASReveal
	vsWaitSASUser
	vsWaitEnrolOffer
	vsWaitChallengeResponse
	vsWaitAnchorKey
	vsWaitAnchorSig
	vsWaitEnrolConfirm
	// attestation
	vsWaitHello
	vsWaitEvidence
	vsWaitDecision
	vsWaitReceiptSig
	vsWaitReceiptAck
	// terminal
	vsDone
	vsFailed
)

// Verifier is one session's state machine.
type Verifier struct {
	cfg     VerifierConfig
	enrol   bool
	state   vstate
	hs      *Handshake
	sess    *Session
	record  *MachineRecord
	pattern HandshakePattern

	// enrolment
	commit            []byte
	nonceP            []byte
	offer             *EnrolOffer
	secret            []byte
	anchor            []byte
	accTBS            []byte
	baseVer           *Verdict
	ekBy              string // vendor that vouched for the EK, or ""
	anchorAttestation []byte
	ekNote            string // why the EK is not verified

	// attestation
	hello    *Hello
	nonceV   []byte
	sel      PCRSelection
	evidence *Evidence
	verdict  *Verdict
	qd       []byte
	receipt  *Receipt
	remember bool
	evlog    []byte
	evlogSum []byte
	evlogTot uint32
}

func (c *VerifierConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *VerifierConfig) rng() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}

func (c *VerifierConfig) policyID() string {
	if c.PolicyID != "" {
		return c.PolicyID
	}
	return "default"
}

func (c *VerifierConfig) ttl() time.Duration {
	if c.ReceiptTTL > 0 {
		return c.ReceiptTTL
	}
	return 5 * time.Minute
}

func (c *VerifierConfig) validate() error {
	if c.NoiseStatic == nil {
		return errors.New("attest: verifier needs a static Noise key")
	}
	if c.VerifierID == "" || len(c.VerifierID) > maxShortString {
		return errors.New("attest: verifier id must be 1-64 bytes")
	}
	return nil
}

// NewEnrolVerifier starts an enrolment session.
func NewEnrolVerifier(cfg VerifierConfig) (*Verifier, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	hs, err := NewHandshake(PatternXX, true, cfg.NoiseStatic, nil, cfg.rng())
	if err != nil {
		return nil, err
	}
	return &Verifier{cfg: cfg, enrol: true, hs: hs, pattern: PatternXX}, nil
}

// NewAttestVerifier starts an attestation session against an enrolled machine.
func NewAttestVerifier(cfg VerifierConfig, rec *MachineRecord) (*Verifier, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	hs, err := NewHandshake(PatternIK, true, cfg.NoiseStatic, rec.MachineNoisePub, cfg.rng())
	if err != nil {
		return nil, err
	}
	cp := *rec
	return &Verifier{cfg: cfg, hs: hs, record: &cp, pattern: PatternIK}, nil
}

// Finished reports whether the session has ended (successfully or not).
func (v *Verifier) Finished() bool { return v.state == vsDone || v.state == vsFailed }

// Succeeded reports whether the session ended normally.
func (v *Verifier) Succeeded() bool { return v.state == vsDone }

func (v *Verifier) recordKind() byte {
	if v.pattern == PatternIK {
		return RecordHandshakeIK
	}
	return RecordHandshakeXX
}

// fail ends the session, tells the peer if a channel exists, and reports it.
func (v *Verifier) fail(out *Output, code uint16, msg string) (*Output, error) {
	if v.sess != nil && v.state != vsFailed && v.state != vsDone {
		if b, err := (&ErrorMsg{Code: code, Message: msg}).Encode(); err == nil {
			if ct, err := v.sess.Seal(b); err == nil {
				out.Records = append(out.Records, append([]byte{RecordTransport}, ct...))
			}
		}
	}
	v.state = vsFailed
	out.Events = append(out.Events, Event{Type: EvError, Code: code, Message: msg})
	return out, errors.New(msg)
}

func (v *Verifier) send(out *Output, msg []byte, err error) error {
	if err != nil {
		return err
	}
	ct, err := v.sess.Seal(msg)
	if err != nil {
		return err
	}
	out.Records = append(out.Records, append([]byte{RecordTransport}, ct...))
	return nil
}

// Start produces the first handshake message.
func (v *Verifier) Start() (*Output, error) {
	out := &Output{}
	if v.state != vsInit {
		return out, errors.New("attest: session already started")
	}
	m, err := v.hs.WriteMessage(nil)
	if err != nil {
		return v.fail(out, ErrCodeProtocol, err.Error())
	}
	out.Records = append(out.Records, append([]byte{v.recordKind()}, m...))
	v.state = vsHandshake
	return out, nil
}

// Abort ends the session at the user's request.
func (v *Verifier) Abort(reason string) *Output {
	out := &Output{}
	if v.Finished() {
		return out
	}
	if reason == "" {
		reason = "cancelled on the phone"
	}
	out, _ = v.fail(out, ErrCodeUserAborted, reason)
	return out
}

// HandleRecord consumes one complete record from the machine.
func (v *Verifier) HandleRecord(rec []byte) (*Output, error) {
	out := &Output{}
	if v.Finished() {
		return out, errors.New("attest: session has ended")
	}
	if len(rec) == 0 || len(rec) > MaxRecordSize {
		return v.fail(out, ErrCodeProtocol, "invalid record size")
	}
	if rec[0] == RecordPlainError && v.sess == nil {
		em, err := PlainErrorFromRecord(rec)
		if err != nil {
			return v.fail(out, ErrCodeProtocol, "malformed error record")
		}
		v.state = vsFailed
		out.Events = append(out.Events, Event{Type: EvError, Code: em.Code, Message: "machine (unauthenticated): " + em.Message})
		return out, em
	}
	if v.state == vsHandshake {
		if rec[0] != v.recordKind() {
			return v.fail(out, ErrCodeProtocol, "unexpected record during handshake")
		}
		if _, err := v.hs.ReadMessage(rec[1:]); err != nil {
			// For IK this is what a wrong machine looks like: it cannot
			// decrypt or answer for a key it does not hold.
			return v.fail(out, ErrCodeProtocol, "handshake failed: "+err.Error())
		}
		if !v.hs.Complete() {
			m, err := v.hs.WriteMessage(nil)
			if err != nil {
				return v.fail(out, ErrCodeProtocol, err.Error())
			}
			out.Records = append(out.Records, append([]byte{v.recordKind()}, m...))
		}
		if v.hs.Complete() {
			s, err := v.hs.Session()
			if err != nil {
				return v.fail(out, ErrCodeProtocol, err.Error())
			}
			v.sess = s
			if v.enrol {
				v.state = vsWaitSASCommit
			} else {
				v.state = vsWaitHello
			}
		}
		return out, nil
	}
	if rec[0] != RecordTransport || v.sess == nil {
		return v.fail(out, ErrCodeProtocol, "unexpected record kind")
	}
	pt, err := v.sess.Open(rec[1:])
	if err != nil {
		return v.fail(out, ErrCodeProtocol, err.Error())
	}
	d, err := Decode(pt)
	if err != nil {
		return v.fail(out, ErrCodeProtocol, err.Error())
	}
	if d.Type == MsgError {
		em, err := DecodeErrorMsg(d)
		if err != nil {
			return v.fail(out, ErrCodeProtocol, "malformed error message")
		}
		v.state = vsFailed
		out.Events = append(out.Events, Event{Type: EvError, Code: em.Code, Message: "machine: " + em.Message})
		return out, em
	}
	if v.enrol {
		return v.handleEnrol(out, d)
	}
	return v.handleAttest(out, d)
}

// ---- enrolment ----

func (v *Verifier) handleEnrol(out *Output, d *Decoder) (*Output, error) {
	switch v.state {
	case vsWaitSASCommit:
		c, err := decodeNonceMsg(d, MsgSASCommit)
		if err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		v.commit = c
		v.nonceP = make([]byte, NonceSize)
		if _, err := io.ReadFull(v.cfg.rng(), v.nonceP); err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		b, err := EncodeSASNonce(v.nonceP)
		if err := v.send(out, b, err); err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		v.state = vsWaitSASReveal
		return out, nil

	case vsWaitSASReveal:
		nonceM, err := decodeNonceMsg(d, MsgSASReveal)
		if err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		cb := v.sess.ChannelBinding()
		if subtle.ConstantTimeCompare(SASCommitment(cb, nonceM), v.commit) != 1 {
			return v.fail(out, ErrCodeSASRejected, "machine's code commitment does not open: possible interception")
		}
		v.state = vsWaitSASUser
		out.Events = append(out.Events, Event{Type: EvSAS, SAS: ShortAuthString(cb, v.nonceP, nonceM)})
		return out, nil

	case vsWaitEnrolOffer:
		offer, err := DecodeEnrolOffer(d)
		if err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		if err := v.checkOffer(offer); err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		v.offer = offer
		v.secret = make([]byte, 32)
		if _, err := io.ReadFull(v.cfg.rng(), v.secret); err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		blob, enc, err := MakeCredential(v.cfg.rng(), offer.EKPub, offer.AKName, v.secret)
		if err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		b, err := (&Challenge{CredentialBlob: blob, EncryptedSecret: enc}).Encode()
		if err := v.send(out, b, err); err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		v.state = vsWaitChallengeResponse
		return out, nil

	case vsWaitChallengeResponse:
		cr, err := DecodeChallengeResponse(d)
		if err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		if subtle.ConstantTimeCompare(cr.Secret, v.secret) != 1 {
			return v.fail(out, ErrCodeActivationFailed, "credential activation failed: the attestation key is not in the TPM that owns this EK")
		}
		v.state = vsWaitAnchorKey
		cov, pcrs := initrdCoverage(v.offer)
		out.Events = append(out.Events, Event{
			Type: EvNeedAnchorKey, DeviceID: v.offer.DeviceID, FriendlyName: v.offer.FriendlyName,
			EKVerifiedBy: v.ekBy, EKNote: v.ekNote, InitrdCoverage: cov, InitrdPCRs: pcrs,
			AttestationChallenge: AnchorAttestationChallenge(v.sess.ChannelBinding()),
		})
		return out, nil

	case vsWaitEnrolConfirm:
		ec, err := DecodeEnrolConfirm(d)
		if err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		if !bytes.Equal(ec.AnchorDigest, AnchorDigest(v.anchor)) {
			return v.fail(out, ErrCodeStorage, "machine stored a different anchor")
		}
		now := v.cfg.now()
		rec := &MachineRecord{
			Version:         MachineRecordVersion,
			DeviceID:        v.offer.DeviceID,
			FriendlyName:    v.offer.FriendlyName,
			EKPub:           v.offer.EKPub,
			EKCert:          v.offer.EKCert,
			AKPub:           v.offer.AKPub,
			AKName:          v.offer.AKName,
			MachineNoisePub: v.sess.RemoteStatic(),
			AdvKey:          v.offer.AdvKey,
			AnchorPub:       v.anchor,
			VerifierID:      v.cfg.VerifierID,
			Slot:            ec.Slot,
			Policy: Policy{
				ID:        v.cfg.policyID(),
				Selection: v.offer.Selection.Indices,
				PCRAlg:    v.offer.Selection.Alg,
				Profiles:  []Profile{ProfileFromValues("enrolment baseline", v.offer.BaselineValues(), now, v.offer.BaselineAddedBy())},
			},
			ResetCount:      v.baseVer.ResetCount,
			FirmwareVersion: v.baseVer.FirmwareVersion,
			ReceiptTTL:      uint32(v.cfg.ttl() / time.Second),
			BaselineEvlog:   v.offer.EventlogSHA256,
			EKVerifiedBy:    v.ekBy,
			EnrolledAt:      now,
		}
		b, err := EncodeEmpty(MsgBye)
		if err := v.send(out, b, err); err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		v.record = rec
		v.state = vsDone
		out.Events = append(out.Events, Event{Type: EvEnrolled, Record: rec}, Event{Type: EvDone})
		return out, nil
	}
	return v.fail(out, ErrCodeProtocol, "unexpected "+d.Type.String())
}

// checkMeasurePointValues ties the optional boot-check values to the
// TPM-signed quote (CheckMeasurePointValues): they may differ from the live
// registers only where systemd provably extended PCR 11 after the boot check.
func checkMeasurePointValues(o *EnrolOffer) error {
	if len(o.MeasurePointValues) == 0 {
		return nil
	}
	return CheckMeasurePointValues(o.Selection.Alg, o.PCRValues, o.MeasurePointValues)
}

// checkOffer validates everything in an EnrolOffer that can be checked
// before credential activation, including the baseline quote.
func (v *Verifier) checkOffer(o *EnrolOffer) error {
	if o.Schema != SchemaVersion {
		return fmt.Errorf("machine speaks schema %d, this app %d", o.Schema, SchemaVersion)
	}
	if err := ValidateEKPublic(o.EKPub); err != nil {
		return err
	}
	// The EK certificate is judged below (VerifyEKCertificate) and only ever
	// downgrades the result to "not verified": a certificate Go cannot parse
	// (e.g. the RSA-OAEP key identifier) must not make enrolment impossible.
	if _, err := ParseAKPublic(o.AKPub, o.AKName); err != nil {
		return err
	}
	pol := &Policy{
		ID:        v.cfg.policyID(),
		Selection: o.Selection.Indices,
		PCRAlg:    o.Selection.Alg,
		Profiles:  []Profile{ProfileFromValues("enrolment baseline", o.PCRValues, time.Time{}, "enrolment")},
	}
	pin := &PinnedIdentity{DeviceID: o.DeviceID, AKPub: o.AKPub, AKName: o.AKName}
	ev := &Evidence{
		Schema:    SchemaVersion,
		DeviceID:  o.DeviceID,
		AKName:    o.AKName,
		Quoted:    o.Quoted,
		Signature: o.Signature,
		PCRAlg:    o.Selection.Alg,
		PCRValues: o.PCRValues,
	}
	verdict := Verify(ev, pol, pin, EnrolQualifyingData(v.sess.ChannelBinding()), v.cfg.now())
	if verdict.State != StateMatch {
		msg := "baseline quote does not verify"
		if len(verdict.Reasons) > 0 {
			msg += ": " + verdict.Reasons[0].Detail
		}
		return errors.New(msg)
	}
	v.baseVer = verdict
	if err := checkMeasurePointValues(o); err != nil {
		return err
	}
	if by, err := VerifyEKCertificate(o.EKPub, o.EKCert, o.EKCertChain, v.cfg.now()); err == nil {
		v.ekBy = by
	} else {
		v.ekNote = EKCertNote(err)
	}
	return nil
}

// initrdCoverage compares where the machine says its initrd was measured with
// the PCRs the phone will check. The machine's statement is not TPM-signed;
// it can only add a warning, never remove one.
func initrdCoverage(o *EnrolOffer) (string, []int) {
	bc := o.BootContext
	switch bc.InitrdState {
	case InitrdNone:
		return InitrdNoInitrd, nil
	case InitrdMeasured:
		var pcrs []int
		covered := false
		for _, p := range bc.InitrdPCRs {
			pcrs = append(pcrs, int(p))
			if slices.Contains(o.Selection.Indices, p) {
				covered = true
			}
		}
		if len(pcrs) == 0 {
			return InitrdUnknownMsg, nil
		}
		if covered {
			return InitrdCovered, pcrs
		}
		return InitrdNotCovered, pcrs
	}
	return InitrdUnknownMsg, nil
}

// ConfirmSAS reports the user's comparison of the code on both screens.
func (v *Verifier) ConfirmSAS(match bool) (*Output, error) {
	out := &Output{}
	if v.state != vsWaitSASUser {
		return out, errors.New("attest: no code awaiting confirmation")
	}
	if !match {
		return v.fail(out, ErrCodeSASRejected, "the codes did not match; enrolment aborted")
	}
	b, err := EncodeEmpty(MsgSASConfirm)
	if err := v.send(out, b, err); err != nil {
		return v.fail(out, ErrCodeProtocol, err.Error())
	}
	v.state = vsWaitEnrolOffer
	return out, nil
}

// ProvideAnchorKey hands over the public half of the newly created,
// non-exportable keystore key, as PKIX DER.
func (v *Verifier) ProvideAnchorKey(pubDER []byte) (*Output, error) {
	return v.ProvideAnchorKeyAttested(pubDER, nil)
}

// ProvideAnchorKeyAttested is ProvideAnchorKey with the key's attestation
// certificate chain (concatenated DER, leaf first), which the machine checks.
// The phone does not judge its own attestation; it only passes it on.
func (v *Verifier) ProvideAnchorKeyAttested(pubDER, attestation []byte) (*Output, error) {
	if len(attestation) > MaxAnchorAttestation {
		attestation = nil // too large to send; the machine will say it is missing
	}
	v.anchorAttestation = append([]byte(nil), attestation...)
	out := &Output{}
	if v.state != vsWaitAnchorKey {
		return out, errors.New("attest: no anchor key expected")
	}
	if _, err := ParseAnchor(pubDER); err != nil {
		return out, err // recoverable: the app may retry with a correct key
	}
	v.anchor = append([]byte(nil), pubDER...)
	v.accTBS = EnrolAcceptTBS(v.offer.DeviceID, v.sess.ChannelBinding(), v.offer.AKName, v.anchor, v.cfg.VerifierID, v.cfg.policyID())
	v.state = vsWaitAnchorSig
	out.Events = append(out.Events, Event{Type: EvNeedSignature, Purpose: PurposeEnrolAccept, TBS: v.accTBS})
	return out, nil
}

// ProvideSignature hands over a DER ECDSA signature over SHA-256(TBS) made
// with the anchor key, for the pending need_signature event.
func (v *Verifier) ProvideSignature(sig []byte) (*Output, error) {
	out := &Output{}
	switch v.state {
	case vsWaitAnchorSig:
		anchor, _ := ParseAnchor(v.anchor)
		if !VerifyAnchorSignature(anchor, v.accTBS, sig) {
			// Usually a platform encoding bug (raw r‖s instead of DER).
			return out, errors.New("attest: signature does not verify against the anchor key; it must be DER ECDSA over SHA-256(tbs)")
		}
		b, err := (&EnrolAccept{
			VerifierID:   v.cfg.VerifierID,
			VerifierName: v.cfg.VerifierName,
			AnchorPub:    v.anchor,
			PolicyID:     v.cfg.policyID(),
			ReceiptTTL:   uint32(v.cfg.ttl() / time.Second),
			AnchorSig:    sig,

			AnchorAttestation: v.anchorAttestation,
		}).Encode()
		if err := v.send(out, b, err); err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		v.state = vsWaitEnrolConfirm
		return out, nil

	case vsWaitReceiptSig:
		anchor, err := ParseAnchor(v.record.AnchorPub)
		if err != nil || !VerifyAnchorSignature(anchor, ReceiptTBS(v.receipt), sig) {
			return out, errors.New("attest: signature does not verify against this machine's anchor key; it must be DER ECDSA over SHA-256(tbs)")
		}
		v.receipt.Signature = append([]byte(nil), sig...)
		return v.sendReceipt(out)
	}
	return out, errors.New("attest: no signature expected")
}

// Record returns the machine record (after enrolment, or the updated one
// after attestation).
func (v *Verifier) Record() *MachineRecord { return v.record }

// ---- attestation ----

func (v *Verifier) handleAttest(out *Output, d *Decoder) (*Output, error) {
	switch v.state {
	case vsWaitHello:
		h, err := DecodeHello(d)
		if err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		if !bytes.Equal(h.DeviceID, v.record.DeviceID) {
			return v.fail(out, ErrCodeUnknownDevice, "machine identifies as a different device")
		}
		if h.Schema != SchemaVersion {
			return v.fail(out, ErrCodeProtocol, fmt.Sprintf("machine speaks schema %d, this app %d", h.Schema, SchemaVersion))
		}
		v.hello = h
		sel, _ := v.record.Policy.PCRSelection()
		v.sel = sel
		v.nonceV = make([]byte, NonceSize)
		if _, err := io.ReadFull(v.cfg.rng(), v.nonceV); err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		b, err := (&Request{NonceV: v.nonceV, Selection: sel, PolicyID: v.record.Policy.ID}).Encode()
		if err := v.send(out, b, err); err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		v.state = vsWaitEvidence
		out.Events = append(out.Events, Event{Type: EvHello, DeviceID: h.DeviceID, FriendlyName: v.record.FriendlyName})
		return out, nil

	case vsWaitEvidence:
		ev, err := DecodeEvidence(d)
		if err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		v.evidence = ev
		qd, err := QualifyingData(v.hello.NonceA, v.nonceV, v.sess.ChannelBinding(), v.sel)
		if err != nil {
			return v.fail(out, ErrCodeProtocol, err.Error())
		}
		v.qd = qd
		v.verdict = Verify(ev, &v.record.Policy, v.record.pinned(), qd, v.cfg.now())
		v.evlogSum = ev.EventlogSHA256
		v.evlogTot = ev.EventlogSize
		ve := Event{Type: EvVerdict, Verdict: v.verdict, EventlogAvail: v.evlogSum != nil}
		if v.verdict.State == StateMatch {
			out.Events = append(out.Events, ve)
			return v.prepareReceipt(out, VerdictOK)
		}
		ve.NeedsDecision = true
		v.state = vsWaitDecision
		out.Events = append(out.Events, ve)
		return out, nil

	case vsWaitDecision, vsWaitReceiptSig, vsWaitReceiptAck:
		if d.Type == MsgEventlogChunk {
			return v.handleEventlogChunk(out, d)
		}
		if v.state == vsWaitReceiptAck && d.Type == MsgReceiptAck {
			ack, err := DecodeReceiptAck(d)
			if err != nil {
				return v.fail(out, ErrCodeProtocol, err.Error())
			}
			out.Events = append(out.Events, Event{Type: EvReceiptAck, Result: ack.Result, Message: ack.Message})
			if v.receipt.Verdict.Trusted() {
				v.updateRecord()
				out.Events = append(out.Events, Event{Type: EvRecordUpdated, Record: v.record})
			}
			b, err := EncodeEmpty(MsgBye)
			if err := v.send(out, b, err); err != nil {
				return v.fail(out, ErrCodeProtocol, err.Error())
			}
			v.state = vsDone
			out.Events = append(out.Events, Event{Type: EvDone})
			return out, nil
		}
	}
	return v.fail(out, ErrCodeProtocol, "unexpected "+d.Type.String())
}

func (v *Verifier) handleEventlogChunk(out *Output, d *Decoder) (*Output, error) {
	c, err := DecodeEventlogChunk(d)
	if err != nil {
		return v.fail(out, ErrCodeProtocol, err.Error())
	}
	if v.evlogSum == nil || !bytes.Equal(c.SHA256, v.evlogSum) || c.Total != v.evlogTot || c.Offset != uint32(len(v.evlog)) {
		return v.fail(out, ErrCodeProtocol, "event log chunk does not continue the announced log")
	}
	v.evlog = append(v.evlog, c.Data...)
	ev := Event{Type: EvEventlog, Received: uint32(len(v.evlog)), Total: c.Total}
	if uint32(len(v.evlog)) == c.Total {
		if !bytes.Equal(sha256Sum(v.evlog), v.evlogSum) {
			return v.fail(out, ErrCodeProtocol, "event log does not match its announced hash")
		}
		ev.Complete = true
	}
	out.Events = append(out.Events, ev)
	return out, nil
}

// RequestEventlog asks the machine for its event log, so a human can see
// what changed. Only meaningful while a decision is pending.
func (v *Verifier) RequestEventlog() (*Output, error) {
	out := &Output{}
	if v.state != vsWaitDecision {
		return out, errors.New("attest: event log can only be requested while a decision is pending")
	}
	if v.evlogSum == nil {
		return out, errors.New("attest: the machine announced no event log")
	}
	if v.evlog != nil {
		return out, errors.New("attest: event log already requested")
	}
	v.evlog = []byte{}
	b, err := (&EventlogRequest{SHA256: v.evlogSum}).Encode()
	if err := v.send(out, b, err); err != nil {
		return v.fail(out, ErrCodeProtocol, err.Error())
	}
	return out, nil
}

// Eventlog returns the transferred event log once complete.
func (v *Verifier) Eventlog() []byte {
	if v.evlogTot > 0 && uint32(len(v.evlog)) == v.evlogTot {
		return v.evlog
	}
	return nil
}

// Decide records the human's answer to a verdict that needs one. Approving
// a verdict in which a hard check failed additionally requires confirmName to
// equal the machine's friendly name: the app makes the user type it.
func (v *Verifier) Decide(d Decision, confirmName string) (*Output, error) {
	out := &Output{}
	if v.state != vsWaitDecision {
		return out, errors.New("attest: no decision pending")
	}
	switch d {
	case DecisionReject:
		return v.prepareReceipt(out, VerdictReject)
	case DecisionApproveOnce, DecisionApproveRemember:
		if v.verdict.State == StateFailed && confirmName != v.record.FriendlyName {
			return out, errors.New("attest: approving a failed attestation requires typing the machine's name")
		}
		if v.verdict.Values == nil {
			// The evidence did not even reproduce its own digest; there is
			// nothing authentic to approve or remember.
			return out, errors.New("attest: these PCR values are not authentic and cannot be approved")
		}
		v.remember = d == DecisionApproveRemember
		return v.prepareReceipt(out, VerdictApproved)
	}
	return out, fmt.Errorf("attest: unknown decision %d", d)
}

func (v *Verifier) prepareReceipt(out *Output, code VerdictCode) (*Output, error) {
	now := v.cfg.now()
	ttl := time.Duration(v.record.ReceiptTTL) * time.Second
	if ttl == 0 {
		ttl = v.cfg.ttl()
	}
	v.receipt = &Receipt{
		Verdict:     code,
		DeviceID:    v.record.DeviceID,
		AKName:      v.record.AKName,
		QD:          v.qd,
		QuoteDigest: sha256Sum(v.evidence.Quoted),
		PolicyID:    v.record.Policy.ID,
		IssuedAt:    uint64(now.Unix()),
		ExpiresAt:   uint64(now.Add(ttl).Unix()),
		VerifierID:  v.record.VerifierID,
	}
	if code == VerdictReject {
		// Rejects go out unsigned: no biometric prompt to say "no".
		return v.sendReceipt(out)
	}
	v.state = vsWaitReceiptSig
	out.Events = append(out.Events, Event{Type: EvNeedSignature, Purpose: PurposeReceipt, TBS: ReceiptTBS(v.receipt), VerdictCode: uint8(code)})
	return out, nil
}

func (v *Verifier) sendReceipt(out *Output) (*Output, error) {
	b, err := v.receipt.Encode()
	if err := v.send(out, b, err); err != nil {
		return v.fail(out, ErrCodeProtocol, err.Error())
	}
	v.state = vsWaitReceiptAck
	return out, nil
}

// updateRecord folds what a trusted attestation taught into the record.
func (v *Verifier) updateRecord() {
	now := v.cfg.now()
	r := v.record
	if v.verdict.ResetCount > r.ResetCount {
		r.ResetCount = v.verdict.ResetCount
	} else if v.receipt.Verdict == VerdictApproved && v.verdict.ResetCount < r.ResetCount {
		// A human approved despite the counter going backwards (a cleared
		// TPM): adopt the new baseline, or every later boot fails the same way.
		r.ResetCount = v.verdict.ResetCount
	}
	r.FirmwareVersion = v.verdict.FirmwareVersion
	r.LastAttested = &now
	if v.verdict.Profile != "" {
		for i := range r.Policy.Profiles {
			p := &r.Policy.Profiles[i]
			if p.Name == v.verdict.Profile && p.UsesLeft != nil && *p.UsesLeft > 0 {
				n := *p.UsesLeft - 1
				p.UsesLeft = &n
			}
		}
	}
	if v.remember && v.verdict.Values != nil {
		var vals []PCRValue
		for _, idx := range r.Policy.Selection {
			vals = append(vals, PCRValue{Index: idx, Digest: v.verdict.Values[idx]})
		}
		name := "approved " + now.UTC().Format("2006-01-02 15:04")
		r.Policy.Profiles = append(r.Policy.Profiles, ProfileFromValues(name, vals, now, "approval"))
	}
}
