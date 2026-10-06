package attest

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
)

// The attester side of both exchanges. It runs on the machine, blocks on a
// Conn, and reaches the TPM only through the backend interfaces below, which
// cmd/ implements. Nothing here decides whether the machine is trustworthy;
// it produces evidence and reads receipts.

// QuoteResult is what a backend returns for one TPM2_Quote.
type QuoteResult struct {
	Quoted    []byte // marshalled TPMS_ATTEST
	Signature []byte // marshalled TPMT_SIGNATURE
	Values    []PCRValue
}

// AttesterBackend is the TPM-facing part of the attester.
type AttesterBackend interface {
	// Quote signs the PCRs in sel with the AK, qualifying data qd, and
	// returns PCR values that reproduce the quoted digest.
	Quote(qd []byte, sel PCRSelection) (*QuoteResult, error)
	// BootContext describes the local configuration (informational only).
	BootContext() BootContext
	// Eventlog returns the firmware event log, or nil when there is none.
	Eventlog() ([]byte, error)
	// ProveBootKey answers the phone's boot challenge with the boot key
	// in the TPM (bootkey.go): the proof that it recovered the code, its
	// signature over context and quoteDigest, and BootKeyProved when the
	// TPM released the key, otherwise why not (BootKeyRefused,
	// BootKeyFailed). The code the challenge carries is the backend's to
	// show to the person at the machine; it never travels back.
	ProveBootKey(ch *BootChallenge, context, quoteDigest []byte) (*BootAnswer, uint8)
}

// MeasurePointProvider is an optional AttesterBackend extension for enrolment:
// the PCR values expected at the boot check, where the gate quotes inside the
// initramfs. The TOTP seal predicts the same point, and the provider is meant
// to use the same code. A nil result with a nil error means no prediction.
type MeasurePointProvider interface {
	MeasurePointValues(sel PCRSelection) ([]PCRValue, error)
}

// ReceiptJudge is an optional AttesterBackend extension: the backend reads
// the receipt itself, against the quotes it issued and the anchors it holds,
// instead of the session doing so. It lets the process that talks to the
// phone be a different one from the process that decides what the phone
// said (tpm2-kira's radio worker and its coordinator).
type ReceiptJudge interface {
	JudgeReceipt(r *Receipt, verifierID string) ReceiptCheck
}

// EnrolledVerifier is one pinned verifier, as stored in the attestation blob.
type EnrolledVerifier struct {
	ID        string
	Name      string
	AnchorPub []byte // PKIX DER, ECDSA P-256
	NoisePub  []byte // X25519 static key used in the IK handshake
	PolicyID  string
}

// AttestIdentity is the attester's state for one slot.
type AttestIdentity struct {
	DeviceID     []byte
	AKName       []byte
	NoiseStatic  *NoiseKeypair
	Verifiers    []EnrolledVerifier
	AppVersion   string
	Capabilities uint32
}

// Progress receives human-readable status lines for the console.
type Progress func(format string, args ...any)

func (p Progress) say(format string, args ...any) {
	if p != nil {
		p(format, args...)
	}
}

// AttestResult is the outcome of one attestation session.
type AttestResult struct {
	Verifier *EnrolledVerifier
	Request  *Request
	Receipt  *Receipt
	Check    ReceiptCheck
}

// ErrUnknownVerifier is returned when an IK initiator is not an enrolled phone.
var ErrUnknownVerifier = errors.New("attest: initiator is not an enrolled verifier")

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ServeAttestation runs one attestation session as the responder.
func ServeAttestation(conn Conn, id *AttestIdentity, be AttesterBackend, progress Progress) (*AttestResult, error) {
	res := &AttestResult{}
	ch, err := AcceptHandshake(conn, PatternIK, id.NoiseStatic, func(rs []byte) error {
		for i := range id.Verifiers {
			if EqualKeys(rs, id.Verifiers[i].NoisePub) {
				res.Verifier = &id.Verifiers[i]
				return nil
			}
		}
		return ErrUnknownVerifier
	})
	if err != nil {
		return nil, err
	}
	progress.say("Session established with %s", verifierLabel(res.Verifier))

	nonceA, err := randomBytes(NonceSize)
	if err != nil {
		return nil, err
	}
	hello, err := (&Hello{
		Schema:       SchemaVersion,
		DeviceID:     id.DeviceID,
		NonceA:       nonceA,
		Capabilities: id.Capabilities,
		AppVersion:   id.AppVersion,
	}).Encode()
	if err != nil {
		return nil, err
	}
	if err := ch.SendMsg(hello); err != nil {
		return nil, err
	}

	d, err := ch.RecvMsg()
	if err != nil {
		return nil, err
	}
	req, err := DecodeRequest(d)
	if err != nil {
		ch.SendError(ErrCodeProtocol, err.Error())
		return nil, err
	}
	res.Request = req

	qd, err := QualifyingData(nonceA, req.NonceV, ch.Session().ChannelBinding(), req.Selection)
	if err != nil {
		return nil, err
	}
	q, err := be.Quote(qd, req.Selection)
	if err != nil {
		ch.SendError(ErrCodeTPM, "quote failed")
		return nil, fmt.Errorf("quote: %w", err)
	}
	progress.say("Quote produced over %s", req.Selection)
	bootAnswer, bootState := be.ProveBootKey(&BootChallenge{EphemeralPub: req.EphemeralPub, Sealed: req.Sealed}, qd, sha256Sum(q.Quoted))
	if bootState != BootKeyProved || bootAnswer == nil {
		bootAnswer, bootState = &BootAnswer{}, max(bootState, BootKeyRefused)
	}

	ev := &Evidence{
		Schema:      SchemaVersion,
		DeviceID:    id.DeviceID,
		AKName:      id.AKName,
		Quoted:      q.Quoted,
		Signature:   q.Signature,
		PCRAlg:      req.Selection.Alg,
		PCRValues:   q.Values,
		BootContext: be.BootContext(),
		AppVersion:  id.AppVersion,

		BootKeyState:  bootState,
		BootProof:     bootAnswer.Proof,
		BootSignature: bootAnswer.Signature,
	}
	evlog, _ := be.Eventlog()
	var evlogHash []byte
	if len(evlog) > 0 && len(evlog) <= MaxEventlogSize {
		evlogHash = sha256Sum(evlog)
		ev.EventlogSHA256 = evlogHash
		ev.EventlogSize = uint32(len(evlog))
	}
	evb, err := ev.Encode()
	if err != nil {
		return nil, err
	}
	if err := ch.SendMsg(evb); err != nil {
		return nil, err
	}
	if req.WantEventlog && evlogHash != nil {
		if err := sendEventlog(ch, evlog, evlogHash, 0); err != nil {
			return nil, err
		}
	}

	exp := ReceiptExpectation{
		DeviceID:    id.DeviceID,
		AKName:      id.AKName,
		QD:          qd,
		QuoteDigest: sha256Sum(q.Quoted),
		VerifierID:  res.Verifier.ID,
	}
	for {
		d, err := ch.RecvMsg()
		if err != nil {
			return res, err
		}
		switch d.Type {
		case MsgEventlogRequest:
			er, err := DecodeEventlogRequest(d)
			if err != nil {
				return res, err
			}
			if evlogHash == nil || subtle.ConstantTimeCompare(er.SHA256, evlogHash) != 1 {
				ch.SendError(ErrCodeUnsupported, "no event log with that hash")
				return res, errors.New("attest: event log request for unknown hash")
			}
			progress.say("Sending event log (%d bytes)", len(evlog))
			if err := sendEventlog(ch, evlog, evlogHash, er.Offset); err != nil {
				return res, err
			}
		case MsgReceipt:
			r, err := DecodeReceipt(d)
			if err != nil {
				return res, err
			}
			res.Receipt = r
			if judge, ok := be.(ReceiptJudge); ok {
				res.Check = judge.JudgeReceipt(r, res.Verifier.ID)
			} else {
				anchor, aerr := ParseAnchor(res.Verifier.AnchorPub)
				if aerr != nil {
					anchor = nil
				}
				res.Check = CheckReceipt(r, anchor, exp)
			}
			ack, err := (&ReceiptAck{Result: res.Check.Ack, Message: res.Check.Detail}).Encode()
			if err != nil {
				return res, err
			}
			if err := ch.SendMsg(ack); err != nil {
				return res, err
			}
		case MsgRelease:
			// Factor release (PLAN-FACTORRELEASE.md) is defined in the
			// protocol but not implemented by this attester yet.
			ack, _ := (&ReleaseAck{Status: ReleaseUnsupported, Message: "release not supported by this version"}).Encode()
			if err := ch.SendMsg(ack); err != nil {
				return res, err
			}
		case MsgBye:
			if res.Receipt == nil {
				return res, errors.New("attest: verifier ended the session without a receipt")
			}
			return res, nil
		default:
			ch.SendError(ErrCodeProtocol, "unexpected "+d.Type.String())
			return res, fmt.Errorf("attest: unexpected %s", d.Type)
		}
	}
}

func verifierLabel(v *EnrolledVerifier) string {
	if v == nil {
		return "unknown verifier"
	}
	if v.Name != "" {
		return fmt.Sprintf("%q", v.Name)
	}
	return v.ID
}

func sendEventlog(ch *Channel, evlog, hash []byte, offset uint32) error {
	if int(offset) > len(evlog) {
		return errors.New("attest: event log offset out of range")
	}
	for off := int(offset); off < len(evlog); off += MaxEventlogChunk {
		end := off + MaxEventlogChunk
		if end > len(evlog) {
			end = len(evlog)
		}
		b, err := (&EventlogChunk{SHA256: hash, Offset: uint32(off), Total: uint32(len(evlog)), Data: evlog[off:end]}).Encode()
		if err != nil {
			return err
		}
		if err := ch.SendMsg(b); err != nil {
			return err
		}
	}
	return nil
}

// EnrolBackend is the TPM- and console-facing part of enrolment.
type EnrolBackend interface {
	AttesterBackend
	// EKPublic returns the marshalled EK TPMT_PUBLIC and, if present, its certificate.
	EKPublic() (pub []byte, cert []byte, err error)
	// ActivateCredential runs TPM2_ActivateCredential(AK, EK).
	ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error)
	// ConfirmSAS shows the code to the person at the console and returns
	// whether they confirmed it matches the phone.
	ConfirmSAS(code string) (bool, error)
	// Commit persists the enrolment. Nothing is written before this call.
	Commit(v EnrolledVerifier) error
	// BootKey returns the slot's boot key (bootkey.go), creating it at the
	// first enrolment: its public area, the attestation key's TPM2_Certify
	// statement over it with qd as qualifying data, and the signing key
	// and policy reference its policy is made of.
	BootKey(qd []byte) (*BootKeyOffer, error)
}

// EKChainProvider is implemented by backends that can supply the TPM's
// intermediate certificates for the EK certificate (ekcert.go).
type EKChainProvider interface {
	EKCertChain() []byte
}

// PhoneAttestationJudge is implemented by backends that want to decide on the
// phone's key attestation before the enrolment is stored (keyattest.go).
type PhoneAttestationJudge interface {
	JudgePhone(PhoneAttestation) (bool, error)
}

// EnrolIdentity is the attester's state offered at enrolment.
type EnrolIdentity struct {
	DeviceID     []byte
	FriendlyName string
	AKPub        []byte
	AKName       []byte
	NoiseStatic  *NoiseKeypair
	AdvKey       []byte
	Selection    PCRSelection
	AppVersion   string
	Slot         uint8
}

// ServeEnrolment runs one enrolment as the responder and returns the newly
// pinned verifier once it has been committed.
func ServeEnrolment(conn Conn, id *EnrolIdentity, be EnrolBackend, progress Progress) (*EnrolledVerifier, error) {
	ch, err := AcceptHandshake(conn, PatternXX, id.NoiseStatic, nil)
	if err != nil {
		return nil, err
	}
	cb := ch.Session().ChannelBinding()
	phoneNoise := ch.Session().RemoteStatic()
	progress.say("Encrypted session established; confirming it out of band")

	// Short authentication string, commit-then-reveal (canon.go).
	nonceM, err := randomBytes(NonceSize)
	if err != nil {
		return nil, err
	}
	b, err := EncodeSASCommit(SASCommitment(cb, nonceM))
	if err != nil {
		return nil, err
	}
	if err := ch.SendMsg(b); err != nil {
		return nil, err
	}
	d, err := ch.RecvMsg()
	if err != nil {
		return nil, err
	}
	nonceP, err := decodeNonceMsg(d, MsgSASNonce)
	if err != nil {
		ch.SendError(ErrCodeProtocol, err.Error())
		return nil, err
	}
	if b, err = EncodeSASReveal(nonceM); err != nil {
		return nil, err
	}
	if err := ch.SendMsg(b); err != nil {
		return nil, err
	}
	sas := ShortAuthString(cb, nonceP, nonceM)
	ok, err := be.ConfirmSAS(sas)
	if err != nil {
		ch.SendError(ErrCodeUserAborted, "confirmation aborted on the machine")
		return nil, err
	}
	if !ok {
		ch.SendError(ErrCodeSASRejected, "the code was rejected on the machine")
		return nil, errors.New("attest: confirmation code rejected on the machine; enrolment aborted")
	}
	progress.say("Waiting for the phone to confirm the code ...")
	if d, err = ch.RecvMsg(); err != nil {
		return nil, err
	}
	if err := d.Expect(MsgSASConfirm); err != nil {
		ch.SendError(ErrCodeProtocol, err.Error())
		return nil, err
	}
	progress.say("Code confirmed on both devices")

	ekPub, ekCert, err := be.EKPublic()
	if err != nil {
		ch.SendError(ErrCodeTPM, "EK unavailable")
		return nil, fmt.Errorf("EK: %w", err)
	}
	q, err := be.Quote(EnrolQualifyingData(cb), id.Selection)
	if err != nil {
		ch.SendError(ErrCodeTPM, "quote failed")
		return nil, fmt.Errorf("quote: %w", err)
	}
	offer := &EnrolOffer{
		Schema:       SchemaVersion,
		DeviceID:     id.DeviceID,
		FriendlyName: id.FriendlyName,
		EKPub:        ekPub,
		EKCert:       ekCert,
		AKPub:        id.AKPub,
		AKName:       id.AKName,
		Selection:    id.Selection,
		PCRValues:    q.Values,
		Quoted:       q.Quoted,
		Signature:    q.Signature,
		BootContext:  be.BootContext(),
		AppVersion:   id.AppVersion,
		AdvKey:       id.AdvKey,
	}
	bk, err := be.BootKey(EnrolQualifyingData(cb))
	if err != nil {
		ch.SendError(ErrCodeTPM, "boot key unavailable")
		return nil, fmt.Errorf("boot key: %w", err)
	}
	offer.BootKeyPub, offer.BootKeyCertify, offer.BootKeyCertifySig = bk.PubArea, bk.CertifyInfo, bk.CertifySig
	offer.SigningPub, offer.PolicyRef = bk.SigningPub, bk.PolicyRef
	if evlog, _ := be.Eventlog(); len(evlog) > 0 {
		offer.EventlogSHA256 = sha256Sum(evlog)
	}
	if cp, ok := be.(EKChainProvider); ok && len(ekCert) > 0 {
		if chain := cp.EKCertChain(); len(chain) <= MaxEKCertChain {
			offer.EKCertChain = chain
		}
	}
	if mp, ok := be.(MeasurePointProvider); ok {
		// Why a prediction failed was reported before the session started.
		if vals, err := mp.MeasurePointValues(id.Selection); err == nil && len(vals) > 0 {
			offer.MeasurePointValues = vals
		}
	}
	if b, err = offer.Encode(); err != nil {
		return nil, err
	}
	if err := ch.SendMsg(b); err != nil {
		return nil, err
	}

	if d, err = ch.RecvMsg(); err != nil {
		return nil, err
	}
	chal, err := DecodeChallenge(d)
	if err != nil {
		ch.SendError(ErrCodeProtocol, err.Error())
		return nil, err
	}
	secret, err := be.ActivateCredential(chal.CredentialBlob, chal.EncryptedSecret)
	if err != nil {
		ch.SendError(ErrCodeActivationFailed, "credential activation failed")
		return nil, fmt.Errorf("activate credential: %w", err)
	}
	if b, err = (&ChallengeResponse{Secret: secret}).Encode(); err != nil {
		return nil, err
	}
	if err := ch.SendMsg(b); err != nil {
		return nil, err
	}
	progress.say("Credential activated: the phone has verified the attestation key lives in this TPM")

	if d, err = ch.RecvMsg(); err != nil {
		return nil, err
	}
	acc, err := DecodeEnrolAccept(d)
	if err != nil {
		ch.SendError(ErrCodeProtocol, err.Error())
		return nil, err
	}
	anchor, err := ParseAnchor(acc.AnchorPub)
	if err != nil {
		ch.SendError(ErrCodeProtocol, err.Error())
		return nil, err
	}
	tbs := EnrolAcceptTBS(id.DeviceID, cb, id.AKName, acc.AnchorPub, acc.VerifierID, acc.PolicyID)
	if !VerifyAnchorSignature(anchor, tbs, acc.AnchorSig) {
		ch.SendError(ErrCodeProtocol, "anchor signature does not verify")
		return nil, errors.New("attest: EnrolAccept anchor signature does not verify")
	}
	if judge, ok := be.(PhoneAttestationJudge); ok {
		pa := VerifyPhoneAttestation(acc.AnchorAttestation, acc.AnchorPub, AnchorAttestationChallenge(cb), time.Now())
		accept, err := judge.JudgePhone(pa)
		if err != nil || !accept {
			ch.SendError(ErrCodePolicy, "the machine did not accept this phone's key")
			if err == nil {
				err = errors.New("attest: the phone's key attestation was not accepted on the machine")
			}
			return nil, err
		}
	}

	v := EnrolledVerifier{
		ID:        acc.VerifierID,
		Name:      acc.VerifierName,
		AnchorPub: acc.AnchorPub,
		NoisePub:  phoneNoise,
		PolicyID:  acc.PolicyID,
	}
	if err := be.Commit(v); err != nil {
		ch.SendError(ErrCodeStorage, "could not store the enrolment")
		return nil, fmt.Errorf("commit: %w", err)
	}
	if b, err = (&EnrolConfirm{AnchorDigest: AnchorDigest(acc.AnchorPub), Slot: id.Slot}).Encode(); err != nil {
		return nil, err
	}
	if err := ch.SendMsg(b); err != nil {
		// Committed already; the phone will notice the missing confirmation.
		return &v, fmt.Errorf("enrolment stored, but the confirmation could not be sent: %w", err)
	}
	// Best effort: wait for the phone's Bye so the radio is not torn down
	// under its last write.
	_, _ = ch.RecvMsg()
	return &v, nil
}
