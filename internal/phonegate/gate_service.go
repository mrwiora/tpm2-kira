// Package phonegate is the phone at boot: the coordinator the radio worker
// asks, the TPM's side of an attestation (quotes, the boot key, the EK), the
// record check, and the factor the phone releases for the phone salt.
package phonegate

// The gate's coordinator: the half of phone attestation that holds the TPM.
//
// Attestation over Bluetooth is done by two processes of this one binary.
// The radio worker (tpm2-kira-attest.service) advertises, speaks the
// protocol with the phone and parses whatever the radio delivers; its unit
// gives it Bluetooth sockets and nothing else. The coordinator is the
// process that already owns the console and the TPM at boot (tpm2-kira-boot run):
// it checks the enrolment record, produces the quotes, and reads the phone's
// receipt itself. The worker reaches it over a Unix socket (gate_ipc.go) and
// can ask for exactly that.
//
// So a flaw in the radio path stays where the radio is. The worker has no
// TPM: it cannot have a TOTP code computed while the code screen is up, and
// it cannot produce a verdict either - a verdict is a receipt signed by the
// enrolled phone over a quote this coordinator issued in this boot, and the
// coordinator checks both. What it could still do is deny the phone check,
// or report a rejection nobody gave; neither earns trust.
//
// The coordinator is also where the outcome is known to the rest of the
// boot: the code screen releases on it today, and whatever else is to act
// on a verified boot later has one place to ask.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/attest"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/wipe"
)

// gateIdentity is what the radio worker needs to advertise and to run the
// session: the slot's identifiers and keys for the channel. None of it is
// protected by the TPM (the record is readable by anyone who can talk to
// it); the phones' anchors, which decide a verdict, stay with the coordinator.
type gateIdentity struct {
	Slot           int            `json:"slot"`
	FriendlyName   string         `json:"friendly_name"`
	DeviceID       []byte         `json:"device_id"`
	AKName         []byte         `json:"ak_name"`
	NoisePrivate   []byte         `json:"noise_private"`
	AdvKey         []byte         `json:"adv_key"`
	Verifiers      []gateVerifier `json:"verifiers"`
	RecordVerified bool           `json:"record_verified"`
}

type gateVerifier struct {
	ID       string `json:"id"`
	NoisePub []byte `json:"noise_pub"`
}

// GateHost is what the radio side of the gate needs from the TPM side:
// implemented by the coordinator itself (gateService) and, for the worker,
// by its connection to the coordinator (gateClient).
type GateHost interface {
	// Identity returns the slot to serve, or the exit status with which
	// the gate gives up.
	Identity() (*gateIdentity, int, error)
	attest.AttesterBackend // Quote, BootContext, Eventlog, ProveBootKey
	attest.ReceiptJudge
	attest.FactorBackend // FactorToKeep, TakeRelease (factor.go)
	// Report tells the coordinator where the radio side is. Only progress
	// can be reported; a verdict comes from JudgeReceipt alone.
	Report(state GateState)
}

// maxIssuedQuotes bounds what the coordinator remembers about its quotes.
const maxIssuedQuotes = 32

// GateService is the coordinator for one enrolled slot.
type GateService struct {
	mu    sync.Mutex // status and the issued quotes
	TPMMu sync.Mutex // one TPM operation at a time; the code screen never waits for it

	Ready  chan struct{} // closed when the slot is set up, or refused
	Code   int           // why there is no slot to serve (an exit status), or 0
	Reason error

	TPM            transport.TPM
	Idx            uint32
	Blob           *nvslot.Attestation
	be             *TPMBackend
	recordVerified bool

	Issued      map[string][]byte // SHA-256 of a quote issued this boot -> its qualifying data
	issuedOrder []string
	Current     GateStatus

	// The factor (factor.go). keep is what 'factor enrol' asks the phone
	// to keep, sent in the evidence; salt is the combiner's salt from the
	// factor the phone released and the TPM opened, held for the moment
	// the disk's key is asked for (and wiped with Close).
	keep *attest.FactorBlob
	salt []byte
	// returned: at enrolment, the phone gave keep back unchanged.
	returned bool
	// expectRelease: the unlock mode needs the phone's phone salt, so a
	// receipt is followed by a Release that the boot waits for (bounded by
	// releaseWait from releaseSince).
	ExpectingRelease bool
	ReleaseSince     time.Time
}

// releaseWait bounds how long the boot waits for the phone's phone salt
// after the receipt: the phone writes its record and sends one more
// message; a phone that has no salt sends Bye instead, which ends the
// wait at once. The bound is for a session that dies in between.
const releaseWait = 15 * time.Second

// NewGateService sets the coordinator up in the background (the TPM can be
// slow, and the code screen must not wait for it): finds the enrolled slot,
// checks its record and loads it. tpmDev is used from then on and never
// closed here.
func NewGateService(tpmDev transport.TPM, sealIndex uint32, signerPath string, debug bool) *GateService {
	s := &GateService{Ready: make(chan struct{}), TPM: tpmDev, Issued: map[string][]byte{}}
	go func() {
		defer close(s.Ready)
		s.Code, s.Reason = s.setup(sealIndex, signerPath, debug)
		if s.Code != 0 {
			s.mu.Lock()
			if s.Code == ExitTampered {
				s.Current.State = GateRefused
			} else {
				s.Current.State = GateUnavailable
			}
			s.mu.Unlock()
		}
	}()
	return s
}

func (s *GateService) setup(sealIndex uint32, signerPath string, debug bool) (int, error) {
	var idx uint32
	var err error
	if sealIndex != 0 {
		if idx, err = nvslot.AttestIndexForSlot(sealIndex); err != nil {
			return ExitUsage, err
		}
	} else {
		found := EnrolledSlots(s.TPM, debug)
		if len(found) == 0 {
			return ExitUsage, errors.New("no slot is enrolled for attestation (run 'tpm2-kira phone enrol')")
		}
		idx = found[0]
	}
	s.mu.Lock()
	s.Idx = idx
	s.Current.Slot = int(nvslot.AttestSlot(idx))
	s.mu.Unlock()

	verified, code := GateRecordCheck(s.TPM, idx, signerPath) // prints its own failure
	if code != 0 {
		return code, errors.New("the attestation record is not accepted")
	}
	blob, err := LoadAttestBlob(s.TPM, idx)
	if err != nil {
		return ExitInternal, fmt.Errorf("cannot read the attestation blob at 0x%08X: %w", idx, err)
	}
	if len(blob.Phone.Verifiers) == 0 {
		return ExitUsage, fmt.Errorf("no phone is enrolled for slot %d", nvslot.AttestSlot(idx))
	}
	if _, err := attest.NoiseKeypairFromPrivate(blob.Phone.NoisePrivate); err != nil {
		return ExitInternal, err
	}
	sealIdx := idx // the enrolment lives in the slot's own blob
	s.mu.Lock()
	s.Blob = blob
	s.recordVerified = verified
	s.be = &TPMBackend{TPM: s.TPM, Blob: blob, SealIndex: sealIdx, Sealed: ReadSealedSlot(s.TPM, sealIdx), Debug: debug}
	s.mu.Unlock()
	return 0, nil
}

// Identity implements gateHost.
func (s *GateService) Identity() (*gateIdentity, int, error) {
	<-s.Ready
	if s.Code != 0 {
		return nil, s.Code, s.Reason
	}
	id := &gateIdentity{
		Slot:           int(nvslot.AttestSlot(s.Idx)),
		FriendlyName:   s.Blob.FriendlyName,
		DeviceID:       s.Blob.DeviceID,
		AKName:         s.Blob.AKName,
		NoisePrivate:   s.Blob.Phone.NoisePrivate,
		AdvKey:         s.Blob.Phone.AdvKey,
		RecordVerified: s.recordVerified,
	}
	for _, v := range s.Blob.Phone.Verifiers {
		id.Verifiers = append(id.Verifiers, gateVerifier{ID: v.ID, NoisePub: v.NoisePub})
	}
	return id, 0, nil
}

var errGateNotServing = errors.New("the coordinator has no slot to serve")

// Quote implements attest.AttesterBackend. It is the one TPM operation the
// radio side can cause: a quote by the attestation key, which says what the
// registers are and gives nothing away.
func (s *GateService) Quote(qd []byte, sel attest.PCRSelection) (*attest.QuoteResult, error) {
	<-s.Ready
	if s.Code != 0 {
		return nil, errGateNotServing
	}
	if len(qd) == 0 || len(qd) > 64 {
		return nil, errors.New("qualifying data of an unexpected size")
	}
	if err := sel.Validate(); err != nil {
		return nil, err
	}
	s.TPMMu.Lock()
	q, err := s.be.Quote(qd, sel)
	s.TPMMu.Unlock()
	if err != nil {
		return nil, err
	}
	// Remember it: a receipt counts only for a quote issued here.
	sum := sha256.Sum256(q.Quoted)
	key := hex.EncodeToString(sum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Issued[key]; !ok {
		s.issuedOrder = append(s.issuedOrder, key)
		if len(s.issuedOrder) > maxIssuedQuotes {
			delete(s.Issued, s.issuedOrder[0])
			s.issuedOrder = s.issuedOrder[1:]
		}
	}
	s.Issued[key] = append([]byte(nil), qd...)
	return q, nil
}

// ProveBootKey implements attest.AttesterBackend. The code the challenge
// carries goes to the code screen through Status; the radio side gets the
// proof and never the code.
func (s *GateService) ProveBootKey(ch *attest.BootChallenge, context, quoteDigest []byte) (*attest.BootAnswer, uint8) {
	<-s.Ready
	if s.Code != 0 || ch == nil {
		return nil, attest.BootKeyFailed
	}
	s.TPMMu.Lock()
	answer, state := s.be.ProveBootKey(ch, context, quoteDigest)
	code := s.be.BootCode
	s.TPMMu.Unlock()
	s.mu.Lock()
	s.Current.Code = attest.FormatBootCode(code)
	if state != attest.BootKeyProved {
		s.Current.Code = ""
	}
	s.mu.Unlock()
	return answer, state
}

// BootContext implements attest.AttesterBackend.
func (s *GateService) BootContext() attest.BootContext {
	<-s.Ready
	if s.Code != 0 {
		return attest.BootContext{}
	}
	s.TPMMu.Lock()
	defer s.TPMMu.Unlock()
	return s.be.BootContext()
}

// Eventlog implements attest.AttesterBackend.
func (s *GateService) Eventlog() ([]byte, error) {
	<-s.Ready
	if s.Code != 0 {
		return nil, errGateNotServing
	}
	s.TPMMu.Lock()
	defer s.TPMMu.Unlock()
	return s.be.Eventlog()
}

// JudgeReceipt implements attest.ReceiptJudge: the receipt must be bound to
// a quote this coordinator issued, name an enrolled phone, and carry that
// phone's signature. What the radio side believes about its session plays
// no part.
// Keep sets the factor the next evidence asks the phone to keep.
func (s *GateService) Keep(f *attest.FactorBlob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keep = f
}

// FactorToKeep implements attest.FactorBackend.
func (s *GateService) FactorToKeep() *attest.FactorBlob {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keep
}

// TakeRelease implements attest.FactorBackend: the factor the phone
// released is opened in the TPM now, while the slot's policy still holds
// (before the OS separator), and only the combiner's salt is kept. The
// status tells the phone what the TPM made of it.
//
// At enrolment (Keep was set) the machine runs in the booted system, where
// the slot is locked until the next boot, so nothing is opened: the phone
// must give back exactly what it was asked to keep, which says it kept it.
// That this TPM opens it is the next boot's proof.
func (s *GateService) TakeRelease(r *attest.Release) (uint8, string) {
	<-s.Ready
	if s.Code != 0 || s.Blob == nil || s.be == nil || s.be.Sealed == nil {
		return attest.ReleaseUnsupported, "this machine has no slot to open a phone salt with"
	}
	if r == nil || r.Kind != attest.ReleaseKindFactor {
		return attest.ReleaseUnsupported, "not a phone salt"
	}
	s.mu.Lock()
	keep := s.keep
	s.mu.Unlock()
	if keep != nil {
		if !bytes.Equal(r.CredentialBlob, keep.CredentialBlob) || !bytes.Equal(r.EncryptedSecret, keep.EncryptedSecret) || r.Label != keep.Label {
			return attest.ReleaseTPMRefused, "the phone salt returned is not the one the phone was asked to keep"
		}
		s.mu.Lock()
		s.returned = true
		s.mu.Unlock()
		return attest.ReleaseOK, "the phone keeps the phone salt; this TPM opens it at the next boot"
	}
	defer func() {
		s.mu.Lock()
		s.Current.Releasing = false // taken, one way or the other
		s.mu.Unlock()
	}()
	s.TPMMu.Lock()
	f, err := UnwrapFactor(s.TPM, s.be.Sealed, s.be.SealIndex, s.Blob, &nvslot.WrappedFactor{Credential: r.CredentialBlob, EncryptedSecret: r.EncryptedSecret})
	s.TPMMu.Unlock()
	if err != nil {
		if errors.Is(err, ErrNoReleaseKey) {
			return attest.ReleaseUnsupported, err.Error()
		}
		return attest.ReleaseTPMRefused, "the TPM did not open the phone salt: " + err.Error()
	}
	salt := FactorSalt(f, r.Label)
	wipe.Bytes(f)
	s.mu.Lock()
	wipe.Bytes(s.salt)
	s.salt = salt
	s.Current.SaltTaken = true
	s.mu.Unlock()
	return attest.ReleaseOK, "the TPM opened the salt; the disk's key is derived from it and the password typed at the machine"
}

// Salt returns a copy of the combiner's salt from the released factor,
// or nil when no factor was released in this boot.
func (s *GateService) Salt() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.salt == nil {
		return nil
	}
	return append([]byte(nil), s.salt...)
}

// Returned says whether the phone gave back, at enrolment, what it was
// asked to keep.
func (s *GateService) Returned() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.returned
}

// Forget wipes the salt; called when the key provider is done with it.
func (s *GateService) Forget() {
	s.mu.Lock()
	defer s.mu.Unlock()
	wipe.Bytes(s.salt)
	s.salt = nil
}

func (s *GateService) JudgeReceipt(r *attest.Receipt, verifierID string) attest.ReceiptCheck {
	<-s.Ready
	if s.Code != 0 || r == nil {
		return attest.ReceiptCheck{Ack: attest.AckMalformed, Detail: "no slot is being served"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var verifier *attest.EnrolledVerifier
	for i := range s.Blob.Phone.Verifiers {
		if s.Blob.Phone.Verifiers[i].ID == verifierID {
			verifier = &s.Blob.Phone.Verifiers[i]
		}
	}
	if verifier == nil {
		return attest.ReceiptCheck{Verdict: r.Verdict, Ack: attest.AckBindingMismatch, Detail: "receipt from a phone that is not enrolled"}
	}
	qd, ok := s.Issued[hex.EncodeToString(r.QuoteDigest)]
	if !ok {
		return attest.ReceiptCheck{Verdict: r.Verdict, Ack: attest.AckBindingMismatch, Detail: "receipt is not bound to a quote of this boot"}
	}
	anchor, err := attest.ParseAnchor(verifier.AnchorPub)
	if err != nil {
		anchor = nil
	}
	check := attest.CheckReceipt(r, anchor, attest.ReceiptExpectation{
		DeviceID:    s.Blob.DeviceID,
		AKName:      s.Blob.AKName,
		QD:          qd,
		QuoteDigest: r.QuoteDigest,
		VerifierID:  verifier.ID,
	})
	if state := receiptState(check); state != "" {
		s.Current.State = state
		s.Current.Code = "" // the session it belonged to is answered
		if state == GateAttested && s.ExpectingRelease && len(s.Blob.ReleaseKeyPublic) > 0 {
			s.Current.Releasing = true
			s.ReleaseSince = time.Now()
		}
	}
	return check
}

// ExpectRelease says that the disk's key needs the phone's phone salt:
// an attested boot waits for the Release that follows the receipt.
func (s *GateService) ExpectRelease(expect bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ExpectingRelease = expect
}

// Report implements gateHost. A verdict, once given, stays.
func (s *GateService) Report(state GateState) {
	if state == GateSessionOver {
		s.mu.Lock()
		s.Current.Releasing = false // nothing more comes from that session
		s.mu.Unlock()
		return
	}
	if state != GateWaiting && state != GateSession && state != GateUnavailable {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Current.Verdict() || s.Current.State == GateRefused {
		return
	}
	if state != GateSession {
		s.Current.Code = "" // no session, no code to compare
	}
	s.Current.State = state
}

// Status is the gate's state for the code screen, and for whatever else
// acts on the outcome. False until there is something to say.
func (s *GateService) Status() (GateStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Current.Releasing && time.Since(s.ReleaseSince) > releaseWait {
		s.Current.Releasing = false // the bound: the boot never hangs on it
	}
	return s.Current, s.Current.State != ""
}

// receiptState is what a checked receipt means for the slot: the same
// reading reportReceipt gives on the console.
func receiptState(c attest.ReceiptCheck) GateState {
	switch {
	case c.Authentic && (c.Verdict == attest.VerdictOK || c.Verdict == attest.VerdictApproved):
		return GateAttested
	case c.Verdict == attest.VerdictReject && (c.Authentic || c.Ack == attest.AckRejectNoted):
		return GateRejected
	case c.Ack == attest.AckBadSignature:
		return GateRefused
	}
	return ""
}
