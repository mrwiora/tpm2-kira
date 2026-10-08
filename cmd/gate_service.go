package cmd

// The gate's coordinator: the half of remote attestation that holds the TPM.
//
// Attestation over Bluetooth is done by two processes of this one binary.
// The radio worker (tpm2-kira-attest.service) advertises, speaks the
// protocol with the phone and parses whatever the radio delivers; its unit
// gives it Bluetooth sockets and nothing else. The coordinator is the
// process that already owns the console and the TPM at boot (tpm2-kira run):
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

	"github.com/matthias/tpm2-kira/attest"
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
	Name     string `json:"name"`
	NoisePub []byte `json:"noise_pub"`
}

// gateHost is what the radio side of the gate needs from the TPM side:
// implemented by the coordinator itself (gateService) and, for the worker,
// by its connection to the coordinator (gateClient).
type gateHost interface {
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

// gateService is the coordinator for one enrolled slot.
type gateService struct {
	mu    sync.Mutex // status and the issued quotes
	tpmMu sync.Mutex // one TPM operation at a time; the code screen never waits for it

	ready  chan struct{} // closed when the slot is set up, or refused
	code   int           // why there is no slot to serve (an exit status), or 0
	reason error

	tpm            transport.TPM
	idx            uint32
	blob           *Attestation
	be             *tpmBackend
	recordVerified bool

	issued      map[string][]byte // SHA-256 of a quote issued this boot -> its qualifying data
	issuedOrder []string
	status      GateStatus

	// The factor (factor.go). keep is what 'factor enrol' asks the phone
	// to keep, sent in the evidence; salt is the combiner's salt from the
	// factor the phone released and the TPM opened, held for the moment
	// the disk's key is asked for (and wiped with Close).
	keep *attest.FactorBlob
	salt []byte
	// returned: at enrolment, the phone gave keep back unchanged.
	returned bool
	// expectRelease: the unlock mode needs the phone's remote salt, so a
	// receipt is followed by a Release that the boot waits for (bounded by
	// releaseWait from releaseSince).
	expectRelease bool
	releaseSince  time.Time
}

// releaseWait bounds how long the boot waits for the phone's remote salt
// after the receipt: the phone writes its record and sends one more
// message; a phone that has no salt sends Bye instead, which ends the
// wait at once. The bound is for a session that dies in between.
const releaseWait = 15 * time.Second

// newGateService sets the coordinator up in the background (the TPM can be
// slow, and the code screen must not wait for it): finds the enrolled slot,
// checks its record and loads it. tpmDev is used from then on and never
// closed here.
func newGateService(tpmDev transport.TPM, sealIndex uint32, signerPath string, debug bool) *gateService {
	s := &gateService{ready: make(chan struct{}), tpm: tpmDev, issued: map[string][]byte{}}
	go func() {
		defer close(s.ready)
		s.code, s.reason = s.setup(sealIndex, signerPath, debug)
		if s.code != 0 {
			s.mu.Lock()
			if s.code == ExitTampered {
				s.status.State = GateRefused
			} else {
				s.status.State = GateUnavailable
			}
			s.mu.Unlock()
		}
	}()
	return s
}

func (s *gateService) setup(sealIndex uint32, signerPath string, debug bool) (int, error) {
	var idx uint32
	var err error
	if sealIndex != 0 {
		if idx, err = AttestIndexForSlot(sealIndex); err != nil {
			return ExitUsage, err
		}
	} else {
		found := enrolledSlots(s.tpm, debug)
		if len(found) == 0 {
			return ExitUsage, errors.New("no slot is enrolled for attestation (run 'tpm2-kira attest enrol')")
		}
		idx = found[0]
	}
	s.mu.Lock()
	s.idx = idx
	s.status.Slot = int(attestSlot(idx))
	s.mu.Unlock()

	verified, code := gateRecordCheck(s.tpm, idx, signerPath) // prints its own failure
	if code != 0 {
		return code, errors.New("the attestation record is not accepted")
	}
	blob, err := loadAttestBlob(s.tpm, idx)
	if err != nil {
		return ExitInternal, fmt.Errorf("cannot read the attestation blob at 0x%08X: %w", idx, err)
	}
	if len(blob.Phone.Verifiers) == 0 {
		return ExitUsage, fmt.Errorf("no phone is enrolled for slot %d", attestSlot(idx))
	}
	if _, err := attest.NoiseKeypairFromPrivate(blob.Phone.NoisePrivate); err != nil {
		return ExitInternal, err
	}
	sealIdx := idx // the enrolment lives in the slot's own blob
	s.mu.Lock()
	s.blob = blob
	s.recordVerified = verified
	s.be = &tpmBackend{tpm: s.tpm, blob: blob, sealIndex: sealIdx, sealed: readSealedSlot(s.tpm, sealIdx), debug: debug}
	s.mu.Unlock()
	return 0, nil
}

// Identity implements gateHost.
func (s *gateService) Identity() (*gateIdentity, int, error) {
	<-s.ready
	if s.code != 0 {
		return nil, s.code, s.reason
	}
	id := &gateIdentity{
		Slot:           int(attestSlot(s.idx)),
		FriendlyName:   s.blob.FriendlyName,
		DeviceID:       s.blob.DeviceID,
		AKName:         s.blob.AKName,
		NoisePrivate:   s.blob.Phone.NoisePrivate,
		AdvKey:         s.blob.Phone.AdvKey,
		RecordVerified: s.recordVerified,
	}
	for _, v := range s.blob.Phone.Verifiers {
		id.Verifiers = append(id.Verifiers, gateVerifier{ID: v.ID, Name: v.Name, NoisePub: v.NoisePub})
	}
	return id, 0, nil
}

var errGateNotServing = errors.New("the coordinator has no slot to serve")

// Quote implements attest.AttesterBackend. It is the one TPM operation the
// radio side can cause: a quote by the attestation key, which says what the
// registers are and gives nothing away.
func (s *gateService) Quote(qd []byte, sel attest.PCRSelection) (*attest.QuoteResult, error) {
	<-s.ready
	if s.code != 0 {
		return nil, errGateNotServing
	}
	if len(qd) == 0 || len(qd) > 64 {
		return nil, errors.New("qualifying data of an unexpected size")
	}
	if err := sel.Validate(); err != nil {
		return nil, err
	}
	s.tpmMu.Lock()
	q, err := s.be.Quote(qd, sel)
	s.tpmMu.Unlock()
	if err != nil {
		return nil, err
	}
	// Remember it: a receipt counts only for a quote issued here.
	sum := sha256.Sum256(q.Quoted)
	key := hex.EncodeToString(sum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.issued[key]; !ok {
		s.issuedOrder = append(s.issuedOrder, key)
		if len(s.issuedOrder) > maxIssuedQuotes {
			delete(s.issued, s.issuedOrder[0])
			s.issuedOrder = s.issuedOrder[1:]
		}
	}
	s.issued[key] = append([]byte(nil), qd...)
	return q, nil
}

// ProveBootKey implements attest.AttesterBackend. The code the challenge
// carries goes to the code screen through Status; the radio side gets the
// proof and never the code.
func (s *gateService) ProveBootKey(ch *attest.BootChallenge, context, quoteDigest []byte) (*attest.BootAnswer, uint8) {
	<-s.ready
	if s.code != 0 || ch == nil {
		return nil, attest.BootKeyFailed
	}
	s.tpmMu.Lock()
	answer, state := s.be.ProveBootKey(ch, context, quoteDigest)
	code := s.be.bootCode
	s.tpmMu.Unlock()
	s.mu.Lock()
	s.status.Code = attest.FormatBootCode(code)
	if state != attest.BootKeyProved {
		s.status.Code = ""
	}
	s.mu.Unlock()
	return answer, state
}

// BootContext implements attest.AttesterBackend.
func (s *gateService) BootContext() attest.BootContext {
	<-s.ready
	if s.code != 0 {
		return attest.BootContext{}
	}
	s.tpmMu.Lock()
	defer s.tpmMu.Unlock()
	return s.be.BootContext()
}

// Eventlog implements attest.AttesterBackend.
func (s *gateService) Eventlog() ([]byte, error) {
	<-s.ready
	if s.code != 0 {
		return nil, errGateNotServing
	}
	s.tpmMu.Lock()
	defer s.tpmMu.Unlock()
	return s.be.Eventlog()
}

// JudgeReceipt implements attest.ReceiptJudge: the receipt must be bound to
// a quote this coordinator issued, name an enrolled phone, and carry that
// phone's signature. What the radio side believes about its session plays
// no part.
// Keep sets the factor the next evidence asks the phone to keep.
func (s *gateService) Keep(f *attest.FactorBlob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keep = f
}

// FactorToKeep implements attest.FactorBackend.
func (s *gateService) FactorToKeep() *attest.FactorBlob {
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
func (s *gateService) TakeRelease(r *attest.Release) (uint8, string) {
	<-s.ready
	if s.code != 0 || s.blob == nil || s.be == nil || s.be.sealed == nil {
		return attest.ReleaseUnsupported, "this machine has no slot to open a remote salt with"
	}
	if r == nil || r.Kind != attest.ReleaseKindFactor {
		return attest.ReleaseUnsupported, "not a remote salt"
	}
	s.mu.Lock()
	keep := s.keep
	s.mu.Unlock()
	if keep != nil {
		if !bytes.Equal(r.CredentialBlob, keep.CredentialBlob) || !bytes.Equal(r.EncryptedSecret, keep.EncryptedSecret) || r.Label != keep.Label {
			return attest.ReleaseTPMRefused, "the remote salt returned is not the one the phone was asked to keep"
		}
		s.mu.Lock()
		s.returned = true
		s.mu.Unlock()
		return attest.ReleaseOK, "the phone keeps the remote salt; this TPM opens it at the next boot"
	}
	defer func() {
		s.mu.Lock()
		s.status.Releasing = false // taken, one way or the other
		s.mu.Unlock()
	}()
	s.tpmMu.Lock()
	f, err := unwrapFactor(s.tpm, s.be.sealed, s.be.sealIndex, s.blob, &WrappedFactor{Credential: r.CredentialBlob, EncryptedSecret: r.EncryptedSecret})
	s.tpmMu.Unlock()
	if err != nil {
		if errors.Is(err, errNoReleaseKey) {
			return attest.ReleaseUnsupported, err.Error()
		}
		return attest.ReleaseTPMRefused, "the TPM did not open the remote salt: " + err.Error()
	}
	salt := FactorSalt(f, r.Label)
	wipe(f)
	s.mu.Lock()
	wipe(s.salt)
	s.salt = salt
	s.status.SaltTaken = true
	s.mu.Unlock()
	return attest.ReleaseOK, "the TPM opened the salt; the disk's key is derived from it and the password typed at the machine"
}

// Salt returns a copy of the combiner's salt from the released factor,
// or nil when no factor was released in this boot.
func (s *gateService) Salt() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.salt == nil {
		return nil
	}
	return append([]byte(nil), s.salt...)
}

// Returned says whether the phone gave back, at enrolment, what it was
// asked to keep.
func (s *gateService) Returned() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.returned
}

// Forget wipes the salt; called when the key provider is done with it.
func (s *gateService) Forget() {
	s.mu.Lock()
	defer s.mu.Unlock()
	wipe(s.salt)
	s.salt = nil
}

func (s *gateService) JudgeReceipt(r *attest.Receipt, verifierID string) attest.ReceiptCheck {
	<-s.ready
	if s.code != 0 || r == nil {
		return attest.ReceiptCheck{Ack: attest.AckMalformed, Detail: "no slot is being served"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var verifier *attest.EnrolledVerifier
	for i := range s.blob.Phone.Verifiers {
		if s.blob.Phone.Verifiers[i].ID == verifierID {
			verifier = &s.blob.Phone.Verifiers[i]
		}
	}
	if verifier == nil {
		return attest.ReceiptCheck{Verdict: r.Verdict, Ack: attest.AckBindingMismatch, Detail: "receipt from a phone that is not enrolled"}
	}
	qd, ok := s.issued[hex.EncodeToString(r.QuoteDigest)]
	if !ok {
		return attest.ReceiptCheck{Verdict: r.Verdict, Ack: attest.AckBindingMismatch, Detail: "receipt is not bound to a quote of this boot"}
	}
	anchor, err := attest.ParseAnchor(verifier.AnchorPub)
	if err != nil {
		anchor = nil
	}
	check := attest.CheckReceipt(r, anchor, attest.ReceiptExpectation{
		DeviceID:    s.blob.DeviceID,
		AKName:      s.blob.AKName,
		QD:          qd,
		QuoteDigest: r.QuoteDigest,
		VerifierID:  verifier.ID,
	})
	if state := receiptState(check); state != "" {
		s.status.State = state
		s.status.Phone = verifierName(verifier)
		s.status.Code = "" // the session it belonged to is answered
		if state == GateAttested && s.expectRelease && len(s.blob.ReleaseKeyPublic) > 0 {
			s.status.Releasing = true
			s.releaseSince = time.Now()
		}
	}
	return check
}

// ExpectRelease says that the disk's key needs the phone's remote salt:
// an attested boot waits for the Release that follows the receipt.
func (s *gateService) ExpectRelease(expect bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expectRelease = expect
}

// Report implements gateHost. A verdict, once given, stays.
func (s *gateService) Report(state GateState) {
	if state == GateSessionOver {
		s.mu.Lock()
		s.status.Releasing = false // nothing more comes from that session
		s.mu.Unlock()
		return
	}
	if state != GateWaiting && state != GateSession && state != GateUnavailable {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.Verdict() || s.status.State == GateRefused {
		return
	}
	if state != GateSession {
		s.status.Code = "" // no session, no code to compare
	}
	s.status.State = state
}

// Status is the gate's state for the code screen, and for whatever else
// acts on the outcome. False until there is something to say.
func (s *gateService) Status() (GateStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.Releasing && time.Since(s.releaseSince) > releaseWait {
		s.status.Releasing = false // the bound: the boot never hangs on it
	}
	return s.status, s.status.State != ""
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
