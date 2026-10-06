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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

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
	attest.AttesterBackend
	attest.ReceiptJudge
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
	blob           *AttestBlob
	be             *tpmBackend
	recordVerified bool

	issued      map[string][]byte // SHA-256 of a quote issued this boot -> its qualifying data
	issuedOrder []string
	status      GateStatus
}

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
	if len(blob.Verifiers) == 0 {
		return ExitUsage, fmt.Errorf("no phone is enrolled for slot %d", attestSlot(idx))
	}
	if _, err := attest.NoiseKeypairFromPrivate(blob.NoisePrivate); err != nil {
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
		NoisePrivate:   s.blob.NoisePrivate,
		AdvKey:         s.blob.AdvKey,
		RecordVerified: s.recordVerified,
	}
	for _, v := range s.blob.Verifiers {
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
func (s *gateService) JudgeReceipt(r *attest.Receipt, verifierID string) attest.ReceiptCheck {
	<-s.ready
	if s.code != 0 || r == nil {
		return attest.ReceiptCheck{Ack: attest.AckMalformed, Detail: "no slot is being served"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var verifier *attest.EnrolledVerifier
	for i := range s.blob.Verifiers {
		if s.blob.Verifiers[i].ID == verifierID {
			verifier = &s.blob.Verifiers[i]
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
	}
	return check
}

// Report implements gateHost. A verdict, once given, stays.
func (s *gateService) Report(state GateState) {
	if state != GateWaiting && state != GateSession && state != GateUnavailable {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.Verdict() || s.status.State == GateRefused {
		return
	}
	s.status.State = state
}

// Status is the gate's state for the code screen, and for whatever else
// acts on the outcome. False until there is something to say.
func (s *gateService) Status() (GateStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
