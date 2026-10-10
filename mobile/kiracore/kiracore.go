// Package kiracore is the phone's binding to the tpm2-kira verifier core,
// built with gomobile:
//
//	gomobile bind -target=android -androidapi 28 -o kiracore.aar ./mobile/kiracore
//	gomobile bind -target=ios,iossimulator -o Kiracore.xcframework ./mobile/kiracore
//
// The app moves bytes and pixels; every security decision is made here, by
// the same code that runs in the machine's tests (docs/PROTOCOL-BLE.md §1).
//
// Only gomobile-compatible types cross this boundary: string, []byte, int,
// bool and opaque objects. Structured data travels as JSON strings.
//
// Session methods return a *Step and never an error: under gomobile a
// returned error becomes an exception and the other return value is lost —
// but a failing step still carries the Error record that tells the machine
// to stop. Check Step.Err() instead, and always transmit Step's fragments.
package kiracore

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/mrwiora/tpm2-kira/attest"
	"github.com/mrwiora/tpm2-kira/transport/frame"
)

// ProtocolVersion is the INFO characteristic's protocol byte this core speaks.
func ProtocolVersion() int { return 1 }

// SchemaVersion is the message schema this core speaks.
func SchemaVersion() int { return attest.SchemaVersion }

// UUIDs of the tpm2-kira GATT service (docs/PROTOCOL-BLE.md §3).
const (
	ServiceUUID = "883f0100-9727-459b-a589-a62200c064c0"
	RXCharUUID  = "883f0101-9727-459b-a589-a62200c064c0"
	TXCharUUID  = "883f0102-9727-459b-a589-a62200c064c0"
	InfoUUID    = "883f0103-9727-459b-a589-a62200c064c0"
)

// Decisions for Session.Decide.
const (
	DecisionApproveOnce     = int(attest.DecisionApproveOnce)
	DecisionApproveRemember = int(attest.DecisionApproveRemember)
	DecisionReject          = int(attest.DecisionReject)
	// DecisionContinue confirms a matching boot: every verdict now waits
	// for the person, who compares the code with the machine's screen.
	DecisionContinue = int(attest.DecisionContinue)
)

// Advertisement flags (service data byte 0).
const (
	AdvFlagEnrol  = int(attest.AdvFlagEnrol)
	AdvFlagAttest = int(attest.AdvFlagAttest)
)

// AdvertisementFlags returns the flags byte of a tpm2-kira scan response's
// service data, or -1 if the data is not 13 bytes.
func AdvertisementFlags(serviceData []byte) int {
	if len(serviceData) != attest.AdvServiceDataSize {
		return -1
	}
	return int(serviceData[0])
}

// MatchAdvertisement reports whether service data was produced by the
// machine described by recordJSON. Use it to label a scan result with the
// machine's name before connecting.
func MatchAdvertisement(serviceData []byte, recordJSON string) bool {
	var rec attest.MachineRecord
	if json.Unmarshal([]byte(recordJSON), &rec) != nil {
		return false
	}
	return attest.MatchServiceData(serviceData, rec.AdvKey)
}

// CheckAnchorAttestation runs the machine's check of an anchor key
// attestation (attest.VerifyPhoneAttestation) and returns its result as JSON:
// {"verified","root","security_level","boot_state","device_locked",
// "unlock","patch_level","problems"}. The machine decides; the app may use
// this only to show what the machine will see, and tests use it to check
// real Android attestations against the machine's parser.
func CheckAnchorAttestation(chainDER, spkiDER, challenge []byte) string {
	a := attest.VerifyPhoneAttestation(chainDER, spkiDER, challenge, time.Now())
	b, _ := json.Marshal(struct {
		Verified      bool     `json:"verified"`
		Root          string   `json:"root"`
		SecurityLevel string   `json:"security_level"`
		BootState     string   `json:"boot_state"`
		DeviceLocked  bool     `json:"device_locked"`
		Unlock        string   `json:"unlock"`
		PatchLevel    string   `json:"patch_level"`
		Problems      []string `json:"problems"`
	}{a.Verified, a.Root, a.SecurityLevel, a.BootState, a.DeviceLocked, a.Unlock, a.PatchLevel, a.Problems})
	return string(b)
}

// EKVendors returns, as a JSON array of names, the TPM vendors whose EK
// certificates this core can verify (attest/ekroots/vendors.json).
func EKVendors() string {
	b, _ := json.Marshal(attest.EKVendorNames())
	return string(b)
}

// RecordSummary returns display fields of a stored machine record as JSON:
// {"device_id","friendly_name","enrolled_at","last_attested","profiles","slot","ek_verified_by"}.
func RecordSummary(recordJSON string) (string, error) {
	var rec attest.MachineRecord
	if err := json.Unmarshal([]byte(recordJSON), &rec); err != nil {
		return "", err
	}
	if err := rec.Validate(); err != nil {
		return "", err
	}
	type profile struct {
		Name      string     `json:"name"`
		ValidFrom time.Time  `json:"valid_from"`
		AddedBy   string     `json:"added_by,omitempty"`
		UsesLeft  *uint32    `json:"uses_left,omitempty"`
		Until     *time.Time `json:"valid_until,omitempty"`
	}
	out := struct {
		DeviceID     string     `json:"device_id"`
		FriendlyName string     `json:"friendly_name"`
		EnrolledAt   time.Time  `json:"enrolled_at"`
		LastAttested *time.Time `json:"last_attested,omitempty"`
		Slot         uint8      `json:"slot"`
		Profiles     []profile  `json:"profiles"`
		EKVerifiedBy string     `json:"ek_verified_by,omitempty"`
		// A kept disk factor (PLAN-FACTORRELEASE.md): when it was kept.
		FactorKeptAt *time.Time `json:"factor_kept_at,omitempty"`
	}{FriendlyName: rec.FriendlyName, EnrolledAt: rec.EnrolledAt, LastAttested: rec.LastAttested, Slot: rec.Slot, EKVerifiedBy: rec.EKVerifiedBy}
	if rec.HasFactor() {
		t := rec.Factor.KeptAt
		out.FactorKeptAt = &t
	}
	id, _ := rec.DeviceID.MarshalText()
	out.DeviceID = string(id)
	for _, p := range rec.Policy.Profiles {
		out.Profiles = append(out.Profiles, profile{Name: p.Name, ValidFrom: p.ValidFrom, AddedBy: p.AddedBy, UsesLeft: p.UsesLeft, Until: p.ValidUntil})
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// Config is the phone's settings, given as JSON to the session
// constructors:
//
//	{"policy_id": "default", "receipt_ttl_seconds": 300}
//
// The phone's identity towards a machine (its static Noise key and verifier
// id) is no setting: enrolment makes a new one for every machine and keeps
// it in that machine's record, so no two machines see the same phone, and
// one app attests any number of machines, each through its own record.
type config struct {
	PolicyID   string `json:"policy_id"`
	ReceiptTTL int    `json:"receipt_ttl_seconds"`
}

func parseConfig(cfgJSON string) (attest.VerifierConfig, error) {
	var c config
	if err := json.Unmarshal([]byte(cfgJSON), &c); err != nil {
		return attest.VerifierConfig{}, err
	}
	return attest.VerifierConfig{
		PolicyID:   c.PolicyID,
		ReceiptTTL: time.Duration(c.ReceiptTTL) * time.Second,
	}, nil
}

// Session is one BLE connection's protocol session, enrolment or attestation.
// All methods are safe to call from any thread; calls are serialised.
type Session struct {
	mu   sync.Mutex
	v    *attest.Verifier
	frag *frame.Fragmenter
	reas *frame.Reassembler
	tbs  []byte
}

func newSession(v *attest.Verifier) *Session {
	f, _ := frame.NewFragmenter(frame.MinFragment)
	return &Session{v: v, frag: f, reas: frame.NewReassembler(frame.MaxRecord, frame.DefaultBudget.MaxBytes)}
}

// NewEnrolSession prepares an enrolment. Connect only to a machine whose
// advertisement has AdvFlagEnrol set.
func NewEnrolSession(cfgJSON string) (*Session, error) {
	cfg, err := parseConfig(cfgJSON)
	if err != nil {
		return nil, err
	}
	v, err := attest.NewEnrolVerifier(cfg)
	if err != nil {
		return nil, err
	}
	return newSession(v), nil
}

// NewAttestSession prepares an attestation of the machine in recordJSON.
func NewAttestSession(cfgJSON string, recordJSON string) (*Session, error) {
	cfg, err := parseConfig(cfgJSON)
	if err != nil {
		return nil, err
	}
	var rec attest.MachineRecord
	if err := json.Unmarshal([]byte(recordJSON), &rec); err != nil {
		return nil, err
	}
	v, err := attest.NewAttestVerifier(cfg, &rec)
	if err != nil {
		return nil, err
	}
	return newSession(v), nil
}

// SetMaxFragment sets the largest RX write: the negotiated ATT MTU minus 3.
// Call it after the MTU exchange and before Start; it may be called again
// if the MTU changes. Minimum 20.
func (s *Session) SetMaxFragment(n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frag.SetMax(n)
}

// Start produces the first handshake message. Call it once notifications on
// TX are enabled.
func (s *Session) Start() *Step {
	return s.run(func() (*attest.Output, error) { return s.v.Start() })
}

// OnNotification feeds one TX notification value received from the machine.
func (s *Session) OnNotification(fragment []byte) *Step {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.reas.Feed(fragment)
	if err != nil {
		out := s.v.Abort("framing error: " + err.Error())
		return s.step(out, err)
	}
	if rec == nil {
		return &Step{}
	}
	out, err := s.v.HandleRecord(rec)
	return s.step(out, err)
}

// ConfirmSAS reports whether the six digits on the phone and on the
// machine's console are the same.
func (s *Session) ConfirmSAS(match bool) *Step {
	return s.run(func() (*attest.Output, error) { return s.v.ConfirmSAS(match) })
}

// ProvideAnchorKey hands over the public key of the newly created,
// non-exportable, biometry-bound ECDSA P-256 keystore key, as
// SubjectPublicKeyInfo DER (91 bytes).
func (s *Session) ProvideAnchorKey(spkiDER []byte) *Step {
	return s.run(func() (*attest.Output, error) { return s.v.ProvideAnchorKey(spkiDER) })
}

// ProvideAnchorKeyAttested is ProvideAnchorKey with the key's attestation
// certificate chain (Android: KeyStore.getCertificateChain, concatenated DER,
// leaf first). Create the key with the need_anchor_key event's
// attestation_challenge. The machine judges the chain; nil if unavailable.
func (s *Session) ProvideAnchorKeyAttested(spkiDER, attestationDER []byte) *Step {
	return s.run(func() (*attest.Output, error) { return s.v.ProvideAnchorKeyAttested(spkiDER, attestationDER) })
}

// PendingTBS returns the bytes to sign for the last need_signature event:
// sign them with the anchor key as ECDSA P-256 over SHA-256 (the platform
// hashes), DER-encoded.
func (s *Session) PendingTBS() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.tbs...)
}

// ProvideSignature hands over the DER signature over PendingTBS().
func (s *Session) ProvideSignature(derSig []byte) *Step {
	return s.run(func() (*attest.Output, error) { return s.v.ProvideSignature(derSig) })
}

// Decide answers a verdict event with needs_decision. Approving a verdict
// whose state is "failed" requires confirmName to equal the machine's name,
// typed by the user.
func (s *Session) Decide(decision int, confirmName string) *Step {
	return s.run(func() (*attest.Output, error) { return s.v.Decide(attest.Decision(decision), confirmName) })
}

// RequestEventlog asks the machine for its event log while a decision is
// pending; progress arrives as eventlog events.
func (s *Session) RequestEventlog() *Step {
	return s.run(func() (*attest.Output, error) { return s.v.RequestEventlog() })
}

// Eventlog returns the transferred event log once complete, else nil.
func (s *Session) Eventlog() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v.Eventlog()
}

// Abort ends the session; transmit the returned fragments, then disconnect.
func (s *Session) Abort(reason string) *Step {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.step(s.v.Abort(reason), nil)
}

// Finished reports whether the session has ended; disconnect when it has.
func (s *Session) Finished() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v.Finished()
}

// Succeeded reports whether the session ended normally.
func (s *Session) Succeeded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v.Succeeded()
}

// RecordJSON returns the current machine record (after enrolment, or the
// updated one after attestation), or "" if there is none.
func (s *Session) RecordJSON() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.v.Record(); r != nil {
		b, err := json.Marshal(r)
		if err == nil {
			return string(b)
		}
	}
	return ""
}

func (s *Session) run(f func() (*attest.Output, error)) *Step {
	s.mu.Lock()
	defer s.mu.Unlock()
	out, err := f()
	return s.step(out, err)
}

// step converts an Output into fragments and JSON events.
func (s *Session) step(out *attest.Output, err error) *Step {
	st := &Step{}
	if err != nil {
		st.err = err.Error()
	}
	if out == nil {
		return st
	}
	for _, r := range out.Records {
		frags, ferr := s.frag.Split(r)
		if ferr != nil {
			if st.err != "" {
				st.err += "; "
			}
			st.err += ferr.Error()
			continue
		}
		st.fragments = append(st.fragments, frags...)
	}
	for _, e := range out.Events {
		if e.Type == attest.EvNeedSignature {
			s.tbs = append([]byte(nil), e.TBS...)
		}
		b, jerr := json.Marshal(e)
		if jerr == nil {
			st.events = append(st.events, string(b))
		}
	}
	return st
}

// Step is the result of one call: fragments to write to RX, in order, with
// Write Without Response, and events (JSON) to show or act on.
type Step struct {
	fragments [][]byte
	events    []string
	err       string
}

// FragmentCount is the number of RX writes to perform.
func (st *Step) FragmentCount() int { return len(st.fragments) }

// Fragment returns RX write i.
func (st *Step) Fragment(i int) []byte {
	if i < 0 || i >= len(st.fragments) {
		return nil
	}
	return st.fragments[i]
}

// EventCount is the number of events.
func (st *Step) EventCount() int { return len(st.events) }

// Event returns event i as JSON (docs/PROTOCOL-BLE.md §7).
func (st *Step) Event(i int) string {
	if i < 0 || i >= len(st.events) {
		return ""
	}
	return st.events[i]
}

// Err is non-empty when the call failed. A failed call may still carry
// fragments (an Error message for the machine): send them anyway. Whether
// the session is over is Session.Finished(), not Err().
func (st *Step) Err() string { return st.err }
