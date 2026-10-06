package attest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	. "github.com/matthias/tpm2-kira/attest"
	"github.com/matthias/tpm2-kira/attest/attesttest"
)

func newMachine(t *testing.T) *attesttest.Machine {
	m, err := attesttest.NewMachine()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func newPhone(t *testing.T) *attesttest.Phone {
	p, err := attesttest.NewPhone()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newSoftTPM(t *testing.T) *attesttest.SoftTPM {
	s, err := attesttest.NewSoftTPM()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// enrol runs a full enrolment and returns the phone's record.
func enrol(t *testing.T, m *attesttest.Machine, p *attesttest.Phone) *MachineRecord {
	t.Helper()
	a, b := attesttest.NewPipe()
	type res struct {
		be  *attesttest.SoftEnrol
		err error
	}
	done := make(chan res, 1)
	go func() {
		be, err := m.ServeEnrolment(a, true)
		a.Close()
		done <- res{be, err}
	}()
	v, err := NewEnrolVerifier(p.Config())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Drive(v, b); err != nil {
		t.Fatalf("phone: %v", err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("machine: %v", r.err)
	}
	if r.be.SASSeen == "" || r.be.SASSeen != p.SAS {
		t.Fatalf("SAS differs: machine %q phone %q", r.be.SASSeen, p.SAS)
	}
	if p.Record == nil {
		t.Fatal("phone got no record")
	}
	return p.Record
}

// attestOnce runs one attestation and returns the machine's result.
func attestOnce(t *testing.T, m *attesttest.Machine, p *attesttest.Phone, rec *MachineRecord) (*AttestResult, error, error) {
	t.Helper()
	a, b := attesttest.NewPipe()
	type r struct {
		res *AttestResult
		err error
	}
	done := make(chan r, 1)
	go func() {
		res, err := ServeAttestation(a, m.AttestIdentity(), m.TPM, nil)
		a.Close()
		done <- r{res, err}
	}()
	v, err := NewAttestVerifier(p.Config(), rec)
	if err != nil {
		t.Fatal(err)
	}
	perr := p.Drive(v, b)
	b.Close()
	got := <-done
	return got.res, got.err, perr
}

func TestEnrolAndAttestMatch(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	rec := enrol(t, m, p)

	if !bytes.Equal(rec.AKName, m.TPM.AKName) || !bytes.Equal(rec.MachineNoisePub, m.Noise.Public) {
		t.Fatal("record does not pin the machine's keys")
	}
	if !EqualKeys(m.Verifier.NoisePub, p.Noise.Public) {
		t.Fatal("machine did not pin the phone's Noise key")
	}
	if rec.ResetCount != m.TPM.ResetCount {
		t.Fatalf("reset count not pinned: %d", rec.ResetCount)
	}

	m.TPM.ResetCount++ // next boot
	res, merr, perr := attestOnce(t, m, p, rec)
	if merr != nil || perr != nil {
		t.Fatalf("machine %v phone %v", merr, perr)
	}
	if !res.Check.Authentic || res.Check.Verdict != VerdictOK || res.Check.Ack != AckAccepted {
		t.Fatalf("receipt not accepted: %+v", res.Check)
	}
	if p.Record.LastAttested == nil || p.Record.ResetCount != m.TPM.ResetCount {
		t.Fatal("record not updated after attestation")
	}
}

func TestAttestChangedApproveAndRemember(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	rec := enrol(t, m, p)

	m.TPM.Extend(4, "new bootloader")
	m.TPM.ResetCount++
	p.Decision = DecisionApproveRemember
	p.WantLog = true
	res, merr, perr := attestOnce(t, m, p, rec)
	if merr != nil || perr != nil {
		t.Fatalf("machine %v phone %v", merr, perr)
	}
	if res.Check.Verdict != VerdictApproved || !res.Check.Authentic {
		t.Fatalf("expected an authentic approval, got %+v", res.Check)
	}
	verdict := p.Last(EvVerdict).Verdict
	if verdict == nil || verdict.State != StateChanged || len(verdict.PCRDiff) != 1 || verdict.PCRDiff[0].Index != 4 {
		t.Fatalf("expected a one-register diff on PCR 4, got %+v", verdict)
	}
	if e := p.Last(EvEventlog); e == nil || !e.Complete {
		t.Fatal("event log was not transferred")
	}
	if len(p.Record.Policy.Profiles) != 2 {
		t.Fatalf("approved state was not remembered: %d profiles", len(p.Record.Policy.Profiles))
	}

	// The remembered state now matches without a decision.
	p.Events = nil
	p.WantLog = false
	m.TPM.ResetCount++
	res, merr, perr = attestOnce(t, m, p, p.Record)
	if merr != nil || perr != nil {
		t.Fatalf("machine %v phone %v", merr, perr)
	}
	if res.Check.Verdict != VerdictOK {
		t.Fatalf("remembered profile did not match: %+v", res.Check)
	}
}

func TestAttestRejectIsUnsignedAndNoted(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	rec := enrol(t, m, p)
	m.TPM.Extend(7, "secure boot off")
	p.Decision = DecisionReject
	res, merr, perr := attestOnce(t, m, p, rec)
	if merr != nil || perr != nil {
		t.Fatalf("machine %v phone %v", merr, perr)
	}
	if res.Check.Verdict != VerdictReject || res.Check.Ack != AckRejectNoted || res.Check.Authentic {
		t.Fatalf("unexpected check %+v", res.Check)
	}
	if len(res.Receipt.Signature) != 0 {
		t.Fatal("reject should go out unsigned")
	}
}

func TestFailedApprovalNeedsTypedName(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	rec := enrol(t, m, p)
	m.TPM.ResetCount = rec.ResetCount - 1 // a hard failure
	p.Decision = DecisionApproveOnce
	_, _, perr := attestOnce(t, m, p, rec)
	if perr == nil {
		t.Fatal("approving a failed attestation without the typed name must be refused")
	}
	p.Events = nil
	p.Confirm = "Thinkpad-X1"
	res, merr, perr := attestOnce(t, m, p, rec)
	if merr != nil || perr != nil || res.Check.Verdict != VerdictApproved {
		t.Fatalf("typed-name approval failed: machine %v phone %v", merr, perr)
	}
}

func TestUnknownPhoneGetsNoAnswer(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	rec := enrol(t, m, p)
	stranger := newPhone(t)
	res, merr, perr := attestOnce(t, m, stranger, rec)
	if !errors.Is(merr, ErrUnknownVerifier) {
		t.Fatalf("machine should refuse an unknown phone, got %v (%v)", merr, res)
	}
	if perr == nil {
		t.Fatal("stranger's session should fail")
	}
}

func TestWrongMachineFailsHandshake(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	rec := enrol(t, m, p)
	other := newMachine(t)
	other.Verifier = m.Verifier
	_, merr, perr := attestOnce(t, other, p, rec)
	if merr == nil || perr == nil {
		t.Fatalf("handshake with the wrong machine must fail: machine %v phone %v", merr, perr)
	}
}

func runEnrolExpectFailure(t *testing.T, m *attesttest.Machine, p *attesttest.Phone, be attesttest.EnrolBackendFunc) *attesttest.SoftEnrol {
	t.Helper()
	a, b := attesttest.NewPipe()
	soft := &attesttest.SoftEnrol{SoftTPM: m.TPM, SASAnswer: true}
	done := make(chan error, 1)
	go func() {
		_, err := ServeEnrolment(a, m.EnrolIdentity(), be(soft), nil)
		a.Close()
		done <- err
	}()
	v, _ := NewEnrolVerifier(p.Config())
	if err := p.Drive(v, b); err == nil {
		t.Fatal("phone should see the session fail")
	}
	if err := <-done; err == nil {
		t.Fatal("machine should abort")
	}
	if soft.Committed != nil {
		t.Fatal("nothing may be committed after a failed enrolment")
	}
	return soft
}

func TestSASRejectedOnMachineAborts(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	runEnrolExpectFailure(t, m, p, func(s *attesttest.SoftEnrol) EnrolBackend {
		s.SASAnswer = false
		return s
	})
}

func TestSASRejectedOnPhoneAborts(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	p.SASAnswer = false
	runEnrolExpectFailure(t, m, p, func(s *attesttest.SoftEnrol) EnrolBackend { return s })
}

// forgedActivation simulates an AK that is not in the EK's TPM.
type forgedActivation struct{ *attesttest.SoftEnrol }

func (b forgedActivation) ActivateCredential(blob, enc []byte) ([]byte, error) {
	other := make([]byte, 32)
	rand.Read(other)
	return other, nil // a forger can only guess
}

func TestActivationMismatchAborts(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	runEnrolExpectFailure(t, m, p, func(s *attesttest.SoftEnrol) EnrolBackend { return forgedActivation{s} })
}

func TestSoftActivateRejectsOtherName(t *testing.T) {
	s := newSoftTPM(t)
	secret := bytes.Repeat([]byte{9}, 32)
	blob, enc, err := MakeCredential(nil, s.EKPub, s.AKName, secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.ActivateCredential(blob, enc)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round trip failed: %v", err)
	}
	other := newSoftTPM(t)
	blob, enc, _ = MakeCredential(nil, s.EKPub, other.AKName, secret)
	if _, err := s.ActivateCredential(blob, enc); err == nil {
		t.Fatal("credential bound to another AK Name must not activate")
	}
}

// ---- Verify() corpus ----

type corpusCase struct {
	name   string
	mutate func(f *fixture)
	state  string
	reason string
}

type fixture struct {
	tpm    *attesttest.SoftTPM
	pol    *Policy
	pin    *PinnedIdentity
	qd     []byte
	ev     *Evidence
	now    time.Time
	sel    PCRSelection
	quoteQ []byte // qualifying data used when producing the quote
}

func newFixture(t *testing.T) *fixture {
	s := newSoftTPM(t)
	sel, _ := NewPCRSelection(AlgSHA256, []int{0, 7, 11})
	f := &fixture{tpm: s, sel: sel, now: time.Date(2026, 10, 4, 7, 0, 0, 0, time.UTC)}
	f.qd = bytes.Repeat([]byte{0xAA}, 32)
	f.quoteQ = f.qd
	var vals []PCRValue
	for _, i := range sel.Indices {
		vals = append(vals, PCRValue{Index: i, Digest: s.PCRs[i]})
	}
	f.pol = &Policy{ID: "default", Selection: sel.Indices, PCRAlg: AlgSHA256,
		Profiles: []Profile{ProfileFromValues("baseline", vals, f.now.Add(-time.Hour), "test")}}
	f.pin = &PinnedIdentity{DeviceID: bytes.Repeat([]byte{1}, 16), AKPub: s.AKPub, AKName: s.AKName, ResetCount: s.ResetCount, FirmwareVersion: s.Firmware}
	return f
}

func (f *fixture) build(t *testing.T) {
	q, err := f.tpm.Quote(f.quoteQ, f.sel)
	if err != nil {
		t.Fatal(err)
	}
	f.ev = &Evidence{Schema: SchemaVersion, DeviceID: f.pin.DeviceID, AKName: f.tpm.AKName,
		Quoted: q.Quoted, Signature: q.Signature, PCRAlg: f.sel.Alg, PCRValues: q.Values}
}

func TestVerifyCorpus(t *testing.T) {
	cases := []corpusCase{
		{"good", func(f *fixture) {}, StateMatch, ""},
		{"replayed (other qd)", func(f *fixture) { f.quoteQ = bytes.Repeat([]byte{0xBB}, 32) }, StateFailed, ReasonQDMismatch},
		{"wrong magic", func(f *fixture) {
			f.tpm.TamperQuote = func(a *tpm2.TPMSAttest) { a.Magic = 0x12345678 }
		}, StateFailed, ReasonBadMagic},
		{"non-quote type", func(f *fixture) {
			f.tpm.TamperQuote = func(a *tpm2.TPMSAttest) {
				a.Type = tpm2.TPMSTAttestTime
				a.Attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestTime, &tpm2.TPMSTimeAttestInfo{})
			}
		}, StateFailed, ReasonBadType},
		{"weaker selection", func(f *fixture) {
			weak, _ := NewPCRSelection(AlgSHA256, []int{0})
			f.tpm.TamperQuote = func(a *tpm2.TPMSAttest) {
				q, _ := a.Attested.Quote()
				q.PCRSelect = weak.ToTPM()
			}
		}, StateFailed, ReasonSelectionMismatch},
		{"reset count backwards", func(f *fixture) { f.tpm.ResetCount = f.pin.ResetCount - 1 }, StateFailed, ReasonResetCountDecreased},
		{"pinned firmware changed", func(f *fixture) {
			fw := f.tpm.Firmware + 1
			f.pol.FirmwareVersion = &fw
		}, StateFailed, ReasonFirmwareChanged},
		{"expired profile", func(f *fixture) {
			until := f.now.Add(-time.Minute)
			f.pol.Profiles[0].ValidUntil = &until
		}, StateChanged, ReasonNoProfileMatch},
		{"exhausted pre-registered profile", func(f *fixture) {
			zero := uint32(0)
			f.pol.Profiles[0].UsesLeft = &zero
		}, StateChanged, ReasonNoProfileMatch},
		{"changed PCR", func(f *fixture) { f.tpm.Extend(11, "new kernel") }, StateChanged, ReasonNoProfileMatch},
		{"other AK pinned", func(f *fixture) {
			o := newSoftTPM(t)
			f.pin.AKPub, f.pin.AKName = o.AKPub, o.AKName
		}, StateFailed, ReasonAKMismatch},
		{"clock unsafe required", func(f *fixture) { f.tpm.Safe = false; f.pol.RequireClockSafe = true }, StateFailed, ReasonClockUnsafe},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			c.mutate(f)
			f.build(t)
			v := Verify(f.ev, f.pol, f.pin, f.qd, f.now)
			assertVerdict(t, v, c.state, c.reason)
		})
	}

	evidenceCases := []corpusCase{
		{"forged pcr_values", func(f *fixture) { f.ev.PCRValues[1].Digest = bytes.Repeat([]byte{0xEE}, 32) }, StateFailed, ReasonPCRDigestMismatch},
		{"missing pcr value", func(f *fixture) { f.ev.PCRValues = f.ev.PCRValues[:2] }, StateFailed, ReasonPCRValuesInvalid},
		{"bank downgrade claim", func(f *fixture) { f.ev.PCRAlg = AlgSHA1 }, StateFailed, ReasonPCRValuesInvalid},
		{"flipped quote byte", func(f *fixture) { f.ev.Quoted[len(f.ev.Quoted)-1] ^= 1 }, StateFailed, ReasonBadSignature},
		{"sha1 signature", func(f *fixture) {
			sig, _ := tpm2.Unmarshal[tpm2.TPMTSignature](f.ev.Signature)
			e, _ := sig.Signature.ECDSA()
			e.Hash = tpm2.TPMAlgSHA1
			f.ev.Signature = tpm2.Marshal(*sig)
		}, StateFailed, ReasonBadSignature},
		{"other device", func(f *fixture) { f.ev.DeviceID = bytes.Repeat([]byte{2}, 16) }, StateFailed, ReasonDeviceMismatch},
	}
	for _, c := range evidenceCases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.build(t)
			c.mutate(f)
			v := Verify(f.ev, f.pol, f.pin, f.qd, f.now)
			assertVerdict(t, v, c.state, c.reason)
		})
	}
}

func assertVerdict(t *testing.T, v *Verdict, state, reason string) {
	t.Helper()
	if v.State != state {
		t.Fatalf("state %q, want %q (reasons %+v)", v.State, state, v.Reasons)
	}
	if reason == "" {
		if len(v.Reasons) != 0 {
			t.Fatalf("unexpected reasons %+v", v.Reasons)
		}
		return
	}
	for _, r := range v.Reasons {
		if r.Code == reason {
			return
		}
	}
	t.Fatalf("reason %q not reported; got %+v", reason, v.Reasons)
}

// ---- receipts ----

func TestCheckReceipt(t *testing.T) {
	anchorKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	exp := ReceiptExpectation{DeviceID: bytes.Repeat([]byte{1}, 16), AKName: []byte{0, 11, 1}, QD: bytes.Repeat([]byte{2}, 32), QuoteDigest: bytes.Repeat([]byte{3}, 32), VerifierID: "phone-1"}
	mk := func(v VerdictCode, key *ecdsa.PrivateKey) *Receipt {
		r := &Receipt{Verdict: v, DeviceID: exp.DeviceID, AKName: exp.AKName, QD: exp.QD, QuoteDigest: exp.QuoteDigest, PolicyID: "default", IssuedAt: 1, ExpiresAt: 2, VerifierID: "phone-1"}
		if key != nil {
			d := sha256.Sum256(ReceiptTBS(r))
			r.Signature, _ = ecdsa.SignASN1(rand.Reader, key, d[:])
		}
		return r
	}
	if c := CheckReceipt(mk(VerdictOK, anchorKey), &anchorKey.PublicKey, exp); !c.Authentic || c.Ack != AckAccepted {
		t.Fatalf("valid receipt rejected: %+v", c)
	}
	if c := CheckReceipt(mk(VerdictOK, otherKey), &anchorKey.PublicKey, exp); c.Authentic || c.Ack != AckBadSignature {
		t.Fatalf("foreign signature accepted: %+v", c)
	}
	if c := CheckReceipt(mk(VerdictOK, nil), &anchorKey.PublicKey, exp); c.Authentic {
		t.Fatal("unsigned OK accepted")
	}
	r := mk(VerdictOK, anchorKey)
	r.QD = bytes.Repeat([]byte{9}, 32) // receipt from another session
	if c := CheckReceipt(r, &anchorKey.PublicKey, exp); c.Authentic || c.Ack != AckBindingMismatch {
		t.Fatalf("moved receipt accepted: %+v", c)
	}
	r = mk(VerdictOK, anchorKey)
	r.Verdict = VerdictApproved // signature covers the verdict
	if c := CheckReceipt(r, &anchorKey.PublicKey, exp); c.Authentic {
		t.Fatal("verdict change not detected")
	}
}

func TestEnrolAcceptSignatureFormatChecked(t *testing.T) {
	// A raw r‖s signature (a common platform mistake) must be refused by
	// the core with a helpful error instead of being sent to the machine.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if _, err := ParseAnchor(der); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("x"))
	r, s, _ := ecdsa.Sign(rand.Reader, key, d[:])
	raw := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	if VerifyAnchorSignature(&key.PublicKey, []byte("x"), raw) {
		t.Fatal("raw signature must not verify as DER")
	}
}

// bootCheckValues returns the machine's live values with PCR 11 replaced by
// what the boot check would see (before systemd's later phases).
func bootCheckValues(t *testing.T, m *attesttest.Machine) ([]PCRValue, []byte) {
	t.Helper()
	live, err := m.TPM.Quote(nil, m.Sel)
	if err != nil {
		t.Fatal(err)
	}
	gate := sha256.Sum256([]byte("PCR 11 at enter-initrd"))
	vals := append([]PCRValue(nil), live.Values...)
	for i := range vals {
		if vals[i].Index == 11 {
			vals[i] = PCRValue{Index: 11, Digest: gate[:]}
		}
	}
	return vals, gate[:]
}

// The gate quotes inside the initramfs, before systemd extends PCR 11 with
// its later boot phases, so the running system's registers at enrolment can
// never match a boot check. The machine therefore predicts the boot-check
// values and the phone pins those; the first boot then matches.
func TestEnrolPinsBootCheckValues(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	m.Sel, _ = NewPCRSelection(AlgSHA256, []int{0, 2, 4, 7, 11})
	m.TPM.Extend(11, "leave-initrd") // the running system has moved on
	predicted, gate := bootCheckValues(t, m)
	m.MeasurePoint = predicted

	rec := enrol(t, m, p)
	prof := rec.Policy.Profiles[0]
	if !bytes.Equal(prof.Values[11], gate) || prof.AddedBy != BaselineMeasurePoint {
		t.Fatalf("baseline does not pin the boot-check values: %+v", prof)
	}

	// Next boot: the registers show the boot-check values.
	m.TPM.PCRs[11] = gate
	m.TPM.ResetCount++
	res, merr, perr := attestOnce(t, m, p, rec)
	if merr != nil || perr != nil {
		t.Fatalf("machine %v phone %v", merr, perr)
	}
	if res.Check.Verdict != VerdictOK {
		t.Fatalf("first boot after enrolment should match, got %+v", p.Last(EvVerdict).Verdict)
	}
}

// Boot-check values must cover exactly the quoted PCRs.
func TestEnrolRejectsBootCheckValuesForOtherPCRs(t *testing.T) {
	m, p := newMachine(t), newPhone(t)
	m.MeasurePoint = []PCRValue{{Index: 4, Digest: make([]byte, 32)}}
	a, b := attesttest.NewPipe()
	go func() { _, _ = m.ServeEnrolment(a, true); a.Close() }()
	v, err := NewEnrolVerifier(p.Config())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Drive(v, b); err == nil || p.Record != nil {
		t.Fatalf("phone accepted boot-check values for other PCRs: %v", err)
	}
}
