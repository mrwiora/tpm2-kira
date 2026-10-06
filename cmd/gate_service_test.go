package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matthias/tpm2-kira/attest"
)

// A coordinator for one slot with one enrolled phone and no TPM behind it:
// quotes are registered by hand, as Quote would after the TPM signed one.
func testCoordinator(t *testing.T) (*gateService, *ecdsa.PrivateKey) {
	t.Helper()
	phone, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	anchor, _ := x509.MarshalPKIXPublicKey(&phone.PublicKey)
	s := &gateService{ready: make(chan struct{}), issued: map[string][]byte{}, idx: NVRAMSlotStart + 2}
	s.blob = &Attestation{
		DeviceID: []byte("0123456789abcdef"), AKName: []byte("ak-name"), FriendlyName: "box",
		Phone: PhoneAttestation{
			NoisePrivate: make([]byte, 32), AdvKey: make([]byte, 32),
			Verifiers: []attest.EnrolledVerifier{{ID: "phone-1", Name: "Pixel", AnchorPub: anchor, NoisePub: make([]byte, 32)}},
		},
	}
	s.status.Slot = 2
	close(s.ready)
	return s, phone
}

func (s *gateService) issue(quoted, qd []byte) []byte {
	sum := sha256.Sum256(quoted)
	s.issued[hex.EncodeToString(sum[:])] = qd
	return sum[:]
}

func signedReceipt(t *testing.T, s *gateService, key *ecdsa.PrivateKey, verdict attest.VerdictCode, digest, qd []byte) *attest.Receipt {
	t.Helper()
	r := &attest.Receipt{
		Verdict: verdict, DeviceID: s.blob.DeviceID, AKName: s.blob.AKName,
		QD: qd, QuoteDigest: digest, VerifierID: "phone-1",
	}
	if key != nil {
		d := sha256.Sum256(attest.ReceiptTBS(r))
		sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
		if err != nil {
			t.Fatal(err)
		}
		r.Signature = sig
	}
	return r
}

// The verdict is the coordinator's reading of a receipt: signed by the
// enrolled phone, over a quote the coordinator itself issued. Nothing the
// radio worker says can stand in for that.
func TestOnlyThePhonesReceiptGivesAVerdict(t *testing.T) {
	s, phone := testCoordinator(t)
	qd := []byte("qualifying-data-of-this-session!")
	digest := s.issue([]byte("quote issued by this coordinator"), qd)

	status := func() GateState { st, _ := s.Status(); return st.State }

	// The worker reports progress; it cannot report a verdict.
	s.Report(GateWaiting)
	s.Report(GateAttested)
	s.Report(GateRejected)
	s.Report(GateState("anything"))
	if status() != GateWaiting {
		t.Fatalf("a report changed the state to %q", status())
	}

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	notIssued := sha256.Sum256([]byte("a quote the worker made up"))
	for name, r := range map[string]*attest.Receipt{
		"unsigned":                   signedReceipt(t, s, nil, attest.VerdictOK, digest, qd),
		"signed by another key":      signedReceipt(t, s, other, attest.VerdictOK, digest, qd),
		"for a quote never issued":   signedReceipt(t, s, phone, attest.VerdictOK, notIssued[:], qd),
		"with other qualifying data": signedReceipt(t, s, phone, attest.VerdictOK, digest, []byte("some other session's data.......")),
		"for another machine": func() *attest.Receipt {
			r := signedReceipt(t, s, phone, attest.VerdictOK, digest, qd)
			r.DeviceID = []byte("another-machine!")
			return r
		}(),
		"altered after it was signed": func() *attest.Receipt {
			r := signedReceipt(t, s, phone, attest.VerdictReject, digest, qd)
			r.Verdict = attest.VerdictOK
			return r
		}(),
	} {
		c := s.JudgeReceipt(r, "phone-1")
		if c.Authentic || c.Ack == attest.AckAccepted || status() == GateAttested {
			t.Fatalf("receipt %s was accepted: %+v, state %q", name, c, status())
		}
	}
	if c := s.JudgeReceipt(signedReceipt(t, s, phone, attest.VerdictOK, digest, qd), "someone-else"); c.Authentic || status() == GateAttested {
		t.Fatalf("receipt attributed to a phone that is not enrolled was accepted: %+v", c)
	}

	// The genuine receipt.
	c := s.JudgeReceipt(signedReceipt(t, s, phone, attest.VerdictOK, digest, qd), "phone-1")
	st, ok := s.Status()
	if !c.Authentic || c.Ack != attest.AckAccepted || !ok || st.State != GateAttested || st.Phone != "Pixel" || st.Slot != 2 {
		t.Fatalf("genuine receipt: %+v, status %+v", c, st)
	}
	// Progress reports do not take a verdict back.
	s.Report(GateWaiting)
	if status() != GateAttested {
		t.Fatal("a report replaced the verdict")
	}
}

func TestRejectionsAreNoted(t *testing.T) {
	s, phone := testCoordinator(t)
	qd := []byte("qualifying-data-of-this-session!")
	digest := s.issue([]byte("quote"), qd)
	// A reject needs no signature: believing a false "no" costs a check.
	if c := s.JudgeReceipt(signedReceipt(t, s, nil, attest.VerdictReject, digest, qd), "phone-1"); c.Ack != attest.AckRejectNoted {
		t.Fatalf("%+v", c)
	}
	if st, _ := s.Status(); st.State != GateRejected {
		t.Fatalf("state %q", st.State)
	}
	if c := s.JudgeReceipt(signedReceipt(t, s, phone, attest.VerdictReject, digest, qd), "phone-1"); !c.Authentic {
		t.Fatalf("%+v", c)
	}
}

// A coordinator that found the record replaced serves nothing, and says why.
func TestRefusedCoordinatorServesNothing(t *testing.T) {
	s := &gateService{ready: make(chan struct{}), issued: map[string][]byte{}, code: ExitTampered, reason: errors.New("not accepted")}
	s.status.State = GateRefused
	close(s.ready)
	if _, code, err := s.Identity(); code != ExitTampered || err == nil {
		t.Fatalf("identity: %d %v", code, err)
	}
	if _, err := s.Quote(make([]byte, 32), attest.PCRSelection{Alg: attest.AlgSHA256, Indices: []uint8{0}}); err == nil {
		t.Fatal("a refused coordinator quoted")
	}
	if c := s.JudgeReceipt(&attest.Receipt{Verdict: attest.VerdictOK}, "x"); c.Authentic {
		t.Fatal("a refused coordinator accepted a receipt")
	}
	s.Report(GateWaiting)
	if st, _ := s.Status(); st.State != GateRefused {
		t.Fatalf("state %q", st.State)
	}
}

// fakeHost records what reaches the coordinator over the socket.
type fakeHost struct {
	identity *gateIdentity
	code     int
	quotes   int
	reports  []GateState
	receipt  *attest.Receipt
	evlog    []byte
}

func (f *fakeHost) Identity() (*gateIdentity, int, error) {
	if f.identity == nil {
		return nil, f.code, errors.New("refused")
	}
	return f.identity, 0, nil
}
func (f *fakeHost) Quote(qd []byte, sel attest.PCRSelection) (*attest.QuoteResult, error) {
	f.quotes++
	if len(qd) != 32 {
		return nil, errors.New("bad qualifying data")
	}
	return &attest.QuoteResult{Quoted: append([]byte("quoted:"), qd...), Signature: []byte("sig"),
		Values: []attest.PCRValue{{Index: sel.Indices[0], Digest: make([]byte, 32)}}}, nil
}
func (f *fakeHost) BootContext() attest.BootContext {
	return attest.BootContext{NVRAMIndex: 7, SealPCRSelection: []uint8{0, 7}, MeasurePoint: "on"}
}
func (f *fakeHost) Eventlog() ([]byte, error) { return f.evlog, nil }
func (f *fakeHost) JudgeReceipt(r *attest.Receipt, id string) attest.ReceiptCheck {
	f.receipt = r
	return attest.ReceiptCheck{Verdict: r.Verdict, Authentic: true, Ack: attest.AckAccepted, Detail: id}
}
func (f *fakeHost) Report(s GateState) { f.reports = append(f.reports, s) }

func startTestGate(t *testing.T, host gateHost) string {
	t.Helper()
	path, _ := startTestGateServer(t, host)
	return path
}

func startTestGateServer(t *testing.T, host gateHost) (string, *gateServer) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "run", "gate.sock")
	l, err := listenGate(path)
	if err != nil {
		t.Fatal(err)
	}
	g := serveGate(l, host)
	t.Cleanup(g.Close)
	return path, g
}

// Lazy mode: the coordinator's service ends with the code screen's hold, and
// the worker learns of it at once, also while it is only waiting for a phone.
func TestWorkerLearnsThatTheCoordinatorEnded(t *testing.T) {
	path, server := startTestGateServer(t, &fakeHost{identity: &gateIdentity{FriendlyName: "box"}})
	c, err := dialGate(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, _, err := c.Identity(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Gone():
		t.Fatal("reported gone while the coordinator serves")
	case <-time.After(200 * time.Millisecond):
	}
	server.Close()
	select {
	case <-c.Gone():
	case <-time.After(2 * time.Second):
		t.Fatal("the worker did not learn that the coordinator ended")
	}
	if _, _, err := c.Identity(); err == nil {
		t.Fatal("a closed coordinator answered")
	}
	if _, err := c.Quote(make([]byte, 32), attest.PCRSelection{Alg: attest.AlgSHA256, Indices: []uint8{0}}); err == nil {
		t.Fatal("a closed coordinator quoted")
	}
	// Nobody new is served either.
	if _, err := dialGate(path, 300*time.Millisecond); err == nil {
		t.Fatal("a closed coordinator accepted a worker")
	}
	server.Close() // twice is fine
}

func TestWorkerReachesTheCoordinator(t *testing.T) {
	host := &fakeHost{
		identity: &gateIdentity{Slot: 1, FriendlyName: "box", DeviceID: []byte("dev"), AKName: []byte("ak"),
			NoisePrivate: make([]byte, 32), AdvKey: []byte("adv"), RecordVerified: true,
			Verifiers: []gateVerifier{{ID: "p", Name: "Pixel", NoisePub: []byte("np")}}},
		evlog: make([]byte, 300_000),
	}
	path := startTestGate(t, host)

	// Only the coordinator's user can enter.
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v %v", st.Mode(), err)
	}
	if st, _ := os.Stat(filepath.Dir(path)); st.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode %v", st.Mode())
	}

	c, err := dialGate(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	id, code, err := c.Identity()
	if err != nil || code != 0 || id.FriendlyName != "box" || !id.RecordVerified || len(id.Verifiers) != 1 || id.Verifiers[0].Name != "Pixel" {
		t.Fatalf("identity: %+v %d %v", id, code, err)
	}
	q, err := c.Quote(make([]byte, 32), attest.PCRSelection{Alg: attest.AlgSHA256, Indices: []uint8{7}})
	if err != nil || !strings.HasPrefix(string(q.Quoted), "quoted:") || len(q.Values) != 1 || q.Values[0].Index != 7 {
		t.Fatalf("quote: %+v %v", q, err)
	}
	if _, err := c.Quote([]byte("short"), attest.PCRSelection{Alg: attest.AlgSHA256, Indices: []uint8{7}}); err == nil {
		t.Fatal("the coordinator's refusal did not reach the worker")
	}
	if bc := c.BootContext(); bc.NVRAMIndex != 7 || bc.MeasurePoint != "on" || len(bc.SealPCRSelection) != 2 {
		t.Fatalf("boot context: %+v", bc)
	}
	if log, err := c.Eventlog(); err != nil || len(log) != 300_000 {
		t.Fatalf("event log: %d %v", len(log), err)
	}
	check := c.JudgeReceipt(&attest.Receipt{Verdict: attest.VerdictOK, QD: []byte("qd"), Signature: []byte("s")}, "p")
	if !check.Authentic || check.Detail != "p" || host.receipt == nil || string(host.receipt.QD) != "qd" {
		t.Fatalf("receipt: %+v", check)
	}
	c.Report(GateSession)
	if len(host.reports) != 1 || host.reports[0] != GateSession {
		t.Fatalf("reports %v", host.reports)
	}

	// A refusal carries the coordinator's exit status to the worker's unit.
	refusing := startTestGate(t, &fakeHost{code: ExitTampered})
	c2, err := dialGate(refusing, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if _, code, err := c2.Identity(); code != ExitTampered || err == nil {
		t.Fatalf("refusal: %d %v", code, err)
	}

	// Without a coordinator the worker gives up; it has no TPM to fall back to.
	if _, err := dialGate(filepath.Join(t.TempDir(), "nobody"), 300*time.Millisecond); err == nil {
		t.Fatal("dialled nothing")
	}
}

// What arrives on the socket is input: unknown operations and oversized or
// malformed messages get no service.
func TestCoordinatorTreatsRequestsAsInput(t *testing.T) {
	host := &fakeHost{identity: &gateIdentity{}}
	path := startTestGate(t, host)
	dial := func() net.Conn {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		return conn
	}
	conn := dial()
	if err := writeGateFrame(conn, &gateRequest{Op: "unseal"}, maxGateRequest); err != nil {
		t.Fatal(err)
	}
	var resp gateResponse
	if err := readGateFrame(conn, &resp, maxGateResponse); err != nil || resp.Err == "" {
		t.Fatalf("unknown operation: %+v %v", resp, err)
	}
	if err := writeGateFrame(conn, &gateRequest{Op: gateOpReceipt}, maxGateRequest); err != nil {
		t.Fatal(err)
	}
	if err := readGateFrame(conn, &resp, maxGateResponse); err != nil || resp.Err == "" || host.receipt != nil {
		t.Fatalf("receipt operation without a receipt: %+v %v", resp, err)
	}

	// A length beyond the limit, and bytes that are not a request, end the
	// connection without an answer.
	for _, raw := range [][]byte{
		{0x7f, 0xff, 0xff, 0xff},
		append([]byte{0, 0, 0, 5}, []byte("hello")...),
		{0, 0, 0, 0},
	} {
		conn := dial()
		if _, err := conn.Write(raw); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1)
		if n, err := conn.Read(buf); n != 0 || err == nil {
			t.Fatalf("%x: answered with %d bytes (%v)", raw[:4], n, err)
		}
	}
	if host.quotes != 0 {
		t.Fatal("a malformed request reached the TPM side")
	}
}
