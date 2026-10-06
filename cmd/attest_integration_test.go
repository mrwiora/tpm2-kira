//go:build integration

package cmd

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/matthias/tpm2-kira/attest"
	"github.com/matthias/tpm2-kira/attest/attesttest"
)

// TestAttestationOnSWTPM runs enrolment (real EK, PolicySecret session,
// ActivateCredential) and attestation (real quotes over more than 8 PCRs)
// against the verifier, and stores the blob through PolicySigned NV writes.
func TestAttestationOnSWTPM(t *testing.T) {
	runAttestationOnSWTPM(t, newSWTPMSetup(t))
}

// TestAttestationOnSWTPMSHA1 runs the same exchange on the SHA-1 PCR bank,
// as old firmware TPMs (e.g. Intel PTT 10, ThinkPad T450s) offer only that.
func TestAttestationOnSWTPMSHA1(t *testing.T) {
	s := newSWTPMSetup(t)
	s.blob.PCRAlg = attest.AlgSHA1
	s.blob.PCRSelection = []uint8{0, 2, 4, 7}
	runAttestationOnSWTPM(t, s)
}

func runAttestationOnSWTPM(t *testing.T, s *swtpmSetup) {
	sel, _ := s.blob.Selection()
	phone, _ := attesttest.NewPhone()

	signer := testSigner(t)
	idx := uint32(AttestNVRAMStart + 9)
	s.be.confirmSAS = func(code string) (bool, error) { return true, nil }
	s.be.commit = func(v attest.EnrolledVerifier) error {
		if err := s.blob.UpsertVerifier(v); err != nil {
			return err
		}
		return writeAttestBlob(s.tpm, idx, s.blob, signer)
	}
	noise, _ := attest.NoiseKeypairFromPrivate(s.blob.NoisePrivate)

	a, b := attesttest.NewPipe()
	done := make(chan error, 1)
	go func() {
		_, err := attest.ServeEnrolment(a, &attest.EnrolIdentity{
			DeviceID: s.blob.DeviceID, FriendlyName: s.blob.FriendlyName,
			AKPub: s.blob.AKPublic, AKName: s.blob.AKName, NoiseStatic: noise,
			AdvKey: s.blob.AdvKey, Selection: sel, AppVersion: "test",
		}, s.be, nil)
		a.Close()
		done <- err
	}()
	v, err := attest.NewEnrolVerifier(phone.Config())
	if err != nil {
		t.Fatal(err)
	}
	if err := phone.Drive(v, b); err != nil {
		t.Fatalf("phone: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("machine: %v", err)
	}
	rec := phone.Record
	if rec == nil {
		t.Fatal("no record")
	}
	t.Logf("enrolled: EK %s, AK %s, reset count %d", ekAlgName(s.blob.EKAlg), hex.EncodeToString(rec.AKName[:8]), rec.ResetCount)

	// The blob round-trips through NVRAM.
	stored, err := loadAttestBlob(s.tpm, idx)
	if err != nil {
		t.Fatalf("reading back the attestation blob: %v", err)
	}
	if len(stored.Verifiers) != 1 || !bytes.Equal(stored.AKName, s.blob.AKName) || stored.EKAlg == 0 {
		t.Fatalf("stored blob incomplete: %+v", stored)
	}

	attestRound := func() *attest.AttestResult {
		a, b := attesttest.NewPipe()
		type r struct {
			res *attest.AttestResult
			err error
		}
		ch := make(chan r, 1)
		go func() {
			res, err := attest.ServeAttestation(a, &attest.AttestIdentity{
				DeviceID: stored.DeviceID, AKName: stored.AKName, NoiseStatic: noise,
				Verifiers: stored.Verifiers, AppVersion: "test",
			}, s.be, nil)
			a.Close()
			ch <- r{res, err}
		}()
		v, err := attest.NewAttestVerifier(phone.Config(), phone.Record)
		if err != nil {
			t.Fatal(err)
		}
		if err := phone.Drive(v, b); err != nil {
			t.Fatalf("phone: %v", err)
		}
		got := <-ch
		if got.err != nil {
			t.Fatalf("machine: %v", got.err)
		}
		return got.res
	}

	res := attestRound()
	if res.Check.Verdict != attest.VerdictOK || !res.Check.Authentic {
		t.Fatalf("unchanged machine not attested: %+v (verdict %+v)", res.Check, phone.Last(attest.EvVerdict).Verdict)
	}

	// The same exchange as the units run it: the session in a radio worker
	// that has nothing but the coordinator's socket, the TPM and the
	// reading of the receipt in the coordinator.
	signerPath := filepath.Join(t.TempDir(), "attest-signer.pem")
	der, _ := x509.MarshalPKIXPublicKey(&signer.PublicKey)
	if err := os.WriteFile(signerPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := newGateService(s.tpm, NVRAMSlotStart+(idx-AttestNVRAMStart), signerPath, false)
	worker, err := dialGate(startTestGate(t, svc), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	ident, code, err := worker.Identity()
	if err != nil || code != 0 || !ident.RecordVerified || ident.Slot != 9 {
		t.Fatalf("coordinator identity: %+v %d %v", ident, code, err)
	}
	workerNoise, _ := attest.NoiseKeypairFromPrivate(ident.NoisePrivate)
	workerID := &attest.AttestIdentity{DeviceID: ident.DeviceID, AKName: ident.AKName, NoiseStatic: workerNoise, AppVersion: "test"}
	for _, v := range ident.Verifiers {
		workerID.Verifiers = append(workerID.Verifiers, attest.EnrolledVerifier{ID: v.ID, Name: v.Name, NoisePub: v.NoisePub})
	}
	viaCoordinator := func() *attest.AttestResult {
		a, b := attesttest.NewPipe()
		type r struct {
			res *attest.AttestResult
			err error
		}
		ch := make(chan r, 1)
		go func() {
			res, err := attest.ServeAttestation(a, workerID, worker, nil)
			a.Close()
			ch <- r{res, err}
		}()
		v, err := attest.NewAttestVerifier(phone.Config(), phone.Record)
		if err != nil {
			t.Fatal(err)
		}
		if err := phone.Drive(v, b); err != nil {
			t.Fatalf("phone: %v", err)
		}
		got := <-ch
		if got.err != nil {
			t.Fatalf("worker: %v", got.err)
		}
		return got.res
	}
	if st, ok := svc.Status(); ok && st.Verdict() {
		t.Fatalf("a verdict before any phone answered: %+v", st)
	}
	res = viaCoordinator()
	st, _ := svc.Status()
	if res.Check.Verdict != attest.VerdictOK || !res.Check.Authentic || st.State != GateAttested || st.Slot != 9 {
		t.Fatalf("through the coordinator: %+v, status %+v", res.Check, st)
	}
	// A worker gone wrong asks for a quote of its own and presents the
	// phone's genuine receipt for it: the receipt belongs to another quote.
	q, err := worker.Quote(bytes.Repeat([]byte{7}, 32), sel)
	if err != nil {
		t.Fatalf("quote through the coordinator: %v", err)
	}
	replayed := *res.Receipt
	sum := sha256.Sum256(q.Quoted)
	replayed.QuoteDigest = sum[:]
	if c := worker.JudgeReceipt(&replayed, res.Verifier.ID); c.Authentic {
		t.Fatalf("a receipt moved to another quote was accepted: %+v", c)
	}

	// A boot-chain change is reported as a diff on exactly that PCR.
	s.extend(t, 4, "x")
	phone.Decision = attest.DecisionReject
	res = attestRound()
	verdict := phone.Last(attest.EvVerdict).Verdict
	if verdict.State != attest.StateChanged || len(verdict.PCRDiff) != 1 || verdict.PCRDiff[0].Index != 4 {
		t.Fatalf("expected a diff on PCR 4, got %+v", verdict)
	}
	if res.Check.Verdict != attest.VerdictReject {
		t.Fatalf("reject not delivered: %+v", res.Check)
	}
	t.Logf("diff explanation: %s", verdict.Explanation)
}

// TestOfflineQuoteVerifies covers `attest quote` / `attest verify`'s path:
// a real quote with offline qualifying data checked by Verify.
func TestOfflineQuoteVerifies(t *testing.T) {
	s := newSWTPMSetup(t)
	sel, _ := s.blob.Selection()
	nonce := randBytes(32)
	q, err := s.be.Quote(attest.OfflineQualifyingData(nonce), sel)
	if err != nil {
		t.Fatal(err)
	}
	ev := &attest.Evidence{Schema: attest.SchemaVersion, DeviceID: s.blob.DeviceID, AKName: s.blob.AKName,
		Quoted: q.Quoted, Signature: q.Signature, PCRAlg: sel.Alg, PCRValues: q.Values}
	pol := &attest.Policy{ID: "x", Selection: sel.Indices, PCRAlg: sel.Alg,
		Profiles: []attest.Profile{attest.ProfileFromValues("b", q.Values, time.Now().Add(-time.Minute), "t")}}
	pin := &attest.PinnedIdentity{DeviceID: s.blob.DeviceID, AKPub: s.blob.AKPublic, AKName: s.blob.AKName}
	if v := attest.Verify(ev, pol, pin, attest.OfflineQualifyingData(nonce), time.Now()); v.State != attest.StateMatch {
		t.Fatalf("real quote does not verify: %+v", v.Reasons)
	}
	if v := attest.Verify(ev, pol, pin, attest.OfflineQualifyingData(randBytes(32)), time.Now()); v.State != attest.StateFailed {
		t.Fatal("quote verified against the wrong nonce")
	}
}

// TestReplacedRecordIsRefused performs the attacks on the enrolment record on
// a real TPM, with the owner hierarchy as the attacker has it: a record of
// their own, an older genuine record put back, and every way of making the
// TPM's counter agree with that older record. The gate must refuse them all
// before it advertises - and must accept a newly enrolled phone without the
// initramfs being rebuilt.
func TestReplacedRecordIsRefused(t *testing.T) {
	s := newSWTPMSetup(t)
	mine, attacker := testSigner(t), testSigner(t)
	idx := uint32(AttestNVRAMStart + 4)
	counterIdx := AttestCounterIndex(idx)

	// The initramfs: built once, carrying this machine's signing public key.
	signerPath := filepath.Join(t.TempDir(), "attest-signer.pem")
	der, _ := x509.MarshalPKIXPublicKey(&mine.PublicKey)
	hostKey := filepath.Join(t.TempDir(), "seal.pub")
	if err := os.WriteFile(hostKey, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	buildImage := func() (int, string) { // what the hook does
		var errOut strings.Builder
		pemBytes, code := signerForImage(s.tpm, hostKey, &errOut, false)
		if code == 0 {
			if err := os.WriteFile(signerPath, pemBytes, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return code, errOut.String()
	}
	gate := func() (bool, int) { return gateRecordCheck(s.tpm, idx, signerPath) }
	refused := func(what string) {
		t.Helper()
		if verified, code := gate(); verified || code != ExitTampered {
			t.Fatalf("%s: not refused (verified=%v, exit %d)", what, verified, code)
		}
	}
	accepted := func(what string) {
		t.Helper()
		if verified, code := gate(); !verified || code != 0 {
			t.Fatalf("%s: not accepted (verified=%v, exit %d)", what, verified, code)
		}
	}
	// The attacker writes arbitrary bytes into the record index: undefine
	// with the owner hierarchy, define again under a key of their own.
	plant := func(raw []byte) {
		t.Helper()
		if err := WriteToNVRAM(s.tpm, idx, raw, attacker.Public(), attacker); err != nil {
			t.Fatalf("the owner hierarchy could not replace the index: %v", err)
		}
	}

	s.blob.Verifiers = []attest.EnrolledVerifier{{ID: "my-phone", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(s.tpm, idx, s.blob, mine); err != nil {
		t.Fatal(err)
	}
	onePhone, _ := ReadFromNVRAM(s.tpm, idx)

	// An image from before the key was put into it: served, not verified.
	if verified, code := gateRecordCheck(s.tpm, idx, filepath.Join(t.TempDir(), "none")); verified || code != 0 {
		t.Fatalf("image without the key: %v %d", verified, code)
	}
	if code, out := buildImage(); code != 0 {
		t.Fatalf("image build: %d %s", code, out)
	}
	accepted("own record")

	// A second phone is enrolled. No rebuild: the image is the same.
	s.blob.Verifiers = append(s.blob.Verifiers, attest.EnrolledVerifier{ID: "second-phone", AnchorPub: []byte{2}, NoisePub: make([]byte, 32)})
	if err := writeAttestBlob(s.tpm, idx, s.blob, mine); err != nil {
		t.Fatal(err)
	}
	twoPhones, _ := ReadFromNVRAM(s.tpm, idx)
	accepted("second phone, same image")

	// 1. The attacker's own record, signed with the attacker's key.
	forged := *s.blob
	forged.Verifiers = []attest.EnrolledVerifier{{ID: "attackers-phone", AnchorPub: []byte{9}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(s.tpm, idx, &forged, attacker); err != nil {
		t.Fatal(err)
	}
	refused("attacker's record")
	if code, out := buildImage(); code != ExitTampered || !strings.Contains(out, "TAMPERED") {
		t.Fatalf("the image build accepted a foreign record: %d %s", code, out)
	}

	// 2. An older record this machine's key did sign is put back.
	plant(onePhone)
	refused("older genuine record")

	// 3. ... and the counter is deleted and recreated to make it fit. A
	// TPM counter comes back above where it was.
	before, err := readAttestCounter(s.tpm, counterIdx)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(counterIdx)}.Execute(s.tpm)
	undefine := func(name tpm2.TPM2BName) {
		t.Helper()
		if _, err := (tpm2.NVUndefineSpace{AuthHandle: tpm2.TPMRHOwner, NVIndex: tpm2.NamedHandle{Handle: tpm2.TPMHandle(counterIdx), Name: name}}).Execute(s.tpm); err != nil {
			t.Fatal(err)
		}
	}
	undefine(pub.NVName)
	refused("older record, counter deleted")
	after, err := bumpAttestCounter(s.tpm, counterIdx)
	if err != nil {
		t.Fatal(err)
	}
	if after <= before {
		t.Fatalf("a recreated counter went back: %d after %d", after, before)
	}
	refused("older record, counter recreated")

	// 4. ... or replaced by an ordinary index holding the old record's count.
	old, _ := UnmarshalAttestBlob(onePhone)
	pub, _ = tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(counterIdx)}.Execute(s.tpm)
	undefine(pub.NVName)
	fake := attestCounterPublic(counterIdx)
	fake.Attributes.NT = tpm2.TPMNTOrdinary
	if _, err := (tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, PublicInfo: tpm2.New2B(fake)}).Execute(s.tpm); err != nil {
		t.Fatal(err)
	}
	fakePub, _ := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(counterIdx)}.Execute(s.tpm)
	if _, err := (tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(counterIdx), Name: fakePub.NVName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: binary.BigEndian.AppendUint64(nil, old.Count)},
	}).Execute(s.tpm); err != nil {
		t.Fatal(err)
	}
	refused("older record, counter faked with an ordinary index")

	// The genuine newest record is stale too after all that: the attacker
	// can deny service, never obtain an accepted record.
	plant(twoPhones)
	refused("newest record after the counter was tampered with")

	// Enrolling again repairs it, again without touching the image.
	if err := writeAttestBlob(s.tpm, idx, s.blob, mine); err != nil {
		t.Fatal(err)
	}
	accepted("re-enrolled")
	last, _ := ReadFromNVRAM(s.tpm, idx)

	// 5. The slot is unenrolled (record deleted, counter raised) and the
	// record that was current until then is put back.
	if _, err := bumpAttestCounter(s.tpm, counterIdx); err != nil {
		t.Fatal(err)
	}
	plant(last)
	refused("record put back after unenrol")
}

// TestCoordinatorAndWorker runs the two halves of the gate the way the units
// start them - the coordinator of 'tpm2-kira run --gate' and the worker of
// 'attest gate --coordinator' - up to the point where the worker needs a
// Bluetooth adapter, which a test machine does not have.
func TestCoordinatorAndWorker(t *testing.T) {
	sock := startSWTPM(t)
	s := newSWTPMSetupAt(t, sock, "swtpm-box")
	mine, attacker := testSigner(t), testSigner(t)
	idx := uint32(AttestNVRAMStart + 3)
	s.blob.Verifiers = []attest.EnrolledVerifier{{ID: "my-phone", Name: "Pixel", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(s.tpm, idx, s.blob, mine); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	lazy := filepath.Join(dir, "attest.conf")
	if err := os.WriteFile(lazy, []byte("TPM2_KIRA_ATTEST=lazy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	off := filepath.Join(dir, "off.conf")
	if err := os.WriteFile(off, []byte("TPM2_KIRA_ATTEST=off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The coordinator opens the TPM itself; swtpm serves one client.
	s.tpm.Close()

	// No gate in the image, or no socket asked for: nothing to coordinate.
	for _, c := range [][2]string{
		{filepath.Join(dir, "a", "gate.sock"), off},
		{filepath.Join(dir, "b", "gate.sock"), filepath.Join(dir, "missing.conf")},
		{"", lazy},
	} {
		if svc, end := startCoordinator(sock, c[0], c[1], false); svc != nil {
			t.Fatalf("a coordinator without a gate to coordinate (%v)", c)
		} else {
			end() // nothing to end, and no harm in asking
		}
	}

	gate := filepath.Join(dir, "run", "gate.sock")
	svc, endCoordinator := startCoordinator(sock, gate, lazy, false)
	if svc == nil {
		t.Fatal("no coordinator")
	}
	// The worker: no TPM path, only the socket. It gets as far as the radio.
	code := AttestGate(GateOptions{Coordinator: gate, Adapter: 250, TPMPath: "/nonexistent/tpm"})
	if code != ExitUnavailable {
		t.Fatalf("worker exit %d, want %d (no adapter)", code, ExitUnavailable)
	}
	if st, ok := svc.Status(); !ok || st.State != GateUnavailable || st.Slot != 3 {
		t.Fatalf("coordinator status %+v", st)
	}
	// The TPM half works through the socket.
	worker, err := dialGate(gate, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	sel, _ := s.blob.Selection()
	if q, err := worker.Quote(bytes.Repeat([]byte{1}, 32), sel); err != nil || len(q.Quoted) == 0 || len(q.Values) != len(sel.Indices) {
		t.Fatalf("quote through the coordinator: %+v %v", q, err)
	}

	// The hold ends: so does the coordinator's service, and a worker that
	// comes now finds nobody (it has no TPM of its own to fall back to).
	endCoordinator()
	select {
	case <-worker.Gone():
	case <-time.After(2 * time.Second):
		t.Fatal("the worker did not learn that the hold ended")
	}
	if _, err := os.Stat(gate); err == nil {
		t.Fatal("the socket outlived the coordinator's service")
	}
	endCoordinator()

	// A replaced record: the coordinator refuses, and the worker's unit
	// fails with the same status as before.
	forged := *s.blob
	forged.Verifiers = []attest.EnrolledVerifier{{ID: "attackers-phone", AnchorPub: []byte{9}, NoisePub: make([]byte, 32)}}
	svc.tpmMu.Lock()
	err = writeAttestBlob(svc.tpm, idx, &forged, attacker)
	svc.tpmMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	hostKey := filepath.Join(dir, "seal.pub")
	der, _ := x509.MarshalPKIXPublicKey(&mine.PublicKey)
	if err := os.WriteFile(hostKey, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	refused := newGateService(svc.tpm, 0, hostKey, false)
	if code := AttestGate(GateOptions{Coordinator: startTestGate(t, refused), Adapter: 250}); code != ExitTampered {
		t.Fatalf("worker exit %d for a replaced record, want %d", code, ExitTampered)
	}
	if st, _ := refused.Status(); st.State != GateRefused {
		t.Fatalf("coordinator status %+v", st)
	}
}

// TestStaleEnrolmentCanBeRemoved: a phone enrolment that another
// installation's signing key wrote stays in the TPM when the system is
// reinstalled. 'attest enrol' refuses to build on it; both ways of getting
// rid of it must work without that key, and 'nvram delete' must see it even
// when no TOTP key is sealed.
func TestStaleEnrolmentCanBeRemoved(t *testing.T) {
	sock := startSWTPM(t)
	s := newSWTPMSetupAt(t, sock, "swtpm-box")
	previous, current := testSigner(t), testSigner(t)
	rec0, rec5 := uint32(AttestNVRAMStart), uint32(AttestNVRAMStart+5)
	s.blob.Verifiers = []attest.EnrolledVerifier{{ID: "old-phone", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	for _, idx := range []uint32{rec0, rec5} {
		if err := writeAttestBlob(s.tpm, idx, s.blob, previous); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := ReadFromNVRAM(s.tpm, rec0)
	if err := verifyBeforeExtending(raw, &current.PublicKey, 0); err == nil || !strings.Contains(err.Error(), "nvram delete") {
		t.Fatalf("enrol on a foreign record: %v", err)
	}
	exists := func(idx uint32) bool {
		t.Helper()
		tpmDev, err := transport.OpenTPM(sock)
		if err != nil {
			t.Fatal(err)
		}
		defer tpmDev.Close()
		return NVRAMIndexExists(tpmDev, idx)
	}
	s.tpm.Close() // the commands open the TPM themselves; swtpm serves one client

	// One slot: 'attest unenrol'. The record goes; the counter stays, raised.
	if err := AttestUnenrol(sock, NVRAMSlotStart, false); err != nil {
		t.Fatalf("unenrol of a foreign record: %v", err)
	}
	if exists(rec0) || !exists(AttestCounterIndex(rec0)) {
		t.Fatalf("after unenrol: record %v, counter %v", exists(rec0), exists(AttestCounterIndex(rec0)))
	}

	// Everything: 'nvram delete'. No TOTP key is sealed here; it must find
	// the other enrolment and the counter that unenrol left.
	if err := NVRAMDeleteCommand(sock, 0, true, false); err != nil {
		t.Fatalf("nvram delete: %v", err)
	}
	for _, idx := range []uint32{rec0, rec5, AttestCounterIndex(rec0), AttestCounterIndex(rec5)} {
		if exists(idx) {
			t.Fatalf("0x%08X (%s) survived 'nvram delete'", idx, kiraIndexRole(idx))
		}
	}
	// Nothing left: it says so instead of claiming success.
	if err := NVRAMDeleteCommand(sock, 0, true, false); err == nil || !strings.Contains(err.Error(), "nothing of tpm2-kira") {
		t.Fatalf("second nvram delete: %v", err)
	}

	// A fresh enrolment works again, and a record put back from before
	// the cleanup does not pass: the new counter is above the old one.
	tpmDev, err := transport.OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tpmDev.Close()
	if err := writeAttestBlob(tpmDev, rec0, s.blob, current); err != nil {
		t.Fatalf("enrolling after the cleanup: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&previous.PublicKey)
	oldKey := filepath.Join(t.TempDir(), "old.pub")
	if err := os.WriteFile(oldKey, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteToNVRAM(tpmDev, rec0, raw, previous.Public(), previous); err != nil {
		t.Fatal(err)
	}
	if verified, code := gateRecordCheck(tpmDev, rec0, oldKey); verified || code != ExitTampered {
		t.Fatalf("the record from before the cleanup was accepted again (verified=%v, exit %d)", verified, code)
	}
}

// TestOwnTPMCheckOnSWTPM: swtpm's EK has no vendor certificate, so enrolment
// warns, asks, and stops on "no" or under --verify-tpm=require.
func TestOwnTPMCheckOnSWTPM(t *testing.T) {
	s := newSWTPMSetup(t)
	run := func(p HWCheckPolicy, answer string) (bool, string) {
		var out strings.Builder
		ok, err := checkOwnTPM(s.tpm, p, bufio.NewReader(strings.NewReader(answer)), &out)
		if err != nil {
			t.Fatal(err)
		}
		return ok, out.String()
	}
	if ok, out := run(CheckWarn, "\n"); ok || !strings.Contains(out, "NOT VERIFIED as genuine hardware: the TPM has no vendor certificate") {
		t.Fatalf("warn/no: %v %s", ok, out)
	}
	if ok, _ := run(CheckWarn, "y\n"); !ok {
		t.Fatal("warn/yes refused")
	}
	if ok, _ := run(CheckRequire, "y\n"); ok {
		t.Fatal("require accepted")
	}
	if ok, out := run(CheckOff, ""); !ok || out != "" {
		t.Fatal("off checked")
	}
}
