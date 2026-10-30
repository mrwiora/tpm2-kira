//go:build integration

package admin

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

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/core/attest/attesttest"
	"github.com/mrwiora/tpm2-kira/internal/bootrun"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
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

	// The phones go into the slot's blob, next to its TOTP key, and the
	// boot key shares that key's policy: the slot is really sealed.
	idx := uint32(nvslot.NVRAMSlotStart + 9)
	signer, signerPath := sealRealSlot(t, s.sock, idx)
	s.be.SealIndex, s.be.Sealed = idx, phonegate.ReadSealedSlot(s.tpm, idx)
	s.be.OnConfirmSAS = func(code string) (bool, error) { return true, nil }
	s.be.OnCommit = func(v attest.EnrolledVerifier) error {
		if err := s.blob.UpsertVerifier(v); err != nil {
			return err
		}
		return writeAttestBlob(s.tpm, idx, s.blob, signer)
	}
	noise, _ := attest.NoiseKeypairFromPrivate(s.blob.Phone.NoisePrivate)

	a, b := attesttest.NewPipe()
	done := make(chan error, 1)
	go func() {
		_, err := attest.ServeEnrolment(a, &attest.EnrolIdentity{
			DeviceID: s.blob.DeviceID, FriendlyName: s.blob.FriendlyName,
			AKPub: s.blob.AKPublic, AKName: s.blob.AKName, NoiseStatic: noise,
			AdvKey: s.blob.Phone.AdvKey, Selection: sel, AppVersion: "test",
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
	t.Logf("enrolled: EK %s, AK %s, reset count %d", nvslot.EKAlgName(s.blob.EKAlg), hex.EncodeToString(rec.AKName[:8]), rec.ResetCount)

	// The blob round-trips through NVRAM.
	stored, err := phonegate.LoadAttestBlob(s.tpm, idx)
	if err != nil {
		t.Fatalf("reading back the attestation blob: %v", err)
	}
	if len(stored.Phone.Verifiers) != 1 || !bytes.Equal(stored.AKName, s.blob.AKName) || stored.EKAlg == 0 {
		t.Fatalf("stored blob incomplete: %+v", stored)
	}
	if section, err := stored.Marshal(); err == nil {
		t.Logf("enrolment with one phone: %d bytes in the slot's blob (attestation key %d + %d bytes)",
			len(section), len(stored.AKPublic), len(stored.AKPrivate))
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
				Verifiers: stored.Phone.Verifiers, AppVersion: "test",
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
	// The TPM released the boot key for this boot state: the phone shows
	// the code this machine recovered.
	if vd := phone.Last(attest.EvVerdict).Verdict; vd.BootKey != attest.BootKeyResultProved || s.be.BootCode == "" ||
		vd.Code != attest.FormatBootCode(s.be.BootCode) || !bytes.Equal(rec.BootKeyPub, mustPoint(t, stored)) {
		t.Fatalf("boot key: verdict %q code %q, machine recovered %q", vd.BootKey, vd.Code, s.be.BootCode)
	}
	if res.Check.Verdict != attest.VerdictOK || !res.Check.Authentic {
		t.Fatalf("unchanged machine not attested: %+v (verdict %+v)", res.Check, phone.Last(attest.EvVerdict).Verdict)
	}

	// The same exchange as the units run it: the session in a radio worker
	// that has nothing but the coordinator's socket, the TPM and the
	// reading of the receipt in the coordinator.
	svc := phonegate.NewGateService(s.tpm, idx, signerPath, false)
	worker := startTestGate(t, svc)
	ident, code, err := worker.Identity()
	if err != nil || code != 0 || !ident.RecordVerified || ident.Slot != 9 {
		t.Fatalf("coordinator identity: %+v %d %v", ident, code, err)
	}
	workerNoise, _ := attest.NoiseKeypairFromPrivate(ident.NoisePrivate)
	workerID := &attest.AttestIdentity{DeviceID: ident.DeviceID, AKName: ident.AKName, NoiseStatic: workerNoise, AppVersion: "test"}
	for _, v := range ident.Verifiers {
		workerID.Verifiers = append(workerID.Verifiers, attest.EnrolledVerifier{ID: v.ID, NoisePub: v.NoisePub})
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
	if res.Check.Verdict != attest.VerdictOK || !res.Check.Authentic || st.State != phonegate.GateAttested || st.Slot != 9 {
		t.Fatalf("through the coordinator: %+v, status %+v", res.Check, st)
	}
	// The worker asked the coordinator's TPM for the proof; the phone got a
	// code, which only the coordinator ever held.
	if vd := phone.Last(attest.EvVerdict).Verdict; vd.BootKey != attest.BootKeyResultProved || len(vd.Code) != attest.BootCodeLen+1 {
		t.Fatalf("boot key through the coordinator: %+v", vd)
	}
	if st.Code != "" {
		t.Fatalf("the code stayed on the screen after the phone answered: %q", st.Code)
	}

	// The boot leaves the approved state (as a changed image would, or the
	// OS separator): the TPM refuses the boot key, no code is shown, and
	// the quote still describes the registers.
	if err := extendPCR(s.tpm, 23, "x"); err != nil {
		t.Fatal(err)
	}
	attestRound()
	if vd := phone.Last(attest.EvVerdict).Verdict; vd.BootKey != attest.BootKeyResultRefused || vd.Code != "" || s.be.BootCode != "" {
		t.Fatalf("boot key outside the approved state: %+v, machine recovered %q", vd, s.be.BootCode)
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

func mustPoint(t *testing.T, a *nvslot.Attestation) []byte {
	t.Helper()
	p, err := phonegate.BootKeyPoint(a)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestOfflineQuoteVerifies covers `phone quote` / `phone verify`'s path:
// a real quote with offline qualifying data checked by Verify.
func TestOfflineQuoteVerifies(t *testing.T) {
	s := newSWTPMSetup(t)
	sel, _ := s.blob.Selection()
	nonce := phonegate.RandBytes(32)
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
	if v := attest.Verify(ev, pol, pin, attest.OfflineQualifyingData(phonegate.RandBytes(32)), time.Now()); v.State != attest.StateFailed {
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
	idx := uint32(nvslot.NVRAMSlotStart + 4)
	writeTestSlot(t, s.tpm, idx, mine)
	sealedOnly, _ := nvslot.ReadRecord(idx)
	counterIdx := nvslot.AttestCounterIndex(idx)

	// The initramfs: built once, carrying this machine's signing public key.
	signerPath := filepath.Join(t.TempDir(), "attest-signer.pem")
	der, _ := x509.MarshalPKIXPublicKey(&mine.PublicKey)
	hostKey := filepath.Join(t.TempDir(), "seal.pub")
	if err := os.WriteFile(hostKey, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	buildImage := func() (int, string) { // what the hook does
		var errOut strings.Builder
		pemBytes, code := phonegate.SignerForImage(s.tpm, hostKey, &errOut, false)
		if code == 0 {
			if err := os.WriteFile(signerPath, pemBytes, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return code, errOut.String()
	}
	gate := func() (bool, int) { return phonegate.GateRecordCheck(s.tpm, idx, signerPath) }
	refused := func(what string) {
		t.Helper()
		if verified, code := gate(); verified || code != phonegate.ExitTampered {
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
		if err := nvslot.WriteRecord(idx, raw); err != nil {
			t.Fatalf("the owner hierarchy could not replace the index: %v", err)
		}
	}

	s.blob.Phone.Verifiers = []attest.EnrolledVerifier{{ID: "my-phone", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(s.tpm, idx, s.blob, mine); err != nil {
		t.Fatal(err)
	}
	onePhone, _ := nvslot.ReadRecord(idx)
	// One blob: the phone went in and retired the TOTP key; the approval
	// is as it was.
	if before, _ := nvslot.UnmarshalSealedBlob(sealedOnly); before.Payload.Attestation != nil {
		t.Fatalf("the sealed slot already had an enrolment: %+v", before)
	}
	if after, err := nvslot.UnmarshalSealedBlob(onePhone); err != nil || after.Payload.Attestation == nil ||
		after.HasTOTPKey() || after.Payload.Generation != testSlotBlob().Payload.Generation {
		t.Fatalf("enrolling kept the slot's TOTP key or did not store the phone: %+v %v", after, err)
	}

	// An image from before the key was put into it: served, not verified.
	if verified, code := phonegate.GateRecordCheck(s.tpm, idx, filepath.Join(t.TempDir(), "none")); verified || code != 0 {
		t.Fatalf("image without the key: %v %d", verified, code)
	}
	if code, out := buildImage(); code != 0 {
		t.Fatalf("image build: %d %s", code, out)
	}
	accepted("own record")

	// A second phone is enrolled. No rebuild: the image is the same.
	s.blob.Phone.Verifiers = append(s.blob.Phone.Verifiers, attest.EnrolledVerifier{ID: "second-phone", AnchorPub: []byte{2}, NoisePub: make([]byte, 32)})
	if err := writeAttestBlob(s.tpm, idx, s.blob, mine); err != nil {
		t.Fatal(err)
	}
	twoPhones, _ := nvslot.ReadRecord(idx)
	accepted("second phone, same image")

	// 1. The attacker's own blob for the slot, with the attacker's phone
	// and the count the TPM is at, signed with the attacker's key.
	forged := *s.blob
	forged.Phone.Verifiers = []attest.EnrolledVerifier{{ID: "attackers-phone", AnchorPub: []byte{9}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(s.tpm, idx, &forged, attacker); err == nil || !strings.Contains(err.Error(), "not signed by your signing key") {
		t.Fatalf("another key was allowed to add a phone to the slot: %v", err)
	}
	forged.Count, _ = nvslot.ReadAttestCounter(s.tpm, counterIdx)
	forgedSlot := testSlotBlob()
	withPhones(forgedSlot, &forged)
	plant(signSlot(t, forgedSlot, attacker))
	refused("attacker's record")
	if code, out := buildImage(); code != phonegate.ExitTampered || !strings.Contains(out, "TAMPERED") {
		t.Fatalf("the image build accepted a foreign record: %d %s", code, out)
	}

	// 2. An older record this machine's key did sign is put back.
	plant(onePhone)
	refused("older genuine record")

	// 3. ... and the counter is deleted and recreated to make it fit. A
	// TPM counter comes back above where it was.
	before, err := nvslot.ReadAttestCounter(s.tpm, counterIdx)
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
	after, err := nvslot.BumpAttestCounter(s.tpm, counterIdx)
	if err != nil {
		t.Fatal(err)
	}
	if after <= before {
		t.Fatalf("a recreated counter went back: %d after %d", after, before)
	}
	refused("older record, counter recreated")

	// 4. ... or replaced by an ordinary index holding the old record's count.
	oldSlot, _ := nvslot.UnmarshalSealedBlob(onePhone)
	old := oldSlot.Payload.Attestation
	pub, _ = tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(counterIdx)}.Execute(s.tpm)
	undefine(pub.NVName)
	fake := nvslot.AttestCounterPublic(counterIdx)
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
	last, _ := nvslot.ReadRecord(idx)

	// 5. The phones are removed (the blob rewritten without them, the
	// counter raised) and the blob that was current until then is put back.
	if err := writeAttestBlob(s.tpm, idx, nil, mine); err != nil {
		t.Fatal(err)
	}
	unenrolled, _ := nvslot.ReadRecord(idx)
	if a, err := nvslot.UnmarshalSealedBlob(unenrolled); err != nil || a.Payload.Attestation != nil || a.HasTOTPKey() {
		t.Fatalf("removing the phones: %+v %v", a, err)
	}
	if verified, code := gate(); verified || code != phonegate.ExitTampered {
		t.Fatalf("a slot without phones was served (verified=%v, exit %d)", verified, code)
	}
	plant(last)
	refused("blob put back after unenrol")
}

// TestCoordinatorAndWorker runs the two halves of the gate the way 'run'
// starts them - the coordinator, and the radio worker as a process of its
// own ('gate-child', this test binary) - up to the point where the worker
// needs a Bluetooth adapter, which a test machine does not have.
func TestCoordinatorAndWorker(t *testing.T) {
	sock := startSWTPM(t)
	s := newSWTPMSetupAt(t, sock, "swtpm-box")
	mine, attacker := testSigner(t), testSigner(t)
	idx := uint32(nvslot.NVRAMSlotStart + 3)
	writeTestSlot(t, s.tpm, idx, mine)
	s.blob.Phone.Verifiers = []attest.EnrolledVerifier{{ID: "my-phone", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(s.tpm, idx, s.blob, mine); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "control.conf")
	if err := os.WriteFile(conf, []byte("TPM2_KIRA_ATTEST_ADAPTER=0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The gate is in the image when the hook put the signer there.
	signer := filepath.Join(dir, "attest-signer.pem")
	if err := os.WriteFile(signer, []byte("not read here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	noSigner := filepath.Join(dir, "no-signer.pem")
	// The coordinator opens the TPM itself; swtpm serves one client.
	s.tpm.Close()

	// No gate in the image: nothing to coordinate.
	if svc, end := bootrun.StartCoordinator(sock, noSigner, false); svc != nil {
		t.Fatal("a coordinator without a gate to coordinate")
	} else {
		end() // nothing to end, and no harm in asking
	}
	svc, endCoordinator := bootrun.StartCoordinator(sock, signer, false)
	if svc == nil {
		t.Fatal("no coordinator")
	}
	// The started worker waits for an adapter; one in this process with an
	// adapter that is not there gets as far as the radio.
	worker := startTestGate(t, svc)
	code := phonegate.RunGateRadio(worker, phonegate.GateOptions{Adapter: 250, Worker: true}, func(string, ...any) {}, worker.Gone())
	if code != phonegate.ExitUnavailable {
		t.Fatalf("worker exit %d, want %d (no adapter)", code, phonegate.ExitUnavailable)
	}
	if st, ok := svc.Status(); !ok || st.State != phonegate.GateUnavailable || st.Slot != 3 {
		t.Fatalf("coordinator status %+v", st)
	}
	// The TPM half works through the connection.
	sel, _ := s.blob.Selection()
	if q, err := worker.Quote(bytes.Repeat([]byte{1}, 32), sel); err != nil || len(q.Quoted) == 0 || len(q.Values) != len(sel.Indices) {
		t.Fatalf("quote through the coordinator: %+v %v", q, err)
	}

	// The hold ends: so does the coordinator's service, and the started
	// worker with it (endCoordinator waits for it).
	endCoordinator()
	endCoordinator()

	// A replaced record: the coordinator refuses, and the worker ends with
	// the same status as before.
	forged := *s.blob
	forged.Phone.Verifiers = []attest.EnrolledVerifier{{ID: "attackers-phone", AnchorPub: []byte{9}, NoisePub: make([]byte, 32)}}
	forged.Count, _ = nvslot.ReadAttestCounter(svc.TPM, nvslot.AttestCounterIndex(idx))
	forgedSlot := testSlotBlob()
	withPhones(forgedSlot, &forged)
	svc.TPMMu.Lock()
	err := nvslot.WriteRecord(idx, signSlot(t, forgedSlot, attacker))
	svc.TPMMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	hostKey := filepath.Join(dir, "seal.pub")
	der, _ := x509.MarshalPKIXPublicKey(&mine.PublicKey)
	if err := os.WriteFile(hostKey, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	refused := phonegate.NewGateService(svc.TPM, 0, hostKey, false)
	w := startTestGate(t, refused)
	if code := phonegate.RunGateRadio(w, phonegate.GateOptions{Adapter: 250, Worker: true}, func(string, ...any) {}, w.Gone()); code != phonegate.ExitTampered {
		t.Fatalf("worker exit %d for a replaced record, want %d", code, phonegate.ExitTampered)
	}
	if st, _ := refused.Status(); st.State != phonegate.GateRefused {
		t.Fatalf("coordinator status %+v", st)
	}
}

// TestStaleSlotCanBeRemoved: a slot is one thing. What a previous
// installation left in it - TOTP key and phones, signed by a signing key
// that no longer exists - cannot be extended, and goes as a whole, without
// that key. A companion index whose slot is gone is found and removed too.
func TestStaleSlotCanBeRemoved(t *testing.T) {
	sock := startSWTPM(t)
	s := newSWTPMSetupAt(t, sock, "swtpm-box")
	previous, current := testSigner(t), testSigner(t)
	slot0, slot5 := uint32(nvslot.NVRAMSlotStart), uint32(nvslot.NVRAMSlotStart+5)
	s.blob.Phone.Verifiers = []attest.EnrolledVerifier{{ID: "old-phone", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	for _, idx := range []uint32{slot0, slot5} {
		writeTestSlot(t, s.tpm, idx, previous)
		if err := writeAttestBlob(s.tpm, idx, s.blob, previous); err != nil {
			t.Fatal(err)
		}
	}
	oldBlob, _ := nvslot.ReadRecord(slot0)
	// A record counter whose slot is gone, as an interrupted command leaves it.
	orphan := nvslot.AttestCounterIndex(nvslot.NVRAMSlotStart + 7)
	if _, err := nvslot.BumpAttestCounter(s.tpm, orphan); err != nil {
		t.Fatal(err)
	}

	// The new installation's key cannot add a phone to, or take one out
	// of, what the previous one signed.
	err := writeAttestBlob(s.tpm, slot0, s.blob, current)
	if err == nil || !strings.Contains(err.Error(), "slot delete --nvram 0") {
		t.Fatalf("enrol into a foreign slot: %v", err)
	}
	if err := writeAttestBlob(s.tpm, slot0, nil, current); err == nil {
		t.Fatal("a foreign slot's phones were removed by re-signing it")
	}
	// Nor into a slot that has no TOTP key.
	if err := writeAttestBlob(s.tpm, nvslot.NVRAMSlotStart+2, s.blob, current); err == nil || !strings.Contains(err.Error(), "slot add --nvram 2") {
		t.Fatalf("enrol without a sealed slot: %v", err)
	}
	exists := func(idx uint32) bool {
		t.Helper()
		tpmDev, err := transport.OpenTPM(sock)
		if err != nil {
			t.Fatal(err)
		}
		defer tpmDev.Close()
		return tpmdev.NVRAMIndexExists(tpmDev, idx)
	}
	s.tpm.Close() // the commands open the TPM themselves; swtpm serves one client

	// One slot: 'slot delete --nvram 0' takes the blob and its counter.
	if err := NVRAMDeleteCommand(sock, slot0, false, false); err != nil {
		t.Fatalf("deleting a foreign slot: %v", err)
	}
	record := func(idx uint32) bool { _, err := nvslot.ReadRecord(idx); return err == nil }
	if record(slot0) || exists(nvslot.AttestCounterIndex(slot0)) || exists(nvslot.GenerationIndex(slot0)) {
		t.Fatal("slot 0 was not deleted whole")
	}
	if !record(slot5) || !exists(nvslot.GenerationIndex(slot5)) || !exists(nvslot.AttestCounterIndex(slot5)) || !exists(orphan) {
		t.Fatal("deleting slot 0 touched something else")
	}
	// Without the signing key the phones cannot be taken out of a slot;
	// the slot can only go whole.
	if err := AttestUnenrol(sock, slot5, filepath.Join(t.TempDir(), "no-key"), false); err == nil || !strings.Contains(err.Error(), "slot delete --nvram 5") {
		t.Fatalf("unenrol without the signing key: %v", err)
	}

	// Everything: the other slot, and the counter that belongs to no slot.
	if err := NVRAMDeleteCommand(sock, 0, true, false); err != nil {
		t.Fatalf("slot delete: %v", err)
	}
	for idx := uint32(nvslot.AppNVRAMStart); idx <= nvslot.AppNVRAMEnd; idx++ {
		if role := kiraIndexRole(idx); role != "" && exists(idx) {
			t.Fatalf("0x%08X (%s) survived 'slot delete'", idx, role)
		}
	}
	if record(nvslot.NVRAMSlotStart + 5) {
		t.Fatal("slot 5's record survived 'slot delete'")
	}
	// Nothing left: it says so instead of claiming success.
	if err := NVRAMDeleteCommand(sock, 0, true, false); err == nil || !strings.Contains(err.Error(), "nothing of tpm2-kira") {
		t.Fatalf("second slot delete: %v", err)
	}

	// The new installation seals and enrols; the blob from before the
	// cleanup does not pass if it is put back: the new counter is above
	// the old one, and the image's key is another.
	tpmDev, err := transport.OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tpmDev.Close()
	writeTestSlot(t, tpmDev, slot0, current)
	if err := writeAttestBlob(tpmDev, slot0, s.blob, current); err != nil {
		t.Fatalf("enrolling after the cleanup: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&previous.PublicKey)
	oldKey := filepath.Join(t.TempDir(), "old.pub")
	if err := os.WriteFile(oldKey, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := nvslot.WriteRecord(slot0, oldBlob); err != nil {
		t.Fatal(err)
	}
	if verified, code := phonegate.GateRecordCheck(tpmDev, slot0, oldKey); verified || code != phonegate.ExitTampered {
		t.Fatalf("the blob from before the cleanup was accepted again (verified=%v, exit %d)", verified, code)
	}
}

// TestOwnTPMCheckOnSWTPM: swtpm's EK has no vendor certificate, so enrolment
// warns, asks, and stops on "no" or under --verify-tpm=require.
func TestOwnTPMCheckOnSWTPM(t *testing.T) {
	s := newSWTPMSetup(t)
	run := func(p phonegate.HWCheckPolicy, answer string) (bool, string) {
		var out strings.Builder
		ok, err := phonegate.CheckOwnTPM(s.tpm, p, bufio.NewReader(strings.NewReader(answer)), &out)
		if err != nil {
			t.Fatal(err)
		}
		return ok, out.String()
	}
	if ok, out := run(phonegate.CheckWarn, "\n"); ok || !strings.Contains(out, "NOT VERIFIED as genuine hardware: the TPM has no vendor certificate") {
		t.Fatalf("warn/no: %v %s", ok, out)
	}
	if ok, _ := run(phonegate.CheckWarn, "y\n"); !ok {
		t.Fatal("warn/yes refused")
	}
	if ok, _ := run(phonegate.CheckRequire, "y\n"); ok {
		t.Fatal("require accepted")
	}
	if ok, out := run(phonegate.CheckOff, ""); !ok || out != "" {
		t.Fatal("off checked")
	}
}

// startTestGate links a coordinator serving host to a worker's client.
func startTestGate(t *testing.T, host phonegate.GateHost) *phonegate.GateClient {
	t.Helper()
	g, files, err := phonegate.LinkGate(host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	c, err := phonegate.GateClientFromFiles(files[0], files[1])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
