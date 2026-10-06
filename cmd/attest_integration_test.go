//go:build integration

package cmd

import (
	"bufio"
	"bytes"
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
