//go:build integration

package cmd

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// TestReplacedRecordIsRefused performs the record-replacement attack on a
// real TPM: the owner hierarchy undefines the attestation index and writes a
// record of its own (here: the attacker's phone, signed with the attacker's
// key). The gate must refuse it before advertising, and the image build must
// refuse to accept it; so must an older record that this machine's key did sign.
func TestReplacedRecordIsRefused(t *testing.T) {
	s := newSWTPMSetup(t)
	mine, attacker := testSigner(t), testSigner(t)
	idx := uint32(AttestNVRAMStart + 4)
	pubPath := filepath.Join(t.TempDir(), "seal.pub")
	der, _ := x509.MarshalPKIXPublicKey(&mine.PublicKey)
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprintPath := filepath.Join(t.TempDir(), "attest-record.sha256")
	// What the initramfs hook does when the image is built.
	buildImage := func() (int, string) {
		var errOut strings.Builder
		fps, code := fingerprintSlots(s.tpm, pubPath, &errOut, false)
		if code == 0 {
			if err := os.WriteFile(fingerprintPath, FormatRecordFingerprints(fps), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return code, errOut.String()
	}
	// What the gate does at boot, before it advertises.
	gate := func() (bool, int) { return gateRecordCheck(s.tpm, idx, fingerprintPath) }

	if known, code := gateRecordCheck(s.tpm, idx, filepath.Join(t.TempDir(), "none")); known || code != ExitInternal {
		t.Fatalf("no record at all: %v %d", known, code)
	}

	s.blob.Verifiers = []attest.EnrolledVerifier{{ID: "my-phone", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(s.tpm, idx, s.blob, mine); err != nil {
		t.Fatal(err)
	}
	old, _ := ReadFromNVRAM(s.tpm, idx)

	// An image built before fingerprints existed: served, but not as verified.
	if known, code := gateRecordCheck(s.tpm, idx, filepath.Join(t.TempDir(), "none")); known || code != 0 {
		t.Fatalf("image without a fingerprint: %v %d", known, code)
	}
	if code, out := buildImage(); code != 0 {
		t.Fatalf("own record not accepted: %d %s", code, out)
	}
	if known, code := gate(); !known || code != 0 {
		t.Fatalf("own record, image built for it: %v %d", known, code)
	}

	// A second phone is enrolled: the image must be rebuilt first.
	s.blob.Verifiers = append(s.blob.Verifiers, attest.EnrolledVerifier{ID: "second-phone", AnchorPub: []byte{2}, NoisePub: make([]byte, 32)})
	if err := writeAttestBlob(s.tpm, idx, s.blob, mine); err != nil {
		t.Fatal(err)
	}
	if _, code := gate(); code != ExitTampered {
		t.Fatalf("a record changed since the image was built must be refused, got %d", code)
	}
	if code, out := buildImage(); code != 0 {
		t.Fatalf("rebuild after enrolment: %d %s", code, out)
	}
	if known, code := gate(); !known || code != 0 {
		t.Fatalf("after the rebuild: %v %d", known, code)
	}

	// The attack: undefine (owner auth, empty) and write the attacker's record.
	forged := *s.blob
	forged.Verifiers = []attest.EnrolledVerifier{{ID: "attackers-phone", AnchorPub: []byte{9}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(s.tpm, idx, &forged, attacker); err != nil {
		t.Fatalf("the owner hierarchy could not replace the index: %v", err)
	}
	if _, code := gate(); code != ExitTampered {
		t.Fatalf("the attacker's record was not refused: %d", code)
	}
	before, _ := os.ReadFile(fingerprintPath)
	if code, out := buildImage(); code != ExitTampered || !strings.Contains(out, "TAMPERED") {
		t.Fatalf("the image build accepted a foreign record: %d %s", code, out)
	}
	if after, _ := os.ReadFile(fingerprintPath); string(after) != string(before) {
		t.Fatal("a refused build must not touch the fingerprint file")
	}

	// Putting back an older record this machine's key did sign (a removed
	// phone returns): validly signed, and still not what the image was built for.
	restored, _ := UnmarshalAttestBlob(old)
	restored.Signature = nil
	if err := writeAttestBlob(s.tpm, idx, restored, mine); err != nil {
		t.Fatal(err)
	}
	if _, code := gate(); code != ExitTampered {
		t.Fatalf("a rolled-back record was not refused: %d", code)
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
