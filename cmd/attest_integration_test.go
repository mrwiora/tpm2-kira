//go:build integration

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/matthias/tpm2-kira/attest"
	"github.com/matthias/tpm2-kira/attest/attesttest"
)

// startSWTPM runs a software TPM and returns its socket path.
func startSWTPM(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "swtpm.sock")
	cmd := exec.Command("swtpm", "socket", "--tpm2",
		"--tpmstate", "dir="+dir,
		"--server", "type=unixio,path="+sock,
		"--ctrl", "type=unixio,path="+sock+".ctrl",
		"--flags", "not-need-init,startup-clear")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			time.Sleep(100 * time.Millisecond)
			return sock
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("swtpm did not start")
	return ""
}

type swtpmSetup struct {
	tpm  transport.TPMCloser
	blob *AttestBlob
	be   *tpmBackend
}

func newSWTPMSetup(t *testing.T) *swtpmSetup {
	sock := startSWTPM(t)
	tpmDev, err := transport.OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tpmDev.Close() })

	pub, priv, name, err := CreateAK(tpmDev)
	if err != nil {
		t.Fatalf("CreateAK: %v", err)
	}
	if _, err := attest.ParseAKPublic(pub, name); err != nil {
		t.Fatalf("TPM-created AK fails the verifier's own checks: %v", err)
	}
	noise, _ := attest.GenerateNoiseKeypair(nil)
	sel, _ := attest.NewPCRSelection(attest.AlgSHA256, []int{0, 2, 4, 7, 8, 9, 10, 11, 14})
	blob := &AttestBlob{
		AppVersion:   "test",
		DeviceID:     randBytes(16),
		FriendlyName: "swtpm-box",
		AKPublic:     pub,
		AKPrivate:    priv,
		AKName:       name,
		NoisePrivate: noise.Private,
		AdvKey:       randBytes(32),
		PCRAlg:       sel.Alg,
		PCRSelection: sel.Indices,
	}
	be := &tpmBackend{tpm: tpmDev, blob: blob, sealIndex: NVRAMSlotStart}
	return &swtpmSetup{tpm: tpmDev, blob: blob, be: be}
}

func (s *swtpmSetup) extend(t *testing.T, pcr int, data string) {
	_, err := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcr), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{
			HashAlg: tpm2.TPMAlgSHA256,
			Digest:  bytes.Repeat([]byte(data[:1]), 32),
		}}},
	}.Execute(s.tpm)
	if err != nil {
		t.Fatal(err)
	}
}

// TestAttestationOnSWTPM runs enrolment (real EK, PolicySecret session,
// ActivateCredential) and attestation (real quotes over more than 8 PCRs)
// against the verifier, and stores the blob through PolicySigned NV writes.
func TestAttestationOnSWTPM(t *testing.T) {
	s := newSWTPMSetup(t)
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

func testSigner(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
