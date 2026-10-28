//go:build integration

package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/mrwiora/tpm2-kira/attest"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
	"github.com/mrwiora/tpm2-kira/internal/wipe"
)

// The factor's round trip on swtpm: wrapped for this TPM's EK and the
// slot's release key, it opens in the boot state the signing key approved
// and nowhere else - not after a PCR of the selection moved, not on another
// TPM, and not without the command code the release key's policy ends in.
func TestFactorOpensOnlyInTheApprovedBootState(t *testing.T) {
	sock := startSWTPM(t)
	const slot = nvslot.NVRAMSlotStart + 1
	signer, pubPath := sealRealSlot(t, sock, slot) // sealed to PCR 23
	s := newSWTPMSetupAt(t, sock, "box")
	tpm := s.tpm
	s.blob.EKAlg = uint16(tpm2.TPMAlgECC)
	_, sealed, err := phonegate.ReadSlot(tpm, slot)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := phonegate.CreateReleaseKey(tpm, sealed)
	if err != nil {
		t.Fatalf("release key: %v", err)
	}
	s.blob.ReleaseKeyPublic, s.blob.ReleaseKeyPrivate = pub, priv
	// The blob carries the key like the boot key: written and read back.
	if err := writeAttestBlob(tpm, slot, s.blob, signer); err != nil {
		t.Fatal(err)
	}
	_, sb, err := phonegate.ReadSlot(tpm, slot)
	if err != nil {
		t.Fatal(err)
	}
	att := sb.Payload.Attestation
	if !bytes.Equal(att.ReleaseKeyPublic, pub) {
		t.Fatal("the release key did not survive the blob")
	}

	f, w, err := phonegate.WrapFactor(tpm, att, nil)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if len(f) != phonegate.FactorSize || len(w.Credential) == 0 || len(w.EncryptedSecret) == 0 {
		t.Fatalf("wrapped: %d bytes, %d, %d", len(f), len(w.Credential), len(w.EncryptedSecret))
	}
	got, err := phonegate.UnwrapFactor(tpm, sb, slot, att, w)
	if err != nil {
		t.Fatalf("unwrap in the approved state: %v", err)
	}
	if !bytes.Equal(got, f) {
		t.Fatal("the TPM opened the credential to something else")
	}
	salt := phonegate.FactorSalt(f, "")
	if len(salt) != 64 || strings.Trim(string(salt), "0123456789abcdef") != "" {
		t.Fatalf("salt %q", salt)
	}
	if bytes.Equal(salt, phonegate.FactorSalt(f, "home")) || !bytes.Equal(salt, phonegate.FactorSalt(f, "luks")) {
		t.Fatal("labels")
	}

	// The coordinator does the same at boot, from a Release, and keeps
	// only the salt.
	s.blob.Phone.Verifiers = []attest.EnrolledVerifier{{ID: "my-phone", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(tpm, slot, s.blob, signer); err != nil {
		t.Fatal(err)
	}
	svc := phonegate.NewGateService(tpm, slot, pubPath, false)
	status, msg := svc.TakeRelease(&attest.Release{Kind: attest.ReleaseKindFactor, CredentialBlob: w.Credential, EncryptedSecret: w.EncryptedSecret})
	if status != attest.ReleaseOK {
		t.Fatalf("the coordinator did not open the factor: %d %s", status, msg)
	}
	if !bytes.Equal(svc.Salt(), salt) {
		t.Fatal("the coordinator's salt is not the factor's")
	}
	svc.Forget()
	if svc.Salt() != nil {
		t.Fatal("the salt survived Forget")
	}
	if status, _ := svc.TakeRelease(&attest.Release{Kind: attest.ReleaseKindPassphrase}); status != attest.ReleaseUnsupported {
		t.Fatalf("a passphrase release was taken: %d", status)
	}

	// At enrolment nothing is opened (the booted system has the slot
	// locked): the phone must give back what it was asked to keep.
	keep := &attest.FactorBlob{CredentialBlob: w.Credential, EncryptedSecret: w.EncryptedSecret, Label: "luks"}
	svc.Keep(keep)
	if status, msg := svc.TakeRelease(&attest.Release{Kind: attest.ReleaseKindFactor, CredentialBlob: w.Credential, EncryptedSecret: []byte{1, 2, 3}, Label: "luks"}); status != attest.ReleaseTPMRefused || svc.Returned() {
		t.Fatalf("a different credential was taken as returned: %d %s", status, msg)
	}
	if status, msg := svc.TakeRelease(&attest.Release{Kind: attest.ReleaseKindFactor, CredentialBlob: w.Credential, EncryptedSecret: w.EncryptedSecret, Label: "luks"}); status != attest.ReleaseOK || !svc.Returned() || svc.Salt() != nil {
		t.Fatalf("the returned credential: %d %s returned=%v", status, msg, svc.Returned())
	}
	svc.Keep(nil)

	// A different TPM (a second swtpm) with the same blob: the EK is
	// another, and the credential does not open.
	other := startSWTPM(t)
	otherTPM, err := tpmdev.Open(other)
	if err != nil {
		t.Fatal(err)
	}
	defer otherTPM.Close()
	if _, err := phonegate.UnwrapFactor(otherTPM, sb, slot, att, w); err == nil {
		t.Fatal("another TPM opened the credential")
	}

	// Without the command code the policy is the slot's, not the release
	// key's: the TPM refuses the ADMIN action.
	rk, err := phonegate.LoadReleaseKey(tpm, att)
	if err != nil {
		t.Fatal(err)
	}
	ek, _, err := phonegate.CreateEK(tpm, att.EKAlg)
	if err != nil {
		t.Fatal(err)
	}
	session, done, err := nvslot.ApprovedSession(tpm, sb, slot)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: rk.Handle, Name: rk.Name, Auth: session},
		KeyHandle:      tpm2.AuthHandle{Handle: ek.Handle, Name: ek.Name, Auth: phonegate.EndorsementPolicy()},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: w.Credential},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: w.EncryptedSecret},
	}.Execute(tpm)
	done()
	tpmdev.FlushHandle(tpm, rk.Handle)
	tpmdev.FlushHandle(tpm, ek.Handle)
	if err == nil {
		t.Fatal("the slot's policy alone opened the credential")
	}

	// The boot state moves: PCR 23 is extended, and the approval no longer
	// holds. The factor is not released.
	s.extend(t, 23, "something else booted")
	if _, err := phonegate.UnwrapFactor(tpm, sb, slot, att, w); !errors.Is(err, phonegate.ErrFactorRefused) {
		t.Fatalf("after a PCR change: %v", err)
	}
	if status, _ := svc.TakeRelease(&attest.Release{Kind: attest.ReleaseKindFactor, CredentialBlob: w.Credential, EncryptedSecret: w.EncryptedSecret}); status != attest.ReleaseTPMRefused || svc.Salt() != nil {
		t.Fatalf("the coordinator took a factor after a PCR change: %d", status)
	}
}

// A slot without a release key has no factor; an attestation without one
// says so rather than failing in the TPM.
func TestFactorNeedsAReleaseKey(t *testing.T) {
	sock := startSWTPM(t)
	s := newSWTPMSetupAt(t, sock, "box")
	if _, _, err := phonegate.WrapFactor(s.tpm, s.blob, nil); !errors.Is(err, phonegate.ErrNoReleaseKey) {
		t.Fatalf("%v", err)
	}
}

// factor status says whether a slot has a release key; factor unenrol
// takes it out, after which the phone's kept factor cannot be opened.
func TestFactorStatusAndUnenrol(t *testing.T) {
	sock := startSWTPM(t)
	const slot = nvslot.NVRAMSlotStart + 1
	signer, pubPath := sealRealSlot(t, sock, slot)
	privPath := strings.TrimSuffix(pubPath, "seal.pub") + "seal.key"
	s := newSWTPMSetupAt(t, sock, "box")
	tpm := s.tpm
	s.blob.EKAlg = uint16(tpm2.TPMAlgECC)
	s.blob.Phone.Verifiers = []attest.EnrolledVerifier{{ID: "my-phone", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(tpm, slot, s.blob, signer); err != nil {
		t.Fatal(err)
	}
	tpm.Close() // the commands open the TPM themselves

	out := grabStdout(t, func() {
		if err := FactorStatus(sock, 0, false, false); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Slot 1") || !strings.Contains(out, "no phone salt") {
		t.Fatalf("status without a factor: %q", out)
	}
	if err := FactorUnenrol(sock, 1, privPath, false); err == nil || !strings.Contains(err.Error(), "no phone salt enrolled") {
		t.Fatalf("unenrol without a factor: %v", err)
	}

	tpmDev, err := tpmdev.Open(sock)
	if err != nil {
		t.Fatal(err)
	}
	_, sealed, err := phonegate.ReadSlot(tpmDev, slot)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := phonegate.CreateReleaseKey(tpmDev, sealed)
	if err != nil {
		t.Fatal(err)
	}
	s.blob.ReleaseKeyPublic, s.blob.ReleaseKeyPrivate = pub, priv
	if err := writeAttestBlob(tpmDev, slot, s.blob, signer); err != nil {
		t.Fatal(err)
	}
	att, _ := phonegate.LoadAttestBlob(tpmDev, slot)
	f, w, err := phonegate.WrapFactor(tpmDev, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	wipe.Bytes(f)
	tpmDev.Close()

	out = grabStdout(t, func() {
		if err := FactorStatus(sock, 1, true, false); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, `"release_key": true`) || !strings.Contains(out, `"phones": 1`) {
		t.Fatalf("status json: %q", out)
	}

	if err := FactorUnenrol(sock, 1, privPath, false); err != nil {
		t.Fatalf("unenrol: %v", err)
	}
	tpmDev, _ = tpmdev.Open(sock)
	defer tpmDev.Close()
	_, sb, _ := phonegate.ReadSlot(tpmDev, slot)
	if len(sb.Payload.Attestation.ReleaseKeyPublic) != 0 {
		t.Fatal("the release key is still in the blob")
	}
	if _, err := phonegate.UnwrapFactor(tpmDev, sb, slot, sb.Payload.Attestation, w); !errors.Is(err, phonegate.ErrNoReleaseKey) {
		t.Fatalf("the kept factor after unenrol: %v", err)
	}
}

// grabStdout is captureStdout for the integration build.
func grabStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	defer func() { os.Stdout = old }()
	fn()
	w.Close()
	return string(<-done)
}
