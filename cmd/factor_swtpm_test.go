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

	"github.com/matthias/tpm2-kira/attest"
)

// The factor's round trip on swtpm: wrapped for this TPM's EK and the
// slot's release key, it opens in the boot state the signing key approved
// and nowhere else - not after a PCR of the selection moved, not on another
// TPM, and not without the command code the release key's policy ends in.
func TestFactorOpensOnlyInTheApprovedBootState(t *testing.T) {
	sock := startSWTPM(t)
	const slot = NVRAMSlotStart + 1
	signer, pubPath := sealRealSlot(t, sock, slot) // sealed to PCR 23
	s := newSWTPMSetupAt(t, sock, "box")
	tpm := s.tpm
	s.blob.EKAlg = uint16(tpm2.TPMAlgECC)
	_, sealed, err := readSlot(tpm, slot)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := createReleaseKey(tpm, sealed)
	if err != nil {
		t.Fatalf("release key: %v", err)
	}
	s.blob.ReleaseKeyPublic, s.blob.ReleaseKeyPrivate = pub, priv
	// The blob carries the key like the boot key: written and read back.
	if err := writeAttestBlob(tpm, slot, s.blob, signer); err != nil {
		t.Fatal(err)
	}
	_, sb, err := readSlot(tpm, slot)
	if err != nil {
		t.Fatal(err)
	}
	att := sb.Payload.Attestation
	if !bytes.Equal(att.ReleaseKeyPublic, pub) {
		t.Fatal("the release key did not survive the blob")
	}

	f, w, err := wrapFactor(tpm, att, nil)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if len(f) != FactorSize || len(w.Credential) == 0 || len(w.EncryptedSecret) == 0 {
		t.Fatalf("wrapped: %d bytes, %d, %d", len(f), len(w.Credential), len(w.EncryptedSecret))
	}
	got, err := unwrapFactor(tpm, sb, slot, att, w)
	if err != nil {
		t.Fatalf("unwrap in the approved state: %v", err)
	}
	if !bytes.Equal(got, f) {
		t.Fatal("the TPM opened the credential to something else")
	}
	salt := FactorSalt(f, "")
	if len(salt) != 64 || strings.Trim(string(salt), "0123456789abcdef") != "" {
		t.Fatalf("salt %q", salt)
	}
	if bytes.Equal(salt, FactorSalt(f, "home")) || !bytes.Equal(salt, FactorSalt(f, "luks")) {
		t.Fatal("labels")
	}

	// The coordinator does the same at boot, from a Release, and keeps
	// only the salt.
	s.blob.Phone.Verifiers = []attest.EnrolledVerifier{{ID: "my-phone", Name: "Pixel", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(tpm, slot, s.blob, signer); err != nil {
		t.Fatal(err)
	}
	svc := newGateService(tpm, slot, pubPath, false)
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

	// A different TPM (a second swtpm) with the same blob: the EK is
	// another, and the credential does not open.
	other := startSWTPM(t)
	otherTPM, err := OpenTPM(other)
	if err != nil {
		t.Fatal(err)
	}
	defer otherTPM.Close()
	if _, err := unwrapFactor(otherTPM, sb, slot, att, w); err == nil {
		t.Fatal("another TPM opened the credential")
	}

	// Without the command code the policy is the slot's, not the release
	// key's: the TPM refuses the ADMIN action.
	rk, err := loadReleaseKey(tpm, att)
	if err != nil {
		t.Fatal(err)
	}
	ek, _, err := createEK(tpm, att.EKAlg)
	if err != nil {
		t.Fatal(err)
	}
	session, done, err := approvedSession(tpm, sb, slot)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: rk.handle, Name: rk.name, Auth: session},
		KeyHandle:      tpm2.AuthHandle{Handle: ek.handle, Name: ek.name, Auth: endorsementPolicy()},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: w.Credential},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: w.EncryptedSecret},
	}.Execute(tpm)
	done()
	FlushHandle(tpm, rk.handle)
	FlushHandle(tpm, ek.handle)
	if err == nil {
		t.Fatal("the slot's policy alone opened the credential")
	}

	// The boot state moves: PCR 23 is extended, and the approval no longer
	// holds. The factor is not released.
	s.extend(t, 23, "something else booted")
	if _, err := unwrapFactor(tpm, sb, slot, att, w); !errors.Is(err, errFactorRefused) {
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
	if _, _, err := wrapFactor(s.tpm, s.blob, nil); !errors.Is(err, errNoReleaseKey) {
		t.Fatalf("%v", err)
	}
}

// factor status says whether a slot has a release key; factor unenrol
// takes it out, after which the phone's kept factor cannot be opened.
func TestFactorStatusAndUnenrol(t *testing.T) {
	sock := startSWTPM(t)
	const slot = NVRAMSlotStart + 1
	signer, pubPath := sealRealSlot(t, sock, slot)
	privPath := strings.TrimSuffix(pubPath, "seal.pub") + "seal.key"
	s := newSWTPMSetupAt(t, sock, "box")
	tpm := s.tpm
	s.blob.EKAlg = uint16(tpm2.TPMAlgECC)
	s.blob.Phone.Verifiers = []attest.EnrolledVerifier{{ID: "my-phone", Name: "Pixel", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(tpm, slot, s.blob, signer); err != nil {
		t.Fatal(err)
	}
	tpm.Close() // the commands open the TPM themselves

	out := grabStdout(t, func() {
		if err := FactorStatus(sock, 0, false, false); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Slot 1") || !strings.Contains(out, "no remote salt") {
		t.Fatalf("status without a factor: %q", out)
	}
	if err := FactorUnenrol(sock, 1, privPath, false); err == nil || !strings.Contains(err.Error(), "no remote salt enrolled") {
		t.Fatalf("unenrol without a factor: %v", err)
	}

	tpmDev, err := OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	_, sealed, err := readSlot(tpmDev, slot)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := createReleaseKey(tpmDev, sealed)
	if err != nil {
		t.Fatal(err)
	}
	s.blob.ReleaseKeyPublic, s.blob.ReleaseKeyPrivate = pub, priv
	if err := writeAttestBlob(tpmDev, slot, s.blob, signer); err != nil {
		t.Fatal(err)
	}
	att, _ := loadAttestBlob(tpmDev, slot)
	f, w, err := wrapFactor(tpmDev, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	wipe(f)
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
	tpmDev, _ = OpenTPM(sock)
	defer tpmDev.Close()
	_, sb, _ := readSlot(tpmDev, slot)
	if len(sb.Payload.Attestation.ReleaseKeyPublic) != 0 {
		t.Fatal("the release key is still in the blob")
	}
	if _, err := unwrapFactor(tpmDev, sb, slot, sb.Payload.Attestation, w); !errors.Is(err, errNoReleaseKey) {
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
