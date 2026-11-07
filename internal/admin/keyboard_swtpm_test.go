//go:build integration

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/core/vaultproto"
	"github.com/tpm2-trust/tpm2-kira/internal/diskkey"
	"github.com/tpm2-trust/tpm2-kira/internal/measure"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/phonegate"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"
	"github.com/tpm2-trust/tpm2-kira/internal/vaultkey"
)

// The phone's keyboard on a real TPM: the release key passes what the phone checks, a pad wrapped for
// it opens in the approved boot state through the gate, keys and pad make the salt behind the enrolled
// key, and with a PCR of the selection moved the TPM refuses.
func TestPhoneKeyboardOnATPM(t *testing.T) {
	sock := startSWTPM(t)
	const slot = nvslot.NVRAMSlotStart + 1
	signer, pubPath := sealRealSlot(t, sock, slot) // sealed to PCR 23
	s := newSWTPMSetupAt(t, sock, "box")
	tpm := s.tpm
	_, sealed, err := phonegate.ReadSlot(tpm, slot)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := phonegate.CreateReleaseKey(tpm, sealed)
	if err != nil {
		t.Fatal(err)
	}
	s.blob.ReleaseKeyPublic, s.blob.ReleaseKeyPrivate = pub, priv
	if err := writeAttestBlob(tpm, slot, s.blob, signer); err != nil {
		t.Fatal(err)
	}
	_, sb, err := phonegate.ReadSlot(tpm, slot)
	if err != nil {
		t.Fatal(err)
	}
	att := sb.Payload.Attestation
	p := &sb.Payload
	s.blob.Phone.Verifiers = []attest.EnrolledVerifier{{ID: "my-phone", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	s.sealChannel(t, tpm, slot)
	if err := writeAttestBlob(tpm, slot, s.blob, signer); err != nil {
		t.Fatal(err)
	}

	// What the phone checks of the hand-over, against this TPM's real key.
	name, err := attest.ReleaseKeyName(att.ReleaseKeyPublic, p.SigningPublic, p.PolicyRef)
	if err != nil {
		t.Fatalf("the phone would refuse the release key: %v", err)
	}
	ek, ekPub, err := phonegate.CreateEK(tpm, att.EKAlg)
	if err != nil {
		t.Fatal(err)
	}
	tpmdev.FlushHandle(tpm, ek.Handle)
	f, w, err := phonegate.WrapFactor(tpm, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	pepper := []byte("correct9horse")
	release := func() (*attest.Release, *attest.KeyboardLayout) {
		seed, err := attest.NewKeyboardSeed(nil)
		if err != nil {
			t.Fatal(err)
		}
		layout, err := attest.KeyboardLayoutOf(seed)
		if err != nil {
			t.Fatal(err)
		}
		blob, enc, err := attest.MakeCredential(nil, ekPub, name, seed)
		if err != nil {
			t.Fatal(err)
		}
		return &attest.Release{Kind: attest.ReleaseKindFactor, Slot: uint8(nvslot.SlotNumber(slot)), CredentialBlob: w.Credential, EncryptedSecret: w.EncryptedSecret,
			Label: "luks", KeyboardCredential: blob, KeyboardSecret: enc}, layout
	}

	svc := phonegate.NewGateService(tpm, slot, pubPath, false)
	r, layout := release()
	status, msg := svc.TakeRelease(r)
	if status != attest.ReleaseOK || !strings.Contains(msg, "keyboard") {
		t.Fatalf("the TPM did not open salt and seed: %d %s", status, msg)
	}
	if got := svc.Salt(); !bytes.Equal(got, phonegate.FactorSalt(f, "luks")) {
		t.Fatal("not the phone salt")
	}
	sess := svc.KeyboardSession()
	if sess == nil {
		t.Fatal("no keyboard")
	}
	keys, err := layout.Keys(pepper)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sess.Pepper(keys)
	if err != nil || !bytes.Equal(got, pepper) {
		t.Fatalf("the keys of the phone's layout make %s, not %s: %v", got, pepper, err)
	}
	if _, err := sess.Pepper([]byte("not keys")); !errors.Is(err, diskkey.ErrNotAPepper) {
		t.Fatalf("keys outside the layout: %v", err)
	}

	// A release without a seed opens the salt alone: no keyboard.
	plain := phonegate.NewGateService(tpm, slot, pubPath, false)
	r, _ = release()
	r.KeyboardCredential, r.KeyboardSecret = nil, nil
	if status, _ := plain.TakeRelease(r); status != attest.ReleaseOK || plain.KeyboardSession() != nil || plain.Salt() == nil {
		t.Fatalf("without a seed: %d", status)
	}

	// On the booted system nothing is opened: the phone only says it keeps the salt.
	keep := phonegate.NewGateService(tpm, slot, pubPath, false)
	keep.Keep(&attest.FactorBlob{CredentialBlob: w.Credential, EncryptedSecret: w.EncryptedSecret, Label: "luks"})
	keep.KeepKeyboard(&attest.KeyboardKeep{ReleaseKeyPublic: att.ReleaseKeyPublic})
	r, _ = release()
	if status, _ := keep.TakeRelease(r); status != attest.ReleaseOK || !keep.Returned() || keep.KeyboardSession() != nil {
		t.Fatalf("the hand-over: %d, returned %v", status, keep.Returned())
	}
	if keep.KeyboardToKeep() == nil {
		t.Fatal("nothing to keep")
	}

	// A boot state the signing key did not approve.
	s.extend(t, 23, "x")
	moved := phonegate.NewGateService(tpm, slot, pubPath, false)
	r, _ = release()
	if status, _ := moved.TakeRelease(r); status != attest.ReleaseTPMRefused || moved.KeyboardSession() != nil {
		t.Fatalf("a moved PCR opened the seed: %d", status)
	}
}

// The vault's keyboard on a real TPM, against the vault's protocol: at boot R and the seed open
// while the slot's policy holds; the pepper is typed through the layout the vault showed after the
// boot's close, when the TPM would refuse. Password, salt and pepper make the enrolled key.
func TestVaultKeyboardOnATPM(t *testing.T) {
	sock := startSWTPM(t)
	const slot = nvslot.NVRAMSlotStart + 4
	privPath, pubPath := signingKeyFiles(t)
	if err := Seal(sock, "23", slot, pubPath, privPath, false, measure.PCRHashAlgoSHA256, false, true); err != nil {
		t.Fatal(err)
	}
	tv := &testVault{token: "tok-k", nonces: map[string][]byte{}}
	srv := httptest.NewTLSServer(tv)
	defer srv.Close()
	trustTestVault(t, srv)

	pepper := "correct9horse"
	oldAsk := terminalAsk
	answers := map[string]string{"Pepper": pepper, "The same pepper": pepper, "Password": "hunter2", "The same password": "hunter2"}
	answer := func(prompt string) ([]byte, error) {
		for _, k := range []string{"The same pepper", "The same password", "Pepper", "Password"} {
			if strings.HasPrefix(prompt, k) {
				return []byte(answers[k]), nil
			}
		}
		return nil, fmt.Errorf("unexpected prompt %q", prompt)
	}
	terminalAsk = answer
	defer func() { terminalAsk = oldAsk }()
	key, _, err := vaultEnrolKey(VaultEnrolOptions{TPMPath: sock, SealIndex: slot, URL: srv.URL, TypedPassword: true, Keyboard: true,
		Pin: vaultproto.PinOf(srv.Certificate().RawSubjectPublicKeyInfo), Token: "tok-k", PrivKeyPath: privPath})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if !tv.enrol.Keyboard || len(tv.enrol.Remote.Credential) == 0 {
		t.Fatalf("the enrolment sent: keyboard %v", tv.enrol.Keyboard)
	}
	if body, _ := json.Marshal(tv.enrol); strings.Contains(string(body), pepper) {
		t.Fatal("the pepper went to the vault")
	}
	tpmDev, err := transport.OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tpmDev.Close()
	vs := vaultkey.Slots(tpmDev, false)[0]
	if v := vs.Att.Vault; !v.Keyboard || v.Unattended() || v.Pepper || vaultRecipeOf(&v) != diskkey.RecipeVaultKeyboard {
		t.Fatalf("the vault method %+v", v)
	}

	salt, sess, err := vaultkey.OpenKeyboard(context.Background(), tpmDev, vs, func(string) {})
	if err != nil {
		t.Fatalf("at boot: %v", err)
	}
	// The boot closes; from here on the TPM opens nothing of the slot's.
	if err := extendPCR(tpmDev, 15, "close"); err != nil {
		t.Fatal(err)
	}
	keys, err := tv.layout.Keys([]byte(pepper))
	if err != nil {
		t.Fatal(err)
	}
	got, err := sess.Pepper(keys)
	if err != nil || string(got) != pepper {
		t.Fatalf("the keys of the vault's layout make %s: %v", got, err)
	}
	if _, err := sess.Pepper([]byte("short")); !errors.Is(err, diskkey.ErrNotAPepper) {
		t.Fatalf("not a pepper: %v", err)
	}
	if k, _ := diskkey.Combine([]byte("hunter2"), diskkey.KeyboardSalt(salt, got)); !bytes.Equal(k, key) {
		t.Fatal("password, salt and pepper do not make the enrolled key")
	}
	if k, _ := diskkey.Combine([]byte("hunter2"), salt); bytes.Equal(k, key) {
		t.Fatal("the key opens without the pepper")
	}
}
