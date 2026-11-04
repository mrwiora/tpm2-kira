//go:build integration

package admin

import (
	"bytes"
	"context"
	"crypto/rand"
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
	salt := []byte("abcd2345")
	release := func() (*attest.Release, []byte) {
		secret := make([]byte, attest.KeyboardSecretSize)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		pad, err := attest.KeyboardPadFrom(secret, len(salt))
		if err != nil {
			t.Fatal(err)
		}
		keys, err := attest.KeyboardKeys(salt, pad)
		if err != nil {
			t.Fatal(err)
		}
		blob, enc, err := attest.MakeCredential(nil, ekPub, name, secret)
		if err != nil {
			t.Fatal(err)
		}
		return &attest.Release{Kind: attest.ReleaseKindKeyboard, Slot: uint8(nvslot.SlotNumber(slot)), CredentialBlob: blob, EncryptedSecret: enc, Label: "luks"}, keys
	}

	svc := phonegate.NewGateService(tpm, slot, pubPath, false)
	r, keys := release()
	status, msg := svc.TakeRelease(r)
	if status != attest.ReleaseOK {
		t.Fatalf("the TPM did not open the pad: %d %s", status, msg)
	}
	sess := svc.KeyboardSession()
	if sess == nil {
		t.Fatal("no keyboard")
	}
	got, err := sess.Salt(keys)
	if err != nil {
		t.Fatal(err)
	}
	if want := phonegate.FactorSalt(salt, "luks"); !bytes.Equal(got, want) {
		t.Fatalf("keys and pad make %s, not %s", got, want)
	}
	if _, err := sess.Salt([]byte("not keys")); !errors.Is(err, diskkey.ErrWrongKeys) {
		t.Fatalf("keys outside the alphabet: %v", err)
	}
	wrong, err := sess.Salt([]byte("aaaaaaaa"))
	if err != nil || bytes.Equal(wrong, got) {
		t.Fatalf("wrong keys gave the salt: %v", err)
	}

	// On the booted system nothing is opened: the phone only says it keeps the salt.
	keep := phonegate.NewGateService(tpm, slot, pubPath, false)
	keep.KeepKeyboard(&attest.KeyboardKeep{Salt: salt})
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
		t.Fatalf("a moved PCR opened the pad: %d", status)
	}
}

// The vault's keyboard on a real TPM, against the vault's protocol: enrolled, the salt goes over TLS
// once; at boot K and the pad open while the slot's policy holds; the keys are proved, and a pepper
// comes under K, after the boot's close, when the TPM would refuse. Keys and pepper make the enrolled key.
func TestVaultKeyboardOnATPM(t *testing.T) {
	for _, withPepper := range []bool{false, true} {
		t.Run(fmt.Sprintf("pepper=%v", withPepper), func(t *testing.T) {
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

			old := terminalAsk
			answers := map[string]string{"Pepper": "s3cret pepper", "The same pepper": "s3cret pepper", "Password": "hunter2", "The same password": "hunter2"}
			terminalAsk = func(prompt string) ([]byte, error) {
				for _, k := range []string{"The same pepper", "The same password", "Pepper", "Password"} {
					if strings.HasPrefix(prompt, k) {
						return []byte(answers[k]), nil
					}
				}
				return nil, fmt.Errorf("unexpected prompt %q", prompt)
			}
			defer func() { terminalAsk = old }()
			key, _, err := vaultEnrolKey(VaultEnrolOptions{TPMPath: sock, SealIndex: slot, URL: srv.URL, TypedPassword: true, Keyboard: true,
				Pin: vaultproto.PinOf(srv.Certificate().RawSubjectPublicKeyInfo), Token: "tok-k", PrivKeyPath: privPath, Pepper: withPepper})
			if err != nil {
				t.Fatalf("enrol: %v", err)
			}
			if len(tv.enrol.KeyboardSalt) != attest.KeyboardDefaultLength || attest.CheckKeyboardSalt(tv.enrol.KeyboardSalt) != nil {
				t.Fatalf("the salt sent: %d characters", len(tv.enrol.KeyboardSalt))
			}
			tpmDev, err := transport.OpenTPM(sock)
			if err != nil {
				t.Fatal(err)
			}
			defer tpmDev.Close()
			vs := vaultkey.Slots(tpmDev, false)[0]
			want := diskkey.RecipeVaultKeyboard
			if withPepper {
				want = diskkey.RecipeVaultKeyboardPepper
			}
			if v := vs.Att.Vault; !v.Keyboard || v.Unattended() || v.Pepper != withPepper || vaultRecipeOf(&v) != want {
				t.Fatalf("the vault method %+v", v)
			}

			tv.peppers, tv.gave = [][]byte{[]byte("s3cret pepper")}, 0
			sess, err := vaultkey.OpenKeyboard(context.Background(), tpmDev, vs, func(string) {})
			if err != nil {
				t.Fatalf("at boot: %v", err)
			}
			// The boot closes; from here on the TPM opens nothing of the slot's.
			if err := extendPCR(tpmDev, 15, "close"); err != nil {
				t.Fatal(err)
			}
			if !sess.NeedKeys() {
				t.Fatal("the keys are not asked for")
			}
			if _, err := sess.Salt([]byte("short")); !errors.Is(err, diskkey.ErrWrongKeys) {
				t.Fatalf("not keys: %v", err)
			}
			wrong := bytes.Clone(tv.keys)
			wrong[0] = attest.KeyboardAlphabet[(strings.IndexByte(attest.KeyboardAlphabet, wrong[0])+1)%len(attest.KeyboardAlphabet)]
			if _, err := sess.Salt(wrong); !errors.Is(err, diskkey.ErrWrongKeys) {
				t.Fatalf("wrong keys: %v", err)
			}
			salt, err := sess.Salt(tv.keys)
			if err != nil {
				t.Fatalf("the right keys: %v", err)
			}
			if sess.NeedKeys() {
				t.Fatal("the keys are asked for again")
			}
			if got, _ := diskkey.Combine([]byte("hunter2"), salt); !bytes.Equal(got, key) {
				t.Fatal("password, keys and pepper do not make the enrolled key")
			}
		})
	}
}
