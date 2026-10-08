package cmd

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/hkdf"

	"github.com/mrwiora/tpm2-kira/attest"
)

// The factor: one half of the disk's key, held by the phone, opened by this
// TPM (PLAN-FACTORRELEASE.md).
//
// At enrolment the machine draws F (32 bytes), wraps it with
// TPM2_MakeCredential - in software, attest.MakeCredential - for its own
// EK and the name of the slot's release key, and gives the phone the
// credential. The machine keeps nothing: not F, not the credential. At
// boot the phone returns the credential after a verdict it is satisfied
// with, the TPM opens it (TPM2_ActivateCredential) if, and only if, the
// release key's policy holds - the slot's approval for this boot state,
// then PolicyCommandCode - and F is back for as long as the key is being
// derived. The salt given to the combiner is not F but a derivation of
// it, so F itself never meets the password.

// FactorSize is the size of F: what TPM2_MakeCredential carries directly.
const FactorSize = 32

// factorInfo is the derivation string of the salt (PLAN-FACTORRELEASE.md
// §5.1): part of the contract between an enrolled keyslot and this code.
const factorInfo = "tpm2-kira/factor/v1"

// errNoReleaseKey: the slot has no release key, so no factor was enrolled.
var errNoReleaseKey = errors.New("the slot has no release key: no factor is enrolled for it")

// errFactorRefused: the TPM did not open the credential, because the slot's
// policy does not hold in this boot state (or the credential is not for
// this TPM and key).
var errFactorRefused = errors.New("the TPM refused to open the factor: this boot state is not one the signing key approved, or the credential is not for this machine")

// createReleaseKey makes the slot's release key under the slot's policy
// extended by PolicyCommandCode(ActivateCredential).
func createReleaseKey(tpmDev transport.TPM, sealed *SealedBlob) (public, private []byte, err error) {
	totp, err := tpm2.Unmarshal[tpm2.TPMTPublic](sealed.Payload.Public)
	if err != nil {
		return nil, nil, fmt.Errorf("the slot's TOTP key has no valid public area: %w", err)
	}
	if len(totp.AuthPolicy.Buffer) == 0 {
		return nil, nil, errors.New("the slot's TOTP key has no policy to share")
	}
	primary, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return nil, nil, err
	}
	defer FlushHandle(tpmDev, primary.ObjectHandle)
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     tpm2.New2B(attest.ReleaseKeyTemplate(attest.ReleaseKeyPolicy(totp.AuthPolicy.Buffer))),
	}.Execute(tpmDev)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create the release key in the TPM: %w", err)
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}
	return tpm2.Marshal(*pub), rsp.OutPrivate.Buffer, nil
}

// loadReleaseKey loads the slot's release key; the caller flushes the handle.
func loadReleaseKey(tpmDev transport.TPM, att *Attestation) (*loadedKey, error) {
	if att == nil || len(att.ReleaseKeyPublic) == 0 {
		return nil, errNoReleaseKey
	}
	primary, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, primary.ObjectHandle)
	rsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](att.ReleaseKeyPublic),
		InPrivate:    tpm2.TPM2BPrivate{Buffer: att.ReleaseKeyPrivate},
	}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to load the release key (was the TPM cleared?): %w", err)
	}
	return &loadedKey{handle: rsp.ObjectHandle, name: rsp.Name}, nil
}

// WrappedFactor is what the phone keeps: a credential only this machine's
// TPM can open, with the release key loaded under the slot's policy.
type WrappedFactor struct {
	Credential      []byte // TPM2B_ID_OBJECT contents
	EncryptedSecret []byte // TPM2B_ENCRYPTED_SECRET contents
}

// wrapFactor draws F and wraps it for this TPM's EK and the slot's release
// key. F is returned for the one-time derivation at enrolment; the caller
// wipes it. Nothing of it is kept here.
func wrapFactor(tpmDev transport.TPM, att *Attestation, rng io.Reader) (f []byte, w *WrappedFactor, err error) {
	if rng == nil {
		rng = rand.Reader
	}
	rk, err := loadReleaseKey(tpmDev, att)
	if err != nil {
		return nil, nil, err
	}
	FlushHandle(tpmDev, rk.handle) // only its name is needed
	ek, ekPub, err := createEK(tpmDev, att.EKAlg)
	if err != nil {
		return nil, nil, err
	}
	FlushHandle(tpmDev, ek.handle)

	f = make([]byte, FactorSize)
	if _, err := io.ReadFull(rng, f); err != nil {
		return nil, nil, fmt.Errorf("no randomness for the factor: %w", err)
	}
	cred, enc, err := attest.MakeCredential(rng, ekPub, rk.name.Buffer, f)
	if err != nil {
		wipe(f)
		return nil, nil, err
	}
	return f, &WrappedFactor{Credential: cred, EncryptedSecret: enc}, nil
}

// unwrapFactor opens a credential the phone returned: the release key is
// loaded and authorised through the slot's approved policy for this boot
// state plus PolicyCommandCode, the EK through the endorsement hierarchy.
// The result is F; the caller wipes it.
func unwrapFactor(tpmDev transport.TPM, sealed *SealedBlob, blobIndex uint32, att *Attestation, w *WrappedFactor) ([]byte, error) {
	if w == nil || len(w.Credential) == 0 || len(w.EncryptedSecret) == 0 {
		return nil, errors.New("no credential to open")
	}
	rk, err := loadReleaseKey(tpmDev, att)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, rk.handle)
	ek, _, err := createEK(tpmDev, att.EKAlg)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, ek.handle)

	session, done, err := approvedSessionThen(tpmDev, sealed, blobIndex, func(tpm transport.TPM, handle tpm2.TPMISHPolicy) error {
		_, err := tpm2.PolicyCommandCode{PolicySession: handle, Code: tpm2.TPMCCActivateCredential}.Execute(tpm)
		return err
	})
	if err != nil {
		return nil, err
	}
	defer done()

	rsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: rk.handle, Name: rk.name, Auth: session},
		KeyHandle:      tpm2.AuthHandle{Handle: ek.handle, Name: ek.name, Auth: endorsementPolicy()},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: w.Credential},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: w.EncryptedSecret},
	}.Execute(tpmDev)
	if err != nil {
		if errors.Is(err, ErrCodesLocked) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", errFactorRefused, err)
	}
	if len(rsp.CertInfo.Buffer) != FactorSize {
		wipe(rsp.CertInfo.Buffer)
		return nil, fmt.Errorf("the credential opened to %d bytes, not a factor", len(rsp.CertInfo.Buffer))
	}
	return rsp.CertInfo.Buffer, nil
}

// FactorSalt derives the combiner's salt from F: 64 lowercase hexadecimal
// characters, HKDF-SHA256(F, info = factorInfo ‖ lp(label)). The label
// (default "luks") lets one factor serve volumes with unrelated salts. The
// characters, not their decoding, are the salt.
func FactorSalt(f []byte, label string) []byte {
	if label == "" {
		label = "luks"
	}
	info := append([]byte(factorInfo), byte(len(label)>>8), byte(len(label)))
	info = append(info, label...)
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, f, nil, info), out); err != nil {
		panic(err) // HKDF with a fixed length cannot fail
	}
	defer wipe(out)
	return []byte(hex.EncodeToString(out))
}
