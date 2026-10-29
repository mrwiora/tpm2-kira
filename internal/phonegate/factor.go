package phonegate

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

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
	"github.com/mrwiora/tpm2-kira/internal/wipe"
)

// The factor: one half of the disk's key, held by the phone, opened by this
// TPM (PLAN-PHONESALT.md).
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

// factorInfo is the derivation string of the salt (PLAN-PHONESALT.md
// §5.1): part of the contract between an enrolled keyslot and this code.
const factorInfo = "tpm2-kira/factor/v1"

// ErrNoReleaseKey: the slot has no release key, so no factor was enrolled.
var ErrNoReleaseKey = errors.New("the slot has no release key: no factor is enrolled for it")

// ErrFactorRefused: the TPM did not open the credential, because the slot's
// policy does not hold in this boot state (or the credential is not for
// this TPM and key).
var ErrFactorRefused = errors.New("the TPM refused to open the factor: this boot state is not one the signing key approved, or the credential is not for this machine")

// CreateReleaseKey makes the slot's release key under the slot's policy
// extended by PolicyCommandCode(ActivateCredential).
func CreateReleaseKey(tpmDev transport.TPM, sealed *nvslot.SealedBlob) (public, private []byte, err error) {
	policy, err := sealed.SlotPolicy()
	if err != nil {
		return nil, nil, err
	}
	primary, err := tpmdev.CreatePrimaryKey(tpmDev)
	if err != nil {
		return nil, nil, err
	}
	defer tpmdev.FlushHandle(tpmDev, primary.ObjectHandle)
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     tpm2.New2B(attest.ReleaseKeyTemplate(attest.ReleaseKeyPolicy(policy))),
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

// LoadReleaseKey loads the slot's release key; the caller flushes the handle.
func LoadReleaseKey(tpmDev transport.TPM, att *nvslot.Attestation) (*loadedKey, error) {
	if att == nil || len(att.ReleaseKeyPublic) == 0 {
		return nil, ErrNoReleaseKey
	}
	primary, err := tpmdev.CreatePrimaryKey(tpmDev)
	if err != nil {
		return nil, err
	}
	defer tpmdev.FlushHandle(tpmDev, primary.ObjectHandle)
	rsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](att.ReleaseKeyPublic),
		InPrivate:    tpm2.TPM2BPrivate{Buffer: att.ReleaseKeyPrivate},
	}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to load the release key (was the TPM cleared?): %w", err)
	}
	return &loadedKey{Handle: rsp.ObjectHandle, Name: rsp.Name}, nil
}

// WrapFactor draws F and wraps it for this TPM's EK and the slot's release
// key. F is returned for the one-time derivation at enrolment; the caller
// wipes it. Nothing of it is kept here.
func WrapFactor(tpmDev transport.TPM, att *nvslot.Attestation, rng io.Reader) (f []byte, w *nvslot.WrappedFactor, err error) {
	if rng == nil {
		rng = rand.Reader
	}
	rk, err := LoadReleaseKey(tpmDev, att)
	if err != nil {
		return nil, nil, err
	}
	tpmdev.FlushHandle(tpmDev, rk.Handle) // only its name is needed
	ek, ekPub, err := CreateEK(tpmDev, att.EKAlg)
	if err != nil {
		return nil, nil, err
	}
	tpmdev.FlushHandle(tpmDev, ek.Handle)

	f = make([]byte, FactorSize)
	if _, err := io.ReadFull(rng, f); err != nil {
		return nil, nil, fmt.Errorf("no randomness for the factor: %w", err)
	}
	cred, enc, err := attest.MakeCredential(rng, ekPub, rk.Name.Buffer, f)
	if err != nil {
		wipe.Bytes(f)
		return nil, nil, err
	}
	return f, &nvslot.WrappedFactor{Credential: cred, EncryptedSecret: enc}, nil
}

// UnwrapFactor opens a credential the phone returned: the release key is
// loaded and authorised through the slot's approved policy for this boot
// state plus PolicyCommandCode, the EK through the endorsement hierarchy.
// The result is F; the caller wipes it.
func UnwrapFactor(tpmDev transport.TPM, sealed *nvslot.SealedBlob, blobIndex uint32, att *nvslot.Attestation, w *nvslot.WrappedFactor) ([]byte, error) {
	if w == nil || len(w.Credential) == 0 || len(w.EncryptedSecret) == 0 {
		return nil, errors.New("no credential to open")
	}
	rk, err := LoadReleaseKey(tpmDev, att)
	if err != nil {
		return nil, err
	}
	defer tpmdev.FlushHandle(tpmDev, rk.Handle)
	ek, _, err := CreateEK(tpmDev, att.EKAlg)
	if err != nil {
		return nil, err
	}
	defer tpmdev.FlushHandle(tpmDev, ek.Handle)

	session, done, err := nvslot.ApprovedSessionThen(tpmDev, sealed, blobIndex, func(tpm transport.TPM, handle tpm2.TPMISHPolicy) error {
		_, err := tpm2.PolicyCommandCode{PolicySession: handle, Code: tpm2.TPMCCActivateCredential}.Execute(tpm)
		return err
	})
	if err != nil {
		return nil, err
	}
	defer done()

	rsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: rk.Handle, Name: rk.Name, Auth: session},
		KeyHandle:      tpm2.AuthHandle{Handle: ek.Handle, Name: ek.Name, Auth: EndorsementPolicy()},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: w.Credential},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: w.EncryptedSecret},
	}.Execute(tpmDev)
	if err != nil {
		if errors.Is(err, nvslot.ErrCodesLocked) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrFactorRefused, err)
	}
	if len(rsp.CertInfo.Buffer) != FactorSize {
		wipe.Bytes(rsp.CertInfo.Buffer)
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
	defer wipe.Bytes(out)
	return []byte(hex.EncodeToString(out))
}

// OpenTPMSalts opens the TPM salt of every slot that holds one (recipe
// 0x1200): while the code screen holds, the only time the slot's policy
// holds. The result maps a slot's number to its part T, for FactorSalt
// with the keyslot's label; the caller wipes them. A slot whose TPM salt
// does not open is named in failed, with why.
func OpenTPMSalts(tpmDev transport.TPM, debug bool) (opened map[int][]byte, failed map[int]error) {
	opened, failed = map[int][]byte{}, map[int]error{}
	for _, idx := range nvslot.FindPopulatedSlots(tpmDev, debug) {
		_, sb, err := ReadSlot(tpmDev, idx)
		if err != nil || sb.Payload.Attestation == nil || len(sb.Payload.Attestation.TPMSalt.Credential) == 0 {
			continue
		}
		att := sb.Payload.Attestation
		t, err := UnwrapFactor(tpmDev, sb, idx, att, &att.TPMSalt)
		if err != nil {
			failed[nvslot.SlotNumber(idx)] = err
			continue
		}
		opened[nvslot.SlotNumber(idx)] = t
	}
	return opened, failed
}
