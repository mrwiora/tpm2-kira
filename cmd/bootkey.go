package cmd

// The boot key (attest/bootkey.go) in this machine's TPM: an ECC key for key
// agreement under the same policy as the slot's TOTP key. Whatever the
// signing key has approved for the slot - PCR values and generation - lets
// the TPM use it, nothing else does; 'cap' locks it with the TOTP key when
// the initrd is left. So "the boot key answered" means exactly what "the
// code is shown" means, without a person comparing six digits against a
// clock.

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/matthias/tpm2-kira/attest"
)

// errBootKeyRefused: the TPM did not let the boot key be used, because the
// slot's policy does not hold in this boot state (or codes are locked).
var errBootKeyRefused = errors.New("the TPM refused the boot key: this boot state is not one the signing key approved")

// createBootKey makes the slot's boot key under the policy of its TOTP key.
func createBootKey(tpmDev transport.TPM, sealed *SealedBlob) (public, private []byte, err error) {
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
		InPublic:     tpm2.New2B(attest.BootKeyTemplate(totp.AuthPolicy.Buffer)),
	}.Execute(tpmDev)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create the boot key in the TPM: %w", err)
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}
	return tpm2.Marshal(*pub), rsp.OutPrivate.Buffer, nil
}

// loadBootKey loads the slot's boot key; the caller flushes the handle.
func loadBootKey(tpmDev transport.TPM, att *Attestation) (*loadedKey, error) {
	primary, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, primary.ObjectHandle)
	rsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](att.BootKeyPublic),
		InPrivate:    tpm2.TPM2BPrivate{Buffer: att.BootKeyPrivate},
	}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to load the boot key (was the TPM cleared?): %w", err)
	}
	return &loadedKey{handle: rsp.ObjectHandle, name: rsp.Name}, nil
}

// certifyBootKey has the attestation key state, for qd, that the boot key
// is an object of this TPM with exactly this public area (TPM2_Certify).
func certifyBootKey(tpmDev transport.TPM, att *Attestation, qd []byte) (info, sig []byte, err error) {
	ak, err := loadAK(tpmDev, att)
	if err != nil {
		return nil, nil, err
	}
	defer FlushHandle(tpmDev, ak.handle)
	boot, err := loadBootKey(tpmDev, att)
	if err != nil {
		return nil, nil, err
	}
	defer FlushHandle(tpmDev, boot.handle)
	rsp, err := tpm2.Certify{
		// Certifying is an ADMIN-role use of the key, which its (empty)
		// auth value allows; using it for key agreement is not.
		ObjectHandle:   tpm2.AuthHandle{Handle: boot.handle, Name: boot.name, Auth: tpm2.PasswordAuth(nil)},
		SignHandle:     tpm2.AuthHandle{Handle: ak.handle, Name: ak.name, Auth: tpm2.PasswordAuth(nil)},
		QualifyingData: tpm2.TPM2BData{Buffer: qd},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(tpmDev)
	if err != nil {
		return nil, nil, fmt.Errorf("TPM2_Certify of the boot key failed: %w", err)
	}
	return rsp.CertifyInfo.Bytes(), tpm2.Marshal(rsp.Signature), nil
}

// bootKeyPoint is the boot key's public point, uncompressed.
func bootKeyPoint(att *Attestation) ([]byte, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](att.BootKeyPublic)
	if err != nil {
		return nil, err
	}
	u, err := pub.Unique.ECC()
	if err != nil || len(u.X.Buffer) > 32 || len(u.Y.Buffer) > 32 {
		return nil, errors.New("the boot key has no P-256 point")
	}
	point := make([]byte, 65)
	point[0] = 4
	copy(point[1+32-len(u.X.Buffer):33], u.X.Buffer)
	copy(point[33+32-len(u.Y.Buffer):], u.Y.Buffer)
	return point, nil
}

// openBootChallenge answers the phone's challenge with the boot key: the
// TPM computes the shared secret if the slot's policy holds, and from it
// come the code for the screen and the proof for the phone.
func openBootChallenge(tpmDev transport.TPM, sealed *SealedBlob, blobIndex uint32, att *Attestation, ch *attest.BootChallenge, context []byte) (code string, proof []byte, err error) {
	if sealed == nil || len(att.BootKeyPublic) == 0 {
		return "", nil, errors.New("the slot has no boot key")
	}
	if len(ch.EphemeralPub) != 65 || ch.EphemeralPub[0] != 4 {
		return "", nil, errors.New("the challenge carries no P-256 point")
	}
	point, err := bootKeyPoint(att)
	if err != nil {
		return "", nil, err
	}
	boot, err := loadBootKey(tpmDev, att)
	if err != nil {
		return "", nil, err
	}
	defer FlushHandle(tpmDev, boot.handle)
	session, done, err := approvedSession(tpmDev, sealed, blobIndex)
	if err != nil {
		return "", nil, fmt.Errorf("%w (%v)", errBootKeyRefused, err)
	}
	defer done()
	rsp, err := tpm2.ECDHZGen{
		KeyHandle: tpm2.AuthHandle{Handle: boot.handle, Name: boot.name, Auth: session},
		InPoint: tpm2.New2B(tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: ch.EphemeralPub[1:33]},
			Y: tpm2.TPM2BECCParameter{Buffer: ch.EphemeralPub[33:65]},
		}),
	}.Execute(tpmDev)
	if err != nil {
		return "", nil, fmt.Errorf("%w (%v)", errBootKeyRefused, err)
	}
	out, err := rsp.OutPoint.Contents()
	if err != nil {
		return "", nil, err
	}
	z := make([]byte, 32)
	copy(z[32-len(out.X.Buffer):], out.X.Buffer)
	return attest.OpenBootChallenge(z, ch.EphemeralPub, point, context, ch.Sealed)
}
