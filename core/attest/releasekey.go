package attest

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/google/go-tpm/tpm2"
)

// The release key (RK): the TPM object a wrapped factor is made for. A
// credential made with TPM2_MakeCredential for (EK, name of RK) opens only
// on the TPM holding that EK, and only with the RK loaded and its ADMIN
// role authorised - which, with adminWithPolicy set, means a policy session
// that ends in PolicyCommandCode(ActivateCredential). The policy before
// that is the slot's own: PolicyAuthorize(signing key, policyRef), the
// approval the signing key gives at seal and reseal for the PCR values of
// the image it approved. So the factor unwraps exactly where the slot's
// TOTP key computes: in the boot the signing key approved, with the
// tpm2-kira that image carries, and nowhere else. The key never signs or
// decrypts anything; it exists for its name.

const (
	ccPolicyCommandCode  = 0x0000016c // TPM_CC_PolicyCommandCode
	ccActivateCredential = 0x00000147 // TPM_CC_ActivateCredential
)

// ReleaseKeyPolicy extends the slot's policy (the TOTP key's authPolicy,
// PolicyAuthorizeDigest(signing key name, policyRef)) by
// PolicyCommandCode(TPM_CC_ActivateCredential), as the TPM computes it:
// H(policy ‖ TPM_CC_PolicyCommandCode ‖ TPM_CC_ActivateCredential).
func ReleaseKeyPolicy(slotPolicy []byte) []byte {
	h := sha256.New()
	h.Write(slotPolicy)
	var cc [8]byte
	binary.BigEndian.PutUint32(cc[:4], ccPolicyCommandCode)
	binary.BigEndian.PutUint32(cc[4:], ccActivateCredential)
	h.Write(cc[:])
	return h.Sum(nil)
}

// ReleaseKeyTemplate is the RK's public area under authPolicy: an ECC P-256
// object that cannot leave this TPM, with ADMIN actions bound to the policy
// and no USER action it could be used for.
func ReleaseKeyTemplate(authPolicy []byte) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			AdminWithPolicy:     true,
			SignEncrypt:         true,
			NoDA:                true,
			// SignEncrypt because an asymmetric object must be one or the
			// other, not because it signs: without UserWithAuth every use
			// needs the policy, and the policy ends in
			// PolicyCommandCode(ActivateCredential), which authorises no
			// Sign. The key's one use is to be the name a credential is
			// made for.
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			CurveID:   tpm2.TPMECCNistP256,
			KDF:       tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}
}
