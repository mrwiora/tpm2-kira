package attest

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// A slot may take PCRs from a key elsewhere instead of from an approval: the
// PCR key signs PCR 11 of a unified kernel image for the phase enter-initrd
// (systemd-measure sign; the image's .pcrsig, handed over by systemd-stub).
// RSA of 2048 bits, which every TPM checks. The approved policy then is
//
//	PolicyPCR(the signed PCRs) ; PolicyAuthorize(PCR key, no reference)
//	; PolicyPCR(the others) ; PolicyNV(generation)
//
// which PolicyAuthorize's reset makes a digest of the PCR key's Name and what
// follows it.

// parsePCRKey is the RSA key in PKIX DER.
func parsePCRKey(der []byte) (*rsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("the PCR key: %w", err)
	}
	rk, ok := k.(*rsa.PublicKey)
	if !ok || rk.N.BitLen() != 2048 {
		return nil, errors.New("the PCR key must be RSA with 2048 bits: what every TPM checks")
	}
	return rk, nil
}

// PCRKeyPublic is the PCR key's public area as it is loaded into a TPM to
// check its signatures.
func PCRKeyPublic(der []byte) (tpm2.TPMTPublic, error) {
	k, err := parsePCRKey(der)
	if err != nil {
		return tpm2.TPMTPublic{}, err
	}
	exp := uint32(k.E)
	if k.E == 65537 {
		exp = 0 // the TPM's default
	}
	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgRSA,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{SignEncrypt: true},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme: tpm2.TPMTRSAScheme{
				Scheme:  tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			KeyBits:  2048,
			Exponent: exp,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: k.N.Bytes()}),
	}, nil
}

// PCRKeyName is the PCR key's Name in a TPM.
func PCRKeyName(der []byte) ([]byte, error) {
	pub, err := PCRKeyPublic(der)
	if err != nil {
		return nil, err
	}
	name, err := tpm2.ObjectName(&pub)
	if err != nil {
		return nil, err
	}
	return name.Buffer, nil
}

// VerifyPCRSignature checks the PCR key's signature (RSASSA, SHA-256 of pol,
// as systemd-measure signs) over pol, a PolicyPCR digest.
func VerifyPCRSignature(der, pol, sig []byte) error {
	k, err := parsePCRKey(der)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(pol)
	return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig)
}

// PCRSignatureForTPM is the signature as TPM2_VerifySignature takes it.
func PCRSignatureForTPM(sig []byte) tpm2.TPMTSignature {
	return tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgRSASSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSASSA, &tpm2.TPMSSignatureRSA{
			Hash: tpm2.TPMAlgSHA256,
			Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: sig},
		}),
	}
}
