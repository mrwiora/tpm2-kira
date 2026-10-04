package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// SigningKeyType indicates the type of the signing key used for PolicySigned
type SigningKeyType byte

const (
	SigningKeyRSA2048 SigningKeyType = 0
	SigningKeyRSA4096 SigningKeyType = 1
	SigningKeyECCP256 SigningKeyType = 2
	SigningKeyECCP384 SigningKeyType = 3
)

// LoadSigningPublicKeyFromPEM reads a PEM file and extracts the public key.
// Supports both X.509 certificates and raw public keys in PEM format. It does
// not check the file; seal and reseal use LoadCheckedSigningPublicKey.
func LoadSigningPublicKeyFromPEM(pemPath string) (crypto.PublicKey, []byte, error) {
	pemData, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key file %s: %w", pemPath, err)
	}
	pubKey, err := parseSigningPublicKeyPEM(pemData, pemPath)
	if err != nil {
		return nil, nil, err
	}
	return pubKey, pemData, nil
}

// LoadCheckedSigningPublicKey reads a public key file through
// ReadSigningKeyFile, so ownership, mode and symlinks are checked on the
// file that is parsed.
func LoadCheckedSigningPublicKey(pemPath string) (crypto.PublicKey, error) {
	pemData, err := ReadSigningKeyFile(pemPath)
	if err != nil {
		return nil, err
	}
	return parseSigningPublicKeyPEM(pemData, pemPath)
}

func parseSigningPublicKeyPEM(pemData []byte, pemPath string) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM data from %s", pemPath)
	}

	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse X.509 certificate from %s: %w", pemPath, err)
		}
		return cert.PublicKey, nil
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key from %s: %w", pemPath, err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q in %s (expected CERTIFICATE or PUBLIC KEY)", block.Type, pemPath)
	}
}

// LoadSigningPrivateKey reads a signing private key file. The file is either
// a PEM private key (RSA or ECDSA; PKCS#1, PKCS#8 or SEC1) or a YubiKey stub
// (see YubiKeyStub), told apart by content.
//
// A stub yields a signer that does not touch the token until it signs, so
// its Public() is available with the token unplugged.
//
// It does not check the file; seal and reseal use LoadCheckedSigningPrivateKey.
func LoadSigningPrivateKey(pemPath string) (crypto.Signer, error) {
	pemData, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", pemPath, err)
	}
	return parseSigningPrivateKey(pemData, pemPath)
}

// LoadCheckedSigningPrivateKey reads a private key file through
// ReadSigningKeyFile, so ownership, mode and symlinks are checked on the
// file that is parsed.
func LoadCheckedSigningPrivateKey(pemPath string) (crypto.Signer, error) {
	pemData, err := ReadSigningKeyFile(pemPath)
	if err != nil {
		return nil, err
	}
	return parseSigningPrivateKey(pemData, pemPath)
}

func parseSigningPrivateKey(pemData []byte, pemPath string) (crypto.Signer, error) {
	if isYubiKeyStub(pemData) {
		stub, pub, slot, err := ParseYubiKeyStub(pemData)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pemPath, err)
		}
		return &yubiKeySigner{path: pemPath, stub: stub, pub: pub, slot: slot}, nil
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM data from %s", pemPath)
	}

	var privKey crypto.Signer

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 RSA private key from %s: %w", pemPath, err)
		}
		privKey = key
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key from %s: %w", pemPath, err)
		}
		privKey = key
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key from %s: %w", pemPath, err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key from %s does not implement crypto.Signer", pemPath)
		}
		privKey = signer
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q in %s (expected RSA PRIVATE KEY, EC PRIVATE KEY, or PRIVATE KEY)", block.Type, pemPath)
	}

	return privKey, nil
}

// PublicKeyToTPM2BPublic converts a crypto.PublicKey to a TPM2B_PUBLIC structure
// suitable for LoadExternal. Supports RSA and ECDSA keys.
func PublicKeyToTPM2BPublic(pubKey crypto.PublicKey) (tpm2.TPM2BPublic, SigningKeyType, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return rsaPublicKeyToTPM2BPublic(key)
	case *ecdsa.PublicKey:
		return ecdsaPublicKeyToTPM2BPublic(key)
	default:
		return tpm2.TPM2BPublic{}, 0, fmt.Errorf("unsupported public key type %T (expected RSA or ECDSA)", pubKey)
	}
}

func rsaPublicKeyToTPM2BPublic(key *rsa.PublicKey) (tpm2.TPM2BPublic, SigningKeyType, error) {
	keyBits := key.N.BitLen()
	var keyType SigningKeyType

	switch keyBits {
	case 2048:
		keyType = SigningKeyRSA2048
	case 4096:
		keyType = SigningKeyRSA4096
	default:
		return tpm2.TPM2BPublic{}, 0, fmt.Errorf("unsupported RSA key size %d bits (expected 2048 or 4096)", keyBits)
	}

	// Get the modulus bytes, padded to the correct length
	nBytes := key.N.Bytes()
	expectedLen := keyBits / 8
	if len(nBytes) < expectedLen {
		padded := make([]byte, expectedLen)
		copy(padded[expectedLen-len(nBytes):], nBytes)
		nBytes = padded
	}

	pub := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: tpm2.TPMKeyBits(keyBits),
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: nBytes,
			},
		),
	})

	return pub, keyType, nil
}

func ecdsaPublicKeyToTPM2BPublic(key *ecdsa.PublicKey) (tpm2.TPM2BPublic, SigningKeyType, error) {
	var curveID tpm2.TPMECCCurve
	var keyType SigningKeyType

	switch key.Curve {
	case elliptic.P256():
		curveID = tpm2.TPMECCNistP256
		keyType = SigningKeyECCP256
	case elliptic.P384():
		curveID = tpm2.TPMECCNistP384
		keyType = SigningKeyECCP384
	default:
		return tpm2.TPM2BPublic{}, 0, fmt.Errorf("unsupported ECDSA curve (expected P-256 or P-384)")
	}

	// Get curve point coordinates as fixed-size big-endian byte slices
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()

	// Pad to expected length
	if len(xBytes) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(xBytes):], xBytes)
		xBytes = padded
	}
	if len(yBytes) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(yBytes):], yBytes)
		yBytes = padded
	}

	pub := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				CurveID: curveID,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: xBytes},
				Y: tpm2.TPM2BECCParameter{Buffer: yBytes},
			},
		),
	})

	return pub, keyType, nil
}

// LoadExternalPublicKey loads a public key into the TPM using LoadExternal.
// Returns the loaded key handle and name. Caller must flush the handle when done.
func LoadExternalPublicKey(tpmDev transport.TPM, pubKey crypto.PublicKey) (*tpm2.LoadExternalResponse, error) {
	tpm2bPub, _, err := PublicKeyToTPM2BPublic(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to TPM2B_PUBLIC: %w", err)
	}

	loadCmd := tpm2.LoadExternal{
		InPublic: tpm2bPub,
		// Hierarchy is left as zero value; the nullable tag maps this to
		// TPM_RH_NULL so the key Name is computed purely from nameAlg.
	}

	loadRsp, err := loadCmd.Execute(tpmDev)
	if err != nil {
		// Provide a clear error for key-size limitations
		if rsaKey, ok := pubKey.(*rsa.PublicKey); ok && rsaKey.N.BitLen() > 2048 {
			return nil, fmt.Errorf("failed to load external public key into TPM: %w\n"+
				"  Hint: this TPM may not support RSA-%d keys. Try using an RSA-2048 or ECC (P-256) key instead.",
				err, rsaKey.N.BitLen())
		}
		return nil, fmt.Errorf("failed to load external public key into TPM: %w", err)
	}

	return loadRsp, nil
}

// ComputeNVWritePolicyDigestWithHandle computes the PolicySigned digest that
// is the AuthPolicy of tpm2-kira's NV indices (blob and generation): any
// write must satisfy a PolicySigned session proving possession of the
// private key belonging to the public key loaded at keyHandle.
func ComputeNVWritePolicyDigestWithHandle(tpmDev transport.TPM, keyHandle tpm2.TPMIDHObject, keyName tpm2.TPM2BName, pubKey crypto.PublicKey) (tpm2.TPM2BDigest, error) {
	return computePolicySignedDigest(tpmDev, keyHandle, keyName, pubKey)
}

// computePolicySignedDigest computes the digest of a policy consisting of
// PolicySigned by the key loaded at keyHandle. A trial session lets the TPM
// compute it, so it matches what a real session produces.
func computePolicySignedDigest(tpmDev transport.TPM, keyHandle tpm2.TPMIDHObject, keyName tpm2.TPM2BName, pubKey crypto.PublicKey) (tpm2.TPM2BDigest, error) {
	// Use a trial policy session so the TPM computes the digest authoritatively.
	// Trial mode skips signature verification, so we provide a dummy signature.
	sess, cleanup, err := tpm2.PolicySession(tpmDev, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to create trial session for PolicySigned: %w", err)
	}
	defer cleanup()

	// Build a dummy signature that is structurally valid for the key type.
	dummySig, err := dummySignatureForKey(pubKey)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to create dummy signature: %w", err)
	}

	// Execute PolicySigned in trial mode — the TPM extends the session digest
	// exactly as it would in a real session, but without checking the signature.
	_, err = tpm2.PolicySigned{
		AuthObject: tpm2.NamedHandle{
			Handle: keyHandle,
			Name:   keyName,
		},
		PolicySession: sess.Handle(),
		Expiration:    0,
		Auth:          dummySig,
	}.Execute(tpmDev)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to execute trial PolicySigned: %w", err)
	}

	// Read back the digest the TPM computed.
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(tpmDev)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to get trial PolicySigned digest: %w", err)
	}

	return pgd.PolicyDigest, nil
}

// dummySignatureForKey returns a structurally valid but meaningless TPMTSignature
// suitable for use in a trial PolicySigned (where the TPM skips verification).
func dummySignatureForKey(pubKey crypto.PublicKey) (tpm2.TPMTSignature, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		sigLen := key.N.BitLen() / 8
		return tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, sigLen)},
				},
			),
		}, nil
	case *ecdsa.PublicKey:
		byteLen := (key.Curve.Params().BitSize + 7) / 8
		return tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSignatureECC{
					Hash:       tpm2.TPMAlgSHA256,
					SignatureR: tpm2.TPM2BECCParameter{Buffer: make([]byte, byteLen)},
					SignatureS: tpm2.TPM2BECCParameter{Buffer: make([]byte, byteLen)},
				},
			),
		}, nil
	default:
		return tpm2.TPMTSignature{}, fmt.Errorf("unsupported key type %T for dummy signature", pubKey)
	}
}

// ParsePublicKeyFromPEM extracts a crypto.PublicKey from PEM-encoded data (cert or public key).
func ParsePublicKeyFromPEM(pemData []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM data")
	}

	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
		}
		return cert.PublicKey, nil
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// signForTPM signs a digest with the private key and returns a TPM-compatible
// signature structure.
//
// It dispatches on the public key and goes through crypto.Signer, so a key
// held on a token signs exactly like a software key. Both produce ASN.1 DER
// for ECDSA, which the TPM wants as raw r and s padded to the curve size.
func signForTPM(privKey crypto.Signer, digest []byte) (tpm2.TPMTSignature, error) {
	switch pub := privKey.Public().(type) {
	case *rsa.PublicKey:
		sig, err := privKey.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			return tpm2.TPMTSignature{}, fmt.Errorf("RSA signing failed: %w", err)
		}
		return tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig: tpm2.TPM2BPublicKeyRSA{
						Buffer: sig,
					},
				},
			),
		}, nil
	case *ecdsa.PublicKey:
		der, err := privKey.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			return tpm2.TPMTSignature{}, fmt.Errorf("ECDSA signing failed: %w", err)
		}
		var parsed struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(der, &parsed)
		if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
			return tpm2.TPMTSignature{}, fmt.Errorf("ECDSA signature is not valid ASN.1 DER")
		}

		byteLen := (pub.Curve.Params().BitSize + 7) / 8
		if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 ||
			parsed.R.BitLen() > byteLen*8 || parsed.S.BitLen() > byteLen*8 {
			return tpm2.TPMTSignature{}, fmt.Errorf("ECDSA signature values out of range for %s", pub.Curve.Params().Name)
		}
		rBytes := parsed.R.FillBytes(make([]byte, byteLen))
		sBytes := parsed.S.FillBytes(make([]byte, byteLen))

		return tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSignatureECC{
					Hash:       tpm2.TPMAlgSHA256,
					SignatureR: tpm2.TPM2BECCParameter{Buffer: rBytes},
					SignatureS: tpm2.TPM2BECCParameter{Buffer: sBytes},
				},
			),
		}, nil
	default:
		return tpm2.TPMTSignature{}, fmt.Errorf("unsupported private key type %T for signing", pub)
	}
}

// verifyKeyPairMatch checks that a public key belongs to a private key.
// It compares public keys only, so it works for keys held on a token.
func verifyKeyPairMatch(pubKey crypto.PublicKey, privKey crypto.Signer) error {
	switch pubKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
	default:
		return fmt.Errorf("unsupported public key type %T", pubKey)
	}
	if !publicKeysEqual(pubKey, privKey.Public()) {
		return fmt.Errorf("public key (fingerprint %s) does not belong to the private key (fingerprint %s)",
			PublicKeyFingerprint(pubKey), PublicKeyFingerprint(privKey.Public()))
	}
	return nil
}

// verifySignature checks a signature in the format crypto.Signer produces
// for a SHA-256 digest: PKCS #1 v1.5 for RSA, ASN.1 DER for ECDSA.
func verifySignature(pub crypto.PublicKey, digest, sig []byte) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig) == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, digest, sig)
	}
	return false
}

// PublicKeyFingerprint computes a SHA-256 fingerprint of the public key for display purposes.
func PublicKeyFingerprint(pubKey crypto.PublicKey) string {
	var data []byte
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		data = key.N.Bytes()
	case *ecdsa.PublicKey:
		data = elliptic.Marshal(key.Curve, key.X, key.Y)
	default:
		return "unknown"
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash[:8])
}

// PublicKeyDescription returns a human-readable description of the public key type and size.
func PublicKeyDescription(pubKey crypto.PublicKey) string {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", key.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-%s", key.Curve.Params().Name)
	default:
		return "unknown"
	}
}

// PublicKeyToPEM encodes a crypto.PublicKey as PEM bytes (PKIX DER wrapped in PEM).
// This is used when we only have a private key and need to store the public key in the blob.
func PublicKeyToPEM(pubKey crypto.PublicKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to PKIX DER: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}
