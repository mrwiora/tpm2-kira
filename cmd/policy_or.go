package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	// DefaultPublicKeyPath is the default path for the signing public key (sbctl secure boot DB cert)
	DefaultPublicKeyPath = "/var/lib/sbctl/keys/db/db.pem"
	// DefaultPrivateKeyPath is the default path for the signing private key (sbctl secure boot DB key)
	DefaultPrivateKeyPath = "/var/lib/sbctl/keys/db/db.key"
)

// SigningKeyType indicates the type of the signing key used for PolicySigned
type SigningKeyType byte

const (
	SigningKeyRSA2048 SigningKeyType = 0
	SigningKeyRSA4096 SigningKeyType = 1
	SigningKeyECCP256 SigningKeyType = 2
	SigningKeyECCP384 SigningKeyType = 3
)

// PolicyORBranchDigests holds the two branch digests for PolicyOR
type PolicyORBranchDigests struct {
	PCRBranchDigest    tpm2.TPM2BDigest // Branch 1: PolicyPCR
	SignedBranchDigest tpm2.TPM2BDigest // Branch 2: PolicySigned
}

// LoadSigningPublicKeyFromPEM reads a PEM file and extracts the public key.
// Supports both X.509 certificates and raw public keys in PEM format.
func LoadSigningPublicKeyFromPEM(pemPath string) (crypto.PublicKey, []byte, error) {
	pemData, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key file %s: %w", pemPath, err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM data from %s", pemPath)
	}

	var pubKey crypto.PublicKey

	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse X.509 certificate from %s: %w", pemPath, err)
		}
		pubKey = cert.PublicKey
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse public key from %s: %w", pemPath, err)
		}
		pubKey = key
	default:
		return nil, nil, fmt.Errorf("unsupported PEM block type %q in %s (expected CERTIFICATE or PUBLIC KEY)", block.Type, pemPath)
	}

	return pubKey, pemData, nil
}

// LoadSigningPrivateKeyFromPEM reads a PEM file and extracts the private key.
// Supports RSA and ECDSA private keys, both PKCS#1, PKCS#8, and SEC1 formats.
func LoadSigningPrivateKeyFromPEM(pemPath string) (crypto.Signer, error) {
	pemData, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", pemPath, err)
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

// ComputeKeyName computes the TPM Name of a public key entirely in software.
// Name = nameAlg || H_nameAlg(TPMT_PUBLIC marshalled bytes)
// This avoids needing LoadExternal, so it works regardless of TPM key-size limits.
func ComputeKeyName(pubKey crypto.PublicKey) (tpm2.TPM2BName, error) {
	tpm2bPub, _, err := PublicKeyToTPM2BPublic(pubKey)
	if err != nil {
		return tpm2.TPM2BName{}, fmt.Errorf("failed to convert public key to TPM2B_PUBLIC: %w", err)
	}

	// TPM2BPublic.Bytes() returns the marshalled TPMT_PUBLIC (without the size prefix)
	publicBytes := tpm2bPub.Bytes()

	// Name = nameAlg (2 bytes big-endian) || SHA-256(marshalled TPMT_PUBLIC)
	nameHash := sha256.Sum256(publicBytes)
	nameAlgBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(nameAlgBytes, uint16(tpm2.TPMAlgSHA256))

	name := append(nameAlgBytes, nameHash[:]...)
	return tpm2.TPM2BName{Buffer: name}, nil
}

// ValidateKeyForTPM attempts to load the public key into the TPM to verify
// the TPM supports it. This should be called at seal time to fail early
// (e.g. if the TPM doesn't support RSA-4096). Returns nil on success.
func ValidateKeyForTPM(tpmDev transport.TPM, pubKey crypto.PublicKey) error {
	loadRsp, err := LoadExternalPublicKey(tpmDev, pubKey)
	if err != nil {
		return err
	}
	FlushHandle(tpmDev, loadRsp.ObjectHandle)
	return nil
}

// ComputePCRBranchDigest computes the policy digest for the PCR-only branch.
// This is the same as ComputePolicyDigestFromPCRValues - it creates a trial
// session with just PolicyPCR.
func ComputePCRBranchDigest(tpmDev transport.TPM, pcrIndices []int, pcrValues map[int][]byte, hashAlgo PCRHashAlgo) (tpm2.TPM2BDigest, error) {
	return ComputePolicyDigestFromPCRValues(tpmDev, pcrIndices, pcrValues, hashAlgo)
}

// ComputeSignedBranchDigest computes the policy digest for the PolicySigned branch.
// This loads the public key into the TPM, then delegates to
// ComputeSignedBranchDigestWithHandle.
//
// PolicySigned extends the digest as:
//
//	policyDigest = H(policyDigest || TPM_CC_PolicySigned || authName || policyRef)
func ComputeSignedBranchDigest(tpmDev transport.TPM, pubKey crypto.PublicKey) (tpm2.TPM2BDigest, error) {
	// Load the key into the TPM to get a handle for PolicySigned.
	loadRsp, err := LoadExternalPublicKey(tpmDev, pubKey)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to load signing key into TPM for name computation: %w", err)
	}
	defer FlushHandle(tpmDev, loadRsp.ObjectHandle)

	return ComputeSignedBranchDigestWithHandle(tpmDev, loadRsp.ObjectHandle, loadRsp.Name, pubKey)
}

// ComputeSignedBranchDigestWithHandle computes the PolicySigned branch digest
// reusing an already-loaded key handle. This avoids a second LoadExternal call
// when the key is already loaded (e.g. during unseal).
func ComputeSignedBranchDigestWithHandle(tpmDev transport.TPM, keyHandle tpm2.TPMIDHObject, keyName tpm2.TPM2BName, pubKey crypto.PublicKey) (tpm2.TPM2BDigest, error) {
	// Use a trial policy session so the TPM computes the digest authoritatively.
	// Trial mode skips signature verification, so we provide a dummy signature.
	sess, cleanup, err := tpm2.PolicySession(tpmDev, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to create trial session for signed branch: %w", err)
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

// ComputeSignedBranchDigestFromName computes the PolicySigned branch digest
// from a pre-computed TPM key Name. This is a pure hash computation.
func ComputeSignedBranchDigestFromName(keyName tpm2.TPM2BName) tpm2.TPM2BDigest {
	// Start with an empty (zero) policy digest (SHA-256)
	policyDigest := make([]byte, sha256.Size)

	// Extend: policyDigest = H(policyDigest || TPM_CC_PolicySigned || keyName)
	ccBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ccBytes, uint32(tpm2.TPMCCPolicySigned))

	h := sha256.New()
	h.Write(policyDigest)
	h.Write(ccBytes)
	h.Write(keyName.Buffer)

	return tpm2.TPM2BDigest{Buffer: h.Sum(nil)}
}

// ComputePolicyORDigest computes the final combined PolicyOR digest from two branches.
// The resulting digest is what gets set as the authPolicy on the sealed object.
func ComputePolicyORDigest(tpmDev transport.TPM, branches PolicyORBranchDigests) (tpm2.TPM2BDigest, error) {
	// Create trial policy session
	sess, cleanup, err := tpm2.PolicySession(tpmDev, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to create trial session for PolicyOR: %w", err)
	}
	defer cleanup()

	// Execute PolicyOR in trial mode with both branch digests
	_, err = tpm2.PolicyOr{
		PolicySession: sess.Handle(),
		PHashList: tpm2.TPMLDigest{
			Digests: []tpm2.TPM2BDigest{
				branches.PCRBranchDigest,
				branches.SignedBranchDigest,
			},
		},
	}.Execute(tpmDev)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to execute PolicyOR in trial session: %w", err)
	}

	// Get the combined policy digest
	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(tpmDev)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("failed to get PolicyOR digest: %w", err)
	}

	return pgd.PolicyDigest, nil
}

// ComputeFullPolicyDigest computes the complete PolicyOR digest combining PCR and Signed branches.
// This is the main entry point for computing the auth policy at seal time.
//
// The signing key is loaded into the TPM via LoadExternal to obtain its canonical Name.
// This ensures the signed branch digest computed at seal time will match what the TPM
// produces at unseal time (PolicySigned uses the TPM's internally-computed key name).
func ComputeFullPolicyDigest(tpmDev transport.TPM, pcrIndices []int, pcrValues map[int][]byte, hashAlgo PCRHashAlgo, pubKey crypto.PublicKey, debug bool) (tpm2.TPM2BDigest, *PolicyORBranchDigests, error) {
	// Load signing key into TPM to get canonical Name and validate compatibility.
	// This replaces the separate ValidateKeyForTPM call and guarantees the Name
	// used here matches what LoadExternal returns at unseal time.
	loadRsp, err := LoadExternalPublicKey(tpmDev, pubKey)
	if err != nil {
		return tpm2.TPM2BDigest{}, nil, fmt.Errorf("signing key incompatible with this TPM: %w", err)
	}
	tpmKeyName := loadRsp.Name
	FlushHandle(tpmDev, loadRsp.ObjectHandle)

	if debug {
		fmt.Printf("TPM key name (from LoadExternal): %x\n", tpmKeyName.Buffer)
		// Compare with software-computed name for diagnostics
		swName, swErr := ComputeKeyName(pubKey)
		if swErr == nil {
			if fmt.Sprintf("%x", swName.Buffer) == fmt.Sprintf("%x", tpmKeyName.Buffer) {
				fmt.Printf("Software key name: %x (MATCHES TPM)\n", swName.Buffer)
			} else {
				fmt.Printf("Software key name: %x (DIFFERS from TPM — software computation is wrong)\n", swName.Buffer)
			}
		}
	}

	// Compute Branch 1: PolicyPCR
	pcrBranchDigest, err := ComputePCRBranchDigest(tpmDev, pcrIndices, pcrValues, hashAlgo)
	if err != nil {
		return tpm2.TPM2BDigest{}, nil, fmt.Errorf("failed to compute PCR branch digest: %w", err)
	}

	if debug {
		fmt.Printf("PolicyOR Branch 1 (PCR): %x\n", pcrBranchDigest.Buffer)
	}

	// Compute Branch 2: PolicySigned using trial session on the TPM.
	// This lets the TPM itself compute the digest, guaranteeing it matches
	// what a real PolicySigned session will produce at unseal time.
	signedBranchDigest, err := ComputeSignedBranchDigest(tpmDev, pubKey)
	if err != nil {
		return tpm2.TPM2BDigest{}, nil, fmt.Errorf("failed to compute signed branch digest: %w", err)
	}

	if debug {
		fmt.Printf("PolicyOR Branch 2 (Signed, trial): %x\n", signedBranchDigest.Buffer)
		// Also show the software-only computation for diagnostics
		swDigest := ComputeSignedBranchDigestFromName(tpmKeyName)
		fmt.Printf("PolicyOR Branch 2 (Signed, software): %x\n", swDigest.Buffer)
		if fmt.Sprintf("%x", signedBranchDigest.Buffer) != fmt.Sprintf("%x", swDigest.Buffer) {
			fmt.Printf("WARNING: Trial and software signed branch digests DIFFER — trial value will be used\n")
		}
	}

	branches := &PolicyORBranchDigests{
		PCRBranchDigest:    pcrBranchDigest,
		SignedBranchDigest: signedBranchDigest,
	}

	// Compute combined PolicyOR digest
	combinedDigest, err := ComputePolicyORDigest(tpmDev, *branches)
	if err != nil {
		return tpm2.TPM2BDigest{}, nil, fmt.Errorf("failed to compute PolicyOR digest: %w", err)
	}

	if debug {
		fmt.Printf("PolicyOR Combined Digest: %x\n", combinedDigest.Buffer)
	}

	return combinedDigest, branches, nil
}

// UnsealWithPCRBranch unseals data using the PCR policy branch of PolicyOR.
// This is the normal unseal path when PCR values match.
// Uses tpm2.Policy() callback to build the full policy session just-in-time.
func UnsealWithPCRBranch(tpmDev transport.TPM, loadedObject *LoadSealedObjectResponse, sealedBlob *SealedBlob, debug bool) ([]byte, error) {
	hashAlgo := sealedBlob.GetHashAlgo()
	pcrIndices := sealedBlob.GetPCRIndices()

	// We need to reconstruct the branch digests to call PolicyOR.
	// Load the signing public key from the blob to compute the signed branch digest.
	pubKey, err := ParsePublicKeyFromPEM(sealedBlob.SigningKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signing public key from blob: %w", err)
	}

	signedBranchDigest, err := ComputeSignedBranchDigest(tpmDev, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute signed branch digest: %w", err)
	}

	// Build a Policy session via callback that satisfies:
	//   1. PolicyPCR  (branch 1)
	//   2. PolicyOR   (combine branches)
	policySession := tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
		// Step 1: Satisfy PolicyPCR (Branch 1)
		_, pcrErr := tpm2.PolicyPCR{
			PolicySession: handle,
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      hashAlgo.TPMAlg(),
						PCRSelect: PcrsToBitmapBytes(pcrIndices),
					},
				},
			},
		}.Execute(tpm)
		if pcrErr != nil {
			return fmt.Errorf("failed to apply PolicyPCR in PCR branch: %w", pcrErr)
		}

		// Get current session digest (this is the PCR branch digest)
		pgd, pcrErr := tpm2.PolicyGetDigest{
			PolicySession: handle,
		}.Execute(tpm)
		if pcrErr != nil {
			return fmt.Errorf("failed to get policy digest after PolicyPCR: %w", pcrErr)
		}

		pcrBranchDigest := pgd.PolicyDigest

		if debug {
			fmt.Printf("PCR branch digest (live): %x\n", pcrBranchDigest.Buffer)
			fmt.Printf("Signed branch digest (computed): %x\n", signedBranchDigest.Buffer)
		}

		// Step 2: Execute PolicyOR to combine
		_, orErr := tpm2.PolicyOr{
			PolicySession: handle,
			PHashList: tpm2.TPMLDigest{
				Digests: []tpm2.TPM2BDigest{
					pcrBranchDigest,
					signedBranchDigest,
				},
			},
		}.Execute(tpm)
		if orErr != nil {
			return fmt.Errorf("failed to execute PolicyOR: %w", orErr)
		}

		return nil
	})

	// Unseal using the policy session
	unsealCmd := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadedObject.ObjectHandle,
			Name:   loadedObject.Name,
			Auth:   policySession,
		},
	}

	unsealRsp, err := unsealCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal data with PCR branch: %w", err)
	}

	return unsealRsp.OutData.Buffer, nil
}

// UnsealWithSignedBranch unseals data using the PolicySigned branch of PolicyOR.
// This is the recovery path when PCRs have changed, requiring the signing private key.
// Uses tpm2.Policy() callback to build the full policy session just-in-time.
func UnsealWithSignedBranch(tpmDev transport.TPM, loadedObject *LoadSealedObjectResponse, sealedBlob *SealedBlob, privateKeyPath string, debug bool) ([]byte, error) {
	// Parse the signing public key from the blob
	pubKey, err := ParsePublicKeyFromPEM(sealedBlob.SigningKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signing public key from blob: %w", err)
	}

	// Load the private key for signing
	privKey, err := LoadSigningPrivateKeyFromPEM(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	// Verify key pair matches
	if err := verifyKeyPairMatch(pubKey, privKey); err != nil {
		return nil, fmt.Errorf("key pair mismatch: %w", err)
	}

	// Load the public key into TPM for PolicySigned verification.
	// This must happen before the policy callback since the handle is captured.
	loadRsp, err := LoadExternalPublicKey(tpmDev, pubKey)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, loadRsp.ObjectHandle)

	// We need BOTH branch digests for PolicyOR, and they must exactly match
	// what was used at seal time. Recompute them now.
	pcrBranchDigest, err := computePCRBranchDigestFromBlob(tpmDev, sealedBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to recompute PCR branch digest: %w", err)
	}

	// Compute the signed branch digest via trial PolicySigned — this must
	// match what was used at seal time (ComputeSignedBranchDigest).
	// Reuse the already-loaded key handle to avoid TPM object memory exhaustion.
	signedBranchDigestExpected, err := ComputeSignedBranchDigestWithHandle(tpmDev, loadRsp.ObjectHandle, loadRsp.Name, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute signed branch digest: %w", err)
	}

	// Capture loaded key handle/name and private key for the closure
	keyHandle := loadRsp.ObjectHandle
	keyName := loadRsp.Name

	if debug {
		fmt.Printf("Unseal signed branch — TPM key name: %x\n", keyName.Buffer)
		fmt.Printf("Unseal signed branch — PCR branch digest (recomputed from blob): %x\n", pcrBranchDigest.Buffer)
		fmt.Printf("Unseal signed branch — signed branch digest (from trial PolicySigned): %x\n", signedBranchDigestExpected.Buffer)
		// Also show what the old software-only computation would give, for diagnostics
		swDigest := ComputeSignedBranchDigestFromName(keyName)
		fmt.Printf("Unseal signed branch — signed branch digest (software-only, for comparison): %x\n", swDigest.Buffer)
	}

	// Build a Policy session via callback that satisfies:
	//   1. PolicySigned  (branch 2)
	//   2. PolicyOR      (combine branches)
	policySession := tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
		if debug {
			// Check initial session digest — should be all zeros for a fresh session
			initPgd, initErr := tpm2.PolicyGetDigest{
				PolicySession: handle,
			}.Execute(tpm)
			if initErr == nil {
				fmt.Printf("Initial session digest (before PolicySigned): %x\n", initPgd.PolicyDigest.Buffer)
			}
			fmt.Printf("PolicySigned nonceTPM: %x\n", nonceTPM.Buffer)
		}

		// Compute aHash = SHA256(nonceTPM || expiration(0) || cpHashA(empty) || policyRef(empty))
		// expiration is a 4-byte signed int32 = 0
		aHashInput := make([]byte, 0, len(nonceTPM.Buffer)+4)
		aHashInput = append(aHashInput, nonceTPM.Buffer...)
		expirationBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(expirationBytes, 0)
		aHashInput = append(aHashInput, expirationBytes...)

		aHash := sha256.Sum256(aHashInput)

		if debug {
			fmt.Printf("PolicySigned aHash: %x\n", aHash)
		}

		// Sign the aHash with the private key
		tpmSig, signErr := signForTPM(privKey, aHash[:])
		if signErr != nil {
			return fmt.Errorf("failed to sign policy nonce: %w", signErr)
		}

		// Step 1: Satisfy PolicySigned (Branch 2)
		_, signedErr := tpm2.PolicySigned{
			AuthObject: tpm2.NamedHandle{
				Handle: keyHandle,
				Name:   keyName,
			},
			PolicySession: handle,
			NonceTPM:      nonceTPM,
			Expiration:    0,
			Auth:          tpmSig,
		}.Execute(tpm)
		if signedErr != nil {
			return fmt.Errorf("failed to execute PolicySigned: %w", signedErr)
		}

		if debug {
			// Get the live session digest after PolicySigned for diagnostics
			pgd, pgdErr := tpm2.PolicyGetDigest{
				PolicySession: handle,
			}.Execute(tpm)
			if pgdErr == nil {
				fmt.Printf("Signed branch digest (live from TPM): %x\n", pgd.PolicyDigest.Buffer)
				fmt.Printf("Signed branch digest (expected from trial): %x\n", signedBranchDigestExpected.Buffer)
				fmt.Printf("PCR branch digest (recomputed from blob): %x\n", pcrBranchDigest.Buffer)
			}
		}

		// Step 2: Execute PolicyOR to combine.
		// Use the SAME branch digests that were used at seal time. The TPM will:
		//   a) verify the current session digest matches one entry in PHashList
		//   b) replace the digest with H(0 || CC_PolicyOR || all entries)
		// Using the seal-time values ensures (b) produces the correct authPolicy.
		_, orErr := tpm2.PolicyOr{
			PolicySession: handle,
			PHashList: tpm2.TPMLDigest{
				Digests: []tpm2.TPM2BDigest{
					pcrBranchDigest,
					signedBranchDigestExpected,
				},
			},
		}.Execute(tpm)
		if orErr != nil {
			return fmt.Errorf("failed to execute PolicyOR: %w", orErr)
		}

		return nil
	})

	// Unseal using the policy session
	unsealCmd := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadedObject.ObjectHandle,
			Name:   loadedObject.Name,
			Auth:   policySession,
		},
	}

	unsealRsp, err := unsealCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal data with signed branch: %w", err)
	}

	return unsealRsp.OutData.Buffer, nil
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

// signForTPM signs a digest with the private key and returns a TPM-compatible signature structure.
func signForTPM(privKey crypto.Signer, digest []byte) (tpm2.TPMTSignature, error) {
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
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
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return tpm2.TPMTSignature{}, fmt.Errorf("ECDSA signing failed: %w", err)
		}

		byteLen := (key.Curve.Params().BitSize + 7) / 8
		rBytes := r.Bytes()
		sBytes := s.Bytes()

		// Pad to expected length
		if len(rBytes) < byteLen {
			padded := make([]byte, byteLen)
			copy(padded[byteLen-len(rBytes):], rBytes)
			rBytes = padded
		}
		if len(sBytes) < byteLen {
			padded := make([]byte, byteLen)
			copy(padded[byteLen-len(sBytes):], sBytes)
			sBytes = padded
		}

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
		return tpm2.TPMTSignature{}, fmt.Errorf("unsupported private key type %T for signing", key)
	}
}

// verifyKeyPairMatch checks that a public key and private key form a valid pair.
func verifyKeyPairMatch(pubKey crypto.PublicKey, privKey crypto.Signer) error {
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		rsaPriv, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("public key is RSA but private key is %T", privKey)
		}
		if pub.N.Cmp(rsaPriv.N) != 0 || pub.E != rsaPriv.E {
			return fmt.Errorf("RSA public and private keys do not match")
		}
	case *ecdsa.PublicKey:
		ecPriv, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("public key is ECDSA but private key is %T", privKey)
		}
		if pub.X.Cmp(ecPriv.PublicKey.X) != 0 || pub.Y.Cmp(ecPriv.PublicKey.Y) != 0 {
			return fmt.Errorf("ECDSA public and private keys do not match")
		}
	default:
		return fmt.Errorf("unsupported public key type %T", pubKey)
	}
	return nil
}

// computePCRBranchDigestFromBlob recomputes the PCR branch policy digest from stored blob data.
// This is needed at unseal time so we can provide the correct branch digest to PolicyOR.
func computePCRBranchDigestFromBlob(tpmDev transport.TPM, sealedBlob *SealedBlob) (tpm2.TPM2BDigest, error) {
	hashAlgo := sealedBlob.GetHashAlgo()
	pcrIndices := sealedBlob.GetPCRIndices()

	// Build PCR values map from blob digests
	pcrValues := make(map[int][]byte)
	for _, pair := range sealedBlob.PCRDigests {
		pcrValues[pair.Index] = pair.Digest.Buffer
	}

	return ComputePCRBranchDigest(tpmDev, pcrIndices, pcrValues, hashAlgo)
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

// VerifyPublicKeyMatch checks if the public key in a PEM file matches
// the signing key stored in a sealed blob.
func VerifyPublicKeyMatch(pemPath string, blobPEM []byte) error {
	filePubKey, _, err := LoadSigningPublicKeyFromPEM(pemPath)
	if err != nil {
		return fmt.Errorf("failed to load public key from %s: %w", pemPath, err)
	}

	blobPubKey, err := ParsePublicKeyFromPEM(blobPEM)
	if err != nil {
		return fmt.Errorf("failed to parse blob signing key: %w", err)
	}

	match := false
	switch fpk := filePubKey.(type) {
	case *rsa.PublicKey:
		if bpk, ok := blobPubKey.(*rsa.PublicKey); ok {
			match = fpk.N.Cmp(bpk.N) == 0 && fpk.E == bpk.E
		}
	case *ecdsa.PublicKey:
		if bpk, ok := blobPubKey.(*ecdsa.PublicKey); ok {
			match = fpk.X.Cmp(bpk.X) == 0 && fpk.Y.Cmp(bpk.Y) == 0
		}
	}

	if !match {
		return fmt.Errorf("public key in %s does not match the signing key stored in the sealed blob", pemPath)
	}

	return nil
}

// extractPublicKeyFromSigner extracts the crypto.PublicKey from a crypto.Signer (private key).
func extractPublicKeyFromSigner(privKey crypto.Signer) crypto.PublicKey {
	return privKey.Public()
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

// DerivePublicKeyPEM extracts the public key from a private key file and returns it as PEM bytes.
// This is a convenience function for when only the private key path is known.
func DerivePublicKeyPEM(privateKeyPath string) ([]byte, crypto.PublicKey, error) {
	privKey, err := LoadSigningPrivateKeyFromPEM(privateKeyPath)
	if err != nil {
		return nil, nil, err
	}

	pubKey := extractPublicKeyFromSigner(privKey)

	pemBytes, err := PublicKeyToPEM(pubKey)
	if err != nil {
		return nil, nil, err
	}

	return pemBytes, pubKey, nil
}

// CreateSealedObjectPolicyOR creates a sealed object using PolicyOR (no password auth).
// The sealed object can only be accessed via policy sessions (PCR or Signed).
func CreateSealedObjectPolicyOR(tpmDev transport.TPM, primaryKey *PrimaryKeyResponse, dataToSeal []byte, policyDigest tpm2.TPM2BDigest) (*CreateSealedObjectResponse, error) {
	createCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: nil, // No password
				},
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: dataToSeal,
				}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:    true,
				FixedParent: true,
				// UserWithAuth deliberately NOT set - policy-only access
			},
			AuthPolicy: policyDigest,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgNull,
					},
				},
			),
		}),
	}

	createRsp, err := createCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to create sealed object with PolicyOR: %w", err)
	}

	return &CreateSealedObjectResponse{
		Public:  createRsp.OutPublic.Bytes(),
		Private: createRsp.OutPrivate.Buffer,
	}, nil
}

// UnsealWithSignedBranchFromBlob is a high-level function that handles the entire
// signed-branch unseal workflow including loading keys and the sealed object.
func UnsealWithSignedBranchFromBlob(tpmDev transport.TPM, nvramIndex uint32, privateKeyPath string, debug bool) (*UnsealWorkflowResult, error) {
	// Read sealed blob from NVRAM
	sealedData, err := ReadFromNVRAM(tpmDev, nvramIndex)
	if err != nil {
		return nil, HandleNVRAMNotFoundError(err, debug)
	}

	// Unmarshal sealed blob
	sealedBlob, err := UnmarshalSealedBlob(sealedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sealed data: %w", err)
	}

	// Verify the blob has a signing key
	if len(sealedBlob.SigningKeyPEM) == 0 {
		return nil, fmt.Errorf("sealed blob does not contain a signing key (was sealed with an older version)")
	}

	// Create primary key
	primaryKey, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, primaryKey.ObjectHandle)

	// Load sealed object
	loadedObject, err := LoadSealedObject(tpmDev, primaryKey, sealedBlob)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, loadedObject.ObjectHandle)

	// Unseal using the signed branch
	unsealedData, err := UnsealWithSignedBranch(tpmDev, loadedObject, sealedBlob, privateKeyPath, debug)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal with signed branch: %w", err)
	}

	return &UnsealWorkflowResult{
		UnsealedData: unsealedData,
		SealedBlob:   sealedBlob,

	}, nil
}

// Ensure our big number padding works for edge cases
func padBigInt(b *big.Int, length int) []byte {
	bytes := b.Bytes()
	if len(bytes) >= length {
		return bytes[:length]
	}
	padded := make([]byte, length)
	copy(padded[length-len(bytes):], bytes)
	return padded
}
