package cmd

import (
	"crypto"
	"crypto/rand"
	"encoding/base32"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Seal generates and seals a TOTP secret to TPM NVRAM with PolicyOR (PCR + Signed branches)
func Seal(tpmPath, pcrsStr string, nvramIndex uint32, pubKeyPath, privKeyPath string, debug bool, hashAlgo PCRHashAlgo) error {
	// Fall back to default key paths when not provided by the user
	if pubKeyPath == "" {
		pubKeyPath = DefaultPublicKeyPath
	}
	if privKeyPath == "" {
		privKeyPath = DefaultPrivateKeyPath
	}

	// Parse PCR specs first to display them
	specs, err := ParsePCRSpecs(pcrsStr)
	if err != nil {
		return fmt.Errorf("invalid PCRs: %w", err)
	}

	// Load and validate the signing public key
	pubKey, _, err := LoadSigningPublicKeyFromPEM(pubKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load signing public key: %w", err)
	}

	// Display which PCRs are being used
	fmt.Println("=== Sealing Configuration ===")
	fmt.Printf("Hash Algorithm: %s (%d-byte PCR digests)\n", hashAlgo.DisplayString(), hashAlgo.DigestSize())
	fmt.Printf("PCRs used for sealing: %s\n", PCRSpecsToString(specs))
	fmt.Printf("Signing Key: %s (%s, fingerprint: %s)\n", pubKeyPath, PublicKeyDescription(pubKey), PublicKeyFingerprint(pubKey))
	fmt.Printf("Authentication: PolicyOR (PCR branch + PolicySigned branch)\n")
	fmt.Println()
	for _, spec := range specs {
		fmt.Printf("  PCR%-2d (%s): %s\n", spec.Index, spec.Source.String(), GetPCRDescription(spec.Index))
	}
	fmt.Println()

	// Generate TOTP secret
	fmt.Println("Generating TOTP secret...")
	dataToSeal, err := generateTOTPSecret()
	if err != nil {
		return fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Seal the generated TOTP secret
	if err := sealDataWithSpecs(tpmPath, specs, nvramIndex, dataToSeal, pubKey, pubKeyPath, privKeyPath, debug, hashAlgo); err != nil {
		return err
	}

	// Display TOTP information
	fmt.Println()
	fmt.Println("=== TOTP Secret Generated ===")
	totpSecret := string(dataToSeal)
	fmt.Printf("Secret: %s\n", totpSecret)
	fmt.Println()
	fmt.Println("Scan QR Code with authenticator app:")
	fmt.Println()

	// Display QR code with slot and PCR information
	displayTOTPQRCode(totpSecret, nvramIndex, PCRSpecsToString(specs))

	fmt.Println()
	fmt.Println("To generate TOTP codes:")
	fmt.Printf("   tpm2-kira reveal --nvram 0x%08X\n", nvramIndex)
	fmt.Println("   (PolicyOR: PCR branch for normal access, PolicySigned for recovery)")

	return nil
}

// sealDataWithSpecs seals data using explicit PCR specs with PolicyOR (PCR + Signed branches)
func sealDataWithSpecs(tpmPath string, specs []PCRSpec, nvramIndex uint32, dataToSeal []byte, pubKey crypto.PublicKey, pubKeyPath, privKeyPath string, debug bool, hashAlgo PCRHashAlgo) error {
	if len(specs) == 0 {
		return fmt.Errorf("no PCRs specified")
	}

	if len(dataToSeal) == 0 {
		return fmt.Errorf("no data to seal")
	}

	if pubKey == nil {
		return fmt.Errorf("no signing public key provided")
	}

	if privKeyPath == "" {
		privKeyPath = DefaultPrivateKeyPath
	}

	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	// Cleanup TPM memory
	CleanupTPM(tpmDev, debug)

	// Load the signing private key — required for PolicySigned NV writes.
	// This is done after the TPM open so that simple input validations and
	// the TPM availability check run first.
	privKey, err := LoadSigningPrivateKeyFromPEM(privKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load signing private key for NV write authorization: %w", err)
	}

	// Read all PCR values from their respective sources using the shared helper
	readResult, err := ReadPCRValues(tpmDev, specs, hashAlgo, MeasurePointModeSetting, debug)
	if err != nil {
		return err
	}

	// Build ordered list of all PCR indices (preserving spec order)
	allPCRIndices := PCRSpecIndices(specs)

	// Compute the full PolicyOR digest (PCR branch + Signed branch)
	combinedDigest, branches, err := ComputeFullPolicyDigest(tpmDev, allPCRIndices, readResult.Values, hashAlgo, pubKey, debug)
	if err != nil {
		return fmt.Errorf("failed to compute PolicyOR digest: %w", err)
	}

	if debug {
		fmt.Println("=== PolicyOR Digest Details ===")
		fmt.Printf("PCR branch digest: %x\n", branches.PCRBranchDigest.Buffer)
		fmt.Printf("Signed branch digest: %x\n", branches.SignedBranchDigest.Buffer)
		fmt.Printf("Combined PolicyOR digest: %x\n", combinedDigest.Buffer)
		fmt.Printf("PCR values used in policy:\n")
		for _, spec := range specs {
			val := readResult.Values[spec.Index]
			sourceLabel := spec.Source.String()
			if spec.Source == PCRSourceUKI {
				sourceLabel = fmt.Sprintf("uki [%s]", spec.Command)
			}
			fmt.Printf("  PCR%-2d (%s): %x\n", spec.Index, sourceLabel, val)
		}
		fmt.Println()
	}

	// Create PCRDigestPair structures with per-PCR source
	pcrDigests := make([]PCRDigestPair, len(specs))
	for i, spec := range specs {
		pcrDigests[i] = PCRDigestPair{
			Index:   spec.Index,
			Source:  spec.Source,
			Command: spec.Command,
			Digest: tpm2.TPM2BDigest{
				Buffer: readResult.Values[spec.Index],
			},
		}
	}

	// Create primary key in owner hierarchy
	primaryKey, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return err
	}
	defer FlushHandle(tpmDev, primaryKey.ObjectHandle)

	// Create sealed object with PolicyOR (no password)
	createRsp, err := CreateSealedObjectPolicyOR(tpmDev, primaryKey, dataToSeal, combinedDigest)
	if err != nil {
		return err
	}

	// Prepare sealed blob (Version 6: signed blob with payload substructure)
	sealedBlob := &SealedBlob{
		Version: CurrentBlobVersion,
		Payload: SealedBlobPayload{
			AppVersion:         AppVersion,
			Public:             createRsp.Public,
			Private:            createRsp.Private,
			PCRDigests:         pcrDigests,
			SignedBranchDigest: branches.SignedBranchDigest.Buffer,
			EventlogInfo:       readResult.EventlogInfo,
			PublicKeyPath:      pubKeyPath,
			PrivateKeyPath:     privKeyPath,
		},
	}

	// Marshal to bytes (unsigned envelope)
	unsignedBlob, err := sealedBlob.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal sealed data: %w", err)
	}

	// Sign the blob — the signature covers Version + PayloadLen + all
	// payload fields.  Any future field added to SealedBlobPayload is
	// automatically included.
	data, err := SignBlobPayload(unsignedBlob, privKey)
	if err != nil {
		return fmt.Errorf("failed to sign sealed blob: %w", err)
	}

	// Write to TPM NVRAM with PolicySigned-protected writes
	if err := WriteToNVRAM(tpmDev, nvramIndex, data, pubKey, privKey); err != nil {
		return fmt.Errorf("failed to write to NVRAM: %w", err)
	}

	if debug {
		fmt.Printf("Successfully sealed TOTP secret to TPM NVRAM index 0x%08X\n", nvramIndex)
		fmt.Printf("Hash algorithm: %s\n", hashAlgo.DisplayString())
		fmt.Printf("PCRs used: %s\n", PCRSpecsToString(specs))
		fmt.Printf("Secret size: %d bytes\n", len(dataToSeal))
		fmt.Printf("Total NVRAM size: %d bytes\n", len(data))
		if readResult.EventlogInfo != nil {
			fmt.Printf("Eventlog path: %s\n", readResult.EventlogInfo.EventlogPath)
			fmt.Printf("Total events: %d\n", readResult.EventlogInfo.TotalEvents)
		}
		fmt.Printf("Authentication: PolicyOR (PCR + PolicySigned)\n")
		fmt.Printf("Signing key: %s (fingerprint: %s)\n", PublicKeyDescription(pubKey), PublicKeyFingerprint(pubKey))
	}

	return nil
}

// generateTOTPSecret generates a TOTP-compatible secret
// Returns a 32-byte (256-bit) random secret encoded in Base32
func generateTOTPSecret() ([]byte, error) {
	// Generate 32 bytes of random data (256 bits)
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to Base32 (standard for TOTP secrets)
	// Remove padding as it's optional for TOTP
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)

	return []byte(secret), nil
}
