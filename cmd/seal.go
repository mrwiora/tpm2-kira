package cmd

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Seal generates and seals a TOTP secret to TPM NVRAM with PCR policy and optional password
func Seal(tpmPath, pcrsStr string, nvramIndex uint32, password string, debug bool) error {
	// Parse PCRs first to display them
	pcrs, err := ParsePCRs(pcrsStr)
	if err != nil {
		return fmt.Errorf("invalid PCRs: %w", err)
	}

	// Display which PCRs are being used
	fmt.Println("=== Sealing Configuration ===")
	fmt.Printf("PCRs used for sealing: %v\n", pcrs)
	fmt.Println()
	for _, pcrIndex := range pcrs {
		fmt.Printf("  PCR%-2d: %s\n", pcrIndex, GetPCRDescription(pcrIndex))
	}
	fmt.Println()

	// Generate TOTP secret
	fmt.Println("Generating TOTP secret...")
	dataToSeal, err := generateTOTPSecret()
	if err != nil {
		return fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Seal the generated TOTP secret
	if err := sealData(tpmPath, pcrsStr, nvramIndex, dataToSeal, password, debug); err != nil {
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

	// Display QR code
	displayTOTPQRCode(totpSecret)

	fmt.Println()
	fmt.Println("To generate TOTP codes:")
	fmt.Printf("   tpm2-kira reveal --nvram 0x%08X\n", nvramIndex)
	if password != "" {
		fmt.Println("   (password fallback enabled for recovery)")
	} else {
		fmt.Println("   (WARNING: no password fallback - reseal will not be possible)")
	}

	return nil
}

// sealData seals the provided data to TPM NVRAM with PCR policy and password
// This is an internal function used by both Seal and Reseal
func sealData(tpmPath, pcrsStr string, nvramIndex uint32, dataToSeal []byte, password string, debug bool) error {
	// Parse PCRs
	pcrs, err := ParsePCRs(pcrsStr)
	if err != nil {
		return fmt.Errorf("invalid PCRs: %w", err)
	}

	if len(dataToSeal) == 0 {
		return fmt.Errorf("no data to seal")
	}

	// Open TPM
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	// Cleanup TPM memory
	CleanupTPM(tpmDev, debug)

	// Read current PCR values
	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: CreatePCRSelection(pcrs),
	}

	pcrReadResp, err := pcrRead.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to read PCRs: %w", err)
	}

	// Compute the policy digest
	policyDigest, err := ComputePolicyDigest(tpmDev, pcrs)
	if err != nil {
		return fmt.Errorf("failed to compute policy digest: %w", err)
	}

	// Create primary key in owner hierarchy
	primaryKey, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return err
	}
	defer FlushHandle(tpmDev, primaryKey.ObjectHandle)

	// Create sealed object
	createRsp, err := CreateSealedObject(tpmDev, primaryKey, dataToSeal, policyDigest, password)
	if err != nil {
		return err
	}

	// Prepare sealed blob
	var passwordHash, passwordSalt []byte
	if password != "" {
		var err error
		passwordHash, passwordSalt, err = HashPasswordArgon2(password)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
	}

	// Create PCRDigestPair structures
	pcrDigests := make([]PCRDigestPair, len(pcrs))
	for i, pcrIndex := range pcrs {
		pcrDigests[i] = PCRDigestPair{
			Index:  pcrIndex,
			Digest: pcrReadResp.PCRValues.Digests[i],
		}
	}

	sealedBlob := &SealedBlob{
		Version:      1,
		AppVersion:   AppVersion,
		Public:       createRsp.Public,
		Private:      createRsp.Private,
		PCRDigests:   pcrDigests,
		HasPassword:  password != "",
		PasswordHash: passwordHash,
		PasswordSalt: passwordSalt,
	}

	// Marshal to bytes
	data, err := sealedBlob.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal sealed data: %w", err)
	}

	// Write to TPM NVRAM
	if err := WriteToNVRAM(tpmDev, nvramIndex, data); err != nil {
		return fmt.Errorf("failed to write to NVRAM: %w", err)
	}

	if debug {
		fmt.Printf("Successfully sealed TOTP secret to TPM NVRAM index 0x%08X\n", nvramIndex)
		fmt.Printf("PCRs used: %v\n", pcrs)
		fmt.Printf("Secret size: %d bytes\n", len(dataToSeal))
		fmt.Printf("Total NVRAM size: %d bytes\n", len(data))
		if password != "" {
			fmt.Printf("Password fallback: enabled\n")
		} else {
			fmt.Printf("Password fallback: disabled\n")
		}
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
