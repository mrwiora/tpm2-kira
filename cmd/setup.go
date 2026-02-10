package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// SetupKeysDir is the directory where tpm2-kira stores its signing keys.
	SetupKeysDir = "/var/lib/tpm2-kira/keys"
)

// Setup performs initial tpm2-kira configuration:
//  1. Checks whether the keys directory already exists.
//     If it does, the system is considered already configured and setup aborts.
//  2. Creates the directory (including parents) and generates a P-256 ECDSA
//     key pair as seal.pub / seal.key.
//  3. Calls the equivalent of "tpm2-kira seal --pcrs 0,7" using the freshly
//     generated key pair.
func Setup(tpmPath string, nvramIndex uint32, debug bool) error {
	pubKeyPath := filepath.Join(SetupKeysDir, "seal.pub")
	privKeyPath := filepath.Join(SetupKeysDir, "seal.key")

	// ── Step 1: Check if keys directory already exists ──
	if info, err := os.Stat(SetupKeysDir); err == nil && info.IsDir() {
		return fmt.Errorf(
			"tpm2-kira has been already configured (directory %s exists).\n"+
				"  Further configuration must be done manually.\n"+
				"  Use 'tpm2-kira seal', 'tpm2-kira reseal', or edit the keys directly.",
			SetupKeysDir,
		)
	}

	// ── Step 2: Create directory and generate P-256 key pair ──
	fmt.Printf("Creating keys directory: %s\n", SetupKeysDir)
	if err := os.MkdirAll(SetupKeysDir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory %s: %w", SetupKeysDir, err)
	}

	fmt.Println("Generating ECDSA P-256 signing key pair...")
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate P-256 key pair: %w", err)
	}

	// Marshal and write the private key (SEC 1 / EC PRIVATE KEY PEM)
	ecDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to marshal EC private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecDER,
	})
	if err := os.WriteFile(privKeyPath, privPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key to %s: %w", privKeyPath, err)
	}
	fmt.Printf("  Private key written to: %s\n", privKeyPath)

	// Marshal and write the public key (PKIX / PUBLIC KEY PEM)
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	if err := os.WriteFile(pubKeyPath, pubPEM, 0644); err != nil {
		return fmt.Errorf("failed to write public key to %s: %w", pubKeyPath, err)
	}
	fmt.Printf("  Public key written to:  %s\n", pubKeyPath)
	fmt.Println()

	// ── Step 3: Seal with PCRs 0,7 using the generated keys ──
	fmt.Println("Proceeding to seal TOTP secret (equivalent to: tpm2-kira seal --pcrs 0,7)")
	fmt.Println()

	pcrsStr := "0,7"
	hashAlgo := PCRHashAlgoSHA256

	if err := Seal(tpmPath, pcrsStr, nvramIndex, pubKeyPath, privKeyPath, debug, hashAlgo); err != nil {
		return fmt.Errorf("seal failed during setup: %w", err)
	}

	fmt.Println()
	fmt.Println("=== Setup Complete ===")
	fmt.Printf("  Keys directory: %s\n", SetupKeysDir)
	fmt.Printf("  Public key:     %s\n", pubKeyPath)
	fmt.Printf("  Private key:    %s\n", privKeyPath)
	fmt.Printf("  PCRs sealed:    %s\n", pcrsStr)
	fmt.Printf("  Hash algorithm: %s\n", hashAlgo.DisplayString())

	return nil
}
