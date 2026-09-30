package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Setup performs initial tpm2-kira configuration: it creates the signing key
// pair and nothing else. Sealing a TOTP secret is a separate step ('seal'),
// which refuses to run until the keys exist.
//
//  1. Checks whether the keys directory already exists.
//     If it does, the system is considered already configured — an
//     informational message is printed and setup returns successfully (exit 0).
//  2. Creates the directory (including parents) and generates a P-256 ECDSA
//     key pair as seal.pub / seal.key.
func Setup() error {
	pubKeyPath := DefaultPublicKeyPath
	privKeyPath := DefaultPrivateKeyPath

	// ── Step 1: Check if keys directory already exists ──
	if info, err := os.Stat(DefaultKeysDir); err == nil && info.IsDir() {
		fmt.Printf("tpm2-kira has been already configured (directory %s exists).\n", DefaultKeysDir)
		fmt.Println("  Further configuration must be done manually.")
		fmt.Println("  Use 'tpm2-kira seal', 'tpm2-kira reseal', or edit the keys directly.")
		return nil
	}

	// ── Step 2: Create directory and generate P-256 key pair ──
	fmt.Printf("Creating keys directory: %s\n", DefaultKeysDir)
	if err := os.MkdirAll(DefaultKeysDir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory %s: %w", DefaultKeysDir, err)
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
	if err := WriteSigningKeyFile(privKeyPath, privPEM); err != nil {
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
	if err := WriteSigningKeyFile(pubKeyPath, pubPEM); err != nil {
		return fmt.Errorf("failed to write public key to %s: %w", pubKeyPath, err)
	}
	fmt.Printf("  Public key written to:  %s\n", pubKeyPath)

	fmt.Println()
	fmt.Println("=== Setup Complete ===")
	fmt.Printf("  Keys directory: %s\n", DefaultKeysDir)
	fmt.Printf("  Public key:     %s\n", pubKeyPath)
	fmt.Printf("  Private key:    %s\n", privKeyPath)
	fmt.Println()
	fmt.Println("Next, seal a TOTP secret and scan the QR code it prints:")
	fmt.Println("   tpm2-kira seal --pcrs 0,7")

	return nil
}
