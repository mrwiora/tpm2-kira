package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// SetupKeyChoice selects where setup puts the signing key.
type SetupKeyChoice struct {
	// Local forces a key file, skipping the token question.
	Local bool
	// TokenRef, when set, forces that token slot.
	TokenRef string
}

// Setup performs initial tpm2-kira configuration:
//  1. Checks whether the keys directory already exists.
//     If it does, the system is considered already configured — an
//     informational message is printed and setup returns successfully (exit 0).
//  2. Decides where the signing key lives. A key file is the default; when a
//     hardware token is connected and someone is there to answer, setup offers
//     it as an alternative rather than leaving the user to find 'yubikey adopt'
//     on their own.
//  3. Generates a P-256 ECDSA key pair as seal.pub / seal.key, or adopts the
//     chosen token slot and caches only its public key.
//  4. Calls the equivalent of "tpm2-kira seal --pcrs 0,7".
func Setup(tpmPath string, nvramIndex uint32, choice SetupKeyChoice, debug bool) error {
	pubKeyPath := DefaultPublicKeyPath
	privKeyPath := DefaultPrivateKeyPath

	// ── Step 1: Check if keys directory already exists ──
	if info, err := os.Stat(DefaultKeysDir); err == nil && info.IsDir() {
		fmt.Printf("tpm2-kira has been already configured (directory %s exists).\n", DefaultKeysDir)
		fmt.Println("  Further configuration must be done manually.")
		fmt.Println("  Use 'tpm2-kira seal', 'tpm2-kira reseal', or edit the keys directly.")
		return nil
	}

	// ── Step 2: Decide where the signing key lives ──
	tokenRef, abort, err := resolveSetupKeyLocation(tpmPath, choice, debug)
	if err != nil {
		return err
	}
	if abort {
		return nil
	}

	if !tokenRef.IsZero() {
		return setupWithToken(tpmPath, nvramIndex, tokenRef, debug)
	}

	// ── Step 3: Create directory and generate P-256 key pair ──
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

	// ── Step 4: Seal with PCRs 0,7 using the generated keys ──
	fmt.Println("Proceeding to seal TOTP secret (equivalent to: tpm2-kira seal --pcrs 0,7)")
	fmt.Println()

	pcrsStr := "0,7"
	hashAlgo := PCRHashAlgoSHA256

	// No UKI verification: setup runs from the mkinitcpio build hook, where the
	// image being built is not the one that booted. These PCRs do not use it anyway.
	if err := Seal(tpmPath, pcrsStr, nvramIndex, pubKeyPath, privKeyPath, debug, hashAlgo, false); err != nil {
		return fmt.Errorf("seal failed during setup: %w", err)
	}

	fmt.Println()
	fmt.Println("=== Setup Complete ===")
	fmt.Printf("  Keys directory: %s\n", DefaultKeysDir)
	fmt.Printf("  Public key:     %s\n", pubKeyPath)
	fmt.Printf("  Private key:    %s\n", privKeyPath)
	fmt.Printf("  PCRs sealed:    %s\n", pcrsStr)
	fmt.Printf("  Hash algorithm: %s\n", hashAlgo.DisplayString())

	return nil
}

// resolveSetupKeyLocation decides whether the signing key goes in a file or on a
// token, asking only when there is something to ask about and someone to ask.
//
// It returns a zero KeyRef for the local-file default. abort is true when the
// user chose to stop so they can prepare a token first, which is a success:
// nothing has been created yet, so re-running setup is clean.
func resolveSetupKeyLocation(tpmPath string, choice SetupKeyChoice, debug bool) (ref KeyRef, abort bool, err error) {
	if choice.Local {
		return KeyRef{}, false, nil
	}

	if choice.TokenRef != "" {
		ref, err := ParseKeyRef(choice.TokenRef)
		if err != nil {
			return KeyRef{}, false, err
		}
		if ref.Kind != KeyRefYubiKey {
			return KeyRef{}, false, fmt.Errorf("--yubikey expects a token reference, got %q", choice.TokenRef)
		}
		return ref, false, nil
	}

	// Nobody to answer a question: take the documented default silently. This
	// is the path the mkinitcpio hook and any packaging script takes.
	if !IsInteractive() {
		if debug {
			fmt.Println("Not a terminal; using a key file without asking about a token")
		}
		return KeyRef{}, false, nil
	}

	fmt.Println("Looking for a hardware token that could hold the signing key...")

	tokens, discoverErr := DiscoverTokens(debug)
	if discoverErr != nil && debug {
		fmt.Printf("  (discovery reported: %v)\n", discoverErr)
	}

	if len(tokens) == 0 {
		fmt.Println("  None found. Using a signing key file, which is the default.")
		fmt.Println()
		return KeyRef{}, false, nil
	}

	var usable []TokenSlotInfo
	for _, token := range tokens {
		usable = append(usable, token.Slots...)
	}

	if len(usable) == 0 {
		return KeyRef{}, promptEmptyToken(tokens), nil
	}

	return promptSlotChoice(usable)
}

// promptSlotChoice offers the populated slots alongside the file default.
func promptSlotChoice(slots []TokenSlotInfo) (KeyRef, bool, error) {
	fmt.Println()
	fmt.Println("The signing key authorises resealing after a firmware or kernel update.")
	fmt.Println("It is only needed then — never at boot — so it can live on a token that")
	fmt.Println("you unplug the rest of the time.")
	fmt.Println()
	fmt.Println("Found these keys on connected tokens:")

	for i, slot := range slots {
		fmt.Printf("  %d) %s\n", i+1, slot.Describe())
		if policies := slot.DescribePolicies(); policies != "" {
			fmt.Printf("       %s\n", policies)
		}
		if warning := slot.UnattendedWarning(); warning != "" {
			fmt.Printf("       note: %s\n", warning)
		}
	}

	fmt.Println()
	fmt.Printf("Where should the signing key live?\n")
	fmt.Printf("  [Enter]  a key file at %s  (default)\n", DefaultPrivateKeyPath)
	if len(slots) == 1 {
		fmt.Printf("  [1]      the token slot above\n")
	} else {
		fmt.Printf("  [1-%d]    one of the token slots above\n", len(slots))
	}
	fmt.Print("\nChoice [Enter]: ")

	answer, _ := ReadLine()
	fmt.Println()

	chosen, err := selectSlot(slots, answer)
	if err != nil {
		return KeyRef{}, false, err
	}

	if chosen == nil {
		fmt.Println("Using a signing key file.")
		fmt.Println()
		return KeyRef{}, false, nil
	}

	fmt.Printf("Using %s\n\n", chosen.Describe())

	return chosen.Ref(), false, nil
}

// selectSlot turns an answer to the menu into a key reference.
//
// An empty answer is the documented default — a key file — so it returns the
// zero KeyRef rather than an error. Anything that is not a listed number is an
// error rather than a silent fall back to the default: someone who typed "9a"
// or "yes" meant something, and quietly doing the opposite would be worse than
// asking them to run setup again.
func selectSlot(slots []TokenSlotInfo, answer string) (*TokenSlotInfo, error) {
	answer = strings.TrimSpace(answer)

	if answer == "" {
		return nil, nil
	}

	index, err := strconv.Atoi(answer)
	if err != nil || index < 1 || index > len(slots) {
		return nil, fmt.Errorf(
			"%q is not one of the offered choices (press Enter for a key file, or 1-%d for a token slot); run setup again",
			answer, len(slots))
	}

	return &slots[index-1], nil
}

// promptEmptyToken handles a token that is present but holds no usable key.
//
// tpm2-kira never writes to a token, so it cannot create one — the honest thing
// is to print the ykman commands and let the user decide whether to stop and run
// them. Returning abort avoids the trap of creating a key file and then refusing
// to run again because the directory exists.
func promptEmptyToken(tokens []TokenInfo) bool {
	fmt.Println()
	for _, token := range tokens {
		if token.Serial != 0 {
			fmt.Printf("Found YubiKey %d, but none of its PIV slots holds a key.\n", token.Serial)
		} else {
			fmt.Printf("Found a PIV card in %s, but none of its slots holds a key.\n", token.Reader)
		}
	}

	fmt.Println()
	fmt.Println("tpm2-kira never writes to a token, so the key has to be created with ykman:")
	fmt.Println()
	fmt.Println("    ykman piv keys generate --algorithm ECCP256 \\")
	fmt.Println("        --pin-policy ONCE --touch-policy NEVER 9a /tmp/seal.pub")
	fmt.Println("    ykman piv certificates generate --subject \"CN=tpm2-kira\" 9a /tmp/seal.pub")
	fmt.Println("    rm /tmp/seal.pub")
	fmt.Println()
	fmt.Println("See docs/YUBIKEY.md for the choices behind those policies, and for how to")
	fmt.Println("import a key you already have instead of generating a new one.")
	fmt.Println()
	fmt.Println("  [Enter]  carry on with a signing key file  (default)")
	fmt.Println("  [s]      stop here, so you can prepare the token first")
	fmt.Print("\nChoice [Enter]: ")

	answer, _ := ReadLine()
	fmt.Println()

	if strings.EqualFold(strings.TrimSpace(answer), "s") {
		fmt.Println("Stopping. Nothing has been created, so run 'tpm2-kira setup' again")
		fmt.Println("once the token holds a key.")
		return true
	}

	fmt.Println("Carrying on with a signing key file.")
	fmt.Println()
	return false
}

// setupWithToken completes setup against a key held on a token.
//
// Only the public key is written to disk. That is what lets reveal, info and the
// blob signature check work with the token unplugged.
func setupWithToken(tpmPath string, nvramIndex uint32, ref KeyRef, debug bool) error {
	fmt.Printf("Using the signing key in %s.\n\n", ref)

	pub, err := yubiKeyPublicKey(ref, debug)
	if err != nil {
		return fmt.Errorf("cannot read the public key from the token: %w", err)
	}

	fmt.Printf("  Key:         %s\n", PublicKeyDescription(pub))
	fmt.Printf("  Fingerprint: %s\n", PublicKeyFingerprint(pub))

	// A key the TPM will not load could never satisfy PolicySigned, and finding
	// that out now beats finding it out during a recovery.
	if err := validateAgainstTPM(tpmPath, pub, debug); err != nil {
		return err
	}

	if err := os.MkdirAll(DefaultKeysDir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory %s: %w", DefaultKeysDir, err)
	}

	pemBytes, err := PublicKeyToPEM(pub)
	if err != nil {
		return err
	}
	if err := os.WriteFile(DefaultPublicKeyPath, pemBytes, 0644); err != nil {
		return fmt.Errorf("failed to cache the public key at %s: %w", DefaultPublicKeyPath, err)
	}
	fmt.Printf("  Public key cached at: %s\n", DefaultPublicKeyPath)
	fmt.Println("  No private key is written: it stays on the token.")
	fmt.Println()

	pcrsStr := "0,7"
	hashAlgo := PCRHashAlgoSHA256

	fmt.Println("Proceeding to seal TOTP secret (equivalent to: tpm2-kira seal --pcrs 0,7)")
	fmt.Println()

	if err := Seal(tpmPath, pcrsStr, nvramIndex, DefaultPublicKeyPath, ref.String(), debug, hashAlgo, false); err != nil {
		return fmt.Errorf("seal failed during setup: %w", err)
	}

	fmt.Println()
	fmt.Println("=== Setup Complete ===")
	fmt.Printf("  Signing key:    %s\n", ref)
	fmt.Printf("  Public key:     %s\n", DefaultPublicKeyPath)
	fmt.Printf("  PCRs sealed:    %s\n", pcrsStr)
	fmt.Printf("  Hash algorithm: %s\n", hashAlgo.DisplayString())
	fmt.Println()
	fmt.Println("The token is needed only to reseal after an update, never at boot.")
	fmt.Printf("Set %s for unattended reseals, or let them be skipped and\n", PINEnvVar)
	fmt.Println("run 'tpm2-kira reseal' by hand. See docs/YUBIKEY.md.")

	return nil
}
