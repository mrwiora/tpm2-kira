package kira

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

// Setup prepares the signing key and nothing else.
//
// It does not seal. Sealing generates a TOTP secret and prints a QR code that
// has to be scanned, and it writes to TPM NVRAM — a different kind of act from
// creating a key, with a different failure mode and a different moment to choose
// PCRs at. Keeping them apart means setup can be re-run reasoning only about
// keys, and 'seal' can be re-run without touching them.
//
// Steps:
//  1. Declines if the keys directory already exists, since its job is done.
//  2. Decides where the signing key lives. A key file is the default; when a
//     hardware token is connected and someone is there to answer, setup offers
//     it rather than leaving the user to find 'yubikey adopt' on their own.
//  3. Generates a P-256 ECDSA pair as seal.pub / seal.key, or registers the
//     chosen token slot and caches only its public key.
//  4. Prints the seal command to run next.
//
// No PIN is ever needed: reading a token's public key does not require one, and
// setup performs no signature.
func Setup(tpmPath string, choice SetupKeyChoice, debug bool) error {
	pubKeyPath := DefaultPublicKeyPath
	privKeyPath := DefaultPrivateKeyPath

	// ── Step 1: Check if keys directory already exists ──
	if info, err := os.Stat(DefaultKeysDir); err == nil && info.IsDir() {
		fmt.Printf("Signing keys already exist in %s.\n", DefaultKeysDir)
		fmt.Println("  setup only creates keys, so there is nothing more for it to do.")
		fmt.Println()
		fmt.Println("  To seal a TOTP secret:            sudo tpm2-kira seal --pcrs \"0,7\"")
		fmt.Println("  To see what is already sealed:    tpm2-kira info")
		fmt.Println("  To move the key onto a YubiKey:   see docs/YUBIKEY.md")
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
		return setupWithToken(tpmPath, tokenRef, debug)
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
	// 0400: the key is written once and only ever read afterwards, so removing
	// the write bit costs nothing and takes an accidental overwrite off the
	// table. OpenSigningKey warns about anything looser.
	if err := os.WriteFile(privKeyPath, privPEM, 0400); err != nil {
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
	fmt.Println("=== Signing keys ready ===")
	fmt.Printf("  Private key: %s\n", privKeyPath)
	fmt.Printf("  Public key:  %s\n", pubKeyPath)
	printSealNext(KeyRef{})

	return nil
}

// printSealNext tells the user the command that actually seals a secret.
//
// setup deliberately stops short of it, so it has to hand over clearly — with
// the key reference filled in, since a token needs one and there is no sealed
// blob yet to remember it from.
func printSealNext(ref KeyRef) {
	fmt.Println()
	fmt.Println("Nothing is sealed yet. Seal a TOTP secret next:")
	fmt.Println()

	if ref.IsZero() {
		fmt.Println("    sudo tpm2-kira seal --pcrs \"0,7\"")
	} else {
		fmt.Printf("    export %s=<your PIN>\n", PINEnvVar)
		fmt.Println("    sudo -E tpm2-kira seal --pcrs \"0,7\" \\")
		fmt.Printf("        --privkey '%s' \\\n", ref)
		fmt.Printf("        --pubkey %s\n", DefaultPublicKeyPath)
	}

	fmt.Println()
	fmt.Println("That generates the secret and prints a QR code to scan with your")
	fmt.Println("authenticator app. 'tpm2-kira pcrtips' explains the PCR choice.")
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

// setupWithToken registers a key held on a token, without sealing.
//
// Only the public key is written to disk. That is what lets reveal, info and the
// blob signature check work later with the token unplugged.
func setupWithToken(tpmPath string, ref KeyRef, debug bool) error {
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

	fmt.Println()
	fmt.Println("=== Signing key ready ===")
	fmt.Printf("  Signing key: %s\n", ref)
	fmt.Printf("  Public key:  %s  (cached)\n", DefaultPublicKeyPath)
	fmt.Println("  No private key is written: it stays on the token.")
	printSealNext(ref)

	fmt.Println()
	fmt.Println("The token is needed to seal and to reseal after an update, never at boot.")

	return nil
}
