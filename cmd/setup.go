package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/matthias/tpm2-kira/internal/piv"
)

// SetupOptions selects where setup puts the signing key.
type SetupOptions struct {
	// UseYubiKey takes the signing key from a YubiKey PIV slot instead of
	// generating local key files.
	UseYubiKey bool
	// Serial picks the YubiKey when several are plugged in; 0 means the
	// only suitable one.
	Serial uint32
	// Slot picks the PIV slot; "" means 9a.
	Slot  string
	Debug bool
}

// Setup performs initial tpm2-kira configuration: it creates the signing key
// pair and nothing else. Sealing a TOTP secret is a separate step ('seal'),
// which refuses to run until the keys exist.
//
//  1. Checks whether the keys directory already exists.
//     If it does, the system is considered already configured — an
//     informational message is printed and setup returns successfully (exit 0).
//  2. Looks for a YubiKey and reports what it found. The probe is read-only
//     and never sends a PIN; without UseYubiKey it only informs.
//  3. Creates the directory and either generates a P-256 ECDSA key pair as
//     seal.pub / seal.key, or, with UseYubiKey, writes the token's public key
//     to seal.pub and a key file naming the token and slot to seal.key.
func Setup(opts SetupOptions) error {
	pubKeyPath := DefaultPublicKeyPath
	privKeyPath := DefaultPrivateKeyPath

	// ── Step 1: Check if keys directory already exists ──
	if info, err := os.Stat(DefaultKeysDir); err == nil && info.IsDir() {
		fmt.Printf("tpm2-kira has been already configured (directory %s exists).\n", DefaultKeysDir)
		fmt.Println("  Further configuration must be done manually.")
		fmt.Println("  Use 'tpm2-kira seal', 'tpm2-kira reseal', or edit the keys directly.")
		return nil
	}

	// ── Step 2: Look for a YubiKey ──
	fmt.Print("Looking for a YubiKey... ")
	tokens, probeErr := ProbeYubiKeys(TokenProbeTimeout)

	var chosen *TokenInfo
	var chosenSlot TokenSlot
	if opts.UseYubiKey {
		fmt.Println()
		t, slot, err := chooseToken(os.Stdout, tokens, probeErr, opts)
		if err != nil {
			return err
		}
		chosen, chosenSlot = t, slot
		fmt.Printf("  Using YubiKey %d, slot %s (%s, PIN %s, touch %s)\n",
			chosen.Serial, chosenSlot.Slot, chosenSlot.Algorithm, chosenSlot.pinPolicyString(), chosenSlot.touchPolicyString())
	} else {
		reportTokens(os.Stdout, tokens, probeErr, opts.Debug)
	}

	// ── Step 3: Create directory and the key files ──
	fmt.Printf("Creating keys directory: %s\n", DefaultKeysDir)
	if err := os.MkdirAll(DefaultKeysDir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory %s: %w", DefaultKeysDir, err)
	}

	var privPEM, pubPEM []byte
	location := "local file"
	if chosen != nil {
		stub, err := MarshalYubiKeyStub(chosen.Serial, chosenSlot)
		if err != nil {
			return fmt.Errorf("failed to encode the YubiKey key file: %w", err)
		}
		privPEM = stub
		if pubPEM, err = PublicKeyToPEM(chosenSlot.PublicKey); err != nil {
			return fmt.Errorf("failed to encode the YubiKey public key: %w", err)
		}
		location = fmt.Sprintf("YubiKey %d, slot %s", chosen.Serial, chosenSlot.Slot)
	} else {
		var err error
		if privPEM, pubPEM, err = generateLocalKeyPair(); err != nil {
			return err
		}
	}

	if err := WriteSigningKeyFile(privKeyPath, privPEM); err != nil {
		return fmt.Errorf("failed to write private key to %s: %w", privKeyPath, err)
	}
	if chosen != nil {
		fmt.Printf("  Key file (refers to the YubiKey) written to: %s\n", privKeyPath)
	} else {
		fmt.Printf("  Private key written to: %s\n", privKeyPath)
	}
	if err := WriteSigningKeyFile(pubKeyPath, pubPEM); err != nil {
		return fmt.Errorf("failed to write public key to %s: %w", pubKeyPath, err)
	}
	fmt.Printf("  Public key written to:  %s\n", pubKeyPath)

	fmt.Println()
	fmt.Println("=== Setup Complete ===")
	fmt.Printf("  Keys directory: %s\n", DefaultKeysDir)
	fmt.Printf("  Public key:     %s\n", pubKeyPath)
	fmt.Printf("  Private key:    %s (%s)\n", privKeyPath, location)
	fmt.Println()
	fmt.Println("Next, seal a TOTP secret and scan the QR code it prints:")
	fmt.Println("   tpm2-kira seal --pcrs 0,7")
	if chosen != nil {
		fmt.Println()
		fmt.Println("Sealing and resealing sign with the YubiKey, so keep it plugged in for")
		fmt.Printf("those and have its PIN ready (prompted for, or set %s).\n", PINEnvVar)
		fmt.Println("Booting and showing codes never need it: remove it afterwards.")
	}

	return nil
}

func generateLocalKeyPair() (privPEM, pubPEM []byte, err error) {
	fmt.Println("Generating ECDSA P-256 signing key pair...")
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate P-256 key pair: %w", err)
	}

	// SEC 1 / EC PRIVATE KEY PEM
	ecDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal EC private key: %w", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})

	// PKIX / PUBLIC KEY PEM
	pubPEM, err = PublicKeyToPEM(&privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return privPEM, pubPEM, nil
}

// reportTokens tells the user what the probe found. It never fails: setup
// goes on with local key files whatever happened here.
func reportTokens(w io.Writer, tokens []TokenInfo, probeErr error, debug bool) {
	if probeErr != nil {
		fmt.Fprintln(w, "none found.")
		fmt.Fprintln(w, "  No YubiKey could be found, so the signing key will be created as local files.")
		if debug {
			fmt.Fprintf(w, "  (%v)\n", probeErr)
		} else {
			fmt.Fprintln(w, "  (If one is plugged in, check that pcscd is running; --debug shows details.)")
		}
		return
	}

	var suitable []TokenInfo
	for _, t := range tokens {
		if t.Suitable() {
			suitable = append(suitable, t)
		}
	}

	switch {
	case len(tokens) == 0:
		fmt.Fprintln(w, "none found.")
		fmt.Fprintln(w, "  No YubiKey could be found, so the signing key will be created as local files.")
		return
	case len(suitable) == 0:
		fmt.Fprintln(w, "found, but none is suitable for tpm2-kira:")
		PrintTokenReport(w, tokens)
		fmt.Fprintln(w, "  A suitable key is RSA-2048, ECC P-256 or ECC P-384 in a PIV slot. To create one in")
		fmt.Fprintln(w, "  slot 9a (this overwrites whatever is in that slot):")
		fmt.Fprintln(w, "      ykman piv keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy NEVER 9a /tmp/seal.pub")
		fmt.Fprintln(w, "      ykman piv certificates generate --subject \"CN=tpm2-kira\" 9a /tmp/seal.pub")
		fmt.Fprintln(w, "  Continuing with local key files.")
		return
	}

	if len(suitable) == 1 {
		fmt.Fprintln(w, "found one suitable for tpm2-kira:")
	} else {
		fmt.Fprintf(w, "found %d suitable for tpm2-kira:\n", len(suitable))
	}
	PrintTokenReport(w, tokens)
	fmt.Fprintln(w, "  Continuing with local key files. To keep the signing key on a YubiKey instead,")
	fmt.Fprintln(w, "  remove them again before sealing anything and run setup with --yubikey:")
	for _, t := range suitable {
		slotArg := ""
		if _, ok := recommendedSlot(t); !ok {
			slotArg = " --slot <slot>"
		}
		fmt.Fprintf(w, "      sudo rm -r %s && sudo tpm2-kira setup --yubikey=%d%s\n", DefaultKeysDir, t.Serial, slotArg)
	}
}

// chooseToken picks the token and slot for setup --yubikey. Any ambiguity is
// an error that lists the choices; nothing is picked by guesswork.
func chooseToken(w io.Writer, tokens []TokenInfo, probeErr error, opts SetupOptions) (*TokenInfo, TokenSlot, error) {
	if probeErr != nil {
		return nil, TokenSlot{}, fmt.Errorf("cannot use a YubiKey: %w", probeErr)
	}
	var candidates []TokenInfo
	for _, t := range tokens {
		if opts.Serial != 0 && t.Serial != opts.Serial {
			continue
		}
		candidates = append(candidates, t)
	}

	switch {
	case len(candidates) == 0 && opts.Serial != 0:
		return nil, TokenSlot{}, fmt.Errorf("no YubiKey with serial %d found%s", opts.Serial, foundSerials(tokens))
	case len(candidates) == 0:
		return nil, TokenSlot{}, errors.New("no YubiKey found — plug one in, or run setup without --yubikey to use local key files")
	}

	var suitable []TokenInfo
	for _, t := range candidates {
		if t.Suitable() {
			suitable = append(suitable, t)
		}
	}
	if len(suitable) == 0 {
		PrintTokenReport(w, candidates)
		return nil, TokenSlot{}, errors.New("no YubiKey found holds a key usable by tpm2-kira (RSA-2048, ECC P-256 or ECC P-384); " +
			"create one with 'ykman piv keys generate' first — tpm2-kira never writes to the token")
	}
	if len(suitable) > 1 {
		PrintTokenReport(w, suitable)
		return nil, TokenSlot{}, fmt.Errorf("several suitable YubiKeys are plugged in; choose one with --yubikey=<serial>")
	}
	t := suitable[0]

	if opts.Slot == "" {
		if s, ok := recommendedSlot(t); ok {
			return &t, s, nil
		}
		PrintTokenReport(w, []TokenInfo{t})
		return nil, TokenSlot{}, fmt.Errorf("slot 9a of YubiKey %d holds no usable key; choose a slot with --slot "+
			"(a slot shared with another tool, such as sbctl in 9c, is only used when named explicitly)", t.Serial)
	}
	id, err := piv.ParseSlot(opts.Slot)
	if err != nil {
		return nil, TokenSlot{}, err
	}
	s, ok := t.SlotByID(id)
	if !ok {
		return nil, TokenSlot{}, fmt.Errorf("slot %s of YubiKey %d is empty", id, t.Serial)
	}
	if s.Unsuitable != "" {
		return nil, TokenSlot{}, fmt.Errorf("slot %s of YubiKey %d cannot be used: %s", id, t.Serial, s.Unsuitable)
	}
	return &t, s, nil
}

func foundSerials(tokens []TokenInfo) string {
	var serials []string
	for _, t := range tokens {
		if t.Serial != 0 {
			serials = append(serials, fmt.Sprint(t.Serial))
		}
	}
	if len(serials) == 0 {
		return ""
	}
	return " (found: " + strings.Join(serials, ", ") + ")"
}

// YubiKeyList implements 'tpm2-kira yubikey list'.
func YubiKeyList() error {
	tokens, err := ProbeYubiKeys(TokenProbeTimeout)
	if err != nil {
		return fmt.Errorf("cannot look for YubiKeys: %w", err)
	}
	if len(tokens) == 0 {
		fmt.Println("No YubiKey found.")
		return nil
	}
	fmt.Println("YubiKeys found (read-only; no PIN was used):")
	PrintTokenReport(os.Stdout, tokens)
	for _, t := range tokens {
		if t.Suitable() {
			fmt.Println()
			fmt.Println("Use one for the signing key with: sudo tpm2-kira setup --yubikey=<serial> [--slot <slot>]")
			break
		}
	}
	return nil
}
