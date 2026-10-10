package cmd

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/mrwiora/tpm2-kira/internal/piv"
	"golang.org/x/sys/unix"
)

// SetupOptions selects where setup puts the signing key.
type SetupOptions struct {
	// UseYubiKey takes the signing key from a YubiKey PIV slot without
	// asking. Serial and Slot narrow the choice.
	UseYubiKey bool
	// Serial picks the YubiKey when several are plugged in; 0 means the
	// only suitable one.
	Serial uint32
	// Slot picks the PIV slot; "" means 9a.
	Slot string
	// Local generates local key files without looking for a YubiKey.
	Local bool
	Debug bool
}

// setupTerminal returns the terminal to ask on, or nil when stdin is not one.
// Tests replace it.
var setupTerminal = func() *bufio.Reader {
	if _, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS); err != nil {
		return nil
	}
	return bufio.NewReader(os.Stdin)
}

// Setup performs initial tpm2-kira configuration: it creates the signing key
// pair and nothing else. Sealing a TOTP secret is a separate step ('seal'),
// which refuses to run until the keys exist.
//
//  1. Checks whether the keys directory already exists.
//     If it does, the system is considered already configured — an
//     informational message is printed and setup returns successfully (exit 0).
//  2. Looks for a YubiKey. The probe is read-only and never sends a PIN.
//     When a usable key is found, the user chooses on the terminal between
//     it and local key files, even when there is only one candidate.
//  3. Creates the directory and either generates a P-256 ECDSA key pair as
//     seal.pub / seal.key, or writes the token's public key to seal.pub and a
//     key file naming the token and slot to seal.key. No private key is
//     written in that case.
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

	// ── Step 2: Decide where the key lives ──
	var chosen *TokenInfo
	var chosenSlot TokenSlot
	if opts.Local {
		fmt.Println("Using local key files (--local); not looking for a YubiKey.")
	} else {
		fmt.Print("Looking for a YubiKey... ")
		tokens, probeErr := ProbeYubiKeys(TokenProbeTimeout)
		var err error
		if opts.UseYubiKey {
			fmt.Println()
			chosen, chosenSlot, err = chooseToken(os.Stdout, tokens, probeErr, opts)
		} else {
			chosen, chosenSlot, err = askKeyLocation(os.Stdout, setupTerminal(), tokens, probeErr, opts.Debug)
		}
		if err != nil {
			return err
		}
		if chosen != nil {
			fmt.Printf("Using YubiKey %d, slot %s (%s, PIN %s, touch %s).\n",
				chosen.Serial, chosenSlot.Slot, chosenSlot.Algorithm, chosenSlot.pinPolicyString(), chosenSlot.touchPolicyString())
			if w := pinPolicyWarning(chosenSlot); w != "" {
				fmt.Println(w)
			}
		}
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
		location = fmt.Sprintf("reference to YubiKey %d, slot %s; the key never leaves the token", chosen.Serial, chosenSlot.Slot)
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
		fmt.Printf("  YubiKey reference written to: %s\n", privKeyPath)
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
	fmt.Printf("   tpm2-kira seal --pcrs %s\n", RecommendedPCRs())
	fmt.Println("   (README \"Choosing PCRs\" explains the selection and its trade-offs)")
	if chosen != nil {
		fmt.Println()
		printPINInstructions(os.Stdout, *chosen, chosenSlot)
	}

	return nil
}

// printPINInstructions explains when the token and its PIN are needed and how
// to hand the PIN to tpm2-kira, including for the unattended reseal.
func printPINInstructions(w io.Writer, t TokenInfo, s TokenSlot) {
	fmt.Fprintf(w, "The YubiKey (serial %d) signs whenever tpm2-kira seals or reseals; keep it\n", t.Serial)
	fmt.Fprintln(w, "plugged in for those. Booting and showing codes never need it.")
	if s.PoliciesKnown && s.effectivePINPolicy() == piv.PINPolicyNever {
		fmt.Fprintln(w, "This key needs no PIN, so there is nothing to configure — see the warning above.")
		return
	}
	fmt.Fprintln(w)

	path := controlConfigPath()
	if pin, loose := configPIN(path); pin != "" {
		fmt.Fprintf(w, "%s stores the PIN: sealing, resealing and the automatic reseal\n", path)
		fmt.Fprintln(w, "after kernel and initramfs updates all take it from there.")
		if loose {
			fmt.Fprintf(w, "The file can be read by other users, so tpm2-kira refuses to use the PIN until\n"+
				"it is readable by root only:\n    chown root: %s && chmod 600 %s\n", path, path)
		}
		return
	}
	fmt.Fprintln(w, "Setup did not use the PIN; sealing does. Stored in one place, every step finds")
	fmt.Fprintln(w, "it - seal, reseal, and the reseal the initramfs hooks run after every kernel")
	fmt.Fprintln(w, "or initramfs update: 'tpm2-kira control' stores it (the signing key step),")
	fmt.Fprintf(w, "as %s='<your PIN>' in %s, readable by root alone.\n", PINEnvVar, path)
	fmt.Fprintln(w, "Without it, seal and reseal ask for the PIN on the terminal (or take it from")
	fmt.Fprintf(w, "%s: read -rs %s && export %s), and the automatic reseal\n", PINEnvVar, PINEnvVar, PINEnvVar)
	fmt.Fprintln(w, "reports SKIPPED: the next boot then shows a PCR mismatch until you run")
	fmt.Fprintln(w, "'tpm2-kira reseal' with the YubiKey plugged in.")
}

// pinPolicyWarning returns a warning when the key can sign without a PIN, or
// when its PIN policy cannot be read; "" otherwise.
func pinPolicyWarning(s TokenSlot) string {
	if !s.PoliciesKnown {
		return fmt.Sprintf("  NOTE: the PIN policy of slot %s cannot be read on firmware before 5.3.\n"+
			"  Make sure the key requires a PIN; tpm2-kira cannot check it.", s.Slot)
	}
	if s.effectivePINPolicy() == piv.PINPolicyNever {
		return fmt.Sprintf("  WARNING: the key in slot %s needs no PIN (PIN policy 'never'). Anyone holding\n"+
			"  the YubiKey can then authorise a reseal, which is the way around a PCR mismatch.\n"+
			"  Consider a key with PIN policy 'once' (see 'ykman piv keys generate --pin-policy').", s.Slot)
	}
	return ""
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

// reportTokens tells the user what the probe found and reports whether a
// usable key is among it. Without one, setup goes on with local key files.
func reportTokens(w io.Writer, tokens []TokenInfo, probeErr error, debug bool) bool {
	if probeErr != nil {
		fmt.Fprintln(w, "none found.")
		fmt.Fprintln(w, "  No YubiKey could be found, so the signing key will be created as local files.")
		if debug {
			fmt.Fprintf(w, "  (%v)\n", probeErr)
		} else {
			fmt.Fprintln(w, "  (If one is plugged in, check that pcscd is running; --debug shows details.)")
		}
		return false
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
		return false
	case len(suitable) == 0:
		fmt.Fprintln(w, "found, but none is suitable for tpm2-kira:")
		PrintTokenReport(w, tokens)
		fmt.Fprintln(w, "  A suitable key is ECC P-256 (the smallest in the TPM), ECC P-384 or RSA-2048 in a PIV slot. To create one in")
		fmt.Fprintln(w, "  slot 9a (this overwrites whatever is in that slot):")
		fmt.Fprintln(w, "      ykman piv keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy NEVER 9a /tmp/seal.pub")
		fmt.Fprintln(w, "      ykman piv certificates generate --subject \"CN=tpm2-kira\" 9a /tmp/seal.pub")
		fmt.Fprintln(w, "  Continuing with local key files.")
		return false
	}

	if len(suitable) == 1 {
		fmt.Fprintln(w, "found one suitable for tpm2-kira:")
	} else {
		fmt.Fprintf(w, "found %d suitable for tpm2-kira:\n", len(suitable))
	}
	PrintTokenReport(w, tokens)
	return true
}

// askKeyLocation reports what the probe found and, when there is a usable
// key, lets the user choose between it and local key files — also when there
// is only one candidate. tty is nil when there is no terminal: setup then
// uses local key files and says how to choose without one. A nil token means
// local key files.
func askKeyLocation(w io.Writer, tty *bufio.Reader, tokens []TokenInfo, probeErr error, debug bool) (*TokenInfo, TokenSlot, error) {
	if !reportTokens(w, tokens, probeErr, debug) {
		return nil, TokenSlot{}, nil
	}

	type choice struct {
		token TokenInfo
		slot  TokenSlot
	}
	var choices []choice
	for _, t := range tokens {
		if !t.Suitable() {
			continue
		}
		for _, s := range t.Slots {
			if s.Unsuitable == "" {
				choices = append(choices, choice{t, s})
			}
		}
	}
	local := len(choices) + 1
	def := local
	for i, c := range choices {
		if c.slot.Slot == piv.SlotAuthentication {
			def = i + 1
			break
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Where should the signing key live?")
	for i, c := range choices {
		note := ""
		if i+1 == def {
			note = "  [recommended]"
		}
		if !c.slot.PoliciesKnown {
			note += "  [PIN policy unknown]"
		} else if c.slot.effectivePINPolicy() == piv.PINPolicyNever {
			note += "  [no PIN required: insecure]"
		}
		fmt.Fprintf(w, "  %d) YubiKey %d, slot %s  (%s, PIN %s, touch %s)%s\n", i+1, c.token.Serial, c.slot.Slot,
			c.slot.Algorithm, c.slot.pinPolicyString(), c.slot.touchPolicyString(), note)
	}
	fmt.Fprintf(w, "  %d) Local key files in %s (the private key is stored on disk)\n", local, DefaultKeysDir)

	if tty == nil {
		fmt.Fprintln(w, "No terminal to ask on, so local key files are used. To choose without a")
		fmt.Fprintln(w, "terminal, run setup with --yubikey=SERIAL [--slot SLOT] or with --local.")
		return nil, TokenSlot{}, nil
	}

	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintf(w, "Choice [%d]: ", def)
		line, err := tty.ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintln(w)
			return nil, TokenSlot{}, errors.New("no choice made; nothing was written")
		}
		answer := strings.TrimSpace(line)
		n := def
		if answer != "" {
			if n, err = strconv.Atoi(answer); err != nil || n < 1 || n > local {
				fmt.Fprintf(w, "Please enter a number from 1 to %d.\n", local)
				continue
			}
		}
		if n == local {
			return nil, TokenSlot{}, nil
		}
		c := choices[n-1]
		return &c.token, c.slot, nil
	}
	return nil, TokenSlot{}, errors.New("no valid choice made; nothing was written")
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
