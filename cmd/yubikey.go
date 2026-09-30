package cmd

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/matthias/tpm2-kira/internal/pcsc"
	"github.com/matthias/tpm2-kira/internal/piv"
)

// The YubiKey backend for SigningKey.
//
// tpm2-kira only ever reads from the token and asks it to sign. Populating a
// slot is done with ykman; see docs/YUBIKEY.md. That keeps the card code small
// and means a bug here cannot damage a key the slot may share with sbctl.

// yubiKeySigningKey is a signing key held in a PIV slot.
type yubiKeySigningKey struct {
	ref    KeyRef
	pub    crypto.PublicKey
	serial uint32

	session *tokenSession
	pin     PINProvider

	pinPolicy   byte
	touchPolicy byte
	pinVerified bool
	debug       bool
}

// tokenSession owns the pcscd connection for one process.
//
// A PIV PIN allows three attempts before the slot is blocked, and a reseal may
// sign a dozen times across several NVRAM slots. Opening the card once and
// verifying once is what keeps a mistyped PIN from being retried into a
// blocked token.
type tokenSession struct {
	client *pcsc.Client
	card   *pcsc.Card
	piv    *piv.Card
	closed bool
}

func (s *tokenSession) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true

	if s.card != nil {
		_ = s.card.Disconnect()
	}
	return s.client.Close()
}

// openTokenSession finds the token a reference names and selects the PIV
// application on it.
func openTokenSession(ref KeyRef, debug bool) (*tokenSession, uint32, error) {
	client, err := pcsc.Connect()
	if err != nil {
		if errors.Is(err, pcsc.ErrDaemonUnavailable) {
			return nil, 0, &KeyUnavailableError{
				Ref:    ref,
				Reason: "the PC/SC daemon is not running",
				Hint:   "start it with: sudo systemctl start pcscd",
				Err:    err,
			}
		}
		return nil, 0, err
	}

	readers, err := client.Readers(true)
	if err != nil {
		client.Close()
		return nil, 0, err
	}

	if len(readers) == 0 {
		client.Close()
		return nil, 0, &KeyUnavailableError{
			Ref:    ref,
			Reason: "no smart card reader has a card in it",
			Hint:   "plug in the YubiKey",
			Err:    pcsc.ErrNoReader,
		}
	}

	var lastErr error

	for _, reader := range readers {
		if debug {
			fmt.Printf("Trying reader: %s\n", reader)
		}

		card, err := client.ConnectCard(reader)
		if err != nil {
			lastErr = err
			continue
		}

		pivCard, err := piv.Open(card)
		if err != nil {
			// Not a PIV card, or the applet is unavailable.
			lastErr = err
			_ = card.Disconnect()
			continue
		}

		serial, err := pivCard.Serial()
		if err != nil {
			lastErr = err
			_ = card.Disconnect()
			continue
		}

		if ref.Serial != 0 && serial != ref.Serial {
			if debug {
				fmt.Printf("Reader %s holds token %d, looking for %d\n", reader, serial, ref.Serial)
			}
			_ = card.Disconnect()
			continue
		}

		return &tokenSession{client: client, card: card, piv: pivCard}, serial, nil
	}

	client.Close()

	reason := "no YubiKey with a PIV application was found"
	if ref.Serial != 0 {
		reason = fmt.Sprintf("no YubiKey with serial %d is present", ref.Serial)
	}

	return nil, 0, &KeyUnavailableError{
		Ref:    ref,
		Reason: reason,
		Hint:   "plug in the token, or run 'tpm2-kira yubikey list' to see what is connected",
		Err:    lastErr,
	}
}

// openYubiKeySigningKey resolves a yubikey: reference into a usable key.
func openYubiKeySigningKey(ref KeyRef, pin PINProvider, debug bool) (SigningKey, error) {
	session, serial, err := openTokenSession(ref, debug)
	if err != nil {
		return nil, err
	}

	key := &yubiKeySigningKey{
		ref:     ref,
		serial:  serial,
		session: session,
		pin:     pin,
		debug:   debug,
		// Assume the strictest PIN policy until the card says otherwise, so
		// a card that cannot report metadata still works.
		pinPolicy:   piv.PINPolicyAlways,
		touchPolicy: piv.TouchPolicyNever,
	}

	md, mdErr := session.piv.SlotMetadata(ref.Slot)
	switch {
	case mdErr == nil:
		key.pub = md.PublicKey
		key.pinPolicy = md.PINPolicy
		key.touchPolicy = md.TouchPolicy
		if debug {
			fmt.Printf("Slot %s: PIN policy %s, touch policy %s\n",
				PIVSlotName(ref.Slot),
				piv.PINPolicyName(md.PINPolicy),
				piv.TouchPolicyName(md.TouchPolicy))
		}

	case errors.Is(mdErr, piv.ErrMetadataUnsupported):
		// Firmware older than 5.3: fall back to the slot certificate.
		pub, certErr := session.piv.PublicKey(ref.Slot)
		if certErr != nil {
			session.Close()
			return nil, slotError(ref, certErr)
		}
		key.pub = pub

	default:
		session.Close()
		return nil, slotError(ref, mdErr)
	}

	return key, nil
}

// slotError turns an empty slot into an unavailable key rather than a
// malfunction, so reseal can warn instead of failing.
func slotError(ref KeyRef, err error) error {
	if errors.Is(err, piv.ErrSlotEmpty) {
		return &KeyUnavailableError{
			Ref:    ref,
			Reason: fmt.Sprintf("slot %s holds no key", PIVSlotName(ref.Slot)),
			Hint:   "populate it with ykman, then run 'tpm2-kira yubikey adopt'. See docs/YUBIKEY.md",
			Err:    err,
		}
	}
	return err
}

// yubiKeyPublicKey reads a slot's public key without needing a PIN, for the
// paths that only verify signatures.
func yubiKeyPublicKey(ref KeyRef, debug bool) (crypto.PublicKey, error) {
	session, _, err := openTokenSession(ref, debug)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	if md, err := session.piv.SlotMetadata(ref.Slot); err == nil {
		return md.PublicKey, nil
	} else if !errors.Is(err, piv.ErrMetadataUnsupported) {
		return nil, slotError(ref, err)
	}

	pub, err := session.piv.PublicKey(ref.Slot)
	if err != nil {
		return nil, slotError(ref, err)
	}
	return pub, nil
}

func (y *yubiKeySigningKey) Public() crypto.PublicKey { return y.pub }

func (y *yubiKeySigningKey) Ref() KeyRef { return y.ref }

func (y *yubiKeySigningKey) Description() string {
	return fmt.Sprintf("%s in YubiKey %d slot %s",
		PublicKeyDescription(y.pub), y.serial, PIVSlotName(y.ref.Slot))
}

func (y *yubiKeySigningKey) Close() error { return y.session.Close() }

// Sign asks the token to sign a digest.
//
// The PIN is presented according to the slot's policy: once for the whole
// session, or before every signature when the slot demands it. A successful
// verification resets the retry counter, so repeated verification costs
// nothing; only a wrong PIN consumes an attempt, and that aborts rather than
// retrying.
func (y *yubiKeySigningKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("the YubiKey backend signs SHA-256 digests only, got %v", opts.HashFunc())
	}

	if err := y.ensurePIN(); err != nil {
		return nil, err
	}

	if y.touchPolicy == piv.TouchPolicyAlways {
		fmt.Fprintln(os.Stderr, "tpm2-kira: touch the YubiKey to authorise a signature...")
	}

	return y.session.piv.Sign(y.ref.Slot, y.pub, digest)
}

func (y *yubiKeySigningKey) ensurePIN() error {
	switch y.pinPolicy {
	case piv.PINPolicyNever:
		return nil
	case piv.PINPolicyOnce:
		if y.pinVerified {
			return nil
		}
	}

	pin, err := y.pin.PIN()
	if err != nil {
		return err
	}

	// Refuse to spend the last attempt on an unattended guess. Being unable
	// to reseal is recoverable; a blocked slot needs the PUK, and a blocked
	// PUK is permanent.
	retries, err := y.session.piv.PINRetries()
	if err != nil {
		return err
	}
	if retries == 1 {
		return fmt.Errorf("refusing to try the PIN: only one attempt remains before slot %s is blocked.\n"+
			"  Verify it by hand first:  ykman piv access change-pin\n"+
			"  A blocked PIN needs the PUK to reset; a blocked PUK cannot be recovered",
			PIVSlotName(y.ref.Slot))
	}

	if err := y.session.piv.VerifyPIN(pin); err != nil {
		var pinErr *piv.PINError
		if errors.As(err, &pinErr) {
			return fmt.Errorf("the PIN from %s was rejected: %d attempt(s) remain before slot %s is blocked.\n"+
				"  Nothing further will be tried in this run",
				y.pin.Source(), pinErr.Retries, PIVSlotName(y.ref.Slot))
		}
		if errors.Is(err, piv.ErrPINBlocked) {
			return fmt.Errorf("slot %s is blocked: the PIN retry counter is exhausted.\n"+
				"  Reset it with the PUK:  ykman piv access unblock-pin", PIVSlotName(y.ref.Slot))
		}
		return err
	}

	y.pinVerified = true

	if y.debug {
		fmt.Printf("PIN verified (source: %s)\n", y.pin.Source())
	}

	return nil
}

// ── CLI commands ──────────────────────────────────────────────────────────

// YubiKeyList prints every connected token and what its PIV slots hold.
func YubiKeyList(debug bool) error {
	client, err := pcsc.Connect()
	if err != nil {
		return err
	}
	defer client.Close()

	readers, err := client.Readers(true)
	if err != nil {
		return err
	}

	if len(readers) == 0 {
		fmt.Println("No smart card with a PIV application is connected.")
		fmt.Println("Plug in the YubiKey and try again.")
		return nil
	}

	for _, reader := range readers {
		card, err := client.ConnectCard(reader)
		if err != nil {
			fmt.Printf("%s: cannot connect (%v)\n", reader, err)
			continue
		}

		pivCard, err := piv.Open(card)
		if err != nil {
			fmt.Printf("%s: no PIV application\n", reader)
			_ = card.Disconnect()
			continue
		}

		serial, _ := pivCard.Serial()
		fmt.Printf("%s\n", reader)
		if serial != 0 {
			fmt.Printf("  Serial: %d\n", serial)
		}

		if retries, err := pivCard.PINRetries(); err == nil && retries >= 0 {
			fmt.Printf("  PIN attempts remaining: %d\n", retries)
		}

		printSlots(pivCard)
		_ = card.Disconnect()
		fmt.Println()
	}

	return nil
}

// candidateSlots are the slots worth reporting: the four named key slots plus
// the retired ones, which is where a key shared with another tool may live.
var candidateSlots = func() []byte {
	slots := []byte{0x9A, 0x9C, 0x9D, 0x9E}
	for s := byte(0x82); s <= 0x95; s++ {
		slots = append(slots, s)
	}
	return slots
}()

func printSlots(pivCard *piv.Card) {
	found := false

	for _, slot := range candidateSlots {
		md, err := pivCard.SlotMetadata(slot)
		if err != nil {
			if errors.Is(err, piv.ErrMetadataUnsupported) {
				// Older firmware: fall back to the certificate.
				pub, certErr := pivCard.PublicKey(slot)
				if certErr != nil {
					continue
				}
				found = true
				fmt.Printf("  Slot %s: %s\n", PIVSlotName(slot), PublicKeyDescription(pub))
				continue
			}
			continue
		}

		found = true
		origin := "generated on the token"
		if md.Imported {
			origin = "imported — the key has existed off the token"
		}

		fmt.Printf("  Slot %s: %s\n", PIVSlotName(slot), PublicKeyDescription(md.PublicKey))
		fmt.Printf("    PIN policy:   %s\n", piv.PINPolicyName(md.PINPolicy))
		fmt.Printf("    Touch policy: %s\n", piv.TouchPolicyName(md.TouchPolicy))
		fmt.Printf("    Origin:       %s\n", origin)
		fmt.Printf("    Reference:    %s\n", KeyRef{Kind: KeyRefYubiKey, Slot: slot}.String())
	}

	if !found {
		fmt.Println("  No populated PIV key slots.")
		fmt.Println("  See docs/YUBIKEY.md for how to create one with ykman.")
	}
}

// YubiKeyAdopt inspects an existing slot and caches its public key so that
// tpm2-kira can verify signatures and compute policy digests without the token.
//
// It writes nothing to the card.
func YubiKeyAdopt(tpmPath, refStr, outPath string, debug bool) error {
	ref, err := ParseKeyRef(refStr)
	if err != nil {
		return err
	}
	if ref.Kind != KeyRefYubiKey {
		return fmt.Errorf("adopt expects a yubikey reference, got %q", refStr)
	}

	session, serial, err := openTokenSession(ref, debug)
	if err != nil {
		return err
	}
	defer session.Close()

	var pub crypto.PublicKey
	var md *piv.Metadata

	md, err = session.piv.SlotMetadata(ref.Slot)
	if err == nil {
		pub = md.PublicKey
	} else if errors.Is(err, piv.ErrMetadataUnsupported) {
		pub, err = session.piv.PublicKey(ref.Slot)
		if err != nil {
			return slotError(ref, err)
		}
	} else {
		return slotError(ref, err)
	}

	fmt.Printf("YubiKey %d, slot %s\n", serial, PIVSlotName(ref.Slot))
	fmt.Printf("  Key:         %s\n", PublicKeyDescription(pub))
	fmt.Printf("  Fingerprint: %s\n", PublicKeyFingerprint(pub))

	if md != nil {
		fmt.Printf("  PIN policy:   %s\n", piv.PINPolicyName(md.PINPolicy))
		fmt.Printf("  Touch policy: %s\n", piv.TouchPolicyName(md.TouchPolicy))
		if md.Imported {
			fmt.Println("  Origin:       imported — this key has existed outside the token")
		} else {
			fmt.Println("  Origin:       generated on the token")
		}
		printPolicyAdvice(md)
	}

	// The TPM has to be able to load the key for PolicySigned to work at
	// all. Finding that out now beats finding it out during a recovery.
	if err := validateAgainstTPM(tpmPath, pub, debug); err != nil {
		return err
	}

	if outPath == "" {
		outPath = DefaultPublicKeyPath
	}

	pemBytes, err := PublicKeyToPEM(pub)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", filepath.Dir(outPath), err)
	}
	if err := os.WriteFile(outPath, pemBytes, 0o644); err != nil {
		return fmt.Errorf("failed to write the public key to %s: %w", outPath, err)
	}

	effectiveRef := KeyRef{Kind: KeyRefYubiKey, Serial: serial, Slot: ref.Slot}

	fmt.Printf("\n  Public key cached at: %s\n", outPath)
	fmt.Println("\nSeal against this key with:")
	fmt.Printf("    sudo tpm2-kira seal --privkey '%s' --pubkey %s\n", effectiveRef, outPath)
	fmt.Println("\nThe reference is stored in the sealed blob, so later reseals need no flags.")

	return nil
}

// validateAgainstTPM checks that the TPM can load the key, because a key the
// TPM will not load cannot satisfy PolicySigned — which would only be
// discovered during a recovery, when it is least welcome.
//
// An unreachable TPM is reported but not treated as a failure: adopt is useful
// on a machine where the TPM is busy or absent.
func validateAgainstTPM(tpmPath string, pub crypto.PublicKey, debug bool) error {
	tpmDev, err := OpenTPMDevice(tpmPath)
	if err != nil {
		fmt.Printf("\n  TPM check:   skipped, could not open %s (%v)\n", tpmPath, err)
		return nil
	}
	defer tpmDev.Close()

	if err := ValidateKeyForTPM(tpmDev, pub); err != nil {
		return fmt.Errorf("the TPM cannot load this key, so it could never satisfy PolicySigned: %w\n"+
			"  Use an ECC P-256 or RSA-2048 key; many TPMs reject RSA-4096 in TPM2_LoadExternal", err)
	}

	fmt.Println("  TPM check:   the TPM can load this key for PolicySigned")
	return nil
}

func printPolicyAdvice(md *piv.Metadata) {
	if md.TouchPolicy == piv.TouchPolicyAlways {
		fmt.Println("\n  Note: this slot needs a touch for every signature. A reseal signs about")
		fmt.Println("  three times per NVRAM slot, and the reseal that runs automatically after an")
		fmt.Println("  initramfs rebuild has nobody present to touch it. Consider a slot with touch")
		fmt.Println("  policy 'never' or 'cached' for this use.")
	}
	if md.PINPolicy == piv.PINPolicyAlways {
		fmt.Println("\n  Note: this slot verifies the PIN before every signature, which is normal for")
		fmt.Println("  slot 9c. tpm2-kira handles that, but the PIN must be available for the whole")
		fmt.Println("  run — set TPM2_KIRA_PIN or use --pin-file.")
	}
}

// YubiKeyStatus reports whether the token behind a reference is reachable.
func YubiKeyStatus(refStr string, debug bool) error {
	ref, err := ParseKeyRef(refStr)
	if err != nil {
		return err
	}
	if ref.Kind != KeyRefYubiKey {
		return fmt.Errorf("status expects a yubikey reference, got %q", refStr)
	}

	session, serial, err := openTokenSession(ref, debug)
	if err != nil {
		if kue, ok := AsKeyUnavailable(err); ok {
			fmt.Printf("Not available: %s\n", kue.Reason)
			if kue.Hint != "" {
				fmt.Printf("  %s\n", kue.Hint)
			}
			return nil
		}
		return err
	}
	defer session.Close()

	fmt.Printf("YubiKey %d is present\n", serial)

	if retries, err := session.piv.PINRetries(); err == nil && retries >= 0 {
		fmt.Printf("  PIN attempts remaining: %d\n", retries)
		if retries <= 1 {
			fmt.Println("  WARNING: one more wrong PIN blocks the slot and needs the PUK to reset")
		}
	}

	md, err := session.piv.SlotMetadata(ref.Slot)
	if err != nil {
		if errors.Is(err, piv.ErrMetadataUnsupported) {
			pub, certErr := session.piv.PublicKey(ref.Slot)
			if certErr != nil {
				return slotError(ref, certErr)
			}
			fmt.Printf("  Slot %s: %s (fingerprint %s)\n",
				PIVSlotName(ref.Slot), PublicKeyDescription(pub), PublicKeyFingerprint(pub))
			return nil
		}
		return slotError(ref, err)
	}

	fmt.Printf("  Slot %s: %s (fingerprint %s)\n",
		PIVSlotName(ref.Slot), PublicKeyDescription(md.PublicKey), PublicKeyFingerprint(md.PublicKey))
	fmt.Printf("  PIN policy:   %s\n", piv.PINPolicyName(md.PINPolicy))
	fmt.Printf("  Touch policy: %s\n", piv.TouchPolicyName(md.TouchPolicy))

	return nil
}

// YubiKeyExportPubKey writes a slot's public key to a PEM file.
func YubiKeyExportPubKey(refStr, outPath string, debug bool) error {
	ref, err := ParseKeyRef(refStr)
	if err != nil {
		return err
	}
	if ref.Kind != KeyRefYubiKey {
		return fmt.Errorf("export-pubkey expects a yubikey reference, got %q", refStr)
	}

	pub, err := yubiKeyPublicKey(ref, debug)
	if err != nil {
		return err
	}

	pemBytes, err := PublicKeyToPEM(pub)
	if err != nil {
		return err
	}

	if outPath == "" || outPath == "-" {
		fmt.Print(string(pemBytes))
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", filepath.Dir(outPath), err)
	}
	if err := os.WriteFile(outPath, pemBytes, 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", outPath, err)
	}

	fmt.Printf("Public key written to %s (%s, fingerprint %s)\n",
		outPath, PublicKeyDescription(pub), PublicKeyFingerprint(pub))

	return nil
}

// YubiKeyCommand routes the yubikey subcommands.
func YubiKeyCommand(tpmPath string, args []string, ref, out string, debug bool) error {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}

	switch sub {
	case "list":
		return YubiKeyList(debug)
	case "adopt":
		return YubiKeyAdopt(tpmPath, defaultRef(ref), out, debug)
	case "status":
		return YubiKeyStatus(defaultRef(ref), debug)
	case "export-pubkey":
		return YubiKeyExportPubKey(defaultRef(ref), out, debug)
	default:
		return fmt.Errorf("unknown yubikey subcommand %q (expected list, adopt, status or export-pubkey)", sub)
	}
}

// defaultRef fills in a bare yubikey reference when none was given.
func defaultRef(ref string) string {
	if strings.TrimSpace(ref) == "" {
		return YubiKeyRefScheme
	}
	return ref
}

// ── Discovery, for guiding setup ──────────────────────────────────────────

// TokenSlotInfo describes one populated PIV slot found on a connected token.
type TokenSlotInfo struct {
	Serial      uint32
	Slot        byte
	PublicKey   crypto.PublicKey
	PINPolicy   byte
	TouchPolicy byte
	// HasPolicies is false on firmware that cannot report slot metadata, where
	// the key was read from the slot certificate instead.
	HasPolicies bool
	// Imported reports a key that was generated off the token.
	Imported bool
}

// Ref returns the key reference that selects this slot.
func (t TokenSlotInfo) Ref() KeyRef {
	return KeyRef{Kind: KeyRefYubiKey, Serial: t.Serial, Slot: t.Slot}
}

// TokenInfo is a connected token and whatever usable keys it holds.
type TokenInfo struct {
	Serial uint32
	Reader string
	Slots  []TokenSlotInfo
}

// DiscoverTokens lists connected tokens and their populated PIV slots.
//
// Absence is not an error: no daemon, no reader and no card all return an empty
// list with a nil error, because the caller is offering the token as an option
// rather than requiring one. Only a malfunction while talking to a card that is
// present is worth reporting, and even then the caller may ignore it.
func DiscoverTokens(debug bool) ([]TokenInfo, error) {
	client, err := pcsc.Connect()
	if err != nil {
		if debug {
			fmt.Printf("No PC/SC daemon: %v\n", err)
		}
		return nil, nil
	}
	defer client.Close()

	readers, err := client.Readers(true)
	if err != nil {
		if debug {
			fmt.Printf("Cannot list readers: %v\n", err)
		}
		return nil, nil
	}

	var tokens []TokenInfo

	for _, reader := range readers {
		card, err := client.ConnectCard(reader)
		if err != nil {
			if debug {
				fmt.Printf("Cannot connect to %s: %v\n", reader, err)
			}
			continue
		}

		pivCard, err := piv.Open(card)
		if err != nil {
			// Not a PIV card; nothing to offer.
			_ = card.Disconnect()
			continue
		}

		serial, _ := pivCard.Serial()

		token := TokenInfo{Serial: serial, Reader: reader}

		for _, slot := range candidateSlots {
			info, ok := inspectSlot(pivCard, serial, slot)
			if ok {
				token.Slots = append(token.Slots, info)
			}
		}

		tokens = append(tokens, token)
		_ = card.Disconnect()
	}

	return tokens, nil
}

// inspectSlot reads one slot, preferring metadata and falling back to the
// certificate on firmware that cannot report it.
func inspectSlot(pivCard *piv.Card, serial uint32, slot byte) (TokenSlotInfo, bool) {
	md, err := pivCard.SlotMetadata(slot)
	if err == nil {
		return TokenSlotInfo{
			Serial:      serial,
			Slot:        slot,
			PublicKey:   md.PublicKey,
			PINPolicy:   md.PINPolicy,
			TouchPolicy: md.TouchPolicy,
			HasPolicies: true,
			Imported:    md.Imported,
		}, true
	}

	if !errors.Is(err, piv.ErrMetadataUnsupported) {
		return TokenSlotInfo{}, false
	}

	pub, certErr := pivCard.PublicKey(slot)
	if certErr != nil {
		return TokenSlotInfo{}, false
	}

	return TokenSlotInfo{Serial: serial, Slot: slot, PublicKey: pub}, true
}

// Describe renders a slot for a menu, on one line.
func (t TokenSlotInfo) Describe() string {
	out := fmt.Sprintf("YubiKey %d, slot %s — %s",
		t.Serial, PIVSlotName(t.Slot), PublicKeyDescription(t.PublicKey))
	if t.Imported {
		out += " (imported)"
	}
	return out
}

// DescribePolicies renders the PIN and touch policies, or an empty string when
// the card cannot report them.
func (t TokenSlotInfo) DescribePolicies() string {
	if !t.HasPolicies {
		return ""
	}
	return fmt.Sprintf("PIN %s, touch %s",
		piv.PINPolicyName(t.PINPolicy), piv.TouchPolicyName(t.TouchPolicy))
}

// UnattendedWarning returns a caution for a slot whose policies make an
// unattended reseal awkward, or an empty string.
func (t TokenSlotInfo) UnattendedWarning() string {
	if !t.HasPolicies {
		return ""
	}
	if t.TouchPolicy == piv.TouchPolicyAlways {
		return "needs a touch for every signature, so the automatic reseal after an initramfs rebuild will not complete"
	}
	return ""
}
