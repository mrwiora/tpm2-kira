package kira

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/matthias/tpm2-kira/internal/pcsc"
	"github.com/matthias/tpm2-kira/internal/piv"
)

// The 'tpm2-kira yubikey' subcommands: everything the user sees when inspecting
// a token. The backend they sit on top of is in signer_yubikey.go.

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
