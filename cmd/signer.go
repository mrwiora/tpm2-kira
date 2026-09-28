package cmd

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Signing key references and the backends that resolve them.
//
// A signing key used to be a filesystem path threaded through every command.
// It is now a KeyRef — a path, or a slot on a hardware token — resolved once
// into a SigningKey. Everything downstream signs through crypto.Signer and
// never learns where the key actually lives.

// KeyRefKind distinguishes the storage backends a signing key can live in.
// The values are serialised into the sealed blob and must stay stable.
type KeyRefKind uint8

const (
	// KeyRefFile is a PEM file on the filesystem. This is the default.
	KeyRefFile KeyRefKind = 0
	// KeyRefYubiKey is a PIV slot on a YubiKey.
	KeyRefYubiKey KeyRefKind = 1
)

// YubiKeyRefScheme prefixes a key reference that names a PIV slot. A
// filesystem path can never begin with it, so a reference is unambiguous.
const YubiKeyRefScheme = "yubikey:"

// DefaultPIVSlot is the slot used when a yubikey reference does not name one.
// 9a (PIV Authentication) is the slot whose default PIN policy allows several
// signatures per verification; see docs/YUBIKEY.md.
const DefaultPIVSlot = 0x9A

// KeyRef is a reference to a signing key. The zero value means "no key".
type KeyRef struct {
	Kind KeyRefKind

	// Path is the PEM file, for KeyRefFile.
	Path string

	// Serial selects a specific YubiKey. Zero means "whichever one is
	// present", which is the common single-token case.
	Serial uint32

	// Slot is the PIV slot identifier, for KeyRefYubiKey.
	Slot byte
}

// IsZero reports whether the reference names no key at all.
func (r KeyRef) IsZero() bool {
	return r.Kind == KeyRefFile && r.Path == ""
}

// String renders the reference in the same syntax ParseKeyRef accepts.
func (r KeyRef) String() string {
	switch r.Kind {
	case KeyRefYubiKey:
		var b strings.Builder
		b.WriteString(YubiKeyRefScheme)
		if r.Serial != 0 {
			fmt.Fprintf(&b, "serial=%d;", r.Serial)
		}
		fmt.Fprintf(&b, "slot=%02x", r.Slot)
		return b.String()
	default:
		return r.Path
	}
}

// ParseKeyRef parses a key reference.
//
// A bare string is a filesystem path, which keeps every existing --privkey and
// --pubkey invocation working unchanged. A string beginning with "yubikey:"
// names a PIV slot:
//
//	yubikey:                         first token found, default slot
//	yubikey:slot=9c                  first token found, slot 9c
//	yubikey:serial=12345678;slot=9a  that specific token
func ParseKeyRef(s string) (KeyRef, error) {
	if s == "" {
		return KeyRef{}, nil
	}

	if !strings.HasPrefix(s, YubiKeyRefScheme) {
		return KeyRef{Kind: KeyRefFile, Path: s}, nil
	}

	ref := KeyRef{Kind: KeyRefYubiKey, Slot: DefaultPIVSlot}

	params := strings.TrimPrefix(s, YubiKeyRefScheme)
	for _, field := range strings.Split(params, ";") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		key, value, found := strings.Cut(field, "=")
		if !found {
			return KeyRef{}, fmt.Errorf("invalid key reference %q: %q is not a key=value pair", s, field)
		}

		switch strings.ToLower(strings.TrimSpace(key)) {
		case "serial":
			serial, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return KeyRef{}, fmt.Errorf("invalid key reference %q: serial %q is not a number", s, value)
			}
			ref.Serial = uint32(serial)
		case "slot":
			slot, err := ParsePIVSlot(strings.TrimSpace(value))
			if err != nil {
				return KeyRef{}, fmt.Errorf("invalid key reference %q: %w", s, err)
			}
			ref.Slot = slot
		default:
			return KeyRef{}, fmt.Errorf("invalid key reference %q: unknown field %q (expected serial or slot)", s, key)
		}
	}

	return ref, nil
}

// ParsePIVSlot accepts a PIV slot as hex, with or without a 0x prefix.
//
// The slots tpm2-kira can use are the four key slots and the twenty retired
// key-management slots. Slots outside that set hold no signing key, so naming
// one is a mistake worth catching before the token is opened.
func ParsePIVSlot(s string) (byte, error) {
	trimmed := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")

	value, err := strconv.ParseUint(trimmed, 16, 8)
	if err != nil {
		return 0, fmt.Errorf("slot %q is not a hex byte (try 9a, 9c, 9d, 9e or 82-95)", s)
	}

	slot := byte(value)
	switch {
	case slot == 0x9A || slot == 0x9C || slot == 0x9D || slot == 0x9E:
		return slot, nil
	case slot >= 0x82 && slot <= 0x95:
		return slot, nil
	default:
		return 0, fmt.Errorf("slot %02x holds no PIV signing key (expected 9a, 9c, 9d, 9e or 82-95)", slot)
	}
}

// PIVSlotName gives the conventional name of a PIV slot, for output.
func PIVSlotName(slot byte) string {
	switch slot {
	case 0x9A:
		return "9a (PIV Authentication)"
	case 0x9C:
		return "9c (Digital Signature)"
	case 0x9D:
		return "9d (Key Management)"
	case 0x9E:
		return "9e (Card Authentication)"
	default:
		if slot >= 0x82 && slot <= 0x95 {
			return fmt.Sprintf("%02x (Retired Key Management %d)", slot, slot-0x81)
		}
		return fmt.Sprintf("%02x", slot)
	}
}

// SigningKey is a resolved signing key. Callers sign through crypto.Signer and
// do not care whether the key is a file or a slot on a token.
type SigningKey interface {
	crypto.Signer

	// Ref returns the reference this key was resolved from.
	Ref() KeyRef

	// Description is a short human-readable summary for command output,
	// for example "ECDSA-P-256 in YubiKey 12345678 slot 9a".
	Description() string

	// Close releases whatever the backend holds. It is safe to call twice.
	Close() error
}

// KeyUnavailableError reports that a signing key could not be resolved for a
// reason the user can act on — an absent token, a missing file, a refused PIN.
//
// It exists so that reseal can degrade into a warning (see the SKIPPED path)
// instead of failing, while seal and setup can still treat it as fatal. A
// genuine malfunction is returned as an ordinary error and is never wrapped in
// this type.
type KeyUnavailableError struct {
	Ref KeyRef
	// Reason is one clause, lower case, naming what is missing.
	Reason string
	// Hint, when set, tells the user how to fix it.
	Hint string
	Err  error
}

func (e *KeyUnavailableError) Error() string {
	if e.Ref.IsZero() {
		return fmt.Sprintf("no signing key: %s", e.Reason)
	}
	return fmt.Sprintf("signing key %s is not available: %s", e.Ref, e.Reason)
}

func (e *KeyUnavailableError) Unwrap() error { return e.Err }

// IsKeyUnavailable reports whether err means "the key is not here right now",
// as opposed to "something went wrong while using it".
func IsKeyUnavailable(err error) bool {
	var kue *KeyUnavailableError
	return errors.As(err, &kue)
}

// AsKeyUnavailable extracts the typed error, for callers that want the reason.
func AsKeyUnavailable(err error) (*KeyUnavailableError, bool) {
	var kue *KeyUnavailableError
	ok := errors.As(err, &kue)
	return kue, ok
}

// fileSigningKey is the default backend: a PEM private key on disk.
type fileSigningKey struct {
	signer crypto.Signer
	ref    KeyRef
}

func (f *fileSigningKey) Public() crypto.PublicKey { return f.signer.Public() }

func (f *fileSigningKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return f.signer.Sign(rand, digest, opts)
}

func (f *fileSigningKey) Ref() KeyRef { return f.ref }

func (f *fileSigningKey) Description() string {
	return fmt.Sprintf("%s in %s", PublicKeyDescription(f.signer.Public()), f.ref.Path)
}

func (f *fileSigningKey) Close() error { return nil }

// OpenSigningKey resolves a reference into a usable signing key.
//
// A reference that names nothing, a file that is not there, or a token that is
// not plugged in all produce a *KeyUnavailableError so that callers can choose
// between warning and failing. The PIN provider is only consulted by backends
// that need one.
func OpenSigningKey(ref KeyRef, pin PINProvider, debug bool) (SigningKey, error) {
	if ref.IsZero() {
		return nil, &KeyUnavailableError{
			Ref:    ref,
			Reason: "no key reference was given and none is stored in the sealed blob",
			Hint:   "pass --privkey <path>, or run 'tpm2-kira setup' to create one",
		}
	}

	switch ref.Kind {
	case KeyRefFile:
		if _, err := os.Stat(ref.Path); err != nil {
			if os.IsNotExist(err) {
				return nil, &KeyUnavailableError{
					Ref:    ref,
					Reason: fmt.Sprintf("no such file: %s", ref.Path),
					Hint:   "pass --privkey <path> to point at the key, or restore it from your backup",
					Err:    err,
				}
			}
			return nil, &KeyUnavailableError{
				Ref:    ref,
				Reason: fmt.Sprintf("cannot read %s: %v", ref.Path, err),
				Err:    err,
			}
		}

		signer, err := LoadSigningPrivateKeyFromPEM(ref.Path)
		if err != nil {
			// The file is there but unusable. That is a real error, not
			// an absent key, so it is not wrapped as unavailable.
			return nil, err
		}

		if debug {
			fmt.Printf("Opened signing key from %s (%s)\n", ref.Path, PublicKeyDescription(signer.Public()))
		}

		return &fileSigningKey{signer: signer, ref: ref}, nil

	case KeyRefYubiKey:
		return openYubiKeySigningKey(ref, pin, debug)

	default:
		return nil, fmt.Errorf("unknown key reference kind %d", ref.Kind)
	}
}

// PublicKeyForRef loads the public half of a key reference without needing the
// key itself to be usable — no PIN, and for a token no signing capability.
//
// reseal needs the public key to verify the blob signature and to recompute the
// PolicyOR digest, and both must keep working when the token is in a drawer.
// The cached public key file is therefore the preferred source, and the backend
// is only asked when there is no cached copy.
func PublicKeyForRef(ref KeyRef, cachedPubKeyPath string, debug bool) (crypto.PublicKey, error) {
	if cachedPubKeyPath != "" {
		pubKey, _, err := LoadSigningPublicKeyFromPEM(cachedPubKeyPath)
		if err == nil {
			if debug {
				fmt.Printf("Using cached public key from %s\n", cachedPubKeyPath)
			}
			return pubKey, nil
		}
		if debug {
			fmt.Printf("Cached public key at %s unusable (%v); falling back to the key itself\n", cachedPubKeyPath, err)
		}
	}

	switch ref.Kind {
	case KeyRefYubiKey:
		return yubiKeyPublicKey(ref, debug)
	default:
		if ref.Path == "" {
			return nil, fmt.Errorf("no public key available: no cached copy and no key reference")
		}
		signer, err := LoadSigningPrivateKeyFromPEM(ref.Path)
		if err != nil {
			return nil, err
		}
		return signer.Public(), nil
	}
}

// tokenSerialOf reports the hardware token a key was read from, or zero when
// the key is not on one. It is recorded in the blob so that plugging in the
// wrong YubiKey gives a name rather than a policy failure.
func tokenSerialOf(key SigningKey) uint32 {
	if yk, ok := key.(*yubiKeySigningKey); ok {
		return yk.serial
	}
	return 0
}
