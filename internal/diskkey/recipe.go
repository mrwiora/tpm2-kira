package diskkey

import (
	"fmt"
	"strconv"
	"strings"
)

// Recipe identifies how a keyslot's key is made: a 16-bit number 0xPSFF,
// P the password's source, S the salt's, FF flags. The key is always
// Combine(password, salt); the recipe says where each comes from. The
// keyslot's token stores the number, and names are for display alone.
//
// The password is typed by the person in front of the machine - nothing on
// the machine holds it - or, in an unattended recipe, held by this TPM.
// The salt is held by a device - this TPM, the phone, the vault - or typed,
// in the recovery recipe alone. The pepper is a person's, entered at the
// vault's approval, and goes into the salt.
type Recipe uint16

// The sources of the password (P) and of the salt (S).
const (
	PasswordTyped uint8 = 0x1 // typed at the machine (its console or the boot SSH server)
	PasswordTPM   uint8 = 0x2 // held by this TPM: an unattended recipe

	SaltTyped uint8 = 0x1 // typed: the recovery recipe
	SaltTPM   uint8 = 0x2 // held by this TPM
	SaltPhone uint8 = 0x3 // released by the phone after its attestation
	SaltVault uint8 = 0x4 // released by the vault after its attestation
)

// The flags (FF).
const (
	// FlagPepper: the vault releases the salt with an operator's pepper,
	// which goes into the salt.
	FlagPepper uint8 = 0x01
	// FlagKeyboard: the phone or the vault holds the salt and gives the machine a one-time
	// keyboard instead; the salt is typed through it (core/attest/keyboard.go).
	FlagKeyboard uint8 = 0x02
)

// The recipes. Every other number is refused (Recipe.Check).
const (
	RecipeRecovery              Recipe = 0x1100 // password and salt typed
	RecipeTPMSalt               Recipe = 0x1200 // password typed, salt in this TPM
	RecipePhoneSalt             Recipe = 0x1300 // password typed, salt from the phone
	RecipeVaultSalt             Recipe = 0x1400 // password typed, salt from the vault
	RecipeVaultSaltPepper       Recipe = 0x1401 // password typed, salt from the vault with a pepper
	RecipePhoneKeyboard         Recipe = 0x1302 // password typed, salt typed through the phone's keyboard
	RecipeVaultKeyboard         Recipe = 0x1402 // password typed, salt typed through the vault's keyboard
	RecipeVaultKeyboardPepper   Recipe = 0x1403 // the same with a pepper, after the keys
	RecipeUnattendedVault       Recipe = 0x2400 // password in this TPM, salt from the vault
	RecipeUnattendedVaultPepper Recipe = 0x2401 // password in this TPM, salt from the vault with a pepper
)

// VaultRecipes are the recipes whose salt the vault releases.
var VaultRecipes = []Recipe{RecipeUnattendedVault, RecipeUnattendedVaultPepper, RecipeVaultSalt, RecipeVaultSaltPepper, RecipeVaultKeyboard, RecipeVaultKeyboardPepper}

// Recipes are every recipe, in the order a volume's keyslots are tried at
// boot: what needs nobody first, then a device-held salt with the typed
// password, the recovery recipe last.
var Recipes = []Recipe{
	RecipeUnattendedVault, RecipeUnattendedVaultPepper,
	RecipeVaultSalt, RecipeVaultSaltPepper, RecipeVaultKeyboard, RecipeVaultKeyboardPepper,
	RecipePhoneSalt, RecipePhoneKeyboard, RecipeTPMSalt,
	RecipeRecovery,
}

// Password is the password's source (P).
func (r Recipe) Password() uint8 { return uint8((r >> 12) & 0xF) }

// Salt is the salt's source (S).
func (r Recipe) Salt() uint8 { return uint8((r >> 8) & 0xF) }

func (r Recipe) flags() uint8 { return uint8(r & 0xFF) }

// Pepper says the vault releases the salt with an operator's pepper.
func (r Recipe) Pepper() bool { return r.flags()&FlagPepper != 0 }

// Keyboard says the salt is typed through the one-time keyboard of the phone or the vault.
func (r Recipe) Keyboard() bool { return r.flags()&FlagKeyboard != 0 }

// FromPhone says the phone holds the salt.
func (r Recipe) FromPhone() bool { return r.Salt() == SaltPhone }

// FromVault says the vault releases the salt.
func (r Recipe) FromVault() bool { return r.Salt() == SaltVault }

// Unattended says nothing is typed: the password is held by this TPM.
func (r Recipe) Unattended() bool { return r.Password() == PasswordTPM }

// Bound says the keyslot needs what a tpm2-kira slot holds or releases -
// its TPM part, its phone, its vault - so the token names the slot, and
// deleting the slot deletes the keyslot.
func (r Recipe) Bound() bool { return r.Unattended() || r.Salt() != SaltTyped }

// Check says why r is not a recipe, or nil.
func (r Recipe) Check() error {
	p, s, f := r.Password(), r.Salt(), r.flags()
	switch {
	case p != PasswordTyped && p != PasswordTPM:
		return fmt.Errorf("recipe %s: no password source %#x", r, p)
	case s < SaltTyped || s > SaltVault:
		return fmt.Errorf("recipe %s: no salt source %#x", r, s)
	case f&^(FlagPepper|FlagKeyboard) != 0:
		return fmt.Errorf("recipe %s: unknown flags %#02x", r, f)
	case p == PasswordTPM && s != SaltVault:
		return fmt.Errorf("recipe %s: a password held by this TPM needs a salt from the vault - password and salt both on the machine distribute nothing", r)
	case r.Keyboard() && p != PasswordTyped:
		return fmt.Errorf("recipe %s: a salt typed through the keyboard needs somebody at the machine, and so a typed password", r)
	case r.Keyboard() && s != SaltPhone && s != SaltVault:
		return fmt.Errorf("recipe %s: the keyboard comes from the phone or the vault", r)
	case r.Pepper() && s != SaltVault:
		return fmt.Errorf("recipe %s: a pepper is entered at the vault's approval and needs a salt from the vault", r)
	}
	return nil
}

// RecipeOf is the recipe of the command line's words: the password's
// source (typed, tpm), the salt's (typed, tpm, phone, vault), the pepper, the keyboard.
func RecipeOf(password, salt string, pepper, keyboard bool) (Recipe, error) {
	var p, s uint8
	switch password {
	case "typed":
		p = PasswordTyped
	case "tpm":
		p = PasswordTPM
	default:
		return 0, fmt.Errorf("--password is typed or tpm, not %q", password)
	}
	switch salt {
	case "typed":
		s = SaltTyped
	case "tpm":
		s = SaltTPM
	case "phone":
		s = SaltPhone
	case "vault":
		s = SaltVault
	default:
		return 0, fmt.Errorf("--salt is typed, tpm, phone or vault, not %q", salt)
	}
	var f uint8
	if pepper {
		f |= FlagPepper
	}
	if keyboard {
		f |= FlagKeyboard
	}
	r := Recipe(uint16(p)<<12 | uint16(s)<<8 | uint16(f))
	if err := r.Check(); err != nil {
		var ok []string
		for _, k := range Recipes {
			ok = append(ok, k.Words())
		}
		return 0, fmt.Errorf("%w; the recipes are: %s", err, strings.Join(ok, "; "))
	}
	return r, nil
}

// ParseRecipe reads a recipe's number as String writes it ("0x1401").
func ParseRecipe(s string) (Recipe, error) {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 16)
	if err != nil {
		return 0, fmt.Errorf("a recipe is a number like 0x1401, not %q", s)
	}
	r := Recipe(v)
	return r, r.Check()
}

// String is the recipe's number, "0x1401".
func (r Recipe) String() string { return fmt.Sprintf("0x%04x", uint16(r)) }

// TokenType is the LUKS2 token type of a keyslot of r: the number in it,
// so a plain 'cryptsetup luksDump' names the recipe too ('+' and other
// signs are not allowed in a token type).
func (r Recipe) TokenType() string { return fmt.Sprintf("tpm2-kira-%04x", uint16(r)) }

// Words are the recipe as the command line names it.
func (r Recipe) Words() string {
	w := "--password " + map[uint8]string{PasswordTyped: "typed", PasswordTPM: "tpm"}[r.Password()] +
		" --salt " + map[uint8]string{SaltTyped: "typed", SaltTPM: "tpm", SaltPhone: "phone", SaltVault: "vault"}[r.Salt()]
	if r.Pepper() {
		w += " --pepper"
	}
	if r.Keyboard() {
		w += " --keyboard"
	}
	return w
}

// Describe names the recipe for a person: "0x1401 password typed · salt
// from the vault (pepper)".
func (r Recipe) Describe() string {
	pw := map[uint8]string{PasswordTyped: "password typed", PasswordTPM: "password in this TPM"}[r.Password()]
	salt := map[uint8]string{SaltTyped: "salt typed", SaltTPM: "salt in this TPM", SaltPhone: "salt from the phone", SaltVault: "salt from the vault"}[r.Salt()]
	var notes []string
	if r.Pepper() {
		notes = append(notes, "pepper")
	}
	if r.Keyboard() {
		notes = append(notes, "typed through a one-time keyboard")
	}
	d := r.String() + " " + pw + " · " + salt
	if len(notes) > 0 {
		d += " (" + strings.Join(notes, ", ") + ")"
	}
	return d
}
