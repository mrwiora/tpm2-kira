package diskkey

import (
	"encoding/json"
	"fmt"
)

// The token's type carries the keyslot's recipe, so a plain 'cryptsetup
// luksDump' tells the two apart ('+' is not allowed in a LUKS2 token
// type - it may name a plugin file - so the type spells the mode out).
const (
	LuksTokenTypeSalt      = "tpm2-kira-salt"      // password+salt
	LuksTokenTypePhoneSalt = "tpm2-kira-phonesalt" // password+phonesalt
	LuksTokenTypeVault     = "tpm2-kira-vault"     // tpm+vault
	// LuksTokenTypeOld is the one type of earlier versions, the mode in a
	// field: recognised only to say what to do now - remove it and mark
	// the keyslot anew (Obsolete).
	LuksTokenTypeOld = "tpm2-kira"
)

// TokenTypeOf is the type a mode's token is written with.
func TokenTypeOf(mode string) string {
	switch mode {
	case LuksModePasswordPhoneSalt:
		return LuksTokenTypePhoneSalt
	case LuksModeTPMVault:
		return LuksTokenTypeVault
	}
	return LuksTokenTypeSalt
}

// The modes a keyslot's key is made in, as the token names them. The boot
// reads them from the header itself (header.go): there is no
// configured unlock mode any more.
const (
	LuksModePasswordSalt      = "password+salt"      // a typed password and a typed salt, combined
	LuksModePasswordPhoneSalt = "password+phonesalt" // a typed password and the salt a verifier released
	LuksModeTPMVault          = "tpm+vault"          // a local part from the TPM and a remote part from the vault, nothing typed (internal/vaultkey/vault.go)
)

// boundModes are the modes whose keyslot is bound to a slot: its key needs
// what the slot's enrolment releases.
func BoundMode(mode string) bool {
	return mode == LuksModePasswordPhoneSalt || mode == LuksModeTPMVault
}

// KnownMode says whether mode is one a keyslot can be marked with.
func KnownMode(mode string) bool {
	return mode == LuksModePasswordSalt || mode == LuksModePasswordPhoneSalt || mode == LuksModeTPMVault
}

// ErrMode is the error for a --mode that is none of them.
var ErrMode = fmt.Errorf("--mode must be %s, %s or %s", LuksModePasswordSalt, LuksModePasswordPhoneSalt, LuksModeTPMVault)

// LuksToken is the token's JSON. Slot is the binding to a tpm2-kira slot
// and is written for password+phonesalt alone: that key needs the salt
// the slot's enrolment releases, so deleting the slot deletes the keyslot
// with it. A password+salt keyslot depends on no slot - no TPM is in its
// key - and carries no binding: it survives every slot and coexists with
// the phone salt keyslot (at boot the phone's salt is tried first, the
// typed salt is the fallback).
type LuksToken struct {
	Type     string   `json:"type"`
	Keyslots []string `json:"keyslots"`
	Slot     *int     `json:"slot,omitempty"` // password+phonesalt: the slot whose salt it needs
	Label    string   `json:"label,omitempty"`
	Created  string   `json:"created"`
	// Mode is the type's meaning, derived when reading: the type carries it.
	Mode string `json:"-"`
	// Obsolete marks the old one-type form: shown so the keyslot can be
	// re-marked, used for nothing else.
	Obsolete bool `json:"-"`
}

// ParseKiraToken reads one token's JSON when it is ours: the type carries
// the mode, and the old one-type form is recognised as obsolete.
func ParseKiraToken(raw json.RawMessage) (LuksToken, bool) {
	var tok LuksToken
	if err := json.Unmarshal(raw, &tok); err != nil {
		return tok, false
	}
	switch tok.Type {
	case LuksTokenTypeSalt:
		tok.Mode = LuksModePasswordSalt
	case LuksTokenTypePhoneSalt:
		tok.Mode = LuksModePasswordPhoneSalt
	case LuksTokenTypeVault:
		tok.Mode = LuksModeTPMVault
	case LuksTokenTypeOld:
		tok.Obsolete = true
	default:
		return tok, false
	}
	return tok, true
}

// BoundTo says whether the keyslot is bound to the given tpm2-kira slot.
// An obsolete token binds nothing: it is re-marked, never acted on.
func (t *LuksToken) BoundTo(slot int) bool {
	return !t.Obsolete && t.Slot != nil && *t.Slot == slot
}
