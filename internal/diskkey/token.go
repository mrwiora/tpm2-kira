package diskkey

import (
	"encoding/json"
	"strings"
)

// tokenTypePrefix starts the type of every token of tpm2-kira's; the
// recipe's number follows (Recipe.TokenType).
const tokenTypePrefix = "tpm2-kira"

// LuksToken is the token's JSON: the recipe of the keyslot's key, and, for
// a recipe bound to a slot (Recipe.Bound), the slot whose TPM part, phone
// or vault it needs - deleting the slot deletes the keyslot with it. The
// recovery recipe depends on no slot: it survives every slot.
type LuksToken struct {
	Type     string   `json:"type"`
	Keyslots []string `json:"keyslots"`
	Recipe   Recipe   `json:"recipe"`
	Slot     *int     `json:"slot,omitempty"`
	Label    string   `json:"label,omitempty"`
	Created  string   `json:"created"`
	// Obsolete marks a token of tpm2-kira's that is not one of the current
	// recipes (another version's): shown so the keyslot can be enrolled
	// again, used for nothing else.
	Obsolete bool `json:"-"`
}

// ParseKiraToken reads one token's JSON when it is ours. Its recipe must
// be one, and the type must carry its number; any other token of
// tpm2-kira's is obsolete.
func ParseKiraToken(raw json.RawMessage) (LuksToken, bool) {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &head); err != nil || !strings.HasPrefix(head.Type, tokenTypePrefix) {
		return LuksToken{}, false
	}
	var tok LuksToken
	if err := json.Unmarshal(raw, &tok); err != nil || tok.Recipe.Check() != nil || tok.Type != tok.Recipe.TokenType() ||
		(tok.Recipe.Bound() && tok.Slot == nil) {
		return LuksToken{Type: head.Type, Keyslots: tok.Keyslots, Obsolete: true}, true
	}
	return tok, true
}

// NewLuksToken is the token of a keyslot of recipe r; slot is the bound
// slot, for a bound recipe.
func NewLuksToken(r Recipe, keyslot string, slot int, label, created string) LuksToken {
	t := LuksToken{Type: r.TokenType(), Keyslots: []string{keyslot}, Recipe: r, Label: label, Created: created}
	if r.Bound() {
		t.Slot = &slot
	}
	return t
}

// BoundTo says whether the keyslot is bound to the given tpm2-kira slot.
// An obsolete token binds nothing: it is re-marked, never acted on.
func (t *LuksToken) BoundTo(slot int) bool {
	return !t.Obsolete && t.Slot != nil && *t.Slot == slot
}
