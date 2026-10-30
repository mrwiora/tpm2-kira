package diskkey

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// Of every 16-bit number, exactly the recipes of the table are recipes.
func TestRecipesAreExactlyTheTable(t *testing.T) {
	var valid []Recipe
	for v := 0; v <= 0xFFFF; v++ {
		if Recipe(v).Check() == nil {
			valid = append(valid, Recipe(v))
		}
	}
	want := slices.Clone(Recipes)
	slices.Sort(want)
	if !slices.Equal(valid, want) {
		t.Fatalf("valid recipes %v, want %v", valid, want)
	}
}

// The command line's words name a recipe; what distributes nothing is
// refused with the recipes that are.
func TestRecipeOfWords(t *testing.T) {
	for _, c := range []struct {
		password, salt string
		pepper         bool
		want           Recipe
	}{
		{"typed", "typed", false, RecipeRecovery},
		{"typed", "tpm", false, RecipeTPMSalt},
		{"typed", "phone", false, RecipePhoneSalt},
		{"typed", "vault", false, RecipeVaultSalt},
		{"typed", "vault", true, RecipeVaultSaltPepper},
		{"tpm", "vault", false, RecipeUnattendedVault},
		{"tpm", "vault", true, RecipeUnattendedVaultPepper},
	} {
		r, err := RecipeOf(c.password, c.salt, c.pepper)
		if err != nil || r != c.want {
			t.Errorf("%s/%s pepper %v: %v %v, want %v", c.password, c.salt, c.pepper, r, err, c.want)
		}
		if again, err := RecipeOf(strings.Fields(r.Words())[1], strings.Fields(r.Words())[3], r.Pepper()); err != nil || again != r {
			t.Errorf("%v: its words %q give %v %v", r, r.Words(), again, err)
		}
	}
	for _, c := range []struct {
		password, salt string
		pepper         bool
		why            string
	}{
		{"tpm", "tpm", false, "distribute nothing"},
		{"tpm", "phone", false, "needs a salt from the vault"},
		{"tpm", "typed", false, "needs a salt from the vault"},
		{"typed", "phone", true, "pepper"},
		{"typed", "typed", true, "pepper"},
		{"held", "vault", false, "--password"},
		{"typed", "usb", false, "--salt"},
	} {
		_, err := RecipeOf(c.password, c.salt, c.pepper)
		if err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s/%s pepper %v: %v, want %q", c.password, c.salt, c.pepper, err, c.why)
		}
		if err != nil && strings.HasPrefix(c.password, "t") && strings.Contains(c.salt, "a") && !strings.Contains(err.Error(), "the recipes are:") {
			t.Errorf("%s/%s: the refusal does not name the recipes: %v", c.password, c.salt, err)
		}
	}
}

func TestRecipeNumbers(t *testing.T) {
	r := RecipeVaultSaltPepper
	if r.String() != "0x1401" || r.TokenType() != "tpm2-kira-1401" {
		t.Fatalf("%s %s", r, r.TokenType())
	}
	if r.Password() != PasswordTyped || r.Salt() != SaltVault || !r.Pepper() || r.Unattended() || !r.Bound() {
		t.Fatalf("%s's parts", r)
	}
	if !RecipeUnattendedVault.Unattended() || RecipeRecovery.Bound() {
		t.Fatal("unattended or bound")
	}
	if got, err := ParseRecipe("0x1401"); err != nil || got != r {
		t.Fatalf("ParseRecipe: %v %v", got, err)
	}
	if _, err := ParseRecipe("0x1301"); err == nil {
		t.Fatal("0x1301 parsed: a pepper is the vault's")
	}
	if d := r.Describe(); d != "0x1401 password typed · salt from the vault (pepper)" {
		t.Fatalf("Describe: %q", d)
	}
}

// A token is ours when it is a current recipe; another version's, a type
// that does not carry its recipe, or a bound recipe without its slot is
// obsolete; another program's is not ours.
func TestParseKiraToken(t *testing.T) {
	tok := NewLuksToken(RecipeVaultSalt, "2", 1, "root", "2026-10-29T18:00:00Z")
	raw, _ := json.Marshal(tok)
	if !strings.Contains(string(raw), `"type":"tpm2-kira-1400"`) || !strings.Contains(string(raw), `"recipe":5120`) || !strings.Contains(string(raw), `"slot":1`) {
		t.Fatalf("token JSON %s", raw)
	}
	got, ours := ParseKiraToken(raw)
	if !ours || got.Obsolete || got.Recipe != RecipeVaultSalt || !got.BoundTo(1) {
		t.Fatalf("read back %+v %v", got, ours)
	}
	if rec, _ := json.Marshal(NewLuksToken(RecipeRecovery, "1", 1, "", "x")); strings.Contains(string(rec), `"slot"`) {
		t.Fatalf("the recovery recipe is bound: %s", rec)
	}
	for what, js := range map[string]string{
		"another version's":      `{"type": "tpm2-kira-vault", "keyslots": ["2"], "slot": 1}`,
		"the one-type form":      `{"type": "tpm2-kira", "keyslots": ["2"], "mode": "tpm+vault", "slot": 1}`,
		"type and recipe differ": `{"type": "tpm2-kira-1400", "keyslots": ["2"], "recipe": 5121, "slot": 1}`,
		"no recipe":              `{"type": "tpm2-kira-1402", "keyslots": ["2"], "recipe": 5122, "slot": 1}`,
		"bound without its slot": `{"type": "tpm2-kira-1400", "keyslots": ["2"], "recipe": 5120}`,
	} {
		got, ours := ParseKiraToken(json.RawMessage(js))
		if !ours || !got.Obsolete || got.BoundTo(1) {
			t.Errorf("%s: %+v %v", what, got, ours)
		}
	}
	if _, ours := ParseKiraToken(json.RawMessage(`{"type": "systemd-tpm2", "keyslots": ["2"]}`)); ours {
		t.Error("another program's token is taken as ours")
	}
}
