package diskkey

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// fakeKeyboard takes one set of keys.
type fakeKeyboard struct {
	right   string
	salt    []byte
	proven  bool
	calls   int
	failure error
}

func (k *fakeKeyboard) NeedKeys() bool { return !k.proven }
func (k *fakeKeyboard) From() string   { return "the vault" }
func (k *fakeKeyboard) Salt(keys []byte) ([]byte, error) {
	k.calls++
	if k.failure != nil {
		return nil, k.failure
	}
	if !k.proven && string(keys) != k.right {
		return nil, ErrWrongKeys
	}
	k.proven = true
	return append([]byte(nil), k.salt...), nil
}

func keyboardAsk(answers map[string][]string) (Prompter, *[]string, *[]string) {
	var asked, notes []string
	return func(_, what, note string) ([]byte, error) {
		asked = append(asked, what)
		notes = append(notes, note)
		if len(answers[what]) == 0 {
			return nil, errors.New("nothing to answer " + what)
		}
		a := answers[what][0]
		answers[what] = answers[what][1:]
		return []byte(a), nil
	}, &asked, &notes
}

// The password, then the keys; the key is the password's and the salt's. What the person is told
// says to press what is shown, not the salt.
func TestKeyboardPrompt(t *testing.T) {
	cheapCombine(t)
	sess := &fakeKeyboard{right: "keysabcd", salt: []byte("the salt")}
	ask, asked, notes := keyboardAsk(map[string][]string{"Password": {"hunter2"}, "Keys": {"keysabcd"}})
	key, err := DiskKey(nil, func(string, Recipe) KeyboardSession { return sess }, nil, recipeOf(RecipeVaultKeyboard), ask)("cryptroot")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := derive([]byte("hunter2"), []byte("the salt"))
	if !bytes.Equal(key, want) {
		t.Fatal("the key is not the password's and the salt's")
	}
	if strings.Join(*asked, ",") != "Password,Keys" {
		t.Fatalf("asked %v", *asked)
	}
	if !strings.Contains((*notes)[0], "press the keys the vault shows") {
		t.Fatalf("the note: %q", (*notes)[0])
	}
}

// Wrong keys are asked for again, a few times; then the way goes on to cryptsetup's own prompt.
func TestKeyboardWrongKeys(t *testing.T) {
	cheapCombine(t)
	sess := &fakeKeyboard{right: "keysabcd", salt: []byte("the salt")}
	ask, asked, notes := keyboardAsk(map[string][]string{"Password": {"hunter2"}, "Keys": {"wrong", "keysabcd"}})
	if _, err := DiskKey(nil, func(string, Recipe) KeyboardSession { return sess }, nil, recipeOf(RecipePhoneKeyboard), ask)("cryptroot"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(*asked, ",") != "Password,Keys,Keys" || !strings.Contains((*notes)[2], "not the keys shown") {
		t.Fatalf("asked %v, notes %q", *asked, *notes)
	}

	sess = &fakeKeyboard{right: "keysabcd", salt: []byte("the salt")}
	ask, asked, _ = keyboardAsk(map[string][]string{"Password": {"hunter2"}, "Keys": {"a", "b", "c", "keysabcd"}})
	_, err := DiskKey(nil, func(string, Recipe) KeyboardSession { return sess }, nil, recipeOf(RecipePhoneKeyboard), ask)("cryptroot")
	if !errors.Is(err, ErrUnlockSkipped) {
		t.Fatalf("after three wrong: %v", err)
	}
	if len(*asked) != 4 {
		t.Fatalf("asked %v", *asked)
	}
}

// Once the vault took the keys they are not asked for again: a key that opened nothing, a mistyped
// password say, is asked for from the password on.
func TestKeyboardKeysOnce(t *testing.T) {
	cheapCombine(t)
	sess := &fakeKeyboard{right: "keysabcd", salt: []byte("the salt")}
	ask, asked, _ := keyboardAsk(map[string][]string{"Password": {"typo", "hunter2"}, "Keys": {"keysabcd"}})
	get := DiskKey(nil, func(string, Recipe) KeyboardSession { return sess }, nil, recipeOf(RecipeVaultKeyboard), ask)
	if _, err := get("cryptroot"); err != nil {
		t.Fatal(err)
	}
	if _, err := get("cryptroot"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(*asked, ",") != "Password,Keys,Password" {
		t.Fatalf("asked %v", *asked)
	}
}

// Nothing from the device: the recovery recipe, with what is typed there, as for every device-held
// salt; a refusal after the keys leads to cryptsetup's own prompt.
func TestKeyboardFallbacks(t *testing.T) {
	cheapCombine(t)
	ask, asked, notes := keyboardAsk(map[string][]string{"Password": {"hunter2"}, "Salt": {"typed salt"}})
	key, err := DiskKey(nil, func(string, Recipe) KeyboardSession { return nil }, nil, recipeOf(RecipeVaultKeyboard), ask)("cryptroot")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := derive([]byte("hunter2"), []byte("typed salt"))
	if !bytes.Equal(key, want) || strings.Join(*asked, ",") != "Password,Salt" || !strings.Contains((*notes)[0], "no keyboard from the vault") {
		t.Fatalf("asked %v, notes %q", *asked, *notes)
	}
	ask, _, _ = keyboardAsk(map[string][]string{"Password": {"hunter2"}, "Keys": {"x"}})
	sess := &fakeKeyboard{failure: errors.New("the vault refused")}
	_, err = DiskKey(nil, func(string, Recipe) KeyboardSession { return sess }, nil, recipeOf(RecipeVaultKeyboard), ask)("cryptroot")
	if !errors.Is(err, ErrUnlockSkipped) || !strings.Contains(err.Error(), "the vault refused") {
		t.Fatalf("%v", err)
	}
}

// The recipes: flags and their limits, as the words and numbers say them.
func TestKeyboardRecipes(t *testing.T) {
	for _, c := range []struct {
		password, salt string
		pepper         bool
		want           Recipe
	}{
		{"typed", "phone", false, RecipePhoneKeyboard},
		{"typed", "vault", false, RecipeVaultKeyboard},
		{"typed", "vault", true, RecipeVaultKeyboardPepper},
	} {
		r, err := RecipeOf(c.password, c.salt, c.pepper, true)
		if err != nil || r != c.want || !r.Keyboard() {
			t.Errorf("%v: %v %v", c, r, err)
		}
		fields := strings.Fields(r.Words())
		if fields[len(fields)-1] != "--keyboard" {
			t.Errorf("%v: words %q", r, r.Words())
		}
		if !strings.Contains(r.Describe(), "one-time keyboard") {
			t.Errorf("%v: %q", r, r.Describe())
		}
	}
	for name, c := range map[string][2]string{
		"unattended": {"tpm", "vault"},
		"typed salt": {"typed", "typed"},
		"the TPM's":  {"typed", "tpm"},
	} {
		if _, err := RecipeOf(c[0], c[1], false, true); err == nil {
			t.Errorf("%s with a keyboard is taken", name)
		}
	}
	for _, s := range []string{"0x1302", "0x1402", "0x1403"} {
		if r, err := ParseRecipe(s); err != nil || r.String() != s {
			t.Errorf("%s: %v %v", s, r, err)
		}
	}
	for _, s := range []string{"0x1102", "0x1202", "0x2402", "0x1303"} {
		if _, err := ParseRecipe(s); err == nil {
			t.Errorf("%s is taken", s)
		}
	}
}
