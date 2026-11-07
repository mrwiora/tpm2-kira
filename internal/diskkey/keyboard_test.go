package diskkey

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// fakeKeyboard maps what is typed to upper case: a layout of its own, as good as any for the prompt.
type fakeKeyboard struct {
	calls   int
	failure error
}

func (k *fakeKeyboard) From() string { return "your phone" }
func (k *fakeKeyboard) Pepper(typed []byte) ([]byte, error) {
	k.calls++
	if k.failure != nil {
		return nil, k.failure
	}
	if len(typed) < 8 {
		return nil, ErrNotAPepper
	}
	return bytes.ToUpper(typed), nil
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

func deviceSalt(s string) func(string, Recipe) []byte {
	return func(string, Recipe) []byte { return []byte(s) }
}

// The password, then the pepper through the layout; the key is the password's and the device's
// salt with the pepper the layout made of the keys.
func TestKeyboardPrompt(t *testing.T) {
	cheapCombine(t)
	sess := &fakeKeyboard{}
	ask, asked, notes := keyboardAsk(map[string][]string{"Password": {"hunter2"}, "Pepper": {"keysabcd"}})
	key, err := DiskKey(deviceSalt("the salt"), func(string, Recipe) KeyboardSession { return sess }, nil, recipeOf(RecipePhoneKeyboard), ask)("cryptroot")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := derive([]byte("hunter2"), KeyboardSalt([]byte("the salt"), []byte("KEYSABCD")))
	if !bytes.Equal(key, want) {
		t.Fatal("the key is not the password's with the salt and the mapped pepper")
	}
	if strings.Join(*asked, ",") != "Password,Pepper" {
		t.Fatalf("asked %v", *asked)
	}
	if !strings.Contains((*notes)[0], "layout your phone shows") {
		t.Fatalf("the note: %q", (*notes)[0])
	}
	// The pepper matters: another one, another salt.
	if bytes.Equal(KeyboardSalt([]byte("the salt"), []byte("a")), KeyboardSalt([]byte("the salt"), []byte("b"))) {
		t.Fatal("the pepper changes nothing")
	}
}

// A pepper of the wrong form is asked for again, a few times; then cryptsetup's own prompt.
func TestKeyboardNotAPepper(t *testing.T) {
	cheapCombine(t)
	sess := &fakeKeyboard{}
	ask, asked, notes := keyboardAsk(map[string][]string{"Password": {"hunter2"}, "Pepper": {"short", "keysabcd"}})
	if _, err := DiskKey(deviceSalt("s"), func(string, Recipe) KeyboardSession { return sess }, nil, recipeOf(RecipeVaultKeyboard), ask)("cryptroot"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(*asked, ",") != "Password,Pepper,Pepper" || !strings.Contains((*notes)[2], "not a pepper") {
		t.Fatalf("asked %v, notes %q", *asked, *notes)
	}

	ask, asked, _ = keyboardAsk(map[string][]string{"Password": {"hunter2"}, "Pepper": {"a", "b", "c", "keysabcd"}})
	_, err := DiskKey(deviceSalt("s"), func(string, Recipe) KeyboardSession { return sess }, nil, recipeOf(RecipePhoneKeyboard), ask)("cryptroot")
	if !errors.Is(err, ErrUnlockSkipped) || len(*asked) != 4 {
		t.Fatalf("after three: %v, asked %v", err, *asked)
	}
}

// Nothing from the device - no layout or no salt: the recovery recipe, with what is typed there, as
// for every device-held salt; a failing layout leads to cryptsetup's own prompt.
func TestKeyboardFallbacks(t *testing.T) {
	cheapCombine(t)
	for name, c := range map[string]struct {
		salt func(string, Recipe) []byte
		kb   func(string, Recipe) KeyboardSession
	}{
		"no layout": {deviceSalt("s"), func(string, Recipe) KeyboardSession { return nil }},
		"no salt":   {func(string, Recipe) []byte { return nil }, func(string, Recipe) KeyboardSession { return &fakeKeyboard{} }},
	} {
		ask, asked, notes := keyboardAsk(map[string][]string{"Password": {"hunter2"}, "Salt": {"typed salt"}})
		key, err := DiskKey(c.salt, c.kb, nil, recipeOf(RecipeVaultKeyboard), ask)("cryptroot")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want, _ := derive([]byte("hunter2"), []byte("typed salt"))
		if !bytes.Equal(key, want) || strings.Join(*asked, ",") != "Password,Salt" || !strings.Contains((*notes)[0], "no salt and keyboard from the vault") {
			t.Fatalf("%s: asked %v, notes %q", name, *asked, *notes)
		}
	}
	ask, _, _ := keyboardAsk(map[string][]string{"Password": {"hunter2"}, "Pepper": {"keysabcd"}})
	sess := &fakeKeyboard{failure: errors.New("the layout is gone")}
	_, err := DiskKey(deviceSalt("s"), func(string, Recipe) KeyboardSession { return sess }, nil, recipeOf(RecipeVaultKeyboard), ask)("cryptroot")
	if !errors.Is(err, ErrUnlockSkipped) || !strings.Contains(err.Error(), "the layout is gone") {
		t.Fatalf("%v", err)
	}
}

// The recipes: flags and their limits, as the words and numbers say them.
func TestKeyboardRecipes(t *testing.T) {
	for _, c := range []struct {
		salt string
		want Recipe
	}{{"phone", RecipePhoneKeyboard}, {"vault", RecipeVaultKeyboard}} {
		r, err := RecipeOf("typed", c.salt, false, true)
		if err != nil || r != c.want || !r.Keyboard() {
			t.Errorf("%v: %v %v", c, r, err)
		}
		fields := strings.Fields(r.Words())
		if fields[len(fields)-1] != "--keyboard-pepper" {
			t.Errorf("%v: words %q", r, r.Words())
		}
		if !strings.Contains(r.Describe(), "pepper typed through a one-time keyboard") {
			t.Errorf("%v: %q", r, r.Describe())
		}
	}
	for name, c := range map[string]struct {
		password, salt string
		pepper         bool
	}{
		"unattended":           {"tpm", "vault", false},
		"typed salt":           {"typed", "typed", false},
		"the TPM's":            {"typed", "tpm", false},
		"an operator's pepper": {"typed", "vault", true},
	} {
		if _, err := RecipeOf(c.password, c.salt, c.pepper, true); err == nil {
			t.Errorf("%s with a keyboard is taken", name)
		}
	}
	for _, s := range []string{"0x1302", "0x1402"} {
		if r, err := ParseRecipe(s); err != nil || r.String() != s {
			t.Errorf("%s: %v %v", s, r, err)
		}
	}
	for _, s := range []string{"0x1102", "0x1202", "0x2402", "0x1303", "0x1403"} {
		if _, err := ParseRecipe(s); err == nil {
			t.Errorf("%s is taken", s)
		}
	}
}
