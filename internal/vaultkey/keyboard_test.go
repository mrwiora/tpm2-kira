package vaultkey

import (
	"bytes"
	"testing"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
)

// Each prompt gets a copy of the layout, which it wipes; the next prompt (Debian's tries=) gets the
// whole layout again; Forget wipes the session at run's end.
func TestKeyboardSessionCopiesAndForget(t *testing.T) {
	l, err := attest.KeyboardLayoutOf(bytes.Repeat([]byte{7}, attest.KeyboardSeedSize))
	if err != nil {
		t.Fatal(err)
	}
	want := l.String()
	sess := &KeyboardSession{layout: l}
	vk := &Keys{keys: map[int][]byte{0: []byte("key")}, salts: map[int][]byte{0: []byte("salt")}, keyboards: map[int]*KeyboardSession{0: sess}, done: make(chan struct{})}
	close(vk.done)

	first := sess.copy()
	first.Wipe()
	if first.layout.String() == want {
		t.Fatal("the prompt's copy is not wiped")
	}
	second := sess.copy()
	if second.layout.String() != want {
		t.Fatal("a wiped copy took the session's layout with it")
	}
	salt, key := vk.salts[0], vk.keys[0]
	vk.Forget()
	if sess.layout.String() == want || !bytes.Equal(salt, make([]byte, len(salt))) || !bytes.Equal(key, make([]byte, len(key))) {
		t.Fatal("Forget left the layout, the salt or the key")
	}
	var none *Keys
	none.Forget()
}
