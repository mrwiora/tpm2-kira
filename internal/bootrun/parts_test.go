package bootrun

import (
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/imageplan"
	"github.com/mrwiora/tpm2-kira/internal/sshscreen"
)

// Only what the plan names is started: an image without the phone, the
// vault and SSH starts the disk's key provider and the console alone.
func TestOnlyThePlannedPartsStart(t *testing.T) {
	ps := plannedParts(imageplan.Planned{Codes: true}, sshscreen.Options{}, "/run/gate.sock", "/run/unlock.sock")
	if ps.phone != nil || ps.ssh != nil || ps.vault != nil {
		t.Fatalf("parts the plan does not name: %+v", ps)
	}
	if got := ps.inOrder(); len(got) != 2 || got[0] != ps.unlock || got[1] != ps.console {
		t.Fatalf("started %v", got)
	}

	ps = plannedParts(imageplan.All, sshscreen.Options{On: true}, "/run/gate.sock", "/run/unlock.sock")
	got := ps.inOrder()
	want := []part{ps.phone, ps.ssh, ps.vault, ps.unlock, ps.console}
	if len(got) != len(want) {
		t.Fatalf("started %v", got)
	}
	for i := range want {
		if want[i] == nil || got[i] != want[i] {
			t.Fatalf("part %d: %v, want %v (the layers' order: phone, SSH, vault, the disk's key, the console)", i, got[i], want[i])
		}
	}
}

// A confirmation waits for the display to take it, and gives up when its
// part is released.
func TestOfferGivesUpWhenReleased(t *testing.T) {
	bd := &board{confirm: make(chan string)}
	got := make(chan string, 1)
	go func() { got <- <-bd.confirm }()
	if !bd.offer(confirmedByConsole, make(chan struct{})) {
		t.Fatal("not taken")
	}
	if by := <-got; by != confirmedByConsole {
		t.Fatalf("taken as %q", by)
	}
	stop := make(chan struct{})
	close(stop)
	if bd.offer(confirmedByVault, stop) {
		t.Fatal("taken after the release")
	}
}

// The screen names the prompt that follows, also behind a vault: a typed
// keyslot is asked only when the vault gives no key.
func TestNextPromptNamesTheVaultsFallback(t *testing.T) {
	for _, c := range []struct {
		modes []string
		want  string
	}{
		{nil, "cryptsetup's prompt"},
		{[]string{diskkey.LuksModePasswordSalt}, "the password and salt prompt"},
		{[]string{diskkey.LuksModeTPMVault}, "cryptsetup's prompt without the vault"},
		{[]string{diskkey.LuksModeTPMVault, diskkey.LuksModePasswordSalt}, "the password and salt prompt if the vault gives no key"},
	} {
		if got := nextPrompt(c.modes); got != c.want {
			t.Errorf("%q: %q, want %q", c.modes, got, c.want)
		}
	}
}
