package bootrun

import (
	"testing"
	"time"

	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/imageplan"
	"github.com/mrwiora/tpm2-kira/internal/sshscreen"
)

// Only what the plan names is started: an image without the phone, the
// vault, the TPM salt and SSH starts the disk's key provider and the
// console alone.
func TestOnlyThePlannedPartsStart(t *testing.T) {
	ps := plannedParts(imageplan.Planned{Codes: true}, sshscreen.Options{}, "/run/unlock.sock")
	if ps.phone != nil || ps.ssh != nil || ps.vault != nil || ps.tpmSalt != nil {
		t.Fatalf("parts the plan does not name: %+v", ps)
	}
	if got := ps.inOrder(); len(got) != 2 || got[0] != ps.unlock || got[1] != ps.console {
		t.Fatalf("started %v", got)
	}

	ps = plannedParts(imageplan.All, sshscreen.Options{On: true}, "/run/unlock.sock")
	got := ps.inOrder()
	want := []part{ps.phone, ps.ssh, ps.vault, ps.tpmSalt, ps.unlock, ps.console}
	if len(got) != len(want) {
		t.Fatalf("started %v", got)
	}
	for i := range want {
		if want[i] == nil || got[i] != want[i] {
			t.Fatalf("part %d: %v, want %v (the layers' order: phone, SSH, vault, TPM salt, the disk's key, the console)", i, got[i], want[i])
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
		recipes []diskkey.Recipe
		want    string
	}{
		{nil, "cryptsetup's prompt"},
		{[]diskkey.Recipe{diskkey.RecipeRecovery}, "the password and salt prompt"},
		{[]diskkey.Recipe{diskkey.RecipeUnattendedVault}, "cryptsetup's prompt without the vault"},
		{[]diskkey.Recipe{diskkey.RecipeUnattendedVault, diskkey.RecipeRecovery}, "the password and salt prompt if the vault gives no key"},
		{[]diskkey.Recipe{diskkey.RecipePhoneSalt}, "the password prompt"},
		{[]diskkey.Recipe{diskkey.RecipeVaultSaltPepper, diskkey.RecipeRecovery}, "the password prompt"},
	} {
		if got := nextPrompt(c.recipes); got != c.want {
			t.Errorf("%v: %q, want %q", c.recipes, got, c.want)
		}
	}
}

// The end of the hold waits for an opening the vault part has begun - READY
// would let the separator end the slot's policy under it - and no longer
// than vaultSettle.
func TestVaultPartReleaseWaitsForTheOpening(t *testing.T) {
	done := make(chan struct{})
	p := &vaultPart{cancel: func() {}, quit: make(chan struct{}), done: done}
	go func() { time.Sleep(200 * time.Millisecond); close(done) }()
	start := time.Now()
	p.released(nil, "")
	if waited := time.Since(start); waited < 150*time.Millisecond {
		t.Fatalf("released after %v, before the opening ended", waited)
	}

	old := vaultSettle
	vaultSettle = 100 * time.Millisecond
	defer func() { vaultSettle = old }()
	p = &vaultPart{cancel: func() {}, quit: make(chan struct{}), done: make(chan struct{})}
	start = time.Now()
	p.released(nil, "")
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("an opening that does not end held the boot for %v", waited)
	}
}
