package bootrun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tpm2-trust/tpm2-kira/internal/diskkey"
	"github.com/tpm2-trust/tpm2-kira/internal/imageplan"
	"github.com/tpm2-trust/tpm2-kira/internal/sshscreen"
	"github.com/tpm2-trust/tpm2-kira/internal/totp"
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

// With nothing to show - no slot with a TOTP code or phones - the hold
// lasts while the vault opens what it holds for this boot state, and ends
// when it is done; at the latest when the hold does.
func TestHoldWithoutCodesWaitsForTheVault(t *testing.T) {
	run := func(pending <-chan struct{}, hold time.Duration) (time.Duration, bool) {
		notified := false
		b := &bootDisplay{
			Scan:    func(time.Time) ([]totp.NVRAMSlot, error) { return nil, ErrNoSlots },
			Notify:  func() { notified = true },
			Wait:    func(d time.Duration) bool { time.Sleep(d); return false },
			Now:     time.Now,
			Hold:    hold,
			Pending: func() <-chan struct{} { return pending },
		}
		start := time.Now()
		b.Run()
		return time.Since(start), notified
	}

	done := make(chan struct{})
	go func() { time.Sleep(300 * time.Millisecond); close(done) }()
	if took, notified := run(done, time.Minute); took < 250*time.Millisecond || took > 5*time.Second || !notified {
		t.Fatalf("the vault working: released after %v (notified %v)", took, notified)
	}
	if took, notified := run(make(chan struct{}), 500*time.Millisecond); took < 400*time.Millisecond || took > 5*time.Second || !notified {
		t.Fatalf("the vault never done: released after %v (notified %v)", took, notified)
	}
	if took, notified := run(nil, time.Minute); took > 100*time.Millisecond || !notified {
		t.Fatalf("no vault: released after %v (notified %v)", took, notified)
	}
}

// recPart records what it is told.
type recPart struct {
	name string
	log  *[]string
}

func (p recPart) start(*board)                {}
func (p recPart) released(_ *board, _ string) { *p.log = append(*p.log, "released "+p.name) }
func (p recPart) end(*board)                  {}

// The end of the hold: every part that opens something in the TPM is told
// first and finishes (the vault's opening, the phone's salt), then the
// boot is closed (PCR 15), then READY, and only then does the key provider
// answer - from what was opened before the close. Without a TPM in the
// plan, nothing is closed.
func TestReleaseClosesAfterThePartsAndBeforeReady(t *testing.T) {
	var log []string
	defer func(c func(string), n func()) { closeBoot, notifyReady = c, n }(closeBoot, notifyReady)
	closeBoot = func(tpm string) { log = append(log, "close "+tpm) }
	notifyReady = func() { log = append(log, "ready") }
	ps := parts{}
	for _, p := range []*part{&ps.phone, &ps.ssh, &ps.vault, &ps.tpmSalt, &ps.unlock, &ps.console} {
		*p = recPart{name: map[*part]string{&ps.phone: "phone", &ps.ssh: "ssh", &ps.vault: "vault", &ps.tpmSalt: "tpmsalt", &ps.unlock: "unlock", &ps.console: "console"}[p], log: &log}
	}
	ps.release(&board{tpmPath: "/dev/tpmrm0"}, confirmedByConsole, true)
	want := []string{"released vault", "released console", "released ssh", "released phone", "close /dev/tpmrm0", "ready", "released unlock"}
	if strings.Join(log, "|") != strings.Join(want, "|") {
		t.Fatalf("the order:\n%v\nwant\n%v", log, want)
	}
	log = nil
	ps.release(&board{tpmPath: "/dev/tpmrm0"}, "", false)
	if strings.Contains(strings.Join(log, "|"), "close") {
		t.Fatalf("closed without a TPM in the plan: %v", log)
	}
}

// readySeen is an unlock part that notes whether run's file was there when it was told.
type readySeen struct {
	recPart
	file string
	seen *bool
}

func (p readySeen) released(*board, string) {
	_, err := os.Stat(p.file)
	*p.seen = err == nil
}

// Debian's READY: the file is made past the close and before a key request is answered,
// so the close that waits for it can come neither before run's nor after the answer.
func TestReleaseMakesTheReadyFile(t *testing.T) {
	defer func(c func(string), n func()) { closeBoot, notifyReady = c, n }(closeBoot, notifyReady)
	file := filepath.Join(t.TempDir(), "screen-over")
	closedBefore, seen := false, false
	closeBoot = func(string) {
		_, err := os.Stat(file)
		closedBefore = err != nil
	}
	notifyReady = func() {}
	var log []string
	ps := parts{unlock: readySeen{recPart{name: "unlock", log: &log}, file, &seen}}
	ps.release(&board{readyFile: file}, confirmedByConsole, true)
	if !closedBefore {
		t.Error("the file was there before the close")
	}
	if !seen {
		t.Error("the key provider was told before the file was made")
	}
}
