//go:build integration

package admin

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/diskkey"
)

// luks enrol on a LUKS2 image: the keyslot added through cryptsetup with
// the derived key on its stdin, marked with the token, the mode written;
// the derived key opens the header. Needs root; skipped otherwise:
//
//	sudo -E go test -tags integration -count=1 -run TestLuksEnrolOnAnImage ./internal/admin/
func TestLuksEnrolOnAnImage(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for a loop device")
	}
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Skip("cryptsetup not installed")
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "disk.img")
	f, _ := os.Create(img)
	f.Truncate(20 << 20)
	f.Close()
	existing := filepath.Join(dir, "existing")
	os.WriteFile(existing, []byte("recovery passphrase"), 0o600)
	format := exec.Command("cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", existing, img)
	if out, err := format.CombinedOutput(); err != nil {
		t.Fatalf("luksFormat: %v: %s", err, out)
	}
	loopOut, err := exec.Command("losetup", "--find", "--show", img).Output()
	if err != nil {
		t.Fatal(err)
	}
	loop := strings.TrimSpace(string(loopOut))
	defer exec.Command("losetup", "-d", loop).Run()

	answers := []string{"correct-horse", "correct-horse", "test-salt"}
	oldAsk := terminalAsk
	terminalAsk = func(prompt string) ([]byte, error) {
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
	defer func() { terminalAsk = oldAsk }()
	conf := filepath.Join(dir, "control.conf")
	os.WriteFile(conf, []byte("# comment\nTPM2_KIRA_NOSUCH=skip\n"), 0o644)

	if err := LuksEnrol(LuksEnrolOptions{Device: loop, Mode: diskkey.LuksModePasswordSalt, ExistingKeyFile: existing}); err != nil {
		t.Fatalf("luks enrol: %v", err)
	}
	st := readLuksStatus(loop)
	if st.Error != "" || len(st.Keyslots) != 2 || st.Keyslots[1].Token == nil || st.Keyslots[1].Token.Mode != diskkey.LuksModePasswordSalt || st.Keyslots[0].Token != nil {
		t.Fatalf("after enrol: %+v", st)
	}
	key, _ := diskkey.Combine([]byte("correct-horse"), []byte("test-salt"))
	keyFile := filepath.Join(dir, "key")
	os.WriteFile(keyFile, key, 0o600)
	if out, err := exec.Command("cryptsetup", "open", "--test-passphrase", loop, "--key-file", keyFile).CombinedOutput(); err != nil {
		t.Fatalf("the derived key does not open the header: %v %s", err, out)
	}
	if out, err := exec.Command("cryptsetup", "luksDump", loop).CombinedOutput(); err != nil || !strings.Contains(string(out), "tpm2-kira") {
		t.Fatalf("luksDump shows no token: %v\n%s", err, out)
	}

	// A device whose every keyslot is tpm2-kira's gets no second one: the
	// recovery passphrase must stay.
	if err := LuksMark(LuksMarkOptions{Device: loop, Keyslot: 0, Mode: diskkey.LuksModePasswordSalt}); err != nil {
		t.Fatal(err)
	}
	answers = []string{"x", "x", "y"}
	if err := LuksEnrol(LuksEnrolOptions{Device: loop, Mode: diskkey.LuksModePasswordSalt, ExistingKeyFile: existing}); err == nil || !strings.Contains(err.Error(), "recovery passphrase") {
		t.Fatalf("without a recovery keyslot: %v", err)
	}

	// remove: only tpm2-kira's, never the last. cryptsetup wants a
	// passphrase of a keyslot other than the one killed.
	if err := LuksRemove(LuksRemoveOptions{Device: loop, Keyslot: 0, ExistingKeyFile: keyFile}); err != nil {
		t.Fatal(err)
	}
	st = readLuksStatus(loop)
	if len(st.Keyslots) != 1 || st.Keyslots[0].Keyslot != 1 {
		t.Fatalf("after remove: %+v", st)
	}
	if err := LuksRemove(LuksRemoveOptions{Device: loop, Keyslot: 1, ExistingKeyFile: keyFile}); err == nil || !strings.Contains(err.Error(), "last keyslot") {
		t.Fatalf("the last keyslot: %v", err)
	}
	add := exec.Command("cryptsetup", "luksAddKey", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", keyFile, loop, existing)
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("luksAddKey: %v: %s", err, out)
	}
	if err := LuksRemove(LuksRemoveOptions{Device: loop, Keyslot: 0, ExistingKeyFile: keyFile}); err == nil || !strings.Contains(err.Error(), "not tpm2-kira's") {
		t.Fatalf("a keyslot that is not ours: %v", err)
	}
}

// A disk encrypted with an empty passphrase: the empty answer authorises
// the enrolment and the removal, it is not refused as "not a password".
// A file image, so no root is needed.
//
//	go test -tags integration -count=1 -run TestLuksEnrolWithAnEmptyPassphrase ./internal/admin/
func TestLuksEnrolWithAnEmptyPassphrase(t *testing.T) {
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Skip("cryptsetup not installed")
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "disk.img")
	f, _ := os.Create(img)
	f.Truncate(20 << 20)
	f.Close()
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, nil, 0o600)
	format := exec.Command("cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", empty, img)
	if out, err := format.CombinedOutput(); err != nil {
		t.Fatalf("luksFormat: %v: %s", err, out)
	}

	answers := []string{"correct-horse", "correct-horse", "test-salt"}
	oldAsk, oldExisting := terminalAsk, terminalAskExisting
	terminalAsk = func(string) ([]byte, error) {
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
	asked := 0
	terminalAskExisting = func(string) ([]byte, error) { asked++; return nil, nil } // Enter alone
	defer func() { terminalAsk, terminalAskExisting = oldAsk, oldExisting }()

	if err := LuksEnrol(LuksEnrolOptions{Device: img, Mode: diskkey.LuksModePasswordSalt}); err != nil {
		t.Fatalf("luks enrol with an empty passphrase: %v", err)
	}
	st := readLuksStatus(img)
	if st.Error != "" || len(st.Keyslots) != 2 || st.Keyslots[1].Token == nil {
		t.Fatalf("after enrol: %+v", st)
	}
	if empty, err := emptyPassphraseOpens(img, 0); err != nil || !empty {
		t.Fatalf("the empty passphrase is not found: %v %v", empty, err)
	}
	if empty, err := emptyPassphraseOpens(img, 1); err != nil || empty {
		t.Fatalf("the derived key's keyslot reads as empty: %v %v", empty, err)
	}
	if err := LuksRemove(LuksRemoveOptions{Device: img, Keyslot: 1}); err != nil {
		t.Fatalf("luks remove with an empty passphrase: %v", err)
	}
	if st := readLuksStatus(img); len(st.Keyslots) != 1 || asked != 2 {
		t.Fatalf("after remove: %+v, asked %d", st, asked)
	}
}
