//go:build integration

package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// luks enrol on a LUKS2 image: the keyslot added through cryptsetup with
// the derived key on its stdin, marked with the token, the mode written;
// the derived key opens the header. Needs root; skipped otherwise:
//
//	sudo -E go test -tags integration -count=1 -run TestLuksEnrolOnAnImage ./cmd/
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
	conf := filepath.Join(dir, "unlock.conf")
	os.WriteFile(conf, []byte("# comment\nTPM2_KIRA_UNLOCK=skip\n"), 0o644)

	if err := LuksEnrol(LuksEnrolOptions{Device: loop, Mode: LuksModePasswordSalt, ExistingKeyFile: existing}); err != nil {
		t.Fatalf("luks enrol: %v", err)
	}
	st := readLuksStatus(loop)
	if st.Error != "" || len(st.Keyslots) != 2 || st.Keyslots[1].Token == nil || st.Keyslots[1].Token.Mode != LuksModePasswordSalt || st.Keyslots[0].Token != nil {
		t.Fatalf("after enrol: %+v", st)
	}
	key, _ := Combine([]byte("correct-horse"), []byte("test-salt"))
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
	if err := LuksMark(LuksMarkOptions{Device: loop, Keyslot: 0, Mode: LuksModePasswordSalt}); err != nil {
		t.Fatal(err)
	}
	answers = []string{"x", "x", "y"}
	if err := LuksEnrol(LuksEnrolOptions{Device: loop, Mode: LuksModePasswordSalt, ExistingKeyFile: existing}); err == nil || !strings.Contains(err.Error(), "recovery passphrase") {
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

	// The mode in unlock.conf: replaced, or added, or the file made.
	if err := setUnlockMode(conf, LuksModePasswordSalt); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(conf); string(b) != "# comment\nTPM2_KIRA_UNLOCK=password+salt\n" {
		t.Fatalf("unlock.conf: %q", b)
	}
	fresh := filepath.Join(dir, "fresh.conf")
	if err := setUnlockMode(fresh, LuksModePasswordRemoteSalt); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(fresh); string(b) != "TPM2_KIRA_UNLOCK=password+remotesalt\n" {
		t.Fatalf("fresh unlock.conf: %q", b)
	}
}
