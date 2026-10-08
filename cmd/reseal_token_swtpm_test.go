//go:build integration

package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/piv"
	"github.com/mrwiora/tpm2-kira/internal/piv/pivtest"
)

// The reseal the hooks run after a kernel update, with the signing key on
// a YubiKey and nobody at a terminal: the PIN comes from control.conf, or
// the reseal is skipped (the SKIPPED block, the index untouched). The TPM
// is swtpm, the token the PIV emulator.
func TestResealThroughTokenWithStoredPIN(t *testing.T) {
	sock := startSWTPM(t)
	card := pivtest.New(1)
	key := card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	fake := &fakeTokens{cards: []*pivtest.Card{card}} // typed "": no terminal
	fake.install(t)
	os.Unsetenv(PINEnvVar)
	conf := filepath.Join(t.TempDir(), "control.conf")
	t.Setenv("TPM2_KIRA_CONTROL_CONF", conf)
	os.WriteFile(conf, []byte("TPM2_KIRA_UNLOCK=skip\nTPM2_KIRA_PIN='123456'\n"), 0o600)

	privPath := writeStub(t, 1, probeSlot(t, 1, piv.SlotAuthentication))
	pubPEM, err := PublicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "seal.pub")
	if err := WriteSigningKeyFile(pubPath, pubPEM); err != nil {
		t.Fatal(err)
	}
	idx := ResolveNVRAMIndex(0)
	if err := Seal(sock, "23", idx, pubPath, privPath, false, PCRHashAlgoSHA256, false); err != nil {
		t.Fatalf("seal through the token: %v", err)
	}
	CloseTokenSessions()

	// With the PIN stored: the reseal signs, nobody is asked.
	if err := Reseal(sock, "", idx, pubPath, privPath, false); err != nil {
		t.Fatalf("reseal with the PIN in control.conf: %v", err)
	}
	if fake.prompts != 0 || card.Retries != 3 {
		t.Errorf("prompts %d, attempts left %d", fake.prompts, card.Retries)
	}
	CloseTokenSessions()
	gen1, err := readGenerationAt(t, sock, idx)
	if err != nil {
		t.Fatal(err)
	}

	// Without it, and without a terminal: skipped, and the slot as it was.
	os.WriteFile(conf, []byte("TPM2_KIRA_UNLOCK=skip\n"), 0o600)
	err = Reseal(sock, "", idx, pubPath, privPath, false)
	var skipped *ResealSkippedError
	if !errors.Is(err, ErrResealSkipped) || !errors.As(err, &skipped) || skipped.NVIndex != idx {
		t.Fatalf("reseal without a PIN: %v", err)
	}
	if card.Retries != 3 {
		t.Errorf("an attempt was spent without a PIN: %d left", card.Retries)
	}
	if gen2, err := readGenerationAt(t, sock, idx); err != nil || gen2 != gen1 {
		t.Errorf("the slot was touched by a skipped reseal: generation %d -> %d (%v)", gen1, gen2, err)
	}

	// A PIN the token refuses: skipped too, naming the file the PIN came
	// from, and no second attempt is spent on it.
	os.WriteFile(conf, []byte("TPM2_KIRA_PIN='000000'\n"), 0o600)
	CloseTokenSessions()
	err = Reseal(sock, "", idx, pubPath, privPath, false)
	if !errors.Is(err, ErrResealSkipped) || !strings.Contains(err.Error(), "wrong PIN (2 attempt(s) remaining) (PIN from "+conf+")") {
		t.Fatalf("reseal with a wrong PIN: %v", err)
	}
	if card.Retries != 2 {
		t.Errorf("after one wrong PIN %d attempts left", card.Retries)
	}
	if gen3, err := readGenerationAt(t, sock, idx); err != nil || gen3 != gen1 {
		t.Errorf("the slot was touched by a failed reseal: generation %d -> %d (%v)", gen1, gen3, err)
	}
}

// readGenerationAt is the generation counter of the slot at idx.
func readGenerationAt(t *testing.T, sock string, idx uint32) (uint64, error) {
	t.Helper()
	tpmDev, err := OpenTPM(sock)
	if err != nil {
		return 0, err
	}
	defer tpmDev.Close()
	return ReadGeneration(tpmDev, GenerationIndex(idx))
}
