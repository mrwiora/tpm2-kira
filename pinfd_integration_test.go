//go:build integration
// +build integration

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/piv"
	"github.com/tpm2-trust/tpm2-kira/internal/piv/pivtest"
	"github.com/tpm2-trust/tpm2-kira/internal/signing"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"
	"golang.org/x/sys/unix"
)

// What a hook or a unit runs, by the commands' own flags: slot add, then slot approve
// --unattended, each with --pin-fd, against swtpm and the PIV emulator. No PIN file and
// no terminal: the descriptor alone. A failure would be fail()'s os.Exit, which go test
// reports.
func TestUnattendedApproveThroughADescriptor(t *testing.T) {
	sock, cleanup := setupSoftwareTPM(t)
	defer cleanup()
	card := pivtest.New(1)
	key := card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	oldDial, oldPrompt := signing.DialTokens, signing.PromptPIN
	defer func() { signing.DialTokens, signing.PromptPIN = oldDial, oldPrompt }()
	defer signing.CloseTokenSessions()
	signing.DialTokens = func(time.Duration) ([]*signing.TokenConn, func(), error) {
		return []*signing.TokenConn{{Reader: "emulated", Transport: card, Close: func(reset bool) error {
			if reset {
				card.Reset()
			}
			return nil
		}}}, func() {}, nil
	}
	signing.PromptPIN = func(*signing.YubiKeySigner) ([]byte, error) {
		t.Error("the terminal was asked")
		return nil, errors.New("no terminal")
	}
	dir := t.TempDir()
	t.Setenv("TPM2_KIRA_CONTROL_CONF", filepath.Join(dir, "control.conf"))
	tokens, err := signing.ProbeYubiKeys(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	slot, ok := tokens[0].SlotByID(piv.SlotAuthentication)
	if !ok {
		t.Fatal("no key in the emulated slot")
	}
	stub, err := signing.MarshalYubiKeyStub(1, slot)
	if err != nil {
		t.Fatal(err)
	}
	privPath, pubPath := filepath.Join(dir, "seal.key"), filepath.Join(dir, "seal.pub")
	if err := signing.WriteSigningKeyFile(privPath, stub); err != nil {
		t.Fatal(err)
	}
	pubPEM, err := signing.PublicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.WriteSigningKeyFile(pubPath, pubPEM); err != nil {
		t.Fatal(err)
	}
	descriptor := func() string {
		var p [2]int
		if err := unix.Pipe(p[:]); err != nil {
			t.Fatal(err)
		}
		unix.Write(p[1], []byte("123456\n"))
		unix.Close(p[1])
		return strconv.Itoa(p[0])
	}
	idx := nvslot.ResolveNVRAMIndex(0)
	generation := func() uint64 {
		t.Helper()
		dev, err := tpmdev.Open(sock)
		if err != nil {
			t.Fatal(err)
		}
		defer dev.Close()
		g, err := nvslot.ReadGeneration(dev, nvslot.GenerationIndex(idx))
		if err != nil {
			t.Fatal(err)
		}
		return g
	}

	runSlotAdd([]string{"--nvram", fmt.Sprint(idx), "--pcrs", "23", "--verify-uki=false", "--totp", "--pubkey", pubPath, "--privkey", privPath, "--pin-fd", descriptor()}, sock, false)
	signing.CloseTokenSessions()
	before := generation()

	fd := descriptor()
	runSlotApprove([]string{"--unattended", "--nvram", fmt.Sprint(idx), "--pubkey", pubPath, "--privkey", privPath, "--pin-fd", fd}, sock, false)
	n, _ := strconv.Atoi(fd)
	var st unix.Stat_t
	if err := unix.Fstat(n, &st); !errors.Is(err, unix.EBADF) {
		t.Errorf("the descriptor after approve: %v", err)
	}
	signing.CloseTokenSessions()
	if after := generation(); after <= before {
		t.Errorf("the approval wrote nothing: generation %d -> %d", before, after)
	}
	if card.Retries != 3 {
		t.Errorf("attempts left %d", card.Retries)
	}
	if _, err := os.Stat(signing.PINPath()); !os.IsNotExist(err) {
		t.Errorf("a PIN file appeared: %v", err)
	}
}
