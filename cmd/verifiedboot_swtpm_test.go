//go:build integration

package cmd

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A phone is enrolled only in a boot that the slot's code verified: one
// that passed the code screen, in the state the code is approved for, and
// that the person says they checked.
func TestEnrolmentNeedsAVerifiedBoot(t *testing.T) {
	sock := startSWTPM(t)
	tpm, err := OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	entries := []struct {
		pcr    int
		digest []byte
	}{
		{0, bytes.Repeat([]byte{0x1A}, 32)},
		{2, bytes.Repeat([]byte{0x2B}, 32)},
		{7, bytes.Repeat([]byte{0x3C}, 32)},
	}
	for _, e := range entries {
		extendSHA256(t, tpm, e.pcr, e.digest)
	}
	logPath := filepath.Join(t.TempDir(), "binary_bios_measurements")
	if err := os.WriteFile(logPath, tcg2Log(entries), 0o600); err != nil {
		t.Fatal(err)
	}
	old := DefaultEventlogPath
	DefaultEventlogPath = logPath
	defer func() { DefaultEventlogPath = old }()

	const slot = NVRAMSlotStart
	pubPath, privPath := writeTestKeyPair(t)
	if err := Seal(sock, "0e,2e,7e", slot, pubPath, privPath, false, PCRHashAlgoSHA256, false); err != nil {
		t.Fatalf("seal: %v", err)
	}
	_, sealed, err := readSlot(tpm, slot)
	if err != nil {
		t.Fatal(err)
	}

	// Before the code screen ran: nothing verified this boot.
	if _, err := requireVerifiedBoot(tpm, sealed, 0); err == nil || !strings.Contains(err.Error(), "did not pass tpm2-kira's code screen") {
		t.Fatalf("an uncapped boot was taken: %v", err)
	}

	// Through the code screen, in the approved state: the code was shown.
	if _, err := CapCodes(tpm); err != nil {
		t.Fatal(err)
	}
	matched, err := requireVerifiedBoot(tpm, sealed, 0)
	if err != nil || !matched {
		t.Fatalf("the approved boot: matched=%v %v", matched, err)
	}

	// The person still says so; "no" ends the enrolment.
	for answer, want := range map[string]bool{"y\n": true, "n\n": false, "maybe\nyes\n": true} {
		ok, err := confirmVerifiedBoot(bufio.NewReader(strings.NewReader(answer)), sealed, 0, matched)
		if err != nil || ok != want {
			t.Fatalf("answer %q: %v %v", answer, ok, err)
		}
	}

	// A boot in another state showed no code for the slot.
	extendSHA256(t, tpm, 7, bytes.Repeat([]byte{0x99}, 32))
	entries = append(entries, struct {
		pcr    int
		digest []byte
	}{7, bytes.Repeat([]byte{0x99}, 32)})
	if err := os.WriteFile(logPath, tcg2Log(entries), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := requireVerifiedBoot(tpm, sealed, 0); err == nil || !strings.Contains(err.Error(), "PCR 7 differ") {
		t.Fatalf("a boot outside the approved state was taken: %v", err)
	}
}
