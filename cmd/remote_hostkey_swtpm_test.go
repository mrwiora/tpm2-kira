//go:build integration

package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The image build seals the host key to PCR 0 and 7 as they are at the
// code screen: the end-of-firmware values replayed from the event log,
// even when the build runs after the OS separator. At the code screen it
// unseals; after the separator, or with another Secure Boot state, it
// does not, and the error names the register that moved.
func TestHostKeySealedToPCR0And7(t *testing.T) {
	s := newSWTPMSetup(t)
	entries := []struct {
		pcr    int
		digest []byte
	}{
		{0, bytes.Repeat([]byte{0xA1}, 32)},
		{7, bytes.Repeat([]byte{0xC3}, 32)},
	}
	for _, e := range entries {
		extendSHA256(t, s.tpm, e.pcr, e.digest)
	}
	logPath := filepath.Join(t.TempDir(), "binary_bios_measurements")
	if err := os.WriteFile(logPath, tcg2Log(entries), 0o600); err != nil {
		t.Fatal(err)
	}
	old := DefaultEventlogPath
	DefaultEventlogPath = logPath
	defer func() { DefaultEventlogPath = old }()

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	atCodeScreen, err := sealHostKey(s.tpm, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := unsealHostKey(s.tpm, atCodeScreen); err != nil || !got.Equal(key) {
		t.Fatalf("at the code screen: %v", err)
	}
	// Through the file of the image, as run reads it.
	data, _ := json.Marshal(atCodeScreen)
	var back sealedHostKey
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if got, err := unsealHostKey(s.tpm, &back); err != nil || !got.Equal(key) {
		t.Fatalf("from the file: %v", err)
	}

	// systemd-pcrosseparator runs: the build of the running system still
	// seals the code screen's values, which no longer unseal now.
	for _, pcr := range []int{0, 7} {
		extendSHA256(t, s.tpm, pcr, DigestOf(PCRHashAlgoSHA256, []byte(OSSeparatorWord)))
	}
	rebuilt, err := sealHostKey(s.tpm, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, pcr := range []int{0, 7} {
		if !bytes.Equal(rebuilt.PCRs[pcr], atCodeScreen.PCRs[pcr]) {
			t.Fatalf("PCR %d sealed after the separator: %x, at the code screen %x", pcr, rebuilt.PCRs[pcr], atCodeScreen.PCRs[pcr])
		}
	}
	if _, err := unsealHostKey(s.tpm, rebuilt); err == nil || !strings.Contains(err.Error(), "PCR 0 and 7 changed") {
		t.Fatalf("after the separator: %v", err)
	}

	// Another Secure Boot state.
	sealedNow, err := sealHostKey(s.tpm, key)
	if err != nil {
		t.Fatal(err)
	}
	sealedNow.PCRs[0] = must(ReadPCRRegisters(s.tpm, []int{0}, PCRHashAlgoSHA256, false))[0]
	extendSHA256(t, s.tpm, 7, bytes.Repeat([]byte{0xEE}, 32))
	if _, err := unsealHostKey(s.tpm, sealedNow); err == nil || !strings.Contains(err.Error(), "PCR 7 changed") {
		t.Fatalf("PCR 7 moved: %v", err)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
