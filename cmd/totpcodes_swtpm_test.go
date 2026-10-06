//go:build integration

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestKeyPair writes a P-256 signing key the way setup does (SEC 1 PEM,
// mode 0400, private directory) and returns the paths.
func writeTestKeyPair(t *testing.T) (pubPath, privPath string) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	privPath = filepath.Join(dir, "seal.key")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o400); err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPath = filepath.Join(dir, "seal.pub")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0o400); err != nil {
		t.Fatal(err)
	}
	return pubPath, privPath
}

// While the display holds the boot, the PCRs still hold the sealed values
// and the TPM computes a code per window. Once the OS separator has extended
// them, the slot reports itself locked until the next boot.
func TestCodeBeforeTheSeparatorThenLocked(t *testing.T) {
	sock := startSWTPM(t)
	tpm, err := OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	// Firmware measured something into 0, 2, 7, and the event log says so,
	// so the seal lands on the end-of-firmware values (before any separator).
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

	pubPath, privPath := writeTestKeyPair(t)
	if err := Seal(sock, "0,2,7", NVRAMSlotStart, pubPath, privPath, false, PCRHashAlgoSHA256, false); err != nil {
		t.Fatalf("seal: %v", err)
	}

	// A code per window, as the display asks for them during the hold.
	at := time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)
	first, blob, err := SlotCode(tpm, NVRAMSlotStart, at, false)
	if err != nil {
		t.Fatalf("code during the hold: %v", err)
	}
	if blob.MeasurePoint() != MeasurePointBeforeSeparator {
		t.Fatalf("the blob should be sealed before the separator: %v", blob.MeasurePoint())
	}
	next, _, err := SlotCode(tpm, NVRAMSlotStart, at.Add(30*time.Second), false)
	if err != nil || next == first || len(first) != 6 {
		t.Fatalf("the next window should give another code: %q then %q (%v)", first, next, err)
	}

	// systemd-pcrosseparator runs: the sealed values are unreachable now.
	for _, pcr := range []int{0, 2, 7} {
		extendSHA256(t, tpm, pcr, DigestOf(PCRHashAlgoSHA256, []byte(OSSeparatorWord)))
	}
	if _, _, err := SlotCode(tpm, NVRAMSlotStart, at, false); !errors.Is(err, ErrSeparatorLocked) {
		t.Fatalf("after the separator the slot should be locked, got %v", err)
	}
	slots := ScanNVRAMSlot(tpm, NVRAMSlotStart, false)
	if len(slots) != 1 || !errors.Is(slots[0].Error, ErrSeparatorLocked) {
		t.Fatalf("reveal should report the lock: %+v", slots)
	}
	if line := slotErrorLine(slots[0].Error); line != "Locked until the next boot (the OS separator ran after the measure point)" {
		t.Fatalf("line %q", line)
	}
}
