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
	"strings"
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
	if info := blob.Payload.EventlogInfo; info != nil && strings.Contains(info.MeasurePointExtends, OSSeparatorWord) {
		t.Fatalf("the blob should be sealed before the separator: %q", info.MeasurePointExtends)
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

// TestPhonesLiveInTheSlotsBlob: one blob per slot. Enrolling a phone must
// not disturb the TOTP key next to it, and the phones must survive what
// rewrites that blob: the reseal after every kernel update, and sealing the
// slot again - unless another signing key does the sealing.
func TestPhonesLiveInTheSlotsBlob(t *testing.T) {
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

	const slot = NVRAMSlotStart + 1
	at := time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)
	pubPath, privPath := writeTestKeyPair(t)
	if err := Seal(sock, "0,2,7", slot, pubPath, privPath, false, PCRHashAlgoSHA256, false); err != nil {
		t.Fatalf("seal: %v", err)
	}
	code, _, err := SlotCode(tpm, slot, at, false)
	if err != nil {
		t.Fatalf("code after seal: %v", err)
	}
	sealedSize := func() int { raw, _ := ReadFromNVRAM(tpm, slot); return len(raw) }
	plain := sealedSize()

	// Enrol: the phone goes into the slot's blob.
	priv, err := LoadCheckedSigningPrivateKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAttestBlob(tpm, slot, testEnrolment("box"), priv); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	enrolled := func(what string) *Attestation {
		t.Helper()
		a, err := loadAttestBlob(tpm, slot)
		if err != nil || len(a.Phone.Verifiers) != 1 || a.Phone.Verifiers[0].Name != "Pixel" || a.FriendlyName != "box" {
			t.Fatalf("%s: the phone is gone: %+v %v", what, a, err)
		}
		if verified, exit := gateRecordCheck(tpm, slot, pubPath); !verified || exit != 0 {
			t.Fatalf("%s: the gate does not accept the slot (verified=%v, exit %d)", what, verified, exit)
		}
		return a
	}
	count := enrolled("after enrolling").Count
	if again, _, err := SlotCode(tpm, slot, at, false); err != nil || again != code {
		t.Fatalf("enrolling a phone changed the slot's TOTP code: %q then %q (%v)", code, again, err)
	}
	t.Logf("slot blob: %d bytes sealed, %d bytes with one phone", plain, sealedSize())

	// Reseal, as the hook does after every kernel update.
	if err := Reseal(sock, "", slot, pubPath, privPath, false); err != nil {
		t.Fatalf("reseal: %v", err)
	}
	if got := enrolled("after reseal").Count; got != count {
		t.Fatalf("reseal changed the enrolment's count from %d to %d", count, got)
	}
	if again, _, err := SlotCode(tpm, slot, at, false); err != nil || again != code {
		t.Fatalf("reseal changed the TOTP code: %q then %q (%v)", code, again, err)
	}

	// Seal the slot again: a new TOTP key, the same phones.
	if err := Seal(sock, "0,2,7", slot, pubPath, privPath, false, PCRHashAlgoSHA256, false); err != nil {
		t.Fatalf("second seal: %v", err)
	}
	enrolled("after sealing again")
	if _, _, err := SlotCode(tpm, slot, at, false); err != nil {
		t.Fatalf("code after the second seal: %v", err)
	}

	// Another signing key seals the slot: it does not adopt phones it
	// cannot vouch for: the blob has no attestation part.
	otherPub, otherPriv := writeTestKeyPair(t)
	if err := Seal(sock, "0,2,7", slot, otherPub, otherPriv, false, PCRHashAlgoSHA256, false); err != nil {
		t.Fatalf("seal with another key: %v", err)
	}
	if _, err := loadAttestBlob(tpm, slot); !errors.Is(err, errNotEnrolled) {
		t.Fatalf("a foreign enrolment was carried over: %v", err)
	}
	if _, sb, err := readSlot(tpm, slot); err != nil || sb.Payload.Attestation != nil {
		t.Fatalf("slot sealed by another key: %+v, %v", sb, err)
	}
}
