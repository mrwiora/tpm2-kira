//go:build integration

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A blob stashed when the rewrite of its slot failed goes back into the
// slot with nvram restore: the TPM loads the same sealed object, so the
// codes are the ones from before, and the approval is made afresh for the
// PCRs the blob was sealed to. A slot that holds a blob is not restored
// over.
func TestRestoreBringsTheSlotBack(t *testing.T) {
	sock := startSWTPM(t)
	tpm, err := OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	extendPCR(tpm, 0, "firmware")
	extendPCR(tpm, 7, "secure boot")

	const slot = NVRAMSlotStart + 2
	at := time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC)
	pubPath, privPath := writeTestKeyPair(t)
	if err := Seal(sock, "0,7", slot, pubPath, privPath, false, PCRHashAlgoSHA256, false); err != nil {
		t.Fatalf("seal: %v", err)
	}
	before, _, err := SlotCode(tpm, slot, at, false)
	if err != nil {
		t.Fatalf("code after seal: %v", err)
	}
	stashed, err := ReadFromNVRAM(tpm, slot)
	if err != nil {
		t.Fatal(err)
	}

	// The file as stashUnwrittenBlobFile names it.
	file := filepath.Join(t.TempDir(), "slot-0x"+strings.ToUpper(hexIndex(slot))+"-1759823456.blob")
	if err := os.WriteFile(file, stashed, 0o600); err != nil {
		t.Fatal(err)
	}

	// With the slot in place, restore refuses and names the way.
	err = NVRAMRestore(sock, file, 0, pubPath, privPath, false)
	if err == nil || !strings.Contains(err.Error(), "holds a blob already") || !strings.Contains(err.Error(), "nvram delete --nvram 2") {
		t.Fatalf("restore over a slot: %v", err)
	}

	// The slot is gone, as after a failed rewrite.
	if err := NVRAMDelete(sock, slot, false); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, err := SlotCode(tpm, slot, at, false); err == nil {
		t.Fatal("the slot still computes codes after delete")
	}

	if err := NVRAMRestore(sock, file, 0, pubPath, privPath, false); err != nil {
		t.Fatalf("restore: %v", err)
	}
	after, _, err := SlotCode(tpm, slot, at, false)
	if err != nil {
		t.Fatalf("code after restore: %v", err)
	}
	if after != before {
		t.Fatalf("code %s after restore, %s before: not the same TOTP key", after, before)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("the stashed file was not removed: %v", err)
	}

	// A file whose name carries no index needs --nvram.
	plain := filepath.Join(t.TempDir(), "copy.blob")
	os.WriteFile(plain, stashed, 0o600)
	if err := NVRAMRestore(sock, plain, 0, pubPath, privPath, false); err == nil || !strings.Contains(err.Error(), "pass --nvram") {
		t.Fatalf("no index in the name: %v", err)
	}
}

func hexIndex(i uint32) string {
	const digits = "0123456789abcdef"
	var b [8]byte
	for n := 7; n >= 0; n-- {
		b[n] = digits[i&0xf]
		i >>= 4
	}
	return string(b[:])
}
