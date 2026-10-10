//go:build integration

package cmd

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

// A blob larger than the TPM's NV index limit is refused before the old
// index is touched, and the slot keeps what it held. A blob of exactly the
// limit is written: nothing is refused on a guess.
func TestOversizedBlobLeavesTheSlotAlone(t *testing.T) {
	sock := startSWTPM(t)
	tpmDev, err := transport.OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tpmDev.Close()
	limit := nvIndexLimit(tpmDev)
	if limit == 0 {
		t.Skip("this TPM does not report TPM2_PT_NV_INDEX_MAX")
	}
	key := newKey(t)
	idx := uint32(NVRAMSlotStart + 3)
	writeTestSlot(t, tpmDev, idx, key)
	before, err := ReadFromNVRAM(tpmDev, idx)
	if err != nil {
		t.Fatal(err)
	}

	err = WriteToNVRAM(tpmDev, idx, make([]byte, limit+1), key.Public(), key)
	var tooLarge *BlobTooLargeError
	if !errors.As(err, &tooLarge) || tooLarge.Size != limit+1 || tooLarge.Limit != limit {
		t.Fatalf("a blob over the limit: %v", err)
	}
	after, err := ReadFromNVRAM(tpmDev, idx)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the slot changed although nothing was to be written: %v", err)
	}

	full := bytes.Repeat([]byte{0x5a}, limit)
	if err := WriteToNVRAM(tpmDev, idx, full, key.Public(), key); err != nil {
		t.Fatalf("a blob of exactly the limit (%d bytes): %v", limit, err)
	}
	if got, err := ReadFromNVRAM(tpmDev, idx); err != nil || !bytes.Equal(got, full) {
		t.Fatalf("reading back the full-size blob: %v", err)
	}
}
