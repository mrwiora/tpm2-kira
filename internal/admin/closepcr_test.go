package admin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/nvslot"
)

// logWithClosePCREvent is the Arch test log with one more event, in PCR 15, in
// every bank of its header.
func logWithClosePCREvent(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/arch-uki-eventlog.bin")
	if err != nil {
		t.Fatal(err)
	}
	// The header is a TCG_PCR_EVENT of SHA-1 (32 bytes up to its size field),
	// its data the Spec ID event: 24 bytes, the count, then id/size pairs.
	spec := raw[32:]
	count := binary.LittleEndian.Uint32(spec[24:])
	event := binary.LittleEndian.AppendUint32(nil, 15)
	event = binary.LittleEndian.AppendUint32(event, 0x0d) // EV_IPL
	event = binary.LittleEndian.AppendUint32(event, count)
	for i := range count {
		alg := binary.LittleEndian.Uint16(spec[28+4*i:])
		size := binary.LittleEndian.Uint16(spec[30+4*i:])
		event = binary.LittleEndian.AppendUint16(event, alg)
		event = append(event, make([]byte, size)...)
		event[len(event)-1] = 1
	}
	event = binary.LittleEndian.AppendUint32(event, 5)
	event = append(event, "boot\x00"...)
	path := filepath.Join(t.TempDir(), "eventlog.bin")
	if err := os.WriteFile(path, append(raw, event...), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// An event in PCR 15 in the firmware's log: the approval refuses and status is
// red. Without one, or without a log, nothing is said.
func TestClosePCRChecked(t *testing.T) {
	defer func(p string) { closeEventlogPath = p }(closeEventlogPath)

	closeEventlogPath = "testdata/arch-uki-eventlog.bin"
	if n, err := firmwareClosePCREvents(closeEventlogPath); err != nil || n != 0 {
		t.Fatalf("a clean log: %d %v", n, err)
	}
	if err := checkClosePCRZero(); err != nil {
		t.Fatal(err)
	}
	closeEventlogPath = "/nonexistent"
	if err := checkClosePCRZero(); err != nil {
		t.Fatalf("no log: %v", err)
	}

	closeEventlogPath = logWithClosePCREvent(t)
	if n, err := firmwareClosePCREvents(closeEventlogPath); err != nil || n != 1 {
		t.Fatalf("a log with a PCR 15 event: %d %v", n, err)
	}
	err := checkClosePCRZero()
	if err == nil || !strings.Contains(err.Error(), "nothing of tpm2-kira's opens") {
		t.Fatalf("the check: %v", err)
	}
	if err := approveSSHCASlots(nil, nil, nil); err == nil || !strings.Contains(err.Error(), "cannot approve") {
		t.Fatalf("the CA's approval: %v", err)
	}
	if err := approveAndWrite(nil, nvslot.ResolveNVRAMIndex(0), nil, nil, "", false, nil, false); err == nil || !strings.Contains(err.Error(), "cannot approve") {
		t.Fatalf("the slot's approval: %v", err)
	}
	found := false
	for _, n := range statusNotes(StatusReport{ClosePCREvents: 1}) {
		found = found || n == closePCRWhy
	}
	if !found {
		t.Fatal("status does not judge it")
	}
}
