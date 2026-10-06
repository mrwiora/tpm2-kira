package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGateStatusRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	if _, ok := ReadGateStatus(path); ok {
		t.Fatal("a status without a file")
	}
	for _, want := range []GateStatus{
		{Slot: 0, State: GateWaiting},
		{Slot: 3, State: GateSession},
		{Slot: 15, State: GateAttested, Phone: "Pixel 4a"},
		{Slot: 1, State: GateRejected, Phone: `my "work" phone`},
		{Slot: 0, State: GateRefused},
		{Slot: 0, State: GateUnavailable},
	} {
		writeGateStatus(path, want)
		got, ok := ReadGateStatus(path)
		if !ok || got != want {
			t.Fatalf("wrote %+v, read %+v (%v)", want, got, ok)
		}
	}
	if _, err := os.Stat(path + ".new"); err == nil {
		t.Fatal("temporary file left behind")
	}
	writeGateStatus("", GateStatus{State: GateWaiting}) // run by hand: nowhere to write, no panic
}

// The file comes from the process that listens to the radio: only what a
// gate writes is accepted, and a phone's name cannot drive the console.
func TestGateStatusIsTreatedAsInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status")
	for _, bad := range []string{
		"",
		"attested\n",
		"tpm2-kira-gate-1 0 attested\n",          // no name field
		"tpm2-kira-gate-1 0 trusted \"x\"\n",     // not a state
		"tpm2-kira-gate-1 -1 attested \"x\"\n",   // slot out of range
		"tpm2-kira-gate-1 16 attested \"x\"\n",   // slot out of range
		"tpm2-kira-gate-1 zero attested \"x\"\n", // not a number
		"tpm2-kira-gate-1 0 attested x\n",        // name not quoted
		"tpm2-kira-gate-2 0 attested \"x\"\n",    // another format
		"tpm2-kira-gate-1 0 attested \"" + strings.Repeat("a", 600) + "\"\n", // oversized
	} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if st, ok := ReadGateStatus(path); ok {
			t.Fatalf("accepted %q as %+v", bad, st)
		}
	}
	// A symlink is not followed.
	real := filepath.Join(dir, "real")
	writeGateStatus(real, GateStatus{State: GateAttested})
	os.Remove(path)
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadGateStatus(path); ok {
		t.Fatal("followed a symlink")
	}
	os.Remove(path)

	// Escape sequences and control characters in a phone's name do not
	// reach the console, whoever wrote the file.
	raw := "tpm2-kira-gate-1 0 attested \"ok\\x1b[2J\\x1b[31m\\r\\nALL GOOD\\u009b\"\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	st, ok := ReadGateStatus(path)
	if !ok {
		t.Fatal("a quoted name with escapes was not parsed")
	}
	if strings.ContainsAny(st.Phone, "\x1b\r\n\u009b") || st.Phone != "ok[2J[31mALL GOOD" {
		t.Fatalf("name not reduced to printable characters: %q", st.Phone)
	}
	writeGateStatus(path, GateStatus{State: GateAttested, Phone: strings.Repeat("é", 200)})
	if st, _ := ReadGateStatus(path); len(st.Phone) > 66 {
		t.Fatalf("name of %d bytes kept", len(st.Phone))
	}
}
