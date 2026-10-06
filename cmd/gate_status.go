package cmd

// What the gate tells the code screen.
//
// The gate and the code screen (tpm2-kira run) are two processes, on purpose:
// the gate parses radio input and is confined by its unit, the screen owns
// the console. During the hold both are up, and the screen has to learn one
// thing from the gate: that the phone has given its verdict, which releases
// the boot like Enter does. The gate writes its state as one line into its
// runtime directory; the screen reads it.
//
// The line comes from the process that listens to the radio, so the screen
// treats it as input: a fixed set of states, a slot number in range, and a
// phone name reduced to printable characters. The worst a subverted gate can
// do with it is what its own console lines could already do: claim a verdict.
// The phone's screen is the verdict; the console never was (SECURITY.md).

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// GateState is where the gate is in serving a slot.
type GateState string

const (
	GateWaiting     GateState = "waiting"     // advertising, no phone connected
	GateSession     GateState = "session"     // a phone is connected, no verdict yet
	GateAttested    GateState = "attested"    // the phone accepted or approved this boot
	GateRejected    GateState = "rejected"    // the phone rejected this boot
	GateRefused     GateState = "refused"     // the receipt or the enrolment record was not accepted
	GateUnavailable GateState = "unavailable" // no adapter, or the gate gave up
)

// GateStatus is the gate's state for the slot it serves.
type GateStatus struct {
	Slot  int // the TOTP slot number the enrolment belongs to
	State GateState
	Phone string // the phone's name, once it has answered
}

// DefaultGateStatusPath is where the gate's unit puts the status
// (RuntimeDirectory=tpm2-kira-attest).
const DefaultGateStatusPath = "/run/tpm2-kira-attest/status"

const gateStatusMagic = "tpm2-kira-gate-1"

// Verdict reports whether the phone has spoken, for or against.
func (s GateStatus) Verdict() bool {
	return s.State == GateAttested || s.State == GateRejected || s.State == GateRefused
}

// Asking reports whether a phone can verify the slot right now.
func (s GateStatus) Asking() bool { return s.State == GateWaiting || s.State == GateSession }

// writeGateStatus replaces the status file. Best effort: without a runtime
// directory (the gate run by hand) there is nobody to tell.
func writeGateStatus(path string, s GateStatus) {
	if path == "" {
		return
	}
	line := fmt.Sprintf("%s %d %s %s\n", gateStatusMagic, s.Slot, s.State, strconv.Quote(printableName(s.Phone)))
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(line), 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
	}
}

// ReadGateStatus returns the gate's state, or false when no gate has
// reported or the file is not what a gate writes.
func ReadGateStatus(path string) (GateStatus, bool) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 512 {
		return GateStatus{}, false
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return GateStatus{}, false
	}
	f := strings.SplitN(strings.TrimSuffix(string(data), "\n"), " ", 4)
	if len(f) != 4 || f[0] != gateStatusMagic {
		return GateStatus{}, false
	}
	slot, err := strconv.Atoi(f[1])
	if err != nil || slot < 0 || slot > int(AttestNVRAMEnd-AttestNVRAMStart) {
		return GateStatus{}, false
	}
	state := GateState(f[2])
	switch state {
	case GateWaiting, GateSession, GateAttested, GateRejected, GateRefused, GateUnavailable:
	default:
		return GateStatus{}, false
	}
	name, err := strconv.Unquote(f[3])
	if err != nil {
		return GateStatus{}, false
	}
	return GateStatus{Slot: slot, State: state, Phone: printableName(name)}, true
}

// printableName keeps what can be shown on a console without moving the
// cursor or changing colours: the name is chosen on the phone.
func printableName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 64 {
			break
		}
		if r >= 0x20 && r != 0x7f && !(r >= 0x80 && r < 0xa0) && strconv.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
