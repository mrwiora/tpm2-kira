package cmd

import (
	"strings"
	"testing"
)

// The notes say what does not fit together, and nothing when all does.
func TestStatusNotes(t *testing.T) {
	slot := func(n int, pcrs string, remote bool) StatusSlot {
		return StatusSlot{Slot: n, PCRs: pcrs, Fallback: pcrs == "0e,7e", GenState: "3 (matches)", Signed: true, RemoteSalt: remote}
	}
	zero, two := 0, 2
	dev := func(tokens ...*LuksToken) LuksDeviceStatus {
		d := LuksDeviceStatus{Device: "/dev/x"}
		for i, tok := range tokens {
			d.Keyslots = append(d.Keyslots, KeyslotStatus{Keyslot: i, Token: tok})
		}
		return d
	}
	ok := StatusReport{Slots: []StatusSlot{slot(0, "0e,2e,7e,11u", true), slot(1, "0e,7e", false)},
		Devices: []LuksDeviceStatus{dev(nil, &LuksToken{Mode: LuksModePasswordRemoteSalt, Slot: &zero})}}
	if n := statusNotes(ok); len(n) != 0 {
		t.Errorf("a consistent machine has notes: %v", n)
	}

	cases := []struct {
		name string
		r    StatusReport
		want string
	}{
		{"nothing sealed", StatusReport{}, "no slot is sealed"},
		{"no fallback", StatusReport{Slots: []StatusSlot{slot(0, "0e,2e,7e", false)}}, "no fallback slot"},
		{"reseal due", StatusReport{Slots: []StatusSlot{{Slot: 0, PCRs: "0e,7e", Fallback: true, GenState: "4 — does NOT match the blob", Signed: true}}}, "resealed"},
		{"not signed", StatusReport{Slots: []StatusSlot{{Slot: 0, PCRs: "0e,7e", Fallback: true, GenState: "3 (matches)", SignReason: "no key"}}}, "not signed by this machine"},
		{"salt without a keyslot", StatusReport{Slots: []StatusSlot{slot(0, "0e,2e,7e,11u", true), slot(1, "0e,7e", false)},
			Devices: []LuksDeviceStatus{dev(nil)}}, "no LUKS keyslot is marked password+remotesalt"},
		{"keyslot bound to a gone slot", StatusReport{Slots: []StatusSlot{slot(0, "0e,7e", false)},
			Devices: []LuksDeviceStatus{dev(nil, &LuksToken{Mode: LuksModePasswordRemoteSalt, Slot: &two})}}, "bound to slot 2, which is gone"},
		{"keyslot's slot lost its salt", StatusReport{Slots: []StatusSlot{slot(0, "0e,7e", false)},
			Devices: []LuksDeviceStatus{dev(nil, &LuksToken{Mode: LuksModePasswordRemoteSalt, Slot: &zero})}}, "keyslot 1 needs the remote salt of slot 0"},
	}
	for _, c := range cases {
		notes := strings.Join(statusNotes(c.r), "\n")
		if !strings.Contains(notes, c.want) {
			t.Errorf("%s: want %q in:\n%s", c.name, c.want, notes)
		}
	}

	// A header that could not be read (no root): no guess about keyslots.
	unread := StatusReport{Slots: []StatusSlot{slot(1, "0e,7e", false)},
		Devices: []LuksDeviceStatus{{Device: "/dev/x", Error: "permission denied"}}}
	if n := strings.Join(statusNotes(unread), "\n"); strings.Contains(n, "no LUKS keyslot") {
		t.Errorf("a guess about keyslots whose header was not read: %s", n)
	}
}
