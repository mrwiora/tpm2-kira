package admin

import (
	"strings"
	"testing"
)

// Who is a person: a terminal without the hooks' flag, or the explicit flag; a run
// without a terminal or a flag is not, and the hooks' flag wins over a terminal.
func TestChannelApprovalFor(t *testing.T) {
	for _, tc := range []struct {
		unattended, seal, terminal bool
		want                       ChannelApproval
		wantErr                    bool
	}{
		{false, false, false, ChannelLeave, false},
		{false, false, true, ChannelAsk, false},
		{true, false, false, ChannelLeave, false},
		{true, false, true, ChannelLeave, false},
		{false, true, false, ChannelSeal, false},
		{false, true, true, ChannelSeal, false},
		{true, true, false, ChannelLeave, true},
		{true, true, true, ChannelLeave, true},
	} {
		got, err := ChannelApprovalFor(tc.unattended, tc.seal, tc.terminal)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("unattended %v, seal %v, terminal %v: %v, %v", tc.unattended, tc.seal, tc.terminal, got, err)
		}
	}
}

// Status: the channel's note is a warning, with the command, without colour in a pipe.
func TestStatusSaysTheChannel(t *testing.T) {
	r := StatusReport{TPM: "tpm", Version: "v", Slots: []StatusSlot{{Slot: 4, Signed: true, ChannelMoved: true}}}
	r.Notes = statusNotes(r)
	out := captureStdout(t, func() { printStatus(r) })
	if !strings.Contains(out, "WARNING: slot 4's phone channel is sealed to another PCR 7") || !strings.Contains(out, "sudo tpm2-kira slot approve --nvram 4") {
		t.Errorf("the channel's note:\n%s", out)
	}
	if strings.Contains(out, "\033[") {
		t.Errorf("colour into a pipe:\n%q", out)
	}
}

// Control: a moved channel is a red line of Keys & slots that seals it when picked.
func TestControlShowsTheMovedChannel(t *testing.T) {
	c := &controller{out: &strings.Builder{}}
	c.facts.Status.Slots = []StatusSlot{{Slot: 4, Signed: true, ChannelMoved: true, PCRs: "7"}}
	c.facts.Status.Notes = statusNotes(c.facts.Status)
	var step *controlStep
	for _, s := range c.menuSteps("keys") {
		if s.Key == "channel:4" {
			step = &s
		}
	}
	if step == nil {
		t.Fatalf("no line for the channel: %+v", c.menuSteps("keys"))
	}
	hub := false
	for _, s := range c.hubSteps() {
		hub = hub || strings.Contains(s.Dirty, "phone channel")
	}
	if !hub {
		t.Errorf("the overview does not show it: %+v", c.hubSteps())
	}
	if step.Dirty == "" || !strings.Contains(step.Dirty, "seal it again") || step.Run == nil {
		t.Errorf("its line: %+v", step)
	}
}
