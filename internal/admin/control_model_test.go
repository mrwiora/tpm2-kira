package admin

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/tpm2-trust/tpm2-kira/internal/prompt"
)

// answering is a controller whose questions read the lines given.
func answering(c *controller, lines string) *bytes.Buffer {
	var out bytes.Buffer
	c.out = &out
	c.p = prompt.New(strings.NewReader(lines), &out)
	return &out
}

// Every step says the command it equals, and how dangerous it is: a slot's line, a
// keyslot that is there, a phone's removal destroy; a view reads.
func TestControlAnnotate(t *testing.T) {
	c := wired()
	c.facts.Keys = "local key files"
	c.facts.Status.Slots = []StatusSlot{{Slot: 0, PCRs: "0e,2e,7e,11u", Signed: true, Phones: 1, PhoneSalt: true}}
	for _, s := range []struct {
		step    controlStep
		command string
		danger  int
	}{
		{controlStep{Key: "slot:0"}, "tpm2-kira slot delete --nvram 0", dangerDestroy},
		{controlStep{Key: "seal"}, "tpm2-kira slot add --nvram 0 --pcrs 0e,2e,7e,11u", dangerChange},
		{controlStep{Key: "luks-salt"}, "tpm2-kira luks enrol DEVICE --password typed --salt typed", dangerChange},
		{controlStep{Key: "luks-salt", Done: "keyslot 1 of /dev/sda2"}, "tpm2-kira luks remove DEVICE --keyslot N", dangerDestroy},
		{controlStep{Key: "phone-remove:0"}, "tpm2-kira phone unenrol --nvram 0", dangerDestroy},
		{controlStep{Key: "salt-remove:0"}, "tpm2-kira phone salt unenrol --nvram 0", dangerDestroy},
		{controlStep{Key: "delete-all"}, "tpm2-kira slot delete --yes", dangerDestroy},
		{controlStep{Key: "view:slot info --nvram 0"}, "tpm2-kira slot info --nvram 0", dangerView},
		{controlStep{Key: "help:luks"}, "tpm2-kira help luks", dangerView},
	} {
		got := c.annotate(s.step)
		if got.Command != s.command || got.Danger != s.danger {
			t.Errorf("%s: %q %d, want %q %d", s.step.Key, got.Command, got.Danger, s.command, s.danger)
		}
		if got.Danger == dangerDestroy && got.Destroys == "" && s.step.Key != "phone-remove:0" && s.step.Key != "salt-remove:0" && s.step.Key != "delete-all" {
			t.Errorf("%s destroys without saying what", s.step.Key)
		}
	}
	c.o.TPMPath = "/dev/tpm1"
	if got := c.annotate(controlStep{Key: "slot:3"}); got.Command != "tpm2-kira slot delete --tpm /dev/tpm1 --nvram 3" {
		t.Errorf("another TPM: %q", got.Command)
	}
	// The removals and the views are offered where there is something to remove or see.
	if p := c.phoneRemoveSteps(); len(p) != 1 || p[0].Key != "phone-remove:0" {
		t.Errorf("phone removal: %+v", p)
	}
	if p := c.saltRemoveSteps(); len(p) != 1 || p[0].Key != "salt-remove:0" {
		t.Errorf("salt removal: %+v", p)
	}
	var views []string
	for _, s := range c.toolSteps() {
		views = append(views, s.Key)
	}
	if !strings.Contains(strings.Join(views, ","), "view:slot info --nvram 0") || !strings.Contains(strings.Join(views, ","), "view:status") {
		t.Errorf("views: %v", views)
	}
}

// A destroying question takes its word and nothing else: Enter alone, y, a typo keep
// what is there, and nothing is removed.
func TestConfirmDestroy(t *testing.T) {
	for in, want := range map[string]bool{"0\n": true, " 0 \n": true, "\n": false, "y\n": false, "yes\n": false, "00\n": false} {
		c := wired()
		out := answering(c, in)
		ok, err := c.confirmDestroy("Delete slot 0 whole?", "slot 0", "0")
		if err != nil || ok != want {
			t.Errorf("%q: %v %v", in, ok, err)
		}
		if !strings.Contains(out.String(), "Destroys:") || !strings.Contains(out.String(), "Type 0 to destroy it:") {
			t.Errorf("the question: %q", out.String())
		}
	}
	// The slot's own line: y, the old answer, keeps it - the deletion is never reached.
	c := wired()
	c.facts.Status.Slots = []StatusSlot{{Slot: 0, PCRs: "0e,2e,7e,11u", Signed: true}}
	answering(c, "y\n")
	if err := c.runRemoveSlot(0); !errors.Is(err, errKept) {
		t.Fatalf("y deleted, or asked otherwise: %v", err)
	}
	c = wired()
	c.facts.Keys = "local key files"
	c.facts.Status.Slots = []StatusSlot{{Slot: 0, PCRs: "0e,2e,7e,11u", Signed: true}}
	answering(c, "\n")
	if err := c.deleteAllStep().Run(c); !errors.Is(err, errKept) {
		t.Fatalf("delete everything without its word: %v", err)
	}
}

// A view is the command as it is: tpm2-kira itself, with the TPM when it is not the
// default one, and nothing changes.
func TestControlViewsRunTheCommand(t *testing.T) {
	var ran [][]string
	defer func(old func(string, []string) error) { runSelf = old }(runSelf)
	runSelf = func(tpm string, args []string) error {
		ran = append(ran, append([]string{tpm}, args...))
		return nil
	}
	c := wired()
	c.o.HelpTopics = []string{"luks", "slot"}
	answering(c, "")
	for _, s := range append(c.toolSteps()[:1], c.referenceSteps()...) {
		if err := s.Run(c); err != nil {
			t.Fatal(err)
		}
	}
	if len(ran) != 3 || strings.Join(ran[0][1:], " ") != "status" || strings.Join(ran[2][1:], " ") != "help slot" {
		t.Fatalf("ran %v", ran)
	}
}

// Every section has lines, and the overview's are the hub's.
func TestControlSections(t *testing.T) {
	c := wired()
	c.o.HelpTopics = []string{"luks"}
	for _, sec := range controlSections {
		if len(c.sectionSteps(sec.key)) == 0 {
			t.Errorf("section %s is empty", sec.key)
		}
	}
	for _, s := range c.sectionSteps("chain") {
		if s.Menu == "hub" {
			t.Error("the boot chain's section has the way on to the overview")
		}
	}
}
