package kiratest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tpm2-trust/tpm2-kira/core/mobile/kiracore"
)

// drive plays the app against the demo machine using only the two gomobile
// APIs, exactly as a Kotlin or Swift test would.
// lastSecureBoot is what the last verdict drive saw said of Secure Boot.
var lastSecureBoot string

// lastInitrd is the need_anchor_key event drive saw last.
var lastInitrd map[string]any

// lastLayout is the keyboard_layout event drive saw last.
var lastLayout map[string]any

func drive(t *testing.T, d *DemoMachine, s *kiracore.Session, key **ecdsa.PrivateKey, decision int) (record string, state string) {
	s.SetMaxFragment(182)
	queue := []*kiracore.Step{s.Start()}
	for {
		for len(queue) > 0 {
			st := queue[0]
			queue = queue[1:]
			for i := 0; i < st.FragmentCount(); i++ {
				d.Write(st.Fragment(i))
			}
			for i := 0; i < st.EventCount(); i++ {
				var e map[string]any
				json.Unmarshal([]byte(st.Event(i)), &e)
				switch e["type"] {
				case "sas":
					// The machine records its code in the console hook, which
					// can run just after the phone has already read the reveal.
					shown := d.LastSAS()
					for i := 0; shown == "" && i < 100; i++ {
						time.Sleep(10 * time.Millisecond)
						shown = d.LastSAS()
					}
					if e["sas"] != shown {
						t.Fatalf("SAS differs: %v vs %s", e["sas"], shown)
					}
					queue = append(queue, s.ConfirmSAS(true))
				case "need_anchor_key":
					lastInitrd = e
					*key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					der, _ := x509.MarshalPKIXPublicKey(&(*key).PublicKey)
					queue = append(queue, s.ProvideAnchorKey(der))
				case "need_signature":
					h := sha256.Sum256(s.PendingTBS())
					sig, _ := ecdsa.SignASN1(rand.Reader, *key, h[:])
					queue = append(queue, s.ProvideSignature(sig))
				case "verdict":
					vd := e["verdict"].(map[string]any)
					state = vd["state"].(string)
					if sb, ok := vd["secure_boot"].(map[string]any); ok {
						lastSecureBoot, _ = sb["state"].(string)
					}
					// Nothing is signed before the person answered, and the
					// phone shows the code the machine's screen shows.
					if e["needs_decision"] != true {
						t.Fatalf("a verdict went through without a decision: %s", st.Event(i))
					}
					if vd["boot_key"] == "proved" && (vd["code"] == "" || vd["code"] != d.LastBootCode()) {
						t.Fatalf("code on the phone %v, on the machine %q", vd["code"], d.LastBootCode())
					}
					if vd["boot_key"] != "proved" && vd["code"] != nil {
						t.Fatalf("a code without a proved boot key: %s", st.Event(i))
					}
					dec := decision
					if state == "match" && dec == 0 {
						dec = kiracore.DecisionContinue
					}
					queue = append(queue, s.Decide(dec, "Thinkpad-X1"))
				case "keyboard_layout":
					lastLayout = e
				case "error":
					t.Fatalf("error event: %s", st.Event(i))
				}
			}
		}
		if s.Finished() {
			return s.RecordJSON(), state
		}
		n := d.NextNotification(5000)
		if n == nil {
			t.Fatal("machine went quiet")
		}
		queue = append(queue, s.OnNotification(n))
	}
}

func TestDemoMachineAllStates(t *testing.T) {
	d, err := NewDemoMachine()
	if err != nil {
		t.Fatal(err)
	}
	cfg := `{}`
	var key *ecdsa.PrivateKey

	d.StartEnrolment(185)
	s, _ := kiracore.NewEnrolSession(cfg)
	record, _ := drive(t, d, s, &key, 0)
	if r := d.Outcome(5000); r != "enrolled" {
		t.Fatalf("enrolment: %s", r)
	}
	if !kiracore.MatchAdvertisement(d.ServiceData(), record) {
		t.Fatal("advertisement not matched")
	}

	for _, c := range []struct {
		setup    func()
		decision int
		state    string
		result   string
	}{
		{func() { d.NextBoot() }, 0, "match", "verdict=ok authentic=true"},
		{func() { d.NextBoot(); d.ChangePCR(4) }, kiracore.DecisionApproveRemember, "changed", "verdict=approved authentic=true"},
		{func() { d.NextBoot() }, 0, "match", "verdict=ok"},
		{func() { d.RollbackResetCount() }, kiracore.DecisionReject, "failed", "verdict=reject"},
	} {
		c.setup()
		d.StartAttestation(185)
		s, err := kiracore.NewAttestSession(cfg, record)
		if err != nil {
			t.Fatal(err)
		}
		var state string
		if rec, st := drive(t, d, s, &key, c.decision); rec != "" {
			record, state = rec, st
		}
		if state != c.state {
			t.Fatalf("state %q, want %q", state, c.state)
		}
		if r := d.Outcome(5000); !strings.Contains(r, c.result) {
			t.Fatalf("machine result %q, want %q", r, c.result)
		}
	}
}

// The demo machine shows the phone every state of Secure Boot.
func TestDemoMachineSecureBootStates(t *testing.T) {
	for state, want := range map[string]string{
		"on": "on", "off": "off", "setup_mode": "setup_mode", "no_log": "not_established", "lying": "not_established",
	} {
		d, err := NewDemoMachine()
		if err != nil {
			t.Fatal(err)
		}
		d.SetSecureBoot(state)
		var key *ecdsa.PrivateKey
		d.StartEnrolment(185)
		s, _ := kiracore.NewEnrolSession(`{}`)
		record, _ := drive(t, d, s, &key, 0)
		if r := d.Outcome(5000); r != "enrolled" {
			t.Fatalf("%s: enrolment: %s", state, r)
		}
		d.NextBoot()
		d.StartAttestation(185)
		if s, err = kiracore.NewAttestSession(`{}`, record); err != nil {
			t.Fatal(err)
		}
		lastSecureBoot = ""
		if _, st := drive(t, d, s, &key, 0); st != "match" {
			t.Fatalf("%s: state %q", state, st)
		}
		if lastSecureBoot != want {
			t.Fatalf("%s: secure_boot %q, want %q", state, lastSecureBoot, want)
		}
		d.Outcome(5000)
	}
}

// The enrol screen's word on the initrd: from the demo machine's boot, through the real
// core, never the machine's say.
func TestDemoMachineInitrdStates(t *testing.T) {
	for _, c := range []struct {
		boot, want, pcrs string
	}{{"uki", "covered", "[11 4]"}, {"grub", "covered", "[9]"}, {"no_log", "not_established", "<nil>"}} {
		d, err := NewDemoMachine()
		if err != nil {
			t.Fatal(err)
		}
		if err := d.SetInitrd(c.boot); err != nil {
			t.Fatal(err)
		}
		var key *ecdsa.PrivateKey
		d.StartEnrolment(185)
		s, _ := kiracore.NewEnrolSession(`{}`)
		lastInitrd = nil
		drive(t, d, s, &key, 0)
		if r := d.Outcome(5000); r != "enrolled" {
			t.Fatalf("%s: enrolment: %s", c.boot, r)
		}
		if lastInitrd["initrd_coverage"] != c.want || fmt.Sprint(lastInitrd["initrd_pcrs"]) != c.pcrs {
			t.Errorf("%s: %v", c.boot, lastInitrd)
		}
		if (c.want == "not_established") != (lastInitrd["initrd_detail"] != nil) {
			t.Errorf("%s: the reason: %v", c.boot, lastInitrd)
		}
	}
}

// A phone salt with a keyboard: handed over in one attestation, no layout there; at every boot
// after it the phone shows the layout the machine's TPM opened, another each time.
func TestDemoMachineKeyboard(t *testing.T) {
	d, err := NewDemoMachine()
	if err != nil {
		t.Fatal(err)
	}
	var key *ecdsa.PrivateKey
	d.StartEnrolment(185)
	s, _ := kiracore.NewEnrolSession(`{}`)
	record, _ := drive(t, d, s, &key, 0)
	if r := d.Outcome(5000); r != "enrolled" {
		t.Fatalf("enrolment: %s", r)
	}
	if err := d.EnableKeyboard(); err != nil {
		t.Fatal(err)
	}
	var seen []string
	for boot := 0; boot < 3; boot++ {
		d.NextBoot()
		lastLayout = nil
		d.StartAttestation(185)
		s, err := kiracore.NewAttestSession(`{}`, record)
		if err != nil {
			t.Fatal(err)
		}
		if rec, _ := drive(t, d, s, &key, 0); rec != "" {
			record = rec
		}
		if r := d.Outcome(5000); !strings.Contains(r, "verdict=ok") {
			t.Fatalf("boot %d: %s", boot, r)
		}
		if boot == 0 {
			if lastLayout != nil || d.KeyboardLayout() != "" {
				t.Fatalf("a layout in the hand-over: %v", lastLayout)
			}
			continue
		}
		if lastLayout == nil || lastLayout["layout"] != d.KeyboardLayout() || d.KeyboardLayout() == "" || lastLayout["keyboard_keys"] != "abcdefghijklmnopqrstuvwxyz0123456789" {
			t.Fatalf("boot %d: shown %v, the machine's %q", boot, lastLayout, d.KeyboardLayout())
		}
		seen = append(seen, d.KeyboardLayout())
	}
	if seen[0] == seen[1] {
		t.Fatal("the same layout twice")
	}
}
