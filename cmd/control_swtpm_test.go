//go:build integration

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// control's facts on a software TPM: what it reads from the TPM and the
// slots, the EK verdict a phone would reach, the risks, and the unlock
// step writing control.conf (here a file of the test's, through
// TPM2_KIRA_CONTROL_CONF). The host's own files (keys, Secure Boot, the
// initramfs) are facts too, but of the machine the suite runs on, so
// they are not asserted.
func TestControlFactsOnSWTPM(t *testing.T) {
	sock := startSWTPM(t)
	conf := filepath.Join(t.TempDir(), "control.conf")
	t.Setenv("TPM2_KIRA_CONTROL_CONF", conf)
	sealRealSlot(t, sock, ResolveNVRAMIndex(0))

	f := collectFacts(sock, false)
	if f.TPMErr != "" || !f.SHA256Bank || f.UseSHA1 {
		t.Fatalf("the TPM: err %q, sha256 %v, sha1 in use %v", f.TPMErr, f.SHA256Bank, f.UseSHA1)
	}
	if !f.LogSHA256 && f.PCRs != "0,2,7" {
		t.Errorf("without an event log the selection is %q; want 0,2,7 (%s)", f.PCRs, f.PCRsWhy)
	}
	// swtpm's EK carries no vendor certificate: a phone cannot tell it
	// from a software TPM, and control says so.
	if f.EKBy != "" || !strings.Contains(f.EKNote, "vendor certificate") {
		t.Errorf("EK verdict: by %q, note %q", f.EKBy, f.EKNote)
	}
	if len(f.Status.Slots) != 1 || f.Status.Slots[0].PCRs != "23" || f.Status.Slots[0].Fallback {
		t.Fatalf("slots: %+v", f.Status.Slots)
	}
	if f.Status.Config != conf || f.PINStored || f.PINLoose || f.AttestConf != "" {
		t.Errorf("a missing control.conf: config %q, pin %v/%v, attest %q", f.Status.Config, f.PINStored, f.PINLoose, f.AttestConf)
	}
	// The judged status: swtpm's EK and the test slot's selection are not
	// good, and the lines say the risk.
	judged := (&controller{facts: f}).factsText()
	for _, want := range []string{"none vouches for the endorsement key", "slot 0 leaves the kernel, the initrd or the command line unmeasured"} {
		if !strings.Contains(judged, want) {
			t.Errorf("the status lacks %q:\n%s", want, judged)
		}
	}

	// The steps, with the host's part of the facts (a key, the boot
	// integration, a radio) stubbed: slot 0 exists, the fallback does
	// not, so the seal step offers exactly that; the unlock step waits
	// for a keyslot.
	f.Keys, f.Adapter = "local key files", "hci0"
	f.Initramfs, f.HookState, f.Rebuild, f.NewImage = "mkinitcpio", "", "", ""
	f.Capped = true
	var out strings.Builder
	c := &controller{facts: f, out: &out}
	steps := c.steps()
	if steps[2].Key != "route" || !strings.Contains(steps[2].Blocked, "no LUKS device") {
		t.Errorf("the route step: %+v", steps[2])
	}
	if steps[3].Key != "seal" || !strings.Contains(steps[3].Explain, "the fallback, is missing") {
		t.Errorf("the seal step: %+v", steps[3])
	}
	if steps[4].Key != "slot:0" || steps[5].Key != "attest" || steps[5].Blocked != "" {
		t.Errorf("the tree: %+v %+v", steps[4], steps[5])
	}

	// The Bluetooth policy writes the file, the one thing control writes.
	if err := setAttestBluetooth(conf, "always"); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadControlConfig(conf); err != nil || cfg.Attest.Bluetooth != "always" || cfg.PIN != "" {
		t.Errorf("control.conf loads as %+v, %v", cfg, err)
	}
	f = collectFacts(sock, false)
	if !f.BTAlways {
		t.Errorf("the facts after setAttestBluetooth: always not seen")
	}

	// The PIN stored next to it, as the Signing key step does it; the
	// facts know, and the file is root's alone.
	if err := setControlPIN(conf, "123456"); err != nil {
		t.Fatal(err)
	}
	f = collectFacts(sock, false)
	if !f.PINStored || f.PINLoose {
		t.Errorf("the PIN stored: %v loose %v", f.PINStored, f.PINLoose)
	}
	if st, _ := os.Stat(conf); st.Mode().Perm() != 0o600 {
		t.Errorf("control.conf with the PIN is %v", st.Mode().Perm())
	}
	if cfg, _ := LoadControlConfig(conf); cfg.Attest.Bluetooth != "always" || cfg.PIN != "123456" {
		t.Errorf("the policy kept next to the PIN: %+v", cfg)
	}
	// Readable by others: the PIN counts as disclosed, and that is a risk.
	os.Chmod(conf, 0o644)
	f = collectFacts(sock, false)
	if f.PINStored || !f.PINLoose {
		t.Errorf("a loose file: stored %v loose %v", f.PINStored, f.PINLoose)
	}
	if judged := (&controller{facts: f}).factsText(); !strings.Contains(judged, conf+" holds the PIN, but other users can read it") {
		t.Errorf("the loose file is not marked on the status:\n%s", judged)
	}

	// A file that does not load blocks the attestation step and names itself.
	if err := os.WriteFile(conf, []byte("TPM2_KIRA_ATTEST=lazy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f = collectFacts(sock, false)
	if !strings.Contains(f.AttestConf, "no attestation mode") || f.Status.ConfigError == "" {
		t.Errorf("a broken file: attest %q, config %q", f.AttestConf, f.Status.ConfigError)
	}
	f.Keys, f.Adapter = "local key files", "hci0"
	f.Initramfs, f.HookState, f.Rebuild, f.NewImage = "mkinitcpio", "", "", ""
	f.Capped = true
	c = &controller{facts: f, out: &out}
	if s := c.steps()[5]; s.Key != "attest" || !strings.HasPrefix(s.Blocked, conf+": ") {
		t.Errorf("the attest step with a broken file: %+v", s)
	}
}
