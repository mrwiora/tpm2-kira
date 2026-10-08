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
	if f.Status.UnlockMode != UnlockSkip || f.Status.Config != conf || f.PINStored || f.PINLoose || f.AttestConf != "" {
		t.Errorf("a missing control.conf: mode %q from %q, pin %v/%v, attest %q", f.Status.UnlockMode, f.Status.Config, f.PINStored, f.PINLoose, f.AttestConf)
	}
	for _, want := range []string{"no known vendor vouches", "slot 0 is sealed to PCRs 23"} {
		found := false
		for _, r := range f.Risks {
			found = found || strings.Contains(r, want)
		}
		if !found {
			t.Errorf("risk %q missing: %q", want, f.Risks)
		}
	}

	// The steps, with the host's part of the facts (a key, a radio)
	// stubbed: the TOTP seal is done, the unlock step waits for a keyslot.
	f.Keys, f.Adapter = "local key files", "hci0"
	var out strings.Builder
	c := &controller{facts: f, out: &out}
	steps := c.steps()
	if steps[1].Key != "seal" || steps[1].Done == "" {
		t.Errorf("the seal step: %+v", steps[1])
	}
	if steps[5].Key != "unlock" || steps[5].Blocked != "needs a keyslot of tpm2-kira's" {
		t.Errorf("the unlock step: %+v", steps[5])
	}

	// Setting the mode writes the file, the one thing control writes.
	if err := c.setMode(UnlockPasswordSalt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), conf+": TPM2_KIRA_UNLOCK=password+salt") || !c.ran {
		t.Errorf("setMode said: %q", out.String())
	}
	data, err := os.ReadFile(conf)
	if err != nil || !strings.Contains(string(data), "TPM2_KIRA_UNLOCK=password+salt\n") {
		t.Fatalf("control.conf after setMode: %q %v", data, err)
	}
	if cfg, err := LoadControlConfig(conf); err != nil || cfg.Unlock.Mode != UnlockPasswordSalt || cfg.PIN != "" {
		t.Errorf("control.conf loads as %+v, %v", cfg, err)
	}
	f = collectFacts(sock, false)
	if f.Status.UnlockMode != UnlockPasswordSalt {
		t.Errorf("the facts after setMode: mode %q", f.Status.UnlockMode)
	}
	// The same mode again writes nothing.
	out.Reset()
	c = &controller{facts: f, out: &out}
	if err := c.setMode(UnlockPasswordSalt); err != nil || out.Len() != 0 || c.ran {
		t.Errorf("setting the mode that is set: %v %q", err, out.String())
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
	if cfg, _ := LoadControlConfig(conf); cfg.Unlock.Mode != UnlockPasswordSalt || cfg.PIN != "123456" {
		t.Errorf("the mode kept next to the PIN: %+v", cfg)
	}
	// Readable by others: the PIN counts as disclosed, and that is a risk.
	os.Chmod(conf, 0o644)
	f = collectFacts(sock, false)
	if f.PINStored || !f.PINLoose {
		t.Errorf("a loose file: stored %v loose %v", f.PINStored, f.PINLoose)
	}
	if !strings.Contains(strings.Join(f.Risks, "\n"), conf+" holds the YubiKey PIN, but other users can read it") {
		t.Errorf("the loose file is not a risk: %q", f.Risks)
	}

	// A file that does not load blocks the attestation step and names itself.
	if err := os.WriteFile(conf, []byte("TPM2_KIRA_ATTEST=lazy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f = collectFacts(sock, false)
	if !strings.Contains(f.AttestConf, "no attestation mode") || f.Status.UnlockError == "" {
		t.Errorf("a broken file: attest %q, unlock %q", f.AttestConf, f.Status.UnlockError)
	}
	f.Keys, f.Adapter = "local key files", "hci0"
	c = &controller{facts: f, out: &out}
	if s := c.steps()[2]; s.Key != "attest" || !strings.HasPrefix(s.Blocked, conf+": ") {
		t.Errorf("the attest step with a broken file: %+v", s)
	}
}
