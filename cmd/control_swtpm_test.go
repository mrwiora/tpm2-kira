//go:build integration

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/imageplan"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/signing"
)

// control's facts on a software TPM: what it reads from the TPM and the
// slots, the EK verdict a phone would reach, the risks, the options of
// step 2, and control.conf written (here a file of the test's, through
// TPM2_KIRA_CONTROL_CONF). The host's own files (keys, Secure Boot, the
// initramfs) are facts too, but of the machine the suite runs on, so
// they are not asserted.
func TestControlFactsOnSWTPM(t *testing.T) {
	sock := startSWTPM(t)
	conf := filepath.Join(t.TempDir(), "control.conf")
	t.Setenv("TPM2_KIRA_CONTROL_CONF", conf)
	sealRealSlot(t, sock, nvslot.ResolveNVRAMIndex(0))

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
	// The boot plan read from the TPM: the sealed slot puts the codes in,
	// and the TPM with them; no phone, no gate.
	if !f.planHas(imageplan.PartCodes) || !f.Plan.TPM || f.planHas(imageplan.PartPhone) || f.Plan.Part(imageplan.PartPhone).Why != "no phone is enrolled" {
		t.Errorf("the plan: %+v", f.Plan.Parts)
	}
	if p := ReadBootPlan(PlanOptions{TPMPath: filepath.Join(t.TempDir(), "none"), ConfigPath: conf}); p.Has(imageplan.PartCodes) || p.TPM {
		t.Errorf("the plan without a TPM: %+v", p.Parts)
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

	// The options, with the host's part of the facts (a key, the boot
	// integration, a radio) stubbed: slot 0 exists, the fallback does
	// not, so the seal step offers exactly that; the phone can be enrolled.
	f.Keys, f.Adapter = "local key files", "hci0"
	f.Initramfs, f.HookState, f.Rebuild, f.NewImage = "mkinitcpio", "", "", ""
	f.Capped = true
	var out strings.Builder
	c := &controller{facts: f, out: &out}
	if route := c.routeStep(); !strings.Contains(route.Blocked, "no LUKS device") {
		t.Errorf("the route step: %+v", route)
	}
	keys := c.menuSteps("keys")
	if keys[1].Key != "seal" || !strings.Contains(keys[1].Explain, "the fallback, is missing") {
		t.Errorf("the seal step: %+v", keys[1])
	}
	if keys[2].Key != "slot:0" {
		t.Errorf("the slot line: %+v", keys[2])
	}
	if attest := c.menuSteps("phone")[0]; attest.Key != "attest" || attest.Blocked != "" {
		t.Errorf("the attest step: %+v", attest)
	}

	// The Bluetooth policy writes the file, the one thing control writes.
	if err := setAttestBluetooth(conf, "always"); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadControlConfig(conf); err != nil || cfg.Attest.Bluetooth != "always" {
		t.Errorf("control.conf loads as %+v, %v", cfg, err)
	}
	f = collectFacts(sock, false)
	if !f.BTAlways {
		t.Errorf("the facts after setAttestBluetooth: always not seen")
	}

	// The PIN stored next to it, as the Signing key step does it; the
	// facts know, and the file is root's alone.
	if err := signing.StorePIN(signing.PINPath(), "123456"); err != nil {
		t.Fatal(err)
	}
	f = collectFacts(sock, false)
	if !f.PINStored || f.PINLoose {
		t.Errorf("the PIN stored: %v loose %v", f.PINStored, f.PINLoose)
	}
	if st, _ := os.Stat(signing.PINPath()); st.Mode().Perm() != 0o600 {
		t.Errorf("the PIN file is %v", st.Mode().Perm())
	}
	if cfg, _ := LoadControlConfig(conf); cfg.Attest.Bluetooth != "always" {
		t.Errorf("the policy kept next to the PIN: %+v", cfg)
	}
	if pin, loose := signing.StoredPIN(signing.PINPath()); pin != "123456" || loose {
		t.Errorf("the PIN read back: %q loose %v", pin, loose)
	}
	// A line this version refuses: the settings are invalid (red Config
	// line), the PIN in its own file is untouched by it.
	data, _ := os.ReadFile(conf)
	os.WriteFile(conf, append([]byte("TPM2_KIRA_NOSUCH=0\n"), data...), 0o600)
	f = collectFacts(sock, false)
	if !f.PINStored || f.AttestConf == "" {
		t.Errorf("a refused line next to the PIN: stored %v, config %q", f.PINStored, f.AttestConf)
	}
	os.WriteFile(conf, data, 0o600)
	// Readable by others: the PIN counts as disclosed, and that is a risk.
	os.Chmod(signing.PINPath(), 0o644)
	f = collectFacts(sock, false)
	if f.PINStored || !f.PINLoose {
		t.Errorf("a loose file: stored %v loose %v", f.PINStored, f.PINLoose)
	}
	if judged := (&controller{facts: f}).factsText(); !strings.Contains(judged, signing.PINPath()+" holds the PIN, but other users can read it") {
		t.Errorf("the loose file is not marked on the status:\n%s", judged)
	}

	// A file that does not load blocks the attestation step and names itself.
	if err := os.WriteFile(conf, []byte("TPM2_KIRA_NOSUCH=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f = collectFacts(sock, false)
	if !strings.Contains(f.AttestConf, "unknown key") || f.Status.ConfigError == "" {
		t.Errorf("a broken file: attest %q, config %q", f.AttestConf, f.Status.ConfigError)
	}
	f.Keys, f.Adapter = "local key files", "hci0"
	f.Initramfs, f.HookState, f.Rebuild, f.NewImage = "mkinitcpio", "", "", ""
	f.Capped = true
	c = &controller{facts: f, out: &out}
	if s := c.menuSteps("phone")[0]; s.Key != "attest" || !strings.HasPrefix(s.Blocked, conf+": ") {
		t.Errorf("the attest step with a broken file: %+v", s)
	}
}
