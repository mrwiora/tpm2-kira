package admin

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tpm2-trust/tpm2-kira/internal/piv"
	"github.com/tpm2-trust/tpm2-kira/internal/piv/pivtest"
	"github.com/tpm2-trust/tpm2-kira/internal/signing"
)

const skippedApprovalHelper = "ADMIN_TEST_SKIPPED_APPROVAL"

// runSkippedApproval is the approval as a hook meets it, this test binary in place of
// tpm2-kira: a YubiKey (the emulator: no pcscd here) with no PIN at hand, the signer's own
// terminal prompt and the command's own handling of the variable. Under setsid, which is
// what the hook runs it with, there is no terminal to ask on.
func runSkippedApproval() int {
	signing.IgnorePINEnv(os.Stderr)
	card := pivtest.New(1)
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	signing.DialTokens = func(time.Duration) ([]*signing.TokenConn, func(), error) {
		return []*signing.TokenConn{{Reader: "emulator", Transport: card, Close: func(bool) error { return nil }}}, func() {}, nil
	}
	dir, err := os.MkdirTemp("", "tpm2-kira-hook-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	tokens, err := signing.ProbeYubiKeys(time.Second)
	if err != nil || len(tokens) != 1 || len(tokens[0].Slots) == 0 {
		fmt.Fprintf(os.Stderr, "the emulator: %v %v\n", err, tokens)
		return 1
	}
	stub, err := signing.MarshalYubiKeyStub(1, tokens[0].Slots[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	path := filepath.Join(dir, "seal.key")
	if err := signing.WriteSigningKeyFile(path, stub); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	signer, err := signing.LoadSigningPrivateKey(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	err = signing.PrepareSigningKey(signer)
	var cause *signing.TokenUnavailableError
	if !errors.As(err, &cause) {
		fmt.Printf("tpm2-kira: FAILED: %v\n", err)
		return 0
	}
	PrintResealSkipped(os.Stdout, []*ResealSkippedError{{NVIndex: 0x01803010, KeyFile: path, Cause: cause, SealedPCRs: testBlob().GetPCRSpecs()}})
	signing.CloseTokenSessions()
	return 0
}

// TPM2_KIRA_PIN=... mkinitcpio -P: each hook captures the approval and shows what it
// chooses. What it shows has the reason, the variable named and its value nowhere, in
// Arch's SKIPPED block as well, which leaves the warning line out. Without the variable,
// nothing of it.
func TestHooksShowTheIgnoredPINVariable(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("no setsid: ", err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	keys := filepath.Join(dir, "keys")
	for _, d := range []string{binDir, keys} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	wrapper := fmt.Sprintf(`#!/bin/sh
case "$1 $2" in
"slot list") echo Slots: 1 ;;
"slot approve") exec %q ;;
esac
`, self)
	if err := os.WriteFile(filepath.Join(binDir, "tpm2-kira"), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, hook := range []string{"initramfs/mkinitcpio/post/sd-tpm2-kira", "initramfs/initramfs-tools/post-update.d/tpm2-kira", "initramfs/initramfs-tools/kernel/zzz-tpm2-kira"} {
		t.Run(filepath.Base(filepath.Dir(hook))+"/"+filepath.Base(hook), func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(root, hook))
			if err != nil {
				t.Fatal(err)
			}
			copyPath := filepath.Join(dir, "hook")
			os.Remove(copyPath)
			if err := os.WriteFile(copyPath, []byte(strings.ReplaceAll(string(src), "/etc/tpm2-kira/keys", keys)), 0o755); err != nil {
				t.Fatal(err)
			}
			run := func(extra ...string) string {
				cmd := exec.Command(copyPath, "6.1", "/boot/image")
				var env []string
				for _, e := range os.Environ() {
					if !strings.HasPrefix(e, "TPM2_KIRA_PIN=") {
						env = append(env, e)
					}
				}
				cmd.Env = append(append(env, "PATH="+binDir+":"+os.Getenv("PATH"), skippedApprovalHelper+"=1",
					"TPM2_KIRA_CONTROL_CONF="+filepath.Join(dir, "absent-control.conf")), extra...)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%v:\n%s", err, out)
				}
				return string(out)
			}
			got := run("TPM2_KIRA_PIN=secret-1234")
			if !strings.Contains(got, "SKIPPED:") || !strings.Contains(got, "TPM2_KIRA_PIN is set and ignored: it gives no PIN") {
				t.Errorf("the reason is not shown:\n%s", got)
			}
			if strings.Contains(got, "secret-1234") {
				t.Errorf("the value is shown:\n%s", got)
			}
			got = run()
			if !strings.Contains(got, "SKIPPED:") || !strings.Contains(got, "no PIN:") || strings.Contains(got, "TPM2_KIRA_PIN") {
				t.Errorf("without the variable:\n%s", got)
			}
		})
	}
}
