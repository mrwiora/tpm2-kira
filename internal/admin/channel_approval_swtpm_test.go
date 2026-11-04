//go:build integration

package admin

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/efivars"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"golang.org/x/sys/unix"
)

// A hook's approval goes on with the slot and leaves a moved channel, and says so;
// no terminal without the flag is the same; a person who answers no is the same; a
// person's yes and the explicit flag seal it, having shown old and new. PCR 7 is
// extended by hand on a software TPM, which has no event log: the registers are the
// next boot's values there.
func TestApprovalLeavesAMovedChannel(t *testing.T) {
	s := newSWTPMSetup(t)
	idx := uint32(nvslot.NVRAMSlotStart + 4)
	signer, pubPath := sealRealSlot(t, s.sock, idx)
	privPath := filepath.Join(filepath.Dir(pubPath), "seal.key")
	sb, _ := sealTestChannel(t, s, idx, signer)
	sealed := bytes.Clone(sb.Payload.Attestation.Phone.ChannelPublic)
	generation := sb.Payload.Generation

	moved := func() bool {
		t.Helper()
		m, err := nvslot.ChannelMoved(s.tpm, phonegate.ReadSealedSlot(s.tpm, idx))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	before := hex.EncodeToString(sb.Payload.Attestation.Phone.ChannelPCRs[0].Digest)
	s.extend(t, 7, "a db update")
	if !moved() {
		t.Fatal("not moved")
	}

	approve := func(mode ChannelApproval) (string, error) {
		t.Helper()
		channelEventsShown = false
		var err error
		out := captureStdout(t, func() { err = Reseal(s.sock, "", idx, pubPath, privPath, mode, false) })
		return out, err
	}
	left := func(t *testing.T, out string) {
		t.Helper()
		if !moved() {
			t.Fatal("the channel followed")
		}
		cur := phonegate.ReadSealedSlot(s.tpm, idx)
		if !bytes.Equal(cur.Payload.Attestation.Phone.ChannelPublic, sealed) {
			t.Fatal("the object changed")
		}
		if cur.Payload.Generation <= generation {
			t.Fatalf("the slot itself was not approved: generation %d, was %d", cur.Payload.Generation, generation)
		}
		generation = cur.Payload.Generation
		if !strings.Contains(out, "WARNING: slot 4's phone channel was left") || !strings.Contains(out, "sudo tpm2-kira slot approve --nvram 4") {
			t.Fatalf("not said:\n%s", out)
		}
	}

	t.Run("a hook", func(t *testing.T) {
		out, err := approve(ChannelLeave)
		if err != nil {
			t.Fatal(err)
		}
		left(t, out)
		if !strings.Contains(out, "PCR 7 sealed:    "+before) || !strings.Contains(out, "PCR 7 next boot:") || !strings.Contains(out, "no event log") {
			t.Fatalf("old, new, or that the log is missing:\n%s", out)
		}
		if strings.Contains(out, "sealed again") {
			t.Fatalf("says it sealed:\n%s", out)
		}
	})
	t.Run("a person says no", func(t *testing.T) {
		old := askChannel
		defer func() { askChannel = old }()
		asked := 0
		askChannel = func(string) bool { asked++; return false }
		out, err := approve(ChannelAsk)
		if err != nil || asked != 1 {
			t.Fatalf("%v, asked %d", err, asked)
		}
		left(t, out)
	})
	t.Run("a person says yes, having seen it", func(t *testing.T) {
		old := askChannel
		defer func() { askChannel = old }()
		var seen string
		out := captureStdout(t, func() {
			askChannel = func(q string) bool { seen = q; return true }
			channelEventsShown = false
			if err := Reseal(s.sock, "", idx, pubPath, privPath, ChannelAsk, false); err != nil {
				t.Error(err)
			}
		})
		if moved() || seen == "" || !strings.Contains(out, "PCR 7 sealed:    "+before) || !strings.Contains(out, "sealed again") {
			t.Fatalf("moved %v, asked %q:\n%s", moved(), seen, out)
		}
	})
	t.Run("the explicit flag, without a question", func(t *testing.T) {
		s.extend(t, 7, "another")
		old := askChannel
		defer func() { askChannel = old }()
		askChannel = func(string) bool { t.Error("asked"); return false }
		out, err := approve(ChannelSeal)
		if err != nil || moved() || !strings.Contains(out, "PCR 7 next boot:") {
			t.Fatalf("%v, moved %v:\n%s", err, moved(), out)
		}
	})
	t.Run("nothing moved: nothing said", func(t *testing.T) {
		out, err := approve(ChannelLeave)
		if err != nil || strings.Contains(out, "phone channel") {
			t.Fatalf("%v:\n%s", err, out)
		}
	})
}

// The real binary, through the real hooks: mkinitcpio's post hook and
// initramfs-tools' post-update script against a software TPM, PCR 7 extended by hand.
// Each leaves the channel, passes the warning on, and the record says what it did.
func TestHooksLeaveAMovedChannel(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "tpm2-kira-real")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	s := newSWTPMSetup(t)
	idx := uint32(nvslot.NVRAMSlotStart + 4)
	signer, pubPath := sealRealSlot(t, s.sock, idx)
	privPath := filepath.Join(filepath.Dir(pubPath), "seal.key")
	sealTestChannel(t, s, idx, signer)
	s.extend(t, 7, "a dbx update")

	// The binary sees the test's TPM, key and EFI variables; the hooks find it by
	// the name a machine has. The test's own variables: the binary's TPM2_KIRA_TEST_DIR
	// wants them under efivars/.
	testDir := filepath.Join(dir, "testdir")
	if err := os.MkdirAll(testDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(efivars.Dir, filepath.Join(testDir, "efivars")); err != nil {
		t.Fatal(err)
	}
	wrapper := fmt.Sprintf(`#!/bin/bash
case "$1 $2" in
"slot approve") a=("$1" "$2"); shift 2; exec %q "${a[@]}" --tpm %q --privkey %q --pubkey %q "$@" ;;
"slot list") a=("$1" "$2"); shift 2; exec %q "${a[@]}" --tpm %q "$@" ;;
esac
exec %q "$@"
`, bin, s.sock, privPath, pubPath, bin, s.sock, bin)
	binDir := filepath.Join(dir, "bin")
	os.MkdirAll(binDir, 0o755)
	if err := os.WriteFile(filepath.Join(binDir, "tpm2-kira"), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "keys")
	os.MkdirAll(keys, 0o755)

	for _, hook := range []string{"initramfs/mkinitcpio/post/sd-tpm2-kira", "initramfs/initramfs-tools/post-update.d/tpm2-kira", "initramfs/initramfs-tools/kernel/zzz-tpm2-kira"} {
		t.Run(hook, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(root, hook))
			if err != nil {
				t.Fatal(err)
			}
			text := strings.ReplaceAll(string(src), "/etc/tpm2-kira/keys", keys)
			copyPath := filepath.Join(dir, filepath.Base(hook)+"-copy")
			if err := os.WriteFile(copyPath, []byte(text), 0o755); err != nil {
				t.Fatal(err)
			}
			generation := phonegate.ReadSealedSlot(s.tpm, idx).Payload.Generation
			cmd := exec.Command(copyPath, "6.1", "/boot/image")
			cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"), "TPM2_KIRA_UNPRIVILEGED=1", "TPM2_KIRA_TEST_DIR="+testDir)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%v:\n%s", err, out)
			}
			got := string(out)
			if !strings.Contains(got, "WARNING: slot 4's phone channel was left") || !strings.Contains(got, "PCR 7 next boot:") || !strings.Contains(got, "sudo tpm2-kira slot approve --nvram 4") {
				t.Errorf("not passed on:\n%s", got)
			}
			if strings.Contains(got, "is sealed again") {
				t.Errorf("sealed:\n%s", got)
			}
			if m, err := nvslot.ChannelMoved(s.tpm, phonegate.ReadSealedSlot(s.tpm, idx)); err != nil || !m {
				t.Errorf("the channel followed: %v %v", m, err)
			}
			if g := phonegate.ReadSealedSlot(s.tpm, idx).Payload.Generation; g <= generation {
				t.Errorf("the slot was not approved: generation %d, was %d\n%s", g, generation, got)
			}
			// What the image's hook said in this same build is not said again.
			if n := strings.Count(got, "WARNING: Secure Boot"); (filepath.Base(hook) == "zzz-tpm2-kira" && n != 1) || (filepath.Base(hook) != "zzz-tpm2-kira" && n != 0) {
				t.Errorf("Secure Boot said %d times:\n%s", n, got)
			}
			// As a container's root, under a limit on locked memory: the approval stops
			// before it reads the key, the hook says so and the build goes on.
			generation = phonegate.ReadSealedSlot(s.tpm, idx).Payload.Generation
			locked := exec.Command("/bin/sh", "-c", `ulimit -l 64 && exec "$@"`, "sh", copyPath, "6.1", "/boot/image")
			locked.Env = cmd.Env
			locked.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER,
				UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}}
			out, err = locked.CombinedOutput()
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSPC) {
				t.Skipf("no user namespace here: %v", err)
			}
			if err != nil {
				t.Fatalf("the build stops: %v:\n%s", err, out)
			}
			got = string(out)
			if !strings.Contains(got, "FAILED: nothing was asked or read") || !strings.Contains(got, "RLIMIT_MEMLOCK") || !strings.Contains(strings.ToLower(got), "approval did not succeed") {
				t.Errorf("a refused lock is not said:\n%s", got)
			}
			if g := phonegate.ReadSealedSlot(s.tpm, idx).Payload.Generation; g != generation {
				t.Errorf("a refused lock approved: generation %d, was %d\n%s", g, generation, got)
			}
		})
	}
	// Not a hook, no terminal, no flag: the same. --if-moved with nothing of PCR 4
	// to approve writes nothing. --unattended with --seal-channel is refused.
	run := func(args ...string) (string, error) {
		cmd := exec.Command(bin, append([]string{"slot", "approve", "--tpm", s.sock, "--privkey", privPath, "--pubkey", pubPath, "--nvram", "4"}, args...)...)
		cmd.Env = append(os.Environ(), "TPM2_KIRA_UNPRIVILEGED=1", "TPM2_KIRA_TEST_DIR="+testDir)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run(); err != nil || !strings.Contains(out, "phone channel was left") {
		t.Errorf("no terminal, no flag: %v\n%s", err, out)
	}
	// (A failure of tpm2-kira exits 0, by design: it says so.)
	if out, _ := run("--unattended", "--seal-channel"); !strings.Contains(out, "a person's decision") {
		t.Errorf("--unattended --seal-channel:\n%s", out)
	}
	if out, _ := run("--if-moved", "--seal-channel"); !strings.Contains(out, "a person's decision") {
		t.Errorf("--if-moved --seal-channel:\n%s", out)
	}
	if m, err := nvslot.ChannelMoved(s.tpm, phonegate.ReadSealedSlot(s.tpm, idx)); err != nil || !m {
		t.Errorf("the channel followed: %v %v", m, err)
	}
	// The status of the binary: the warning and the command.
	cmd := exec.Command(bin, "status", "--tpm", s.sock, "--pubkey", pubPath)
	cmd.Env = append(os.Environ(), "TPM2_KIRA_UNPRIVILEGED=1", "TPM2_KIRA_TEST_DIR="+testDir)
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "WARNING: slot 4's phone channel is sealed to another PCR 7") || !strings.Contains(string(out), "WARNING: Secure Boot") {
		t.Errorf("status:\n%s", out)
	}
	// And the explicit flag seals it.
	if out, err := run("--seal-channel"); err != nil || !strings.Contains(out, "is sealed again") {
		t.Errorf("--seal-channel: %v\n%s", err, out)
	}
	if m, err := nvslot.ChannelMoved(s.tpm, phonegate.ReadSealedSlot(s.tpm, idx)); err != nil || m {
		t.Errorf("the channel did not follow: %v %v", m, err)
	}
}
