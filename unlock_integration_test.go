//go:build integration
// +build integration

package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The real systemd-cryptsetup unlocks a LUKS2 volume with the key it reads
// from tpm2-kira's socket, exactly as the initrd will: the volume's key
// file is the socket, the connection names the volume, tpm2-kira asks at
// its prompt and answers. Needs root (loop device, device-mapper),
// cryptsetup and systemd-cryptsetup; skipped otherwise:
//
//	sudo -E go test -tags integration -count=1 -run TestSystemdCryptsetupUnlocksThroughTpm2Kira .
func TestSystemdCryptsetupUnlocksThroughTpm2Kira(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for a loop device and device-mapper")
	}
	for _, tool := range []string{"cryptsetup", "losetup"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	sdc := "/usr/lib/systemd/systemd-cryptsetup"
	if _, err := os.Stat(sdc); err != nil {
		t.Skip("systemd-cryptsetup not installed")
	}

	dir := t.TempDir()
	img := filepath.Join(dir, "disk.img")
	f, err := os.Create(img)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(20 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	const passphrase = "correct horse battery staple"
	format := exec.Command("cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", "-", img)
	format.Stdin = strings.NewReader(passphrase) // no newline: a key file's bytes
	if out, err := format.CombinedOutput(); err != nil {
		t.Fatalf("luksFormat: %v: %s", err, out)
	}
	loopOut, err := exec.Command("losetup", "--find", "--show", img).Output()
	if err != nil {
		t.Fatalf("losetup: %v", err)
	}
	loop := strings.TrimSpace(string(loopOut))
	defer exec.Command("losetup", "-d", loop).Run()

	// tpm2-kira run without a TPM: nothing to show, the hold ends at once,
	// the key socket is served. The prompt goes to a socket the test answers.
	sock := filepath.Join(dir, "unlock.sock")
	console := filepath.Join(dir, "console.sock")
	cl, err := net.Listen("unix", console)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	prompts := make(chan string, 8)
	// What the person "types" at the next prompt; "" closes the console
	// without an answer (Ctrl-D: no key for the volume).
	answers := make(chan string, 8)
	go func() {
		for {
			c, err := cl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 512)
				n, _ := c.Read(buf)
				prompts <- string(buf[:n])
				if a := <-answers; a != "" {
					c.Write([]byte(a + "\n"))
					io.Copy(io.Discard, c)
				}
			}()
		}
	}()
	answers <- passphrase
	run := exec.Command("./tpm2-kira", "run", "--tpm", filepath.Join(dir, "no-tpm"), "--hold", "0", "--unlock", sock)
	run.Env = append(os.Environ(), "TPM2_KIRA_CONSOLE="+console)
	var runOut bytes.Buffer
	run.Stdout, run.Stderr = &runOut, &runOut
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		run.Process.Signal(os.Interrupt)
		run.Wait()
	}()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	volume := "tpm2kira-test-" + strings.ToLower(t.Name()[len(t.Name())-6:])
	attach := exec.Command(sdc, "attach", volume, loop, sock)
	out, err := attach.CombinedOutput()
	if err != nil {
		t.Fatalf("systemd-cryptsetup attach: %v\n%s\ntpm2-kira:\n%s", err, out, runOut.String())
	}
	defer exec.Command(sdc, "detach", volume).Run()
	if _, err := os.Stat("/dev/mapper/" + volume); err != nil {
		t.Fatalf("the volume is not mapped: %v\n%s", err, out)
	}
	select {
	case p := <-prompts:
		if !strings.Contains(p, "passphrase for disk "+volume) {
			t.Errorf("prompt: %q", p)
		}
	default:
		t.Error("tpm2-kira did not ask at its prompt")
	}
	if out, err := exec.Command(sdc, "detach", volume).CombinedOutput(); err != nil {
		t.Fatalf("detach: %v: %s", err, out)
	}

	// The token logic is not served: a saved key request gets nothing and
	// the activation fails rather than hangs.
	bad := exec.Command(sdc, "attach", volume, loop, sock, "tpm2-device=auto")
	bad.Env = append(os.Environ(), "SYSTEMD_LOG_LEVEL=info")
	if out, err := bad.CombinedOutput(); err == nil {
		exec.Command(sdc, "detach", volume).Run()
		t.Fatalf("a token request was served: %s", out)
	}

	// A wrong passphrase at tpm2-kira's prompt is a wrong key file:
	// systemd-cryptsetup drops the key file and asks for a passphrase
	// itself (its password agent) for the remaining tries. headless=true
	// makes that step fail with a message instead of a prompt, which is
	// how the test sees that the fallback was reached.
	answers <- "not the passphrase"
	wrong := exec.Command(sdc, "attach", volume, loop, sock, "headless=true")
	wrong.Env = append(os.Environ(), "SYSTEMD_LOG_LEVEL=info")
	out, err = wrong.CombinedOutput()
	if err == nil {
		exec.Command(sdc, "detach", volume).Run()
		t.Fatalf("a wrong passphrase unlocked the volume: %s", out)
	}
	if !bytes.Contains(out, []byte("Key data incorrect?")) || !bytes.Contains(out, []byte("Password querying disabled via 'headless' option.")) {
		t.Errorf("after a wrong passphrase systemd-cryptsetup should fall back to its own prompt:\n%s", out)
	}
	<-prompts

	// No answer at all (the prompt cancelled: tpm2-kira closes without a
	// key) reads as an empty key file, and the fallback is the same prompt.
	answers <- ""
	none := exec.Command(sdc, "attach", volume, loop, sock, "headless=true")
	none.Env = append(os.Environ(), "SYSTEMD_LOG_LEVEL=info")
	out, err = none.CombinedOutput()
	if err == nil {
		exec.Command(sdc, "detach", volume).Run()
		t.Fatalf("no answer unlocked the volume: %s", out)
	}
	if !bytes.Contains(out, []byte("Password querying disabled via 'headless' option.")) {
		t.Errorf("after no answer systemd-cryptsetup should fall back to its own prompt:\n%s", out)
	}
	<-prompts
}
