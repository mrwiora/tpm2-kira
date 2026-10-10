//go:build integration
// +build integration

package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrwiora/tpm2-kira/cmd"
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
	// A password+salt keyslot: the provider reads the recipe from the
	// volume's own header (the token luks mark writes below) and derives
	// the key from what is typed at its prompts.
	const password, salt = "correct horse", "battery staple"
	conf := filepath.Join(dir, "control.conf")
	if err := os.WriteFile(conf, []byte("# nothing to configure\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := cmd.Combine([]byte(password), []byte(salt))
	if err != nil {
		t.Fatal(err)
	}
	format := exec.Command("cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", "-", img)
	format.Stdin = bytes.NewReader(key)
	if out, err := format.CombinedOutput(); err != nil {
		t.Fatalf("luksFormat: %v: %s", err, out)
	}
	loopOut, err := exec.Command("losetup", "--find", "--show", img).Output()
	if err != nil {
		t.Fatalf("losetup: %v", err)
	}
	loop := strings.TrimSpace(string(loopOut))
	defer exec.Command("losetup", "-d", loop).Run()
	if err := cmd.LuksMark(cmd.LuksMarkOptions{Device: loop, Keyslot: 0, Mode: "password+salt"}); err != nil {
		t.Fatalf("luks mark: %v", err)
	}

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
	// What the person "types" at the prompts of the next attempt: the
	// password and the salt; "" closes the console without an answer
	// (Ctrl-C: no key). The provider opens the console once per prompt,
	// so the answers are kept, not queued.
	var answersMu sync.Mutex
	var current [2]string
	answer := func(pw, salt string) {
		answersMu.Lock()
		current = [2]string{pw, salt}
		answersMu.Unlock()
	}
	go func() {
		for {
			c, err := cl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				answersMu.Lock()
				a := current
				answersMu.Unlock()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					s := string(buf[:n])
					prompts <- s
					if a[0] == "" {
						return // cancelled
					}
					if strings.Contains(s, "Password for disk") {
						c.Write([]byte(a[0] + "\n"))
					} else if strings.Contains(s, "Salt for disk") {
						c.Write([]byte(a[1] + "\n"))
					}
				}
			}()
		}
	}()
	answer(password, salt)
	volume := "tpm2kira-test-" + strings.ToLower(t.Name()[len(t.Name())-6:])
	crypttab := filepath.Join(dir, "crypttab")
	if err := os.WriteFile(crypttab, []byte(volume+" "+loop+" none luks\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := exec.Command("./tpm2-kira", "run", "--tpm", filepath.Join(dir, "no-tpm"), "--hold", "0", "--unlock", sock)
	run.Env = append(os.Environ(), "TPM2_KIRA_CONSOLE="+console, "TPM2_KIRA_CONTROL_CONF="+conf, "TPM2_KIRA_CRYPTTAB="+crypttab)
	var runOut bytes.Buffer
	run.Stdout, run.Stderr = &runOut, &runOut
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		run.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- run.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("tpm2-kira run did not end on SIGINT within 5 s; killed. Its output:\n%s", runOut.String())
			run.Process.Kill()
			<-done
		}
	}()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	attach := exec.Command(sdc, "attach", volume, loop, sock)
	out, err := attach.CombinedOutput()
	if err != nil {
		t.Fatalf("systemd-cryptsetup attach: %v\n%s\ntpm2-kira:\n%s", err, out, runOut.String())
	}
	defer exec.Command(sdc, "detach", volume).Run()
	if _, err := os.Stat("/dev/mapper/" + volume); err != nil {
		t.Fatalf("the volume is not mapped: %v\n%s", err, out)
	}
	seen := ""
	for done := false; !done; {
		select {
		case p := <-prompts:
			seen += p
		default:
			done = true
		}
	}
	if !strings.Contains(seen, "password for disk "+volume) || !strings.Contains(seen, "salt for disk "+volume) {
		t.Errorf("prompts: %q", seen)
	}
	if out, err := exec.Command(sdc, "detach", volume).CombinedOutput(); err != nil {
		t.Fatalf("detach: %v: %s", err, out)
	}

	// The token logic is not served: a saved key request gets nothing, and
	// systemd-cryptsetup goes to its own prompt (headless: fails).
	bad := exec.Command(sdc, "attach", volume, loop, sock, "tpm2-device=auto,headless=true")
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
	answer(password, "not the salt")
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
	for len(prompts) > 0 {
		<-prompts
	}

	// No answer at all (the prompt cancelled: tpm2-kira closes without a
	// key) reads as an empty key file, and the fallback is the same prompt.
	answer("", "")
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
}
