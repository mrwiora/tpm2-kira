package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// /etc/tpm2-kira/control.conf is tpm2-kira's configuration file (aSSH's,
// assh.conf, is beside it: remote_assh.go), and it holds what the boot
// image is built with, nothing else: the radio of the
// attestation by phone (TPM2_KIRA_ATTEST_*) and the image's network and
// SSH server (TPM2_KIRA_NET_*, TPM2_KIRA_SSH_*, remote_config.go).
// KEY=VALUE lines. How the disk's key is made is not configured anywhere:
// the boot reads it from the LUKS header's tokens (luks_header.go). The
// file never goes into the boot image, and no script sources it: tpm2-kira
// reads it, the image build through its boot plan ('initramfs plan',
// bootplan.go), which writes the network and SSH settings into the image
// as files of their own and names the settings of every part it put in -
// so control tells an image built with other settings. 'tpm2-kira
// control' is what writes it; the other commands only read.
//
// Next to it, and written by control too: the YubiKey's PIN for the
// unattended reseal (pin, root's and readable by root alone, else treated
// as disclosed and not used) and the keys that may log in to the image's
// SSH server (authorized_keys).

// DefaultControlConfigPath is the file.
const DefaultControlConfigPath = "/etc/tpm2-kira/control.conf"

// controlConfigPath is DefaultControlConfigPath, or TPM2_KIRA_CONTROL_CONF
// for tests.
func controlConfigPath() string {
	if p := os.Getenv("TPM2_KIRA_CONTROL_CONF"); p != "" {
		return p
	}
	return DefaultControlConfigPath
}

// AttestConfig is the radio part of control.conf.
//
// Both settings are for the running system alone: which adapter's driver
// and firmware the hooks put into the boot image, and when. Nothing of
// this file goes into the image; the gate there takes the adapter that
// comes up and waits as long as the code screen holds, and
// the boot settings' debug switch in the TPM (bootsettings.go, written by
// control) makes it log every step.
type AttestConfig struct {
	Adapter   int    // TPM2_KIRA_ATTEST_ADAPTER: whose driver goes into the image
	Bluetooth string // TPM2_KIRA_ATTEST_BLUETOOTH: "auto" (with an enrolled phone), or "always"
}

// DefaultAttestConfig is used when the file is missing.
func DefaultAttestConfig() AttestConfig {
	return AttestConfig{Bluetooth: "auto"}
}

// ControlConfig is the whole file.
type ControlConfig struct {
	Attest AttestConfig
	// Remote is the boot image's network and SSH server (remote_config.go):
	// unlike the rest, the image build turns it into files of the image.
	Remote RemoteConfig
}

// DefaultControlConfig is a missing file: the radio's defaults.
func DefaultControlConfig() ControlConfig {
	return ControlConfig{Attest: DefaultAttestConfig(), Remote: DefaultRemoteConfig()}
}

// LoadControlConfig reads the file; a missing file is the defaults.
func LoadControlConfig(path string) (ControlConfig, error) {
	cfg := DefaultControlConfig()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return cfg, err
	}
	if err == nil {
		cfg, err = ParseControlConfig(data)
	} else {
		err = nil
	}
	assh, aerr := loadSSHConf(sshConfPath(path), path)
	cfg.Remote.SSH.Assh = assh
	if err == nil {
		err = aerr
	}
	return cfg, err
}

// sshCAPath is the SSH CA of the control.conf at path: DefaultSSHCA, its
// EFI variable, for the real one; a file next to another (a test's).
func sshCAPath(path string) string {
	if path == DefaultControlConfigPath {
		return DefaultSSHCA
	}
	return filepath.Join(filepath.Dir(path), "ssh_ca.json")
}

// sshAuthorizedKeysPath is the SSH server's keys next to the control.conf
// at path, unless assh.conf says otherwise: DefaultSSHAuthorizedKeys for
// the real one.
func sshAuthorizedKeysPath(path string) string {
	return filepath.Join(filepath.Dir(path), "authorized_keys")
}

// LoadAttestConfig is the radio part of the file at path.
func LoadAttestConfig(path string) (AttestConfig, error) {
	cfg, err := LoadControlConfig(path)
	return cfg.Attest, err
}

// ParseControlConfig parses control.conf content: the first line it
// refuses is the error (ControlConfigProblems lists them all).
func ParseControlConfig(data []byte) (ControlConfig, error) {
	cfg := DefaultControlConfig()
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		if err := parseControlLine(&cfg, n, sc.Text()); err != nil {
			return cfg, err
		}
	}
	return cfg, sc.Err()
}

// ControlConfigProblems lists every line of control.conf content that does
// not load, each with its number and what to do; none for a good file.
func ControlConfigProblems(data []byte) []error {
	cfg := DefaultControlConfig()
	var out []error
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		if err := parseControlLine(&cfg, n, sc.Text()); err != nil {
			out = append(out, err)
		}
	}
	if err := sc.Err(); err != nil {
		out = append(out, err)
	}
	return out
}

// parseControlLine takes one line (number n) into cfg.
func parseControlLine(cfg *ControlConfig, n int, line string) error {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	key, val, ok := strings.Cut(line, "=")
	if !ok {
		return fmt.Errorf("control.conf line %d: expected KEY=VALUE", n)
	}
	key = strings.TrimSpace(key)
	val = strings.Trim(strings.TrimSpace(val), `"'`)
	if handled, err := parseRemoteLine(&cfg.Remote, n, key, val); handled {
		return err
	}
	switch key {
	case "TPM2_KIRA_UNLOCK":
		return fmt.Errorf("control.conf line %d: there is no unlock mode to set any more; the boot reads how a key is made from the LUKS header's tokens. Remove the line", n)
	case "TPM2_KIRA_CONTROL":
		return fmt.Errorf("control.conf line %d: there is no guided or manual mode to choose any more; control guides in two steps. Remove the line", n)
	case "TPM2_KIRA_ATTEST_BLUETOOTH":
		switch val {
		case "", "auto", "always":
			cfg.Attest.Bluetooth = val
			if val == "" {
				cfg.Attest.Bluetooth = "auto"
			}
		default:
			return fmt.Errorf("control.conf line %d: TPM2_KIRA_ATTEST_BLUETOOTH must be auto or always, not %q", n, val)
		}
	case PINEnvVar:
		return fmt.Errorf("control.conf line %d: the YubiKey's PIN has a file of its own, %s: remove the line, then store the PIN again with tpm2-kira control (Signing key and TOTP codes)", n, pinFilePath())
	case "TPM2_KIRA_ATTEST":
		return fmt.Errorf("control.conf line %d: there is no attestation mode to set; the phone is served whenever one is enrolled. Remove the line", n)
	case "TPM2_KIRA_ATTEST_ADAPTER":
		v, err := strconv.Atoi(strings.TrimPrefix(val, "hci"))
		if err != nil || v < 0 || v > 255 {
			return fmt.Errorf("control.conf line %d: invalid adapter %q", n, val)
		}
		cfg.Attest.Adapter = v
	case "TPM2_KIRA_ATTEST_TIMEOUT", "TPM2_KIRA_ATTEST_ADAPTER_WAIT":
		return fmt.Errorf("control.conf line %d: %s is gone: the gate in the boot image waits for the adapter and a phone as long as the code screen holds. Remove the line", n, key)
	case "TPM2_KIRA_ATTEST_DEBUG":
		return fmt.Errorf("control.conf line %d: TPM2_KIRA_ATTEST_DEBUG is gone: switch \"Debug at boot\" in 'tpm2-kira control' instead (a setting in the TPM; nothing of control.conf goes into the boot image). Remove the line", n)
	default:
		return fmt.Errorf("control.conf line %d: unknown key %q", n, key)
	}
	return nil
}

// setControlValue writes KEY=value into control.conf, replacing the line
// or adding it; a missing file is created with the line. Only control
// calls it: the commands touch no configuration file.
func setControlValue(path, key, value string) error {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	line := key + "=" + value
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	done := false
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), key+"=") {
			lines[i] = line
			done = true
		}
	}
	if !done {
		if len(data) == 0 {
			lines = nil
		}
		lines = append(lines, line)
	}
	out := []byte(strings.Join(lines, "\n") + "\n")
	if bytes.Equal(out, data) {
		return nil // unchanged: nothing to write
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	return os.WriteFile(path, out, mode)
}

// setAttestBluetooth sets whether the boot plan packs Bluetooth into
// every image, enrolled phone or not.
func setAttestBluetooth(path, value string) error {
	return setControlValue(path, "TPM2_KIRA_ATTEST_BLUETOOTH", value)
}

// pinFilePath is the YubiKey's PIN, next to control.conf: the PIN alone,
// root's and readable by root alone. It is no setting of the image, so it
// has a file of its own: control.conf holds what the image is built with,
// and only that.
func pinFilePath() string {
	return filepath.Join(filepath.Dir(controlConfigPath()), "pin")
}

// storePIN writes the PIN, readable by root alone.
func storePIN(path, pin string) error {
	if strings.ContainsAny(pin, "\n") {
		return fmt.Errorf("the PIN cannot hold a newline")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(pin + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// The PIN's value goes to the signer, to sign with the key, and nowhere
// else; everything else asks pinStored, which says only whether it is
// there.

// storedPIN is the PIN the file at path stores: "" when there is none;
// loose when the file is not root's, or group or others may read it - such
// a PIN is refused, it has to be treated as already disclosed. For the
// signer only (pinFromFile).
func storedPIN(path string) (pin string, loose bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<10))
	if err != nil {
		return "", false
	}
	pin = strings.TrimRight(string(data), "\r\n")
	if pin == "" {
		return "", false
	}
	uid, owned := ownerOf(st)
	return pin, st.Mode().Perm()&0o077 != 0 || !owned || !trustedOwner(uid)
}

// pinStored says whether the file at path stores a PIN, and whether it is
// loose (readable by others): the PIN's value stays out of it.
func pinStored(path string) (stored, loose bool) {
	pin, loose := storedPIN(path)
	return pin != "", loose
}
