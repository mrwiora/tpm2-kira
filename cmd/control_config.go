package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// /etc/tpm2-kira/control.conf is the one configuration file: the radio of
// the attestation by phone (TPM2_KIRA_ATTEST_*) and the YubiKey's PIN for
// the unattended reseal (TPM2_KIRA_PIN). How the disk's key is made is not
// configured anywhere: the boot reads it from the LUKS header's tokens
// (luks_header.go). Shell-style KEY=VALUE lines, so the initramfs
// scripts source it too; the hooks copy it into the initramfs without the
// PIN line. 'tpm2-kira control' is what writes it; the other commands only
// read. A file holding the PIN must be root's and readable by root alone,
// else the PIN in it is treated as disclosed and not used.

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
	PIN    string // TPM2_KIRA_PIN: the YubiKey's PIN, "" when not stored
	// Control is how 'tpm2-kira control' guides: "guided" (the one row,
	// then the reboot, then part 2), "manual" (every step by hand), or ""
	// (not chosen yet: the start screen asks). Changeable there any time.
	Control string // TPM2_KIRA_CONTROL
}

// DefaultControlConfig is a missing file: the radio's defaults.
func DefaultControlConfig() ControlConfig {
	return ControlConfig{Attest: DefaultAttestConfig()}
}

// LoadControlConfig reads the file; a missing file is the defaults.
func LoadControlConfig(path string) (ControlConfig, error) {
	cfg := DefaultControlConfig()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	return ParseControlConfig(data)
}

// LoadAttestConfig is the radio part of the file at path.
func LoadAttestConfig(path string) (AttestConfig, error) {
	cfg, err := LoadControlConfig(path)
	return cfg.Attest, err
}

// ParseControlConfig parses control.conf content.
func ParseControlConfig(data []byte) (ControlConfig, error) {
	cfg := DefaultControlConfig()
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return cfg, fmt.Errorf("control.conf line %d: expected KEY=VALUE", n)
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch key {
		case "TPM2_KIRA_UNLOCK":
			return cfg, fmt.Errorf("control.conf line %d: there is no unlock mode to set any more; the boot reads how a key is made from the LUKS header's tokens. Remove the line", n)
		case "TPM2_KIRA_CONTROL":
			switch val {
			case "guided", "manual":
				cfg.Control = val
			default:
				return cfg, fmt.Errorf("control.conf line %d: TPM2_KIRA_CONTROL must be guided or manual, not %q", n, val)
			}
		case "TPM2_KIRA_ATTEST_BLUETOOTH":
			switch val {
			case "", "auto", "always":
				cfg.Attest.Bluetooth = val
				if val == "" {
					cfg.Attest.Bluetooth = "auto"
				}
			default:
				return cfg, fmt.Errorf("control.conf line %d: TPM2_KIRA_ATTEST_BLUETOOTH must be auto or always, not %q", n, val)
			}
		case PINEnvVar:
			cfg.PIN = val
		case "TPM2_KIRA_ATTEST":
			return cfg, fmt.Errorf("control.conf line %d: there is no attestation mode to set; the phone is served whenever one is enrolled. Remove the line", n)
		case "TPM2_KIRA_ATTEST_ADAPTER":
			v, err := strconv.Atoi(strings.TrimPrefix(val, "hci"))
			if err != nil || v < 0 || v > 255 {
				return cfg, fmt.Errorf("control.conf line %d: invalid adapter %q", n, val)
			}
			cfg.Attest.Adapter = v
		case "TPM2_KIRA_ATTEST_TIMEOUT", "TPM2_KIRA_ATTEST_ADAPTER_WAIT":
			return cfg, fmt.Errorf("control.conf line %d: %s is gone: the gate in the boot image waits for the adapter and a phone as long as the code screen holds. Remove the line", n, key)
		case "TPM2_KIRA_ATTEST_DEBUG":
			return cfg, fmt.Errorf("control.conf line %d: TPM2_KIRA_ATTEST_DEBUG is gone: switch \"Debug at boot\" in 'tpm2-kira control' instead (a setting in the TPM; nothing of control.conf goes into the boot image). Remove the line", n)
		default:
			return cfg, fmt.Errorf("control.conf line %d: unknown key %q", n, key)
		}
	}
	return cfg, sc.Err()
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
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), mode)
}

// setAttestBluetooth sets whether the hooks pack Bluetooth into every
// image, enrolled phone or not.
func setAttestBluetooth(path, value string) error {
	return setControlValue(path, "TPM2_KIRA_ATTEST_BLUETOOTH", value)
}

// setControlGuide keeps the guided/manual choice.
func setControlGuide(path, value string) error {
	return setControlValue(path, "TPM2_KIRA_CONTROL", value)
}

// setControlPIN stores the YubiKey's PIN in control.conf, which is then
// readable by root alone (the hooks leave the line out of the initramfs).
func setControlPIN(path, pin string) error {
	if strings.ContainsAny(pin, "'\n") {
		return fmt.Errorf("the PIN cannot hold a quote or a newline")
	}
	if err := setControlValue(path, PINEnvVar, "'"+pin+"'"); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// configPIN is the PIN control.conf stores: "" when there is none; loose
// when the file is not root's, or group or others may read it - such a PIN
// is refused, it has to be treated as already disclosed.
func configPIN(path string) (pin string, loose bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return "", false
	}
	cfg, err := ParseControlConfig(data)
	if err != nil || cfg.PIN == "" {
		return "", false
	}
	uid, ok := ownerOf(st)
	return cfg.PIN, st.Mode().Perm()&0o077 != 0 || !ok || !trustedOwner(uid)
}
