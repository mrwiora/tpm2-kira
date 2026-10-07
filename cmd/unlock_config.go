package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
)

// DefaultUnlockConfigPath holds how the key provider answers.
const DefaultUnlockConfigPath = "/etc/tpm2-kira/unlock.conf"

// The provider's modes (TPM2_KIRA_UNLOCK).
const (
	UnlockPassphrase = "passphrase" // the passphrase as typed
	UnlockHashpwd2   = "hashpwd2"   // password and salt, combined (combine.go)
)

// UnlockConfig is /etc/tpm2-kira/unlock.conf: shell-style KEY=VALUE lines,
// so the Debian scripts could source it as well.
type UnlockConfig struct {
	Mode string
}

// LoadUnlockConfig reads the file; a missing file means the passphrase.
func LoadUnlockConfig(path string) (UnlockConfig, error) {
	cfg := UnlockConfig{Mode: UnlockPassphrase}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	return ParseUnlockConfig(data)
}

// ParseUnlockConfig parses unlock.conf content.
func ParseUnlockConfig(data []byte) (UnlockConfig, error) {
	cfg := UnlockConfig{Mode: UnlockPassphrase}
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return cfg, fmt.Errorf("unlock.conf line %d: expected KEY=VALUE", n)
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch key {
		case "TPM2_KIRA_UNLOCK":
			switch val {
			case UnlockPassphrase, UnlockHashpwd2:
				cfg.Mode = val
			default:
				return cfg, fmt.Errorf("unlock.conf line %d: TPM2_KIRA_UNLOCK must be passphrase or hashpwd2, not %q", n, val)
			}
		default:
			return cfg, fmt.Errorf("unlock.conf line %d: unknown key %q", n, key)
		}
	}
	return cfg, sc.Err()
}
