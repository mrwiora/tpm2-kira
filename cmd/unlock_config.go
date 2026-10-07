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

// unlockConfigPath is DefaultUnlockConfigPath, or TPM2_KIRA_UNLOCK_CONF
// for tests.
func unlockConfigPath() string {
	if p := os.Getenv("TPM2_KIRA_UNLOCK_CONF"); p != "" {
		return p
	}
	return DefaultUnlockConfigPath
}

// The provider's modes (TPM2_KIRA_UNLOCK): how the disk's key is made.
const (
	UnlockSkip               = "skip"                // tpm2-kira stays out of it: cryptsetup's own prompt
	UnlockPasswordSalt       = "password+salt"       // a typed password and a typed salt, combined (combine.go)
	UnlockPasswordRemoteSalt = "password+remotesalt" // a typed password and the salt a verifier released
)

// UnlockConfig is /etc/tpm2-kira/unlock.conf: shell-style KEY=VALUE lines,
// so the Debian scripts could source it as well.
type UnlockConfig struct {
	Mode string
}

// LoadUnlockConfig reads the file; a missing file means skip.
func LoadUnlockConfig(path string) (UnlockConfig, error) {
	cfg := UnlockConfig{Mode: UnlockSkip}
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
	cfg := UnlockConfig{Mode: UnlockSkip}
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
			case UnlockSkip, UnlockPasswordSalt, UnlockPasswordRemoteSalt:
				cfg.Mode = val
			default:
				return cfg, fmt.Errorf("unlock.conf line %d: TPM2_KIRA_UNLOCK must be skip, password+salt or password+remotesalt, not %q", n, val)
			}
		default:
			return cfg, fmt.Errorf("unlock.conf line %d: unknown key %q", n, key)
		}
	}
	return cfg, sc.Err()
}
