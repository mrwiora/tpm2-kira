package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tpm2-trust/assh/server"
)

// The image's files for the network and the SSH server (control.conf's
// TPM2_KIRA_NET_* and TPM2_KIRA_SSH_*), written by the boot plan
// (bootplan.go) when those parts are in: the systemd-networkd file or the
// boot scripts' remote.conf, the SSH CA, the keys that may log in, and the
// drop-in that makes 'run' the SSH server.

// The paths in the image.
const (
	imageNetworkFile    = "/etc/systemd/network/10-tpm2-kira.network"
	ImageAuthorizedKeys = "/root/.ssh/authorized_keys"
	imageRunDropIn      = "/etc/systemd/system/tpm2-kira.service.d/remote.conf"
	// imageRemoteConf is initramfs-tools' in place of the two above: read
	// by the init-premount script, which brings the network up and starts
	// 'run' with TPM2_KIRA_REMOTE.
	imageRemoteConf = "/etc/tpm2-kira/remote.conf"
)

// The image formats of 'initramfs plan --format'.
const (
	FormatMkinitcpio     = "mkinitcpio"
	FormatInitramfsTools = "initramfs-tools"
)

// imageKeys is the image's authorized_keys: the keys that may log in, one
// per line.
func imageKeys(keys []string) []byte {
	return []byte(strings.Join(keys, "\n") + "\n")
}

func keysSum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// runDropIn makes tpm2-kira.service start the SSH server, and hold as long
// as the setting says - without a limit, the unit may not time out either.
func runDropIn(s SSHConfig) string {
	timeout := "infinity"
	if s.Hold > 0 {
		// The unit's own margin over its 90 s hold, kept.
		timeout = fmt.Sprintf("%d", s.Hold+90)
	}
	return fmt.Sprintf(`# Written by 'tpm2-kira initramfs plan' from /etc/tpm2-kira/control.conf
# (TPM2_KIRA_SSH_*), for the boot image alone.
[Unit]
Wants=systemd-networkd.service

[Service]
TimeoutStartSec=%s
Environment="TPM2_KIRA_REMOTE=--ssh=%d --ssh-hold=%d --ssh-ca=%s"
`, timeout, s.Port, s.Hold, ImageSSHCA)
}

// remoteConf is the image's /etc/tpm2-kira/remote.conf on initramfs-tools,
// sourced by the init-premount script. Every value was checked when
// control.conf was read (addresses, a MAC or an interface name, numbers),
// so none needs more than the double quotes.
func remoteConf(r RemoteConfig) string {
	var b strings.Builder
	b.WriteString("# Written by 'tpm2-kira initramfs plan' from /etc/tpm2-kira/control.conf,\n")
	b.WriteString("# for the boot image alone; read by scripts/init-premount/tpm2-kira.\n")
	for _, kv := range [][2]string{
		{"TPM2_KIRA_NET", r.Net.Mode},
		{"TPM2_KIRA_NET_MATCH", r.Net.Match},
		{"TPM2_KIRA_NET_ADDRESS", strings.Join(r.Net.Addresses, " ")},
		{"TPM2_KIRA_NET_GATEWAY", strings.Join(r.Net.Gateways, " ")},
		{"TPM2_KIRA_NET_DNS", strings.Join(r.Net.DNS, " ")},
	} {
		fmt.Fprintf(&b, "%s=\"%s\"\n", kv[0], kv[1])
	}
	if r.SSH.On {
		fmt.Fprintf(&b, "TPM2_KIRA_REMOTE=\"--ssh=%d --ssh-hold=%d --ssh-ca=%s\"\n", r.SSH.Port, r.SSH.Hold, ImageSSHCA)
	}
	return b.String()
}

// authorizedKeys are the keys of an authorized_keys file that may log in,
// one per line as the file has them, and how many lines were left out: a
// line with options in front of the key (from="...", command="...") is
// not honoured by 'remote serve', so it does not let anyone in either.
func authorizedKeys(path string) ([]string, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("the keys that may log in over SSH: %w", err)
	}
	keys, skipped := server.ParseAuthorizedKeys(data)
	return keys, skipped, nil
}

func writeImageFile(buildroot, path string, data []byte, mode os.FileMode) error {
	dst := filepath.Join(buildroot, path)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, mode); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}
