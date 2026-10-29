package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tpm2-trust/assh/config"
)

// The image's files for the network and the SSH server (control.conf's
// TPM2_KIRA_NET_* and TPM2_KIRA_SSH_*, and assh.conf), written by the boot
// plan (bootplan.go) when those parts are in: the systemd-networkd file or
// the boot scripts' remote.conf, assh.conf and the keys that may log in,
// and the drop-in that makes 'run' the SSH server. The SSH CA is not one
// of them: it stays in its EFI variable.

// The paths in the image.
const (
	imageNetworkFile = "/etc/systemd/network/10-tpm2-kira.network"
	imageRunDropIn   = "/etc/systemd/system/tpm2-kira.service.d/remote.conf"
	// imageRemoteConf is initramfs-tools' in place of the two above: read
	// by the init-premount script, which brings the network up and starts
	// 'run' with TPM2_KIRA_REMOTE.
	imageRemoteConf = "/etc/tpm2-kira/remote.conf"
	// imageUdhcpcScript is initramfs-tools' DHCP with a client identifier:
	// busybox' udhcpc runs it at its events.
	imageUdhcpcScript = "/etc/tpm2-kira/udhcpc.script"
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

// imageSSHConf is the image's assh.conf: the running system's settings.
func imageSSHConf(c config.Config) []byte {
	return config.Format(c, "Written by 'tpm2-kira initramfs plan' from /etc/tpm2-kira/assh.conf,\nfor the boot image alone; read by 'tpm2-kira-boot run --ssh'.")
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
# (TPM2_KIRA_SSH_*), for the boot image alone; the rest is assh.conf's.
[Unit]
Wants=systemd-networkd.service

[Service]
TimeoutStartSec=%s
Environment="TPM2_KIRA_REMOTE=--ssh --ssh-hold=%d"
`, timeout, s.Hold)
}

// remoteConf is the image's /etc/tpm2-kira/remote.conf on initramfs-tools,
// sourced by the init-premount script. Every value was checked when
// control.conf was read (addresses, a MAC or an interface name, numbers),
// so none needs more than the double quotes.
func remoteConf(r RemoteConfig, id dhcpIdentity) string {
	var b strings.Builder
	b.WriteString("# Written by 'tpm2-kira initramfs plan' from /etc/tpm2-kira/control.conf,\n")
	b.WriteString("# for the boot image alone; read by scripts/init-premount/tpm2-kira.\n")
	for _, kv := range [][2]string{
		{"TPM2_KIRA_NET", r.Net.Mode},
		{"TPM2_KIRA_NET_MATCH", r.Net.Match},
		{"TPM2_KIRA_NET_ADDRESS", strings.Join(r.Net.Addresses, " ")},
		{"TPM2_KIRA_NET_GATEWAY", strings.Join(r.Net.Gateways, " ")},
		{"TPM2_KIRA_NET_DNS", strings.Join(r.Net.DNS, " ")},
		// The DHCP client identifier, hex: udhcpc asks with it; without
		// one, klibc's ipconfig asks with none.
		{"TPM2_KIRA_NET_CLIENTID", hex.EncodeToString(id.ID)},
	} {
		fmt.Fprintf(&b, "%s=\"%s\"\n", kv[0], kv[1])
	}
	if r.SSH.On {
		fmt.Fprintf(&b, "TPM2_KIRA_REMOTE=\"--ssh --ssh-hold=%d\"\n", r.SSH.Hold)
	}
	return b.String()
}

// udhcpcScript configures what udhcpc's lease gives (busybox' udhcpc
// passes it in the environment): the address, the default route, the DNS
// servers.
const udhcpcScript = `#!/bin/sh
# Written by 'tpm2-kira initramfs plan': udhcpc's events, for the image's
# network (TPM2_KIRA_NET=dhcp with a client identifier).
case "$1" in
deconfig)
    ip -4 address flush dev "$interface"
    ip link set dev "$interface" up
    ;;
bound | renew)
    ip -4 address flush dev "$interface"
    ip address add "$ip/${mask:-24}" dev "$interface"
    for r in $router; do
        ip route add default via "$r" dev "$interface"
        break
    done
    : > /etc/resolv.conf
    for d in $dns; do
        echo "nameserver $d" >> /etc/resolv.conf
    done
    ;;
esac
exit 0
`

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
