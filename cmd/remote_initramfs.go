package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// What the image build adds for the network and the SSH server
// (control.conf's TPM2_KIRA_NET_* and TPM2_KIRA_SSH_*). The mkinitcpio hook
// calls 'tpm2-kira remote initramfs --buildroot DIR', which writes the
// files into the image under construction and prints, one per line, what
// the hook itself has to add:
//
//	net off                 nothing to add
//	net dhcp|static         systemd-networkd with its user, enabled
//	module NAME             the driver of an interface the network matches
//	modules-all             no interface matched here: every network driver
//	ssh PORT                tinysshd (the hook adds the binary and a shell)
//	warning TEXT            said by the hook, the build goes on
//
// A setting that cannot make a working image (Problem, a missing host key)
// is an error, exit status 2: the hook then adds neither network nor SSH
// and says why - the image still boots, with the code screen at the
// console.

// The paths in the image.
const (
	imageNetworkFile   = "/etc/systemd/network/10-tpm2-kira.network"
	imageSSHHostKeys   = "/etc/tpm2-kira/ssh"
	imageAuthorizedKey = "/root/.ssh/authorized_keys"
	imageRunDropIn     = "/etc/systemd/system/tpm2-kira.service.d/remote.conf"
)

// tinysshHostKeyFiles are the files of a tinysshd key directory
// (tinysshd-makekey); the ed25519 pair is required.
var tinysshHostKeyFiles = []string{"ed25519.pk", ".ed25519.sk", "nistp256ecdsa.pk", ".nistp256ecdsa.sk"}

// RemoteInitramfsCommand implements 'remote initramfs'.
func RemoteInitramfsCommand(configPath, buildroot string, out io.Writer) error {
	if buildroot == "" {
		return errors.New("--buildroot is required")
	}
	cfg, err := LoadControlConfig(configPath)
	if err != nil {
		return err
	}
	r := cfg.Remote
	if p := r.Problem(); p != "" {
		return errors.New(p)
	}
	if r.Net.Mode == "off" {
		fmt.Fprintln(out, "net off")
		return nil
	}
	var keys []string
	if r.SSH.On {
		// Checked before anything is written: an image half with SSH is
		// worse than one without.
		if _, err := os.Stat(filepath.Join(r.SSH.HostKeys, ".ed25519.sk")); err != nil {
			return fmt.Errorf("no SSH host key in %s: create one with 'tinysshd-makekey %s' (tpm2-kira control offers it)", r.SSH.HostKeys, r.SSH.HostKeys)
		}
		if keys, err = ed25519AuthorizedKeys(r.SSH.AuthorizedKeys); err != nil {
			return err
		}
		if len(keys) == 0 {
			return fmt.Errorf("%s holds no ssh-ed25519 key, the only kind tinysshd accepts: nobody could log in", r.SSH.AuthorizedKeys)
		}
	}

	if err := writeImageFile(buildroot, imageNetworkFile, []byte(r.Net.NetworkdFile()), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "net %s\n", r.Net.Mode)
	matched := r.Net.matchedInterfaces()
	if len(matched) == 0 {
		what := "no wired interface"
		if r.Net.Match != "" {
			what = "no interface " + r.Net.Match
		}
		fmt.Fprintln(out, "modules-all")
		fmt.Fprintf(out, "warning %s on this machine: every network driver goes into the image\n", what)
	}
	for _, it := range matched {
		if it.Module != "" {
			fmt.Fprintf(out, "module %s\n", it.Module)
		}
	}

	if !r.SSH.On {
		return nil
	}
	for _, f := range tinysshHostKeyFiles {
		data, err := os.ReadFile(filepath.Join(r.SSH.HostKeys, f))
		if os.IsNotExist(err) && f != "ed25519.pk" && f != ".ed25519.sk" {
			continue
		}
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if strings.HasPrefix(f, ".") {
			mode = 0o600
		}
		if err := writeImageFile(buildroot, filepath.Join(imageSSHHostKeys, f), data, mode); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(buildroot, "/root/.ssh"), 0o700); err != nil {
		return err
	}
	os.Chmod(filepath.Join(buildroot, "/root/.ssh"), 0o700)
	if err := writeImageFile(buildroot, imageAuthorizedKey, []byte(strings.Join(keys, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	if err := writeImageFile(buildroot, imageRunDropIn, []byte(runDropIn(r.SSH)), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "ssh %d\n", r.SSH.Port)
	return nil
}

// runDropIn makes tpm2-kira.service start the SSH server, and hold as long
// as the setting says - without a limit, the unit may not time out either.
func runDropIn(s SSHConfig) string {
	timeout := "infinity"
	if s.Hold > 0 {
		// The unit's own margin over its 90 s hold, kept.
		timeout = fmt.Sprintf("%d", s.Hold+90)
	}
	return fmt.Sprintf(`# Written by 'tpm2-kira remote initramfs' from /etc/tpm2-kira/control.conf
# (TPM2_KIRA_SSH_*), for the boot image alone.
[Unit]
Wants=systemd-networkd.service

[Service]
TimeoutStartSec=%s
Environment="TPM2_KIRA_REMOTE=--ssh=%d --ssh-hold=%d --ssh-hostkeys=%s"
`, timeout, s.Port, s.Hold, imageSSHHostKeys)
}

// ed25519AuthorizedKeys are the ssh-ed25519 lines of an authorized_keys
// file: tinysshd accepts no other kind. Options in front of the key type
// (from="...") are not understood by tinysshd either, so a line with them
// is left out too.
func ed25519AuthorizedKeys(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("the keys that may log in over SSH: %w", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); strings.HasPrefix(l, "ssh-ed25519 ") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
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
