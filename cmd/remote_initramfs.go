package cmd

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
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
//	ssh PORT                the SSH server ('run' itself; nothing for the hook to add)
//	hostkey FINGERPRINT     the host key sealed into the image, for the hook to say
//	warning TEXT            said by the hook, the build goes on
//
// A setting that cannot make a working image (Problem, a host key that is
// missing or cannot be sealed) is an error, exit status 2: the hook then adds neither network nor SSH
// and says why - the image still boots, with the code screen at the
// console.

// The paths in the image.
const (
	imageNetworkFile    = "/etc/systemd/network/10-tpm2-kira.network"
	ImageAuthorizedKeys = "/root/.ssh/authorized_keys"
	imageRunDropIn      = "/etc/systemd/system/tpm2-kira.service.d/remote.conf"
)

// RemoteInitramfsCommand implements 'remote initramfs'.
func RemoteInitramfsCommand(configPath, buildroot, tpmPath string, out io.Writer) error {
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
	var sealed []byte
	var fingerprint string
	if r.SSH.On {
		// Checked before anything is written: an image half with SSH is
		// worse than one without.
		var skipped int
		if keys, skipped, err = authorizedKeys(r.SSH.AuthorizedKeys); err != nil {
			return err
		}
		if len(keys) == 0 {
			return fmt.Errorf("%s holds no key without options: nobody could log in", r.SSH.AuthorizedKeys)
		}
		if skipped > 0 {
			defer fmt.Fprintf(out, "warning %d line(s) of %s left out: options in front of the key are not honoured, and what does not parse is no key\n", skipped, r.SSH.AuthorizedKeys)
		}
		key, err := loadHostKey(r.SSH.HostKey)
		if err != nil {
			return err
		}
		if sealed, err = sealForImage(key, tpmPath); err != nil {
			return err
		}
		fingerprint = hostKeyFingerprint(key.Public().(ed25519.PublicKey))
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
	if err := writeImageFile(buildroot, ImageSealedHostKey, sealed, 0o600); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(buildroot, "/root/.ssh"), 0o700); err != nil {
		return err
	}
	os.Chmod(filepath.Join(buildroot, "/root/.ssh"), 0o700)
	if err := writeImageFile(buildroot, ImageAuthorizedKeys, []byte(strings.Join(keys, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	if err := writeImageFile(buildroot, imageRunDropIn, []byte(runDropIn(r.SSH)), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "ssh %d\n", r.SSH.Port)
	fmt.Fprintf(out, "hostkey %s from %s, sealed to PCR 0+7\n", fingerprint, r.SSH.HostKey)
	return nil
}

// sealForImage seals the host key to the TPM at tpmPath: the file of the
// image. A var for the tests without a TPM.
var sealForImage = func(key ed25519.PrivateKey, tpmPath string) ([]byte, error) {
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("the SSH host key is sealed to the TPM: %w", err)
	}
	defer tpmDev.Close()
	s, err := sealHostKey(tpmDev, key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(s)
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
Environment="TPM2_KIRA_REMOTE=--ssh=%d --ssh-hold=%d --ssh-hostkey=%s"
`, timeout, s.Port, s.Hold, ImageSealedHostKey)
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
	var out []string
	skipped := 0
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		_, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err != nil || len(opts) > 0 {
			skipped++
			continue
		}
		out = append(out, l)
	}
	return out, skipped, nil
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
