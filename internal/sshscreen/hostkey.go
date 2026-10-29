package sshscreen

import (
	"fmt"
	"os"

	"github.com/tpm2-trust/assh/server"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
	"github.com/tpm2-trust/assh/config"
	"github.com/tpm2-trust/assh/hostkey"
	"github.com/tpm2-trust/assh/persist"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// hostKeyAtBoot is what the SSH server serves.
type hostKeyAtBoot struct {
	Signer      ssh.Signer
	Fingerprint string // the host key's
	CA          string // the CA's fingerprint, "" for a temporary key
	Slot        int    // the slot that let the CA certify, -1 for a temporary key
	Temporary   string // why the CA did not certify the key, "" when it did
}

// PrepareHostKey has the TPM make this boot's host key - of conf's type,
// with its key id and principals - and the CA conf names certify it. When it cannot (a firmware or Secure Boot update since
// the build, another TPM, no CA), the key is temporary: made in the TPM
// all the same, not certified, so the ssh client warns of an unknown host
// key, and the console shows its fingerprint to compare. Either way the
// CA's window is closed after. Without a TPM there is no key.
func PrepareHostKey(tpmPath string, conf config.Config) (hostKeyAtBoot, error) {
	caPath := conf.CA
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return hostKeyAtBoot{}, fmt.Errorf("no TPM: %w", err)
	}
	defer tpmDev.Close()
	// The host key's authorization value stays in this process alone.
	hostkey.NoDump()
	o := hostkey.IssueOptions{
		Type:       conf.HostKeyType,
		KeyID:      conf.KeyID,
		Principals: conf.Principals,
		Open:       func() (transport.TPMCloser, error) { return tpmdev.Open(tpmPath) },
	}
	var hk *hostkey.HostKey
	if persist.IsVar(caPath) {
		if err := mountEfivarfs(); err != nil {
			return hostKeyAtBoot{}, err
		}
	}
	ca, err := hostkey.LoadCA(caPath)
	switch {
	case os.IsNotExist(err):
		hk, err = hostkey.TemporaryKey(tpmDev, fmt.Errorf("no SSH CA at %s", caPath), o)
	case err != nil:
		hk, err = hostkey.TemporaryKey(tpmDev, err, o)
	default:
		hk, err = hostkey.Issue(tpmDev, ca, o)
		if err == nil && ca.Window != 0 {
			err = hostkey.Close(tpmDev, ca.Window, sshCAWindowEvent)
		}
	}
	if err != nil {
		return hostKeyAtBoot{}, err
	}
	if hk.Temporary != nil {
		return hostKeyAtBoot{Signer: hk.SSH(), Fingerprint: hk.Fingerprint(), Slot: -1, Temporary: "the SSH CA did not certify a key: " + hk.Temporary.Error()}, nil
	}
	return hostKeyAtBoot{Signer: hk.SSH(), Fingerprint: hk.Fingerprint(), CA: ca.Fingerprint(), Slot: hk.Slot}, nil
}

// mountEfivarfs mounts efivarfs where the boot image has not: systemd does
// in its initrd, initramfs-tools does not. A machine booted without UEFI
// has no variables, and no CA.
func mountEfivarfs() error {
	var st unix.Statfs_t
	if unix.Statfs(efivars, &st) == nil && st.Type == unix.EFIVARFS_MAGIC {
		return nil
	}
	if _, err := os.Stat(efivars); err != nil {
		return nil
	}
	if err := unix.Mount("efivarfs", efivars, "efivarfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mounting efivarfs: %w", err)
	}
	return nil
}

// sshCAWindowEvent is what closes the window.
const sshCAWindowEvent = "tpm2-kira: ssh ca closed"

// efivars is where efivarfs is mounted.
const efivars = "/sys/firmware/efi/efivars"

// AuthorizedKeys are the keys of an authorized_keys file that may log in,
// one per line as the file has them, and how many lines were left out: a
// line with options in front of the key (from="...", command="...") is
// not honoured by 'ssh-child', so it does not let anyone in either.
func AuthorizedKeys(path string) ([]string, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("the keys that may log in over SSH: %w", err)
	}
	keys, skipped := server.ParseAuthorizedKeys(data)
	return keys, skipped, nil
}
