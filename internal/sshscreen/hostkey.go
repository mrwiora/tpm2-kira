package sshscreen

import (
	"fmt"
	"os"
	"time"

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
// key, and the console shows its fingerprint to compare. The CA stays open
// for the code screen: PCR 15, which the CA's policy reads, closes it
// together with every slot object (whose codes, boot key and release key
// the code screen still uses) when the code screen is over - run's close,
// and the image's after it (Close). Without a TPM there is no key.
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
	var ca *hostkey.CA
	if persist.IsVar(caPath) {
		if err := mountEfivarfs(); err != nil {
			return hostKeyAtBoot{}, err
		}
	}
	loaded, err := hostkey.LoadCA(caPath)
	switch {
	case os.IsNotExist(err):
		hk, err = hostkey.TemporaryKey(tpmDev, fmt.Errorf("no SSH CA at %s", caPath), o)
	case err != nil:
		hk, err = hostkey.TemporaryKey(tpmDev, err, o)
	default:
		ca = loaded
		hk, err = hostkey.Issue(tpmDev, ca, o)
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

// closeTPMWait is how long Close waits for the TPM's device: longer than
// run's, since a TPM that does not come stops a resume from hibernation.
var closeTPMWait = 30 * time.Second

// Close closes the boot - PCR 15 extended with aSSH's close event - and
// does nothing else: every slot object (the TOTP key, the sealed
// machine-id, the boot key, the release key) and the SSH CA require PCR 15
// at zero in their own policies, so none can be used until the next boot.
// What the boot image runs when the code screen is over (run itself, then
// systemd: tpm2-kira-close.service; initramfs-tools: init-bottom) and right
// before a resume from hibernation. A resume starts the TPM afresh, which
// sets PCR 15 back to zero, and the resumed system does not run the code
// screen. It needs no CA file and no assh.conf. A TPM that does not come,
// or an extend the TPM refuses, is an error: the boot, or the resume, must
// not go on.
func Close(tpmPath string) error {
	if !tpmdev.AwaitNode(tpmPath, closeTPMWait) {
		return fmt.Errorf("%s did not appear within %s: the boot is not closed (PCR 15)", tpmPath, closeTPMWait)
	}
	return CloseNow(tpmPath)
}

// CloseNow is Close without the wait for the TPM's device: run's close at
// the end of the code screen, which has waited for it at its start.
func CloseNow(tpmPath string) error {
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("the boot is not closed (PCR 15): %w", err)
	}
	defer tpmDev.Close()
	if err := hostkey.Close(tpmDev); err != nil {
		return fmt.Errorf("the boot is not closed: %w", err)
	}
	return nil
}
