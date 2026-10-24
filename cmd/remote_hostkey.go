package cmd

// The SSH server's host key at boot (docs/SSH.md §4), from assh
// (github.com/tpm2-trust/assh/hostkey).
//
// The image is unencrypted, so a key stored in it serves anyone who can
// read /boot to impersonate the machine. Instead this machine has a
// certificate authority in its TPM - the SSH CA, created by control, never
// exported - which signs only while PCR 0 (firmware) and PCR 7 (Secure
// Boot state and keys) hold values the signing key approved. At every boot
// 'run' has the TPM make a new host key under its NULL hierarchy, gone at
// the next reboot, and the CA certify it, at the start of the code screen:
// the boot holds ahead of the OS separator then, which moves PCR 0 and 7
// on, so nothing later in this boot gets a certificate. The clients trust
// the CA (a known_hosts line '@cert-authority'), not a key, so a new key at
// every boot asks them nothing.
//
// The approved values are those of tpm2-kira's measure point, replayed
// from the firmware event log, not the registers of the running system
// (measurepoint.go). control approves them, with the signing key, when the
// CA is created and when a firmware or Secure Boot update has changed
// them; the image carries the approval of the values its boot will meet.
// Without one the image is built without SSH; an image whose approval no
// longer fits (an update since the build) serves a throwaway key that the
// console names.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/hostkey"
	"golang.org/x/crypto/ssh"
)

const (
	// DefaultSSHCA is the SSH CA's file, its public key beside it (.pub).
	DefaultSSHCA = "/etc/tpm2-kira/ssh_ca.json"
	// ImageSSHCA is the CA in the image, with the one approval its boot
	// needs.
	ImageSSHCA = "/etc/tpm2-kira/ssh/ca.json"
	// sshCARef binds the signing key's approvals to this CA's use.
	sshCARef = "tpm2-kira ssh ca"
)

// sshCAUnapproved is why the image has no SSH server while the signing key
// has not approved the next boot's values.
const sshCAUnapproved = "the SSH CA has no approval of PCR 0 and 7 as the next boot meets them (a new CA, or a firmware or Secure Boot update): signed when you quit control"

// sshCAPCRs are the registers the CA is bound to: the firmware and the
// Secure Boot state. Neither changes with the image, so a kernel update
// needs no new approval; both are final before tpm2-kira runs.
var sshCAPCRs = []int{0, 7}

// sshCABank is the PCR bank the CA is bound to: SHA-256 where the TPM has
// it.
func sshCABank(tpmDev transport.TPM) hostkey.Bank {
	if TPMHasPCRBank(tpmDev, PCRHashAlgoSHA256) {
		return hostkey.SHA256
	}
	return hostkey.SHA1
}

// sshCAValues are the CA's PCRs as they will be at the next boot's code
// screen.
func sshCAValues(tpmDev transport.TPM, ca *hostkey.CA) (map[int][]byte, error) {
	specs := make([]PCRSpec, len(ca.PCRs))
	for i, idx := range ca.PCRs {
		specs[i] = PCRSpec{Index: idx, Source: PCRSourceEventlog}
	}
	r, err := ReadPCRValues(tpmDev, specs, PCRHashAlgo(ca.Bank), MeasurePointModeSetting, MeasurePointBeforeSeparator, false)
	if err != nil {
		return nil, fmt.Errorf("the values of %s at boot cannot be told from the event log: %w", hostkey.PCRList(ca.PCRs), err)
	}
	return r.Values, nil
}

// createSSHCA makes the CA in the TPM, has signer approve the next boot's
// values, and writes it with its public key.
func createSSHCA(path, tpmPath string, typ hostkey.Type, signer crypto.Signer) (*hostkey.CA, error) {
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return nil, err
	}
	defer tpmDev.Close()
	ca, err := hostkey.CreateCA(tpmDev, typ, sshCABank(tpmDev), sshCAPCRs, signer.Public(), []byte(sshCARef))
	if err != nil {
		return nil, err
	}
	values, err := sshCAValues(tpmDev, ca)
	if err != nil {
		return nil, err
	}
	if err := ca.Approve(signer, values); err != nil {
		return nil, err
	}
	return ca, saveSSHCA(ca, path)
}

// approveSSHCA has signer approve the next boot's values: the CA keeps
// that approval alone, the states before it are not met again.
func approveSSHCA(path, tpmPath string, signer crypto.Signer) (*hostkey.CA, error) {
	st := readSSHCA(path, tpmPath)
	if st.CA == nil || st.Values == nil {
		return nil, errors.New(st.Err)
	}
	ca := st.CA.Only(func(hostkey.Approval) bool { return false })
	if err := ca.Approve(signer, st.Values); err != nil {
		return nil, err
	}
	return ca, saveSSHCA(ca, path)
}

// saveSSHCA writes the CA and its public key (.pub).
func saveSSHCA(ca *hostkey.CA, path string) error {
	if err := ca.Save(path); err != nil {
		return err
	}
	pub, err := ca.AuthorizedKey()
	if err != nil {
		return err
	}
	return os.WriteFile(path+".pub", pub, 0o644)
}

// sshCAState is what the image build and control know of the CA: whether
// it loads, and the approval of the next boot's values.
type sshCAState struct {
	CA       *hostkey.CA
	Err      string            // why there is no CA to use
	Values   map[int][]byte    // the next boot's values
	Approval *hostkey.Approval // theirs, nil when the signing key has not approved them
}

// readSSHCA reads the CA at path and the values of the next boot.
func readSSHCA(path, tpmPath string) sshCAState {
	ca, err := hostkey.LoadCA(path)
	if os.IsNotExist(err) {
		return sshCAState{Err: "no SSH CA: tpm2-kira control creates it in the TPM"}
	}
	if err != nil {
		return sshCAState{Err: err.Error()}
	}
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return sshCAState{CA: ca, Err: err.Error()}
	}
	defer tpmDev.Close()
	values, err := sshCAValues(tpmDev, ca)
	if err != nil {
		return sshCAState{CA: ca, Err: err.Error()}
	}
	return sshCAState{CA: ca, Values: values, Approval: ca.Approved(values)}
}

// hostKeyAtBoot is what the SSH server serves.
type hostKeyAtBoot struct {
	signer      ssh.Signer
	Fingerprint string // the host key's
	CA          string // the CA's fingerprint, "" for a throwaway key
	Throwaway   string // why the CA did not certify a key, "" when it did
}

// prepareHostKey has the CA in the image certify a new host key in the
// TPM. When it cannot (a firmware or Secure Boot update since the build,
// another TPM, no CA), a throwaway key is served instead: the ssh client
// then warns of an unknown host key, and the console shows the throwaway's
// fingerprint to compare.
func prepareHostKey(tpmPath, caPath string) (hostKeyAtBoot, error) {
	hk, why := certifiedHostKey(tpmPath, caPath)
	if hk != nil {
		return *hk, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return hostKeyAtBoot{}, err
	}
	s, err := ssh.NewSignerFromSigner(k)
	if err != nil {
		return hostKeyAtBoot{}, err
	}
	return hostKeyAtBoot{signer: s, Fingerprint: ssh.FingerprintSHA256(s.PublicKey()), Throwaway: why}, nil
}

// certifiedHostKey is this boot's host key with the CA's certificate, or
// nil and why not.
func certifiedHostKey(tpmPath, caPath string) (*hostKeyAtBoot, string) {
	ca, err := hostkey.LoadCA(caPath)
	if os.IsNotExist(err) {
		return nil, "the image holds no SSH CA"
	}
	if err != nil {
		return nil, err.Error()
	}
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return nil, "no TPM: " + err.Error()
	}
	defer tpmDev.Close()
	// The host key's authorization value stays in this process alone.
	hostkey.NoDump()
	hk, err := hostkey.Issue(tpmDev, ca, hostkey.IssueOptions{
		Type:  ca.Type,
		KeyID: "tpm2-kira boot",
		Open:  func() (transport.TPMCloser, error) { return OpenTPM(tpmPath) },
	})
	if err != nil {
		return nil, "the SSH CA did not certify a key: " + err.Error()
	}
	return &hostKeyAtBoot{signer: hk.SSH(), Fingerprint: hk.Fingerprint(), CA: ca.Fingerprint()}, ""
}
