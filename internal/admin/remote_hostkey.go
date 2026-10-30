package admin

// The SSH server's host key at boot (docs/SSH.md §4), from assh
// (github.com/tpm2-trust/assh/hostkey).
//
// The image is unencrypted, so a key stored in it serves anyone who can
// read /boot to impersonate the machine. Instead this machine has a
// certificate authority in its TPM - the SSH CA, created by control, never
// exported - which signs only while the PCRs hold values the signing key
// approved. At every boot 'run' has the TPM make a new host key under its
// NULL hierarchy, gone at the next reboot, and the CA certify it, at the
// start of the code screen, then closes the CA's window - its window index
// W, read-locked until the next boot - so nothing later in this boot gets a
// certificate. Before a resume from hibernation, which starts the TPM
// afresh, the boot image closes it again (tpm2-kira-boot close). The clients trust the CA (a known_hosts line
// '@cert-authority'), not a key, so a new key at every boot asks them
// nothing.
//
// The CA's slots are assh.conf's (remote_assh.go), scanned in order. When
// control creates the CA it writes two there, worked out for this machine.
// Slot 0, the higher confidence, reads what 'slot add' binds its slot 0 to:
// PCR 0 (firmware), 2 (option ROMs) and 7 (Secure Boot), and the image -
// PCR 11 with a unified kernel image, PCR 8 and 9 with GRUB. Slot 1, the
// lower, reads PCR 7 alone: a kernel update not approved yet, a new option
// ROM or a firmware update leave it standing.
//
// The CA, its approvals with it, lives in the EFI variable KIRAasshCA, not
// in the image: an approval of PCR 11 carried inside the image it measures
// would change that measurement. reseal - which the initramfs hooks run
// after every rebuild - and control approve the next boot's values in both
// slots with the signing key: those of tpm2-kira's measure point, replayed
// from the firmware event log and predicted from the image (measurepoint.go,
// ukipredict.go, grub_predict.go). A boot whose
// approvals no longer fit serves assh's temporary key, made in the TPM too
// but not certified, which the console names.

import (
	"crypto"
	"errors"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"os"
	"slices"

	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/config"
	"github.com/tpm2-trust/assh/hostkey"
	"github.com/tpm2-trust/assh/persist"
)

const (
	// DefaultSSHCA is the SSH CA: an EFI variable, assh's GUID.
	DefaultSSHCA = persist.VarPrefix + "KIRAasshCA"
	// DefaultSSHCAPub is the CA's public key, what clients trust.
	DefaultSSHCAPub = "/etc/tpm2-kira/ssh_ca.pub"
	// sshCARef binds the signing key's approvals to this CA's use.
	sshCARef = "tpm2-kira ssh ca"
)

// sshCAUnapproved is why the next boot serves a temporary key: no slot is
// approved for its values.
const sshCAUnapproved = "the SSH CA has no approval of the PCRs as the next boot meets them: approved when you quit control, and by slot approve after every image rebuild"

// sshCASlots are the slots worked out for this machine. Slot 0, the higher
// confidence, is decided from
// this boot's event log as 'slot add' decides its slot 0: the firmware, the
// option ROMs, the Secure Boot state, and the image's PCRs (11 with a
// unified kernel image, 8 and 9 with GRUB). Slot 1, the lower, is the
// Secure Boot state alone.
func sshCASlots(algo measure.PCRHashAlgo) (map[int][]int, error) {
	sel, _ := DefaultPCRSelection("", algo)
	specs, err := measure.ParsePCRSpecs(sel)
	if err != nil {
		return nil, err
	}
	var slot0 []int
	for _, s := range specs {
		slot0 = append(slot0, s.Index)
	}
	return map[int][]int{0: slot0, 1: {7}}, nil
}

// sshCABank is the PCR bank the CA is bound to: SHA-256 where the TPM has
// it.
func sshCABank(tpmDev transport.TPM) hostkey.Bank {
	if measure.TPMHasPCRBank(tpmDev, measure.PCRHashAlgoSHA256) {
		return hostkey.SHA256
	}
	return hostkey.SHA1
}

// sshCAValues are the CA's PCRs as they will be at the next boot's code
// screen: replayed from the event log (PCR 8 and 9 with GRUB's prediction),
// PCR 11 computed from the unified kernel image.
func sshCAValues(tpmDev transport.TPM, ca *hostkey.CA) (map[int][]byte, error) {
	var specs []measure.PCRSpec
	for _, idx := range ca.PCRs() {
		switch idx {
		case measure.TPM2PCRKernelBoot:
			uki := findUKI()
			if uki == "" {
				uki = measure.DefaultUKIPath
			}
			specs = append(specs, measure.PCRSpec{Index: idx, Source: measure.PCRSourceUKI, Command: uki})
		default:
			specs = append(specs, measure.PCRSpec{Index: idx, Source: measure.PCRSourceEventlog})
		}
	}
	r, err := measure.ReadPCRValues(tpmDev, specs, measure.PCRHashAlgo(ca.Bank), measure.MeasurePointModeSetting, measure.MeasurePointBeforeSeparator, false)
	if err != nil {
		return nil, fmt.Errorf("the values of %s at boot cannot be told: %w", hostkey.PCRList(ca.PCRs()), err)
	}
	return r.Values, nil
}

// approveSSHCASlots has signer approve values in every slot of ca.
func approveSSHCASlots(ca *hostkey.CA, signer crypto.Signer, values map[int][]byte) error {
	for _, s := range ca.Slots {
		if err := ca.Approve(signer, s.Number, values); err != nil {
			return err
		}
	}
	return nil
}

// createSSHCA makes the CA in the TPM as conf says - its key, the bank
// (this TPM's SHA-256 unless conf sets one), the slots (worked out for this
// machine unless conf has some; they go into conf), the window index and
// the policy ref - has signer approve the next boot's values, and writes it
// with its public key.
func createSSHCA(conf *config.Config, tpmPath string, signer crypto.Signer) (*hostkey.CA, error) {
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return nil, err
	}
	defer tpmDev.Close()
	if !conf.Set["ASSH_CA_BANK"] {
		conf.Bank = sshCABank(tpmDev)
	}
	if len(conf.Slots) == 0 {
		if conf.Slots, err = sshCASlots(measure.PCRHashAlgo(conf.Bank)); err != nil {
			return nil, err
		}
	}
	slot0, ok := conf.Slots[0]
	if !ok {
		return nil, errors.New("assh.conf names no slot 0 (ASSH_CA_SLOT_0): the CA is created with it")
	}
	ca, err := hostkey.CreateCA(tpmDev, signer.Public(), hostkey.CAOptions{Type: conf.CAType, Bank: conf.Bank, PCRs: slot0, WindowHandle: tpm2.TPMHandle(conf.WindowHdl), PolicyRef: []byte(conf.PolicyRef)})
	if err != nil {
		return nil, err
	}
	if _, err := conf.Match(ca); err != nil {
		return nil, err
	}
	values, err := sshCAValues(tpmDev, ca)
	if err != nil {
		return nil, err
	}
	if err := approveSSHCASlots(ca, signer, values); err != nil {
		return nil, err
	}
	return ca, saveSSHCA(ca, conf.CA)
}

// approveSSHCA has signer approve the next boot's values in every slot -
// conf's: a slot added or changed there is the CA's from now on. The CA
// keeps those approvals alone, the states before them are not met again.
func approveSSHCA(conf config.Config, tpmPath string, signer crypto.Signer) (*hostkey.CA, error) {
	st := readSSHCA(conf, tpmPath)
	if st.CA == nil || st.Values == nil {
		return nil, errors.New(st.Err)
	}
	ca := st.CA.Only(func(hostkey.Approval) bool { return false })
	if err := approveSSHCASlots(ca, signer, st.Values); err != nil {
		return nil, err
	}
	return ca, saveSSHCA(ca, conf.CA)
}

// syncSSHCASlots makes the slots of the CA conf names conf's and writes
// it when they changed: a slot taken away there goes with its approvals,
// which needs no signing key; one added or changed is approved by reseal
// or control after. No CA is nothing to do.
func syncSSHCASlots(conf config.Config) (changed bool, err error) {
	ca, err := hostkey.LoadCA(conf.CA)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if changed, err = conf.Match(ca); err != nil || !changed {
		return false, err
	}
	return true, saveSSHCA(ca, conf.CA)
}

// saveSSHCA writes the CA and its public key (sshCAPub).
func saveSSHCA(ca *hostkey.CA, path string) error {
	if err := ca.Save(path); err != nil {
		return err
	}
	pub, err := ca.AuthorizedKey()
	if err != nil {
		return err
	}
	return os.WriteFile(sshCAPub(path), pub, 0o644)
}

// sshCAThere says whether a CA is at path (in its EFI variable, or a file).
func sshCAThere(path string) bool {
	if persist.IsVar(path) {
		_, err := persist.ReadVar(path)
		return err == nil
	}
	_, err := os.Stat(path)
	return err == nil
}

// removeSSHCA removes the SSH CA at path the way aSSH removes a CA
// (hostkey.RemoveCA: the variable or file, and in the TPM only what is
// the CA's), then its public key. It gives what went.
func removeSSHCA(tpmPath, path string) ([]string, error) {
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return nil, err
	}
	defer tpmDev.Close()
	removed, err := hostkey.RemoveCA(tpmDev, path, hostkey.Handles{})
	if err != nil {
		return removed, err
	}
	pub := sshCAPub(path)
	if err := os.Remove(pub); err == nil {
		removed = append(removed, pub)
	} else if !os.IsNotExist(err) {
		return removed, err
	}
	return removed, nil
}

// sshCAPub is where the public key of the CA at path goes: DefaultSSHCAPub
// for the variable, beside a file (.pub).
func sshCAPub(path string) string {
	if persist.IsVar(path) {
		return DefaultSSHCAPub
	}
	return path + ".pub"
}

// sshCAState is what the image build and control know of the CA: whether
// it loads, and the approvals of the next boot's values. CA has assh.conf's
// slots, as reseal and control will give them to it.
type sshCAState struct {
	CA     *hostkey.CA
	Err    string         // why there is no CA to use
	Values map[int][]byte // the next boot's values
	// Approvals are those of the next boot's values, one for each slot
	// that has one, in slot order: the first is the one the boot uses.
	Approvals []hostkey.Approval
}

// Approved reports whether a slot lets the CA certify at the next boot.
func (s sshCAState) Approved() bool { return len(s.Approvals) > 0 }

// Unapproved are the slots without an approval of the next boot's values.
func (s sshCAState) Unapproved() []int {
	var n []int
	for _, sl := range s.CA.Slots {
		if !slices.ContainsFunc(s.Approvals, func(a hostkey.Approval) bool { return a.Slot == sl.Number }) {
			n = append(n, sl.Number)
		}
	}
	return n
}

// loadSSHCA reads the CA conf names, with conf's slots: what the image
// build needs to know.
func loadSSHCA(conf config.Config) sshCAState {
	ca, err := hostkey.LoadCA(conf.CA)
	if os.IsNotExist(err) {
		return sshCAState{Err: "no SSH CA: tpm2-kira control creates it in the TPM"}
	}
	if err != nil {
		return sshCAState{Err: err.Error()}
	}
	if _, err := conf.Match(ca); err != nil {
		return sshCAState{Err: "assh.conf: " + err.Error()}
	}
	return sshCAState{CA: ca}
}

// readSSHCA reads the CA conf names, with conf's slots, and the values of
// the next boot.
func readSSHCA(conf config.Config, tpmPath string) sshCAState {
	st := loadSSHCA(conf)
	if st.CA == nil {
		return st
	}
	ca := st.CA
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return sshCAState{CA: ca, Err: err.Error()}
	}
	defer tpmDev.Close()
	values, err := sshCAValues(tpmDev, ca)
	if err != nil {
		return sshCAState{CA: ca, Err: err.Error()}
	}
	return sshCAState{CA: ca, Values: values, Approvals: nextApprovals(ca, values)}
}

// nextApprovals are ca's approvals of values, one for each slot that has
// one, in slot order.
func nextApprovals(ca *hostkey.CA, values map[int][]byte) []hostkey.Approval {
	var as []hostkey.Approval
	for _, s := range ca.Slots {
		if a := ca.Only(func(a hostkey.Approval) bool { return a.Slot == s.Number }).Approved(values, nil); a != nil {
			as = append(as, *a)
		}
	}
	return as
}
