package admin

import (
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/internal/machineid"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// keepMachineID keeps the sealed machine-id (package machineid) current:
// sealed again when slot 0 was made again, the signing key changed or
// /etc/machine-id did. Without slot 0 nothing is sealed. A failure is said,
// never fatal: the boot only goes without the machine-id.
func keepMachineID(tpmDev transport.TPM, out io.Writer) {
	data, err := nvslot.ReadRecord(machineid.Slot)
	if err != nil {
		return
	}
	sb, err := nvslot.UnmarshalSealedBlob(data)
	if err != nil {
		return
	}
	id, err := machineid.ReadID(machineid.EtcPath)
	if err != nil {
		fmt.Fprintf(out, "The machine-id is not sealed for the boot image: %v\n", err)
		return
	}
	if s, err := machineid.Load(); err == nil && s.Current(sb, id) {
		return
	}
	s, err := machineid.Seal(tpmDev, sb, id)
	if err == nil {
		err = s.Save()
	}
	if err != nil {
		fmt.Fprintf(out, "The machine-id is not sealed for the boot image: %v - its network asks with the copied DHCP identity alone\n", err)
		return
	}
	fmt.Fprintf(out, "Sealed the machine-id under slot 0's policy in the EFI variable KIRAmachineID: the boot image releases it before its network starts.\n")
}

// keepMachineIDAt is keepMachineID with the TPM at tpmPath.
func keepMachineIDAt(tpmPath string) {
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return
	}
	defer tpmDev.Close()
	keepMachineID(tpmDev, os.Stdout)
}

// removeMachineID removes the sealed machine-id with slot 0, whose policy
// it is sealed under; it says so when there was one.
func removeMachineID(out io.Writer) error {
	ok, err := machineid.Remove()
	if ok {
		fmt.Fprintln(out, "Removed the sealed machine-id (the EFI variable KIRAmachineID)")
	}
	return err
}
