package admin

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/hostkey"
	"github.com/tpm2-trust/assh/persist"
	"github.com/tpm2-trust/tpm2-kira/internal/efivars"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"
)

// The sweep (slot delete --yes --sweep, and control's "Delete everything"): what
// this or any earlier version of tpm2-kira left in the TPM and the EFI
// variables, by place - not by format: nothing found is read as a slot,
// a blob or a record, it is only named where its place says what it is.
//
//   - every NV index in tpm2-kira's range (nvslot.AppNVRAMStart-End), of this
//     version's layout, an earlier one's (the attestation blobs at
//     0x01803020-2F before blob version 10, say), or another program's;
//   - aSSH's NV indices of the SSH CA at their default handles - the counter,
//     the PIN, the SHA-1 switch and the window index aSSH had before PCR 15
//     closed the CA - which tpm2-kira's CA is the one user of on a machine of
//     tpm2-kira's;
//   - every EFI variable under tpm2-kira's GUID, and aSSH's KIRAasshCA, the
//     variable tpm2-kira's SSH CA is kept in.
//
// What a person was shown and said to take goes, whatever its shape: the
// one place where tpm2-kira removes an index of another shape without
// asking for it on its own (persist.Any, nvslot.RemoveSwept).

// asshSweepHandles are aSSH's NV handles of an SSH CA, and the window index of
// aSSH before PCR 15 closed the CA (d21cdb0).
var asshSweepHandles = []uint32{
	uint32(hostkey.DefaultCounterHandle), uint32(hostkey.DefaultPINHandle), uint32(hostkey.SHA1Handle), 0x01802915,
}

// sshCAVar is the EFI variable tpm2-kira's SSH CA is kept in (DefaultSSHCA).
const sshCAVar = "KIRAasshCA"

// sweepItem is one thing the sweep found: an NV index or an EFI variable.
type sweepItem struct {
	NV   uint32 // the index; 0 for a variable
	Var  string // the variable's file name, NAME-GUID; "" for an index
	What string // what its place says it is
}

func (s sweepItem) String() string {
	if s.Var != "" {
		return fmt.Sprintf("EFI variable %s  %s", s.Var, s.What)
	}
	return fmt.Sprintf("NV index 0x%08X  %s", s.NV, s.What)
}

// sweepFindings is everything at tpm2-kira's places now.
func sweepFindings(tpmDev transport.TPM) ([]sweepItem, error) {
	var out []sweepItem
	all, err := tpmdev.NVIndices(tpmDev, uint32(tpm2.TPMHTNVIndex)<<24)
	if err != nil {
		return nil, err
	}
	for _, idx := range all {
		switch {
		case idx >= nvslot.AppNVRAMStart && idx <= nvslot.AppNVRAMEnd:
			out = append(out, sweepItem{NV: idx, What: sweepRole(idx)})
		case isASSHSweepHandle(idx):
			out = append(out, sweepItem{NV: idx, What: "aSSH's index of an SSH CA (its counter, PIN, SHA-1 switch or an earlier window index)"})
		}
	}
	vars, err := sweepVars()
	return append(out, vars...), err
}

func isASSHSweepHandle(idx uint32) bool {
	for _, h := range asshSweepHandles {
		if h == idx {
			return true
		}
	}
	return false
}

// sweepRole names what an index in tpm2-kira's range is, by its place.
func sweepRole(idx uint32) string {
	if r := kiraIndexRole(idx); r != "" {
		return r
	}
	if idx >= nvslot.NVRAMSlotStart && idx <= nvslot.NVRAMSlotEnd {
		return fmt.Sprintf("slot #%d's place (an earlier version's blob)", nvslot.SlotNumber(idx))
	}
	return "in tpm2-kira's range: an earlier version's layout, or another program's"
}

// sweepVars are the EFI variables of tpm2-kira's GUID, and the SSH CA's.
func sweepVars() ([]sweepItem, error) {
	entries, err := os.ReadDir(efivars.Dir)
	if os.IsNotExist(err) {
		return nil, nil // no EFI variables on this machine
	}
	if err != nil {
		return nil, fmt.Errorf("the EFI variables at %s: %w", efivars.Dir, err)
	}
	var out []sweepItem
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, "-"+efivars.GUIDText):
			out = append(out, sweepItem{Var: name, What: "tpm2-kira's: " + varRole(strings.TrimSuffix(name, "-"+efivars.GUIDText))})
		case name == sshCAVar+"-"+persist.VarGUID:
			out = append(out, sweepItem{Var: name, What: "the SSH CA (aSSH's variable)"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Var < out[j].Var })
	return out, nil
}

// varRole names a variable of tpm2-kira's GUID.
func varRole(name string) string {
	switch {
	case strings.HasPrefix(name, "KIRAslot"):
		return "a slot's record"
	case name == "KIRAmachineID":
		return "the sealed machine-id"
	case name == "KIRAcloseReboot":
		return "the close's reboot count"
	}
	return "an earlier version's variable"
}

// sweepRemove removes what the sweep finds now, and says each; it gives how
// many it could not remove.
func sweepRemove(tpmDev transport.TPM, items []sweepItem) int {
	failed := 0
	for _, it := range items {
		fmt.Printf("Sweeping %s... ", it)
		var err error
		switch {
		case it.Var != "":
			if strings.HasSuffix(it.Var, "-"+efivars.GUIDText) {
				_, err = efivars.Remove(strings.TrimSuffix(it.Var, "-"+efivars.GUIDText))
			} else {
				_, err = persist.RemoveVar(persist.VarPrefix + it.Var)
			}
		case it.NV >= nvslot.AppNVRAMStart && it.NV <= nvslot.AppNVRAMEnd:
			_, err = nvslot.RemoveSwept(tpmDev, it.NV)
		default:
			_, err = persist.RemoveNV(tpmDev, tpm2.TPMHandle(it.NV), persist.Any)
		}
		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
			failed++
			continue
		}
		fmt.Println("done")
	}
	return failed
}
