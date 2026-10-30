package admin

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/mrwiora/tpm2-kira/internal/machineid"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// NVRAMList lists all defined NVRAM indices in the TPM
func NVRAMList(tpmPath string, nvramIndex uint32, debug bool) error {
	// Open TPM
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	// Get capability to list NVRAM indices
	getCap := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTNVIndex) << 24,
		PropertyCount: 128,
	}

	capResp, err := getCap.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to get NVRAM capabilities: %w", err)
	}

	handles, err := capResp.CapabilityData.Data.Handles()
	if err != nil {
		return fmt.Errorf("failed to parse capability data: %w", err)
	}

	if debug {
		// The query caps at 128 handles, so a full result may be truncated.
		fmt.Printf("TPM %s returned %d NV handle(s) (query limit 128)\n\n", tpmPath, len(handles.Handle))
	}

	// The slots: each a record (its EFI variable) and its indices in the
	// TPM; what is left of one without the other is named.
	if states := nvslot.SlotStates(tpmDev); len(states) > 0 {
		fmt.Printf("Slots:\n======\n\n")
		for _, st := range states {
			rec := "no record"
			if data, err := nvslot.ReadRecord(st.Index); err == nil {
				rec = fmt.Sprintf("record KIRAslot%d, %d bytes", nvslot.SlotNumber(st.Index), len(data))
			}
			fmt.Printf("  #%d (0x%08X): %s", nvslot.SlotNumber(st.Index), st.Index, rec)
			if o := st.Orphaned(); o != "" {
				fmt.Printf(" - %s", o)
			}
			fmt.Println()
		}
		fmt.Println()
	}

	if len(handles.Handle) == 0 {
		fmt.Println("No NVRAM indices defined in TPM")
		return nil
	}

	fmt.Printf("Defined NVRAM Indices:\n")
	fmt.Printf("======================\n\n")

	for _, handle := range handles.Handle {
		// Read public area for each index
		readPublic := tpm2.NVReadPublic{
			NVIndex: handle,
		}

		readPublicResp, err := readPublic.Execute(tpmDev)
		if err != nil {
			fmt.Printf("Index: 0x%08X - Error reading details: %v\n", handle, err)
			continue
		}

		nvPublic, err := readPublicResp.NVPublic.Contents()
		if err != nil {
			fmt.Printf("Index: 0x%08X - Error parsing details\n", handle)
			continue
		}

		fmt.Printf("Index: 0x%08X\n", handle)
		if role := kiraIndexRole(uint32(handle)); role != "" {
			fmt.Printf("  tpm2-kira: %s\n", role)
		}
		fmt.Printf("  Size: %d bytes\n", nvPublic.DataSize)
		fmt.Printf("  Name Algorithm: %v\n", nvPublic.NameAlg)

		// Show key attributes
		attrs := []string{}
		if nvPublic.Attributes.OwnerWrite {
			attrs = append(attrs, "OwnerWrite")
		}
		if nvPublic.Attributes.OwnerRead {
			attrs = append(attrs, "OwnerRead")
		}
		if nvPublic.Attributes.AuthWrite {
			attrs = append(attrs, "AuthWrite")
		}
		if nvPublic.Attributes.AuthRead {
			attrs = append(attrs, "AuthRead")
		}
		if nvPublic.Attributes.Written {
			attrs = append(attrs, "Written")
		}
		if nvPublic.Attributes.WriteDefine {
			attrs = append(attrs, "WriteDefine")
		}
		if nvPublic.Attributes.ReadSTClear {
			attrs = append(attrs, "ReadSTClear")
		}

		fmt.Printf("  Attributes: %v\n", attrs)

		// Check if this is our configured index
		if handle == tpm2.TPMHandle(nvramIndex) {
			fmt.Printf("  ** Current configured index **\n")
		}

		fmt.Println()
	}

	return nil
}

// NVRAMDelete deletes the specified NVRAM index
func NVRAMDelete(tpmPath string, nvramIndex uint32, debug bool) error {
	if err := nvslot.ValidateNVRAMIndex(nvramIndex); err != nil {
		return fmt.Errorf("invalid NVRAM index: %w", err)
	}
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	// A slot is deleted whole (nvslot.RemoveSlot): its record, then its
	// generation index and record counter. Without its counter no record of
	// the slot is accepted by the gate again, and a new counter starts above
	// every value this one had. A companion index named by itself goes
	// alone. Only what has tpm2-kira's shape is taken.
	var removed []nvslot.Removed
	if nvslot.ValidateBlobIndex(nvramIndex) == nil && nvramIndex != nvslot.BootSettingsIndex {
		removed, err = nvslot.RemoveSlot(tpmDev, nvramIndex)
	} else {
		ok, rerr := nvslot.RemoveIndex(tpmDev, nvramIndex)
		if ok {
			what := kiraIndexRole(nvramIndex)
			if what == "" {
				what = "an index of tpm2-kira's"
			}
			removed = append(removed, nvslot.Removed{Index: nvramIndex, What: what})
		}
		err = rerr
	}
	for _, r := range removed {
		if nvslot.ValidateBlobIndex(r.Index) == nil && strings.HasPrefix(r.What, "the record") {
			fmt.Printf("Successfully deleted %s\n", r.What)
			continue
		}
		fmt.Printf("Successfully deleted NVRAM index 0x%08X: %s\n", r.Index, r.What)
	}
	// The sealed machine-id goes with slot 0: its policy is the slot's.
	if nvramIndex == machineid.Slot && err == nil {
		err = removeMachineID(os.Stdout)
	}
	if err != nil {
		return err
	}
	if len(removed) == 0 {
		return fmt.Errorf("NVRAM index 0x%08X: nothing to delete (it does not exist)", nvramIndex)
	}
	return nil
}

// kiraIndexRole says what tpm2-kira keeps at an NV index, or "" for an
// index that is not one of its own.
func kiraIndexRole(index uint32) string {
	switch {
	case index == nvslot.BootSettingsIndex:
		return "the boot settings (debug at boot)"
	case index >= nvslot.GenerationIndex(nvslot.NVRAMSlotStart) && index <= nvslot.GenerationIndex(nvslot.NVRAMSlotEnd):
		return fmt.Sprintf("generation index of slot #%d", nvslot.SlotNumber(index-nvslot.GenerationIndexOffset))
	case index >= nvslot.AttestCounterIndex(nvslot.NVRAMSlotStart) && index <= nvslot.AttestCounterIndex(nvslot.NVRAMSlotEnd):
		return fmt.Sprintf("record counter of slot #%d's attestation part", index-nvslot.AttestCounterStart)
	}
	return ""
}

// kiraLeftovers returns the indices that belong to no slot - a record
// counter whose slot (generation index, record) is gone, as an
// interrupted command leaves it - and the boot settings.
func kiraLeftovers(tpmDev transport.TPM, debug bool) []uint32 {
	var out []uint32
	if tpmdev.NVRAMIndexExists(tpmDev, nvslot.BootSettingsIndex) {
		out = append(out, nvslot.BootSettingsIndex)
	}
	slots := map[uint32]bool{}
	for _, st := range nvslot.SlotStates(tpmDev) {
		slots[st.Index] = true
	}
	for idx := uint32(nvslot.NVRAMSlotStart); idx <= nvslot.NVRAMSlotEnd; idx++ {
		if slots[idx] {
			continue
		}
		if c := nvslot.AttestCounterIndex(idx); tpmdev.NVRAMIndexExists(tpmDev, c) {
			out = append(out, c)
		}
	}
	return out
}

// NVRAMDeleteCommand implements 'slot delete'. A slot is one thing: its
// blob holds the TOTP key and the phone enrolment, and its generation index
// and record counter go with it. With an index that slot is deleted;
// without one, every slot and whatever an interrupted command left behind.
func NVRAMDeleteCommand(tpmPath string, nvramIndex uint32, yes bool, debug bool) error {
	if nvramIndex != 0 {
		if err := NVRAMDelete(tpmPath, nvramIndex, debug); err != nil {
			return err
		}
		// What outlives the blob by design of this command - a LUKS keyslot
		// bound to the slot, a recovery blob - makes the slot dirty; say so.
		fmt.Print(slotKeyslotAdvice(tpmPath))
		return nil
	}

	// Everything mode - discover what there is, then delete each.
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	// Every slot of which anything is there: its generation index or its
	// record (a record without its slot goes as well).
	var slots []uint32
	for _, st := range nvslot.SlotStates(tpmDev) {
		slots = append(slots, st.Index)
	}
	enrolled := 0
	for _, idx := range slots {
		if _, err := phonegate.LoadAttestBlob(tpmDev, idx); err == nil {
			enrolled++
		}
	}
	leftovers := kiraLeftovers(tpmDev, debug)
	tpmDev.Close()
	// The SSH CA is tpm2-kira's too: everything of tpm2-kira takes it.
	caPath := ""
	if conf, err := loadSSHConf(sshConfPath(controlConfigPath()), controlConfigPath()); err == nil && sshCAThere(conf.CA) {
		caPath = conf.CA
	}

	_, midErr := machineid.Load()
	mid := midErr == nil
	total := len(slots) + len(leftovers)
	if caPath != "" {
		total++
	}
	if mid {
		total++
	}
	if total == 0 {
		return fmt.Errorf("nothing of tpm2-kira found: no sealed secrets in NVRAM slots 0x%08X – 0x%08X, no leftover indices, no SSH CA, no sealed machine-id",
			nvslot.NVRAMSlotStart, nvslot.NVRAMSlotEnd)
	}

	if len(slots) > 0 {
		fmt.Printf("Found %d sealed slot(s) to delete:", len(slots))
		for _, slotIdx := range slots {
			fmt.Printf(" #%d", nvslot.SlotNumber(slotIdx))
		}
		if enrolled > 0 {
			fmt.Printf(" (%d with phones enrolled)", enrolled)
		}
		fmt.Println()
	}
	if len(leftovers) > 0 {
		fmt.Printf("Found %d leftover index(es) that belong to no slot:\n", len(leftovers))
		for _, idx := range leftovers {
			fmt.Printf("  0x%08X  %s\n", idx, kiraIndexRole(idx))
		}
	}
	if caPath != "" {
		fmt.Printf("Found the SSH CA %s (and %s)\n", caPath, sshCAPub(caPath))
	}
	if mid {
		fmt.Println("Found the sealed machine-id (the EFI variable KIRAmachineID)")
	}
	if err := confirmDeleteAll(len(slots), enrolled, len(leftovers), caPath != "", yes); err != nil {
		return err
	}
	fmt.Println()

	failed := 0
	for _, slotIdx := range slots {
		fmt.Printf("Deleting slot #%d (0x%08X)... ", nvslot.SlotNumber(slotIdx), slotIdx)
		if err := NVRAMDelete(tpmPath, slotIdx, debug); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			failed++
		}
	}
	if len(leftovers) > 0 {
		tpmDev, err := tpmdev.Open(tpmPath)
		if err != nil {
			return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
		}
		for _, idx := range leftovers {
			if !tpmdev.NVRAMIndexExists(tpmDev, idx) {
				continue // went with its slot
			}
			fmt.Printf("Deleting leftover 0x%08X... ", idx)
			if _, err := nvslot.RemoveIndex(tpmDev, idx); err != nil {
				fmt.Printf("FAILED: %v\n", err)
				failed++
				continue
			}
			fmt.Println("done")
		}
		tpmDev.Close()
	}
	if mid {
		if err := removeMachineID(os.Stdout); err != nil {
			fmt.Printf("Deleting the sealed machine-id FAILED: %v\n", err)
			failed++
		}
	}
	if caPath != "" {
		fmt.Printf("Deleting the SSH CA %s... ", caPath)
		if removed, err := removeSSHCA(tpmPath, caPath); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			failed++
		} else {
			fmt.Printf("done (%s)\n", strings.Join(removed, ", "))
		}
	}

	fmt.Println()
	if failed > 0 {
		return fmt.Errorf("%d of %d item(s) failed to delete", failed, total)
	}
	fmt.Printf("All %d item(s) deleted successfully\n", total)
	if enrolled > 0 {
		fmt.Println("The phones still list this machine; remove it there too.")
		fmt.Println("The initramfs may still carry the Bluetooth gate; its next build leaves it out.")
	}
	fmt.Print(slotKeyslotAdvice(tpmPath))
	return nil
}

func confirmDeleteAll(slots, enrolled, leftovers int, ca, yes bool) error {
	if yes {
		return nil
	}
	total := slots + leftovers
	if ca {
		total++
	}
	tty := setupTerminal()
	if tty == nil {
		return fmt.Errorf("refusing to delete all %d item(s) without confirmation; nothing was deleted.\n"+
			"  Each deleted slot means re-enrolling its authenticator and its phones.\n"+
			"  To go ahead, run:\n"+
			"      tpm2-kira slot delete --yes\n"+
			"  or delete one slot with --nvram <slot>", total)
	}
	if slots > 0 {
		fmt.Println("This deletes the sealed secret of every slot listed; each authenticator must then be re-enrolled.")
	}
	if enrolled > 0 {
		fmt.Println("The phones enrolled for those slots go with them; each must then be enrolled again.")
	}
	if ca {
		fmt.Println("The SSH CA goes too: clients that trust it must trust a new one, which control makes when SSH is set up again.")
	}
	fmt.Printf("Type 'yes' to delete all %d item(s): ", total)
	answer, _ := tty.ReadString('\n')
	if strings.TrimSpace(answer) != "yes" {
		return fmt.Errorf("not confirmed; nothing was deleted")
	}
	return nil
}

// slotStatus shows a slot: its record (the EFI variable), what it keeps in
// the TPM, and what the record holds.
func slotStatus(tpmDev transport.TPM, idx uint32, debug bool) error {
	n := nvslot.SlotNumber(idx)
	fmt.Printf("Slot %d (0x%08X)\n", n, idx)
	data, err := nvslot.ReadRecord(idx)
	switch {
	case err == nil:
		fmt.Printf("  Record: EFI variable KIRAslot%d-%s, %d bytes (at most %d)\n", n, nvslot.VarGUID, len(data), nvslot.MaxRecordSize)
	default:
		fmt.Printf("  Record: %v\n", err)
	}
	have := func(i uint32) string {
		if tpmdev.NVRAMIndexExists(tpmDev, i) {
			return "defined"
		}
		return "not defined"
	}
	fmt.Printf("  Generation index 0x%08X: %s\n", nvslot.GenerationIndex(idx), have(nvslot.GenerationIndex(idx)))
	fmt.Printf("  Record counter 0x%08X: %s\n", nvslot.AttestCounterIndex(idx), have(nvslot.AttestCounterIndex(idx)))
	if err != nil {
		return nil
	}
	blob, err := nvslot.UnmarshalSealedBlob(data)
	if err != nil {
		fmt.Printf("  Contents: not a record of this version (%v)\n", err)
		if debug {
			peek := nvslot.PeekBlobVersion(data)
			fmt.Printf("    Version field: %d (supported: %d), first bytes: %x\n", peek.Version, nvslot.CurrentBlobVersion, data[:min(32, len(data))])
		}
		return nil
	}
	fmt.Printf("  PCRs: %v\n", blob.GetPCRIndices())
	if blob.HasTOTPKey() {
		fmt.Printf("  TOTP key: public %d bytes, private %d bytes\n", len(blob.Payload.Public), len(blob.Payload.Private))
	} else {
		fmt.Printf("  TOTP key: none\n")
	}
	if att := blob.Payload.Attestation; att != nil {
		fmt.Printf("  Phones: %d, vault: %v, TPM salt: %v\n", len(att.Phone.Verifiers), att.Vault.Enabled(), len(att.TPMSalt.Credential) > 0)
	}
	return nil
}

// kiraIndexRoleOr is kiraIndexRole, or "not tpm2-kira's" for any other.
func kiraIndexRoleOr(idx uint32) string {
	if r := kiraIndexRole(idx); r != "" {
		return r
	}
	return "not tpm2-kira's"
}

// NVRAMStatus shows detailed status of the specified NVRAM index
func NVRAMStatus(tpmPath string, nvramIndex uint32, debug bool) error {
	// Open TPM
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	if nvslot.ValidateBlobIndex(nvramIndex) == nil {
		return slotStatus(tpmDev, nvramIndex, debug)
	}

	nvIndex := tpm2.TPMHandle(nvramIndex)

	// Read public area
	readPublic := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}

	readPublicResp, err := readPublic.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("NVRAM index 0x%08X does not exist: %w", nvramIndex, err)
	}

	nvPublic, err := readPublicResp.NVPublic.Contents()
	if err != nil {
		return fmt.Errorf("failed to parse NVRAM public area: %w", err)
	}

	fmt.Printf("NVRAM Index Status:\n")
	fmt.Printf("===================\n")
	fmt.Printf("Index: 0x%08X\n", nvramIndex)
	fmt.Printf("Data Size: %d bytes\n", nvPublic.DataSize)
	fmt.Printf("Name Algorithm: %v\n", nvPublic.NameAlg)
	fmt.Printf("\n")

	fmt.Printf("Attributes:\n")
	fmt.Printf("  PPWRITE: %v\n", nvPublic.Attributes.PPWrite)
	fmt.Printf("  OWNERWRITE: %v\n", nvPublic.Attributes.OwnerWrite)
	fmt.Printf("  AUTHWRITE: %v\n", nvPublic.Attributes.AuthWrite)
	fmt.Printf("  POLICYWRITE: %v\n", nvPublic.Attributes.PolicyWrite)
	fmt.Printf("  PPREAD: %v\n", nvPublic.Attributes.PPRead)
	fmt.Printf("  OWNERREAD: %v\n", nvPublic.Attributes.OwnerRead)
	fmt.Printf("  AUTHREAD: %v\n", nvPublic.Attributes.AuthRead)
	fmt.Printf("  POLICYREAD: %v\n", nvPublic.Attributes.PolicyRead)
	fmt.Printf("  WRITTEN: %v\n", nvPublic.Attributes.Written)
	fmt.Printf("  WRITELOCKED: %v\n", nvPublic.Attributes.WriteLocked)
	fmt.Printf("  WRITEDEFINE: %v\n", nvPublic.Attributes.WriteDefine)
	fmt.Printf("  READLOCKED: %v\n", nvPublic.Attributes.ReadLocked)
	fmt.Printf("  READ_STCLEAR: %v\n", nvPublic.Attributes.ReadSTClear)
	fmt.Printf("  WRITE_STCLEAR: %v\n", nvPublic.Attributes.WriteSTClear)
	fmt.Printf("\n")

	if nvPublic.Attributes.Written {
		fmt.Printf("Status: written (%s)\n", kiraIndexRoleOr(nvramIndex))
	} else {
		fmt.Printf("Status: Not yet written\n")
	}

	return nil
}
