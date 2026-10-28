package admin

import (
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
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
	// Validate index is within the safe application range
	if err := nvslot.ValidateNVRAMIndex(nvramIndex); err != nil {
		return fmt.Errorf("invalid NVRAM index: %w", err)
	}

	// Open TPM
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	nvIndex := tpm2.TPMHandle(nvramIndex)

	// Check if index exists
	readPublic := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}

	readPublicResp, err := readPublic.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("NVRAM index 0x%08X does not exist: %w", nvramIndex, err)
	}

	if debug {
		fmt.Printf("NV name: %x\n", readPublicResp.NVName.Buffer)
		if nvPublic, pubErr := readPublicResp.NVPublic.Contents(); pubErr == nil {
			fmt.Printf("Deleting 0x%08X: %d bytes, written=%v\n", nvramIndex, nvPublic.DataSize, nvPublic.Attributes.Written)
		}
	}

	// Undefine NVRAM space
	undefine := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex: tpm2.NamedHandle{
			Handle: nvIndex,
			Name:   readPublicResp.NVName,
		},
	}

	_, err = undefine.Execute(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to delete NVRAM index 0x%08X: %w", nvramIndex, err)
	}

	fmt.Printf("Successfully deleted NVRAM index 0x%08X\n", nvramIndex)

	// A slot is deleted whole: its record counter goes with it. (Without its counter no blob of
	// the slot is accepted by the gate again, and a new counter starts
	// above every value this one had.)
	if nvramIndex >= nvslot.NVRAMSlotStart && nvramIndex <= nvslot.NVRAMSlotEnd {
		if counter := nvslot.AttestCounterIndex(nvramIndex); tpmdev.NVRAMIndexExists(tpmDev, counter) {
			if err := tpmdev.UndefineIndex(tpmDev, counter); err != nil {
				return fmt.Errorf("deleted the slot, but not its record counter 0x%08X: %w", counter, err)
			}
		}
	}

	// A slot's generation index goes with it.
	if nvslot.ValidateBlobIndex(nvramIndex) == nil {
		genIndex := tpm2.TPMHandle(nvslot.GenerationIndex(nvramIndex))
		if genPub, err := (tpm2.NVReadPublic{NVIndex: genIndex}).Execute(tpmDev); err == nil {
			if _, err := (tpm2.NVUndefineSpace{
				AuthHandle: tpm2.TPMRHOwner,
				NVIndex:    tpm2.NamedHandle{Handle: genIndex, Name: genPub.NVName},
			}).Execute(tpmDev); err != nil {
				return fmt.Errorf("deleted the blob, but not its generation index 0x%08X: %w", uint32(genIndex), err)
			}
		}
	}

	return nil
}

// kiraIndexRole says what tpm2-kira keeps at an NV index, or "" for an
// index that is not one of its own.
func kiraIndexRole(index uint32) string {
	switch {
	case index == nvslot.BootSettingsIndex:
		return "the boot settings (debug at boot)"
	case index >= nvslot.NVRAMSlotStart && index <= nvslot.NVRAMSlotEnd:
		return fmt.Sprintf("slot #%d: its TOTP key and, if set up, its attestation part", nvslot.SlotNumber(index))
	case index >= nvslot.GenerationIndex(nvslot.NVRAMSlotStart) && index <= nvslot.GenerationIndex(nvslot.NVRAMSlotEnd):
		return fmt.Sprintf("generation index of slot #%d", nvslot.SlotNumber(index-nvslot.GenerationIndexOffset))
	case index >= nvslot.AttestCounterIndex(nvslot.NVRAMSlotStart) && index <= nvslot.AttestCounterIndex(nvslot.NVRAMSlotEnd):
		return fmt.Sprintf("record counter of slot #%d's attestation part", index-nvslot.AttestCounterStart)
	}
	return ""
}

// kiraLeftovers returns the indices that belong to no slot: the companion
// indices (generation index, record counter) whose slot is gone, as an
// interrupted command leaves them, and the boot settings.
func kiraLeftovers(tpmDev transport.TPM, debug bool) []uint32 {
	var out []uint32
	if tpmdev.NVRAMIndexExists(tpmDev, nvslot.BootSettingsIndex) {
		out = append(out, nvslot.BootSettingsIndex)
	}
	for idx := uint32(nvslot.NVRAMSlotStart); idx <= nvslot.NVRAMSlotEnd; idx++ {
		if tpmdev.NVRAMIndexExists(tpmDev, idx) {
			continue
		}
		for _, companion := range []uint32{nvslot.GenerationIndex(idx), nvslot.AttestCounterIndex(idx)} {
			if tpmdev.NVRAMIndexExists(tpmDev, companion) {
				out = append(out, companion)
			}
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
	slots := nvslot.FindPopulatedSlots(tpmDev, debug)
	enrolled := 0
	for _, idx := range slots {
		if _, err := phonegate.LoadAttestBlob(tpmDev, idx); err == nil {
			enrolled++
		}
	}
	leftovers := kiraLeftovers(tpmDev, debug)
	tpmDev.Close()

	total := len(slots) + len(leftovers)
	if total == 0 {
		return fmt.Errorf("nothing of tpm2-kira found in the TPM: no sealed secrets in NVRAM slots 0x%08X – 0x%08X and no leftover indices",
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
	if err := confirmDeleteAll(len(slots), enrolled, len(leftovers), yes); err != nil {
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
			if err := tpmdev.UndefineIndex(tpmDev, idx); err != nil {
				fmt.Printf("FAILED: %v\n", err)
				failed++
				continue
			}
			fmt.Println("done")
		}
		tpmDev.Close()
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

func confirmDeleteAll(slots, enrolled, leftovers int, yes bool) error {
	if yes {
		return nil
	}
	total := slots + leftovers
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
	fmt.Printf("Type 'yes' to delete all %d item(s): ", total)
	answer, _ := tty.ReadString('\n')
	if strings.TrimSpace(answer) != "yes" {
		return fmt.Errorf("not confirmed; nothing was deleted")
	}
	return nil
}

// NVRAMStatus shows detailed status of the specified NVRAM index
func NVRAMStatus(tpmPath string, nvramIndex uint32, debug bool) error {
	// Open TPM
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

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

	// Try to determine if it contains sealed data
	if nvPublic.Attributes.Written {
		data, readErr := tpmdev.ReadFromNVRAM(tpmDev, nvramIndex)
		switch {
		case readErr != nil:
			fmt.Printf("Contents: unreadable (%v)\n", readErr)
		default:
			blob, unmarshalErr := nvslot.UnmarshalSealedBlob(data)
			if unmarshalErr == nil {
				fmt.Printf("Contains Sealed Data:\n")
				fmt.Printf("  PCR Indices: %v\n", blob.GetPCRIndices())
				fmt.Printf("  Number of PCRs: %d\n", len(blob.Payload.PCRDigests))
				if blob.HasTOTPKey() {
					fmt.Printf("  TOTP key: public %d bytes, private %d bytes\n", len(blob.Payload.Public), len(blob.Payload.Private))
				} else {
					fmt.Printf("  TOTP key: none (attested by its phones)\n")
				}
				break
			}
			fmt.Printf("Data Format: Unknown (not a sealed blob)\n")
			if debug {
				peek := nvslot.PeekBlobVersion(data)
				fmt.Printf("  Raw size: %d bytes\n", peek.DataSize)
				fmt.Printf("  Version field: %d (supported: %d)\n", peek.Version, nvslot.CurrentBlobVersion)
				fmt.Printf("  Parse error: %v\n", unmarshalErr)
				fmt.Printf("  First bytes: %x\n", data[:min(32, len(data))])
			}
		}
	} else {
		fmt.Printf("Status: Not yet written\n")
	}

	return nil
}
