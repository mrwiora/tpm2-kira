package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// ── tree-drawing helpers ────────────────────────────────────────────────

const (
	treeMid  = "├── " // middle branch
	treeLast = "└── " // last branch
	treeBar  = "│   " // continuation
	treeSpc  = "    " // blank after last
)

// branch returns treeLast when last is true, treeMid otherwise.
func branch(last bool) string {
	if last {
		return treeLast
	}
	return treeMid
}

// cont returns treeSpc when last is true, treeBar otherwise.
// It is the continuation prefix that goes below the corresponding branch.
func cont(last bool) string {
	if last {
		return treeSpc
	}
	return treeBar
}

// ── slot-level info data ────────────────────────────────────────────────

// slotInfo holds everything needed to render one slot's information.
type slotInfo struct {
	Index      uint32
	SlotNumber int
	NVPublic   *tpm2.TPMSNVPublic
	Blob       *SealedBlob
}

// SlotInfoJSON is used for JSON multi-slot output.
type SlotInfoJSON struct {
	SlotNumber int             `json:"slot_number"`
	NVRAMIndex string          `json:"nvram_index"`
	Blob       json.RawMessage `json:"blob"`
}

// ── entry point ─────────────────────────────────────────────────────────

// InfoCommand is the top-level entry point for the info CLI command.
// When nvramIndex is 0 it scans every default slot; otherwise it shows
// only the requested index.
func InfoCommand(tpmPath string, nvramIndex uint32, debug bool, jsonOutput bool) error {
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	// Collect slot(s) to display.
	var slots []slotInfo

	if nvramIndex != 0 {
		si, err := readSlotInfo(tpmDev, nvramIndex)
		if err != nil {
			return err
		}
		slots = append(slots, *si)
	} else {
		populated := FindPopulatedSlots(tpmDev, debug)
		if len(populated) == 0 {
			return fmt.Errorf("no sealed secrets found in NVRAM slots 0x%08X – 0x%08X", NVRAMSlotStart, NVRAMSlotEnd)
		}
		for _, idx := range populated {
			si, err := readSlotInfo(tpmDev, idx)
			if err != nil {
				if debug {
					fmt.Printf("Skipping slot 0x%08X: %v\n", idx, err)
				}
				continue
			}
			slots = append(slots, *si)
		}
		if len(slots) == 0 {
			return fmt.Errorf("populated slots found but none could be read")
		}
	}

	if jsonOutput {
		return printJSON(slots)
	}
	printTree(slots)
	return nil
}

// InfoWithFormat is the legacy entry point kept for backward compatibility.
func InfoWithFormat(tpmPath string, nvramIndex uint32, debug bool, jsonOutput bool) error {
	return InfoCommand(tpmPath, nvramIndex, debug, jsonOutput)
}

// ── reading a single slot ───────────────────────────────────────────────

func readSlotInfo(tpmDev transport.TPM, nvramIndex uint32) (*slotInfo, error) {
	nvIndex := tpm2.TPMHandle(nvramIndex)
	readPublic := tpm2.NVReadPublic{NVIndex: nvIndex}

	readPublicResp, err := readPublic.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to read NVRAM index 0x%08X (may not exist): %w", nvramIndex, err)
	}
	nvPublic, err := readPublicResp.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to parse NVRAM public area: %w", err)
	}

	sealedData, err := ReadFromNVRAM(tpmDev, nvramIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to read from NVRAM: %w", err)
	}
	sealedBlob, err := UnmarshalSealedBlob(sealedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sealed data: %w", err)
	}

	return &slotInfo{
		Index:      nvramIndex,
		SlotNumber: SlotNumber(nvramIndex),
		NVPublic:   nvPublic,
		Blob:       sealedBlob,
	}, nil
}

// ── JSON output ─────────────────────────────────────────────────────────

func printJSON(slots []slotInfo) error {
	if len(slots) == 1 {
		// Single slot – emit a plain object for backward compatibility.
		out, err := json.MarshalIndent(slots[0].Blob, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(out))
		return nil
	}

	// Multiple slots – emit an array of annotated objects.
	var items []SlotInfoJSON
	for _, si := range slots {
		raw, err := json.Marshal(si.Blob)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON for slot #%d: %w", si.SlotNumber, err)
		}
		items = append(items, SlotInfoJSON{
			SlotNumber: si.SlotNumber,
			NVRAMIndex: fmt.Sprintf("0x%08X", si.Index),
			Blob:       json.RawMessage(raw),
		})
	}
	out, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

// ── tree output ─────────────────────────────────────────────────────────

func printTree(slots []slotInfo) {
	multiSlot := len(slots) > 1

	for i, si := range slots {
		if multiSlot {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("Slot #%d (0x%08X)\n", si.SlotNumber, si.Index)
		}

		prefix := ""
		if multiSlot {
			// Everything under a slot header is indented by the implicit
			// root level; we use no leading bar because the slot header
			// itself is the root node.
			prefix = ""
		}
		printSlotTree(prefix, &si, multiSlot)
	}
}

func printSlotTree(prefix string, si *slotInfo, multiSlot bool) {
	blob := si.Blob
	nvPub := si.NVPublic
	hashAlgo := blob.GetHashAlgo()

	// The slot body has 7 sections; the last one gets └──.
	// If we are the only slot (no slot header), we print a title first.
	if !multiSlot {
		fmt.Println("Sealed Blob Information")
		fmt.Println()
	}

	// ── 1. Blob Format ──────────────────────────────────────────────
	fmt.Printf("%s%sBlob Format\n", prefix, branch(false))
	sub := prefix + cont(false)
	fmt.Printf("%s%sVersion: %d\n", sub, branch(false), blob.Version)
	fmt.Printf("%s%sApp Version: %s\n", sub, branch(false), blob.AppVersion)
	fmt.Printf("%s%sHash Algorithm: %s (%d-byte PCR digests)\n", sub, branch(true), hashAlgo.DisplayString(), hashAlgo.DigestSize())

	// ── 2. NVRAM ────────────────────────────────────────────────────
	fmt.Printf("%s%sNVRAM\n", prefix, branch(false))
	sub = prefix + cont(false)
	fmt.Printf("%s%sIndex: 0x%08X\n", sub, branch(false), si.Index)
	fmt.Printf("%s%sSize: %d bytes\n", sub, branch(false), nvPub.DataSize)
	attrs := formatNVAttributes(nvPub)
	fmt.Printf("%s%sAttributes: %s\n", sub, branch(true), attrs)

	// ── 3. PCR Configuration ────────────────────────────────────────
	fmt.Printf("%s%sPCR Configuration\n", prefix, branch(false))
	sub = prefix + cont(false)
	fmt.Printf("%s%sIndices: %v\n", sub, branch(false), blob.GetPCRIndices())
	fmt.Printf("%s%sCount: %d\n", sub, branch(false), len(blob.PCRDigests))
	for j, pd := range blob.PCRDigests {
		isLast := j == len(blob.PCRDigests)-1
		fmt.Printf("%s%sPCR %-2d (%s): %s\n", sub, branch(isLast), pd.Index, pd.Source.String(), GetPCRDescription(pd.Index))
	}

	// ── 4. Authentication ───────────────────────────────────────────
	fmt.Printf("%s%sAuthentication: PolicyOR (PCR branch + PolicySigned branch)\n", prefix, branch(false))
	sub = prefix + cont(false)
	if len(blob.SignedBranchDigest) > 0 {
		fmt.Printf("%s%sSigned Branch Digest: %x (%d bytes)\n", sub, branch(false), blob.SignedBranchDigest, len(blob.SignedBranchDigest))
		printSigningKeyInfo(sub, blob)
	} else {
		fmt.Printf("%s%sSigned Branch: not present (incompatible blob)\n", sub, branch(true))
	}

	// ── 5. TPM Objects ──────────────────────────────────────────────
	fmt.Printf("%s%sTPM Objects\n", prefix, branch(false))
	sub = prefix + cont(false)
	fmt.Printf("%s%sPublic Blob: %d bytes\n", sub, branch(false), len(blob.Public))
	fmt.Printf("%s%sPrivate Blob: %d bytes\n", sub, branch(true), len(blob.Private))

	// ── 6. PCR Sources ──────────────────────────────────────────────
	fmt.Printf("%s%sPCR Sources\n", prefix, branch(false))
	sub = prefix + cont(false)
	printPCRSources(sub, blob)

	// ── 7. PCR Digests (last section) ───────────────────────────────
	fmt.Printf("%s%sPCR Digests\n", prefix, branch(true))
	sub = prefix + cont(true)
	for j, pd := range blob.PCRDigests {
		isLast := j == len(blob.PCRDigests)-1
		fmt.Printf("%s%sPCR %-2d (%s): %x (%d bytes)\n",
			sub, branch(isLast), pd.Index, pd.Source.String(), pd.Digest.Buffer, len(pd.Digest.Buffer))
	}

	if !multiSlot {
		fmt.Println()
		fmt.Println("Note: For security reasons, the 'info' command does not display secrets.")
		fmt.Println("Use 'tpm2-kira reveal' to generate TOTP codes.")
	}
}

// ── sub-section helpers ─────────────────────────────────────────────────

func printSigningKeyInfo(sub string, blob *SealedBlob) {
	if blob.PublicKeyPath != "" {
		pubKey, _, keyErr := LoadSigningPublicKeyFromPEM(blob.PublicKeyPath)
		if keyErr == nil {
			fmt.Printf("%s%sSigning Key: %s (fingerprint: %s)\n", sub, branch(false), PublicKeyDescription(pubKey), PublicKeyFingerprint(pubKey))
			fmt.Printf("%s%sSigning Key Path: %s\n", sub, branch(true), blob.PublicKeyPath)
			return
		}
	}
	if blob.PrivateKeyPath != "" {
		privKey, keyErr := LoadSigningPrivateKeyFromPEM(blob.PrivateKeyPath)
		if keyErr == nil {
			pubKey := privKey.Public()
			fmt.Printf("%s%sSigning Key: %s (fingerprint: %s)\n", sub, branch(false), PublicKeyDescription(pubKey), PublicKeyFingerprint(pubKey))
			fmt.Printf("%s%sSigning Key Path: %s (derived from private key)\n", sub, branch(true), blob.PrivateKeyPath)
			return
		}
	}
	// No key could be loaded – close the branch.
	fmt.Printf("%s%sSigning Key: unavailable (key paths not accessible)\n", sub, branch(true))
}

func printPCRSources(sub string, blob *SealedBlob) {
	hasEventlog := blob.HasEventlogPCRs()
	hasPredict := blob.HasPredictPCRs()
	regPCRs := blob.GetRegisterPCRIndices()
	hasRegister := len(regPCRs) > 0

	// Summary line
	switch {
	case hasEventlog && hasPredict && hasRegister:
		fmt.Printf("%s%sMode: mixed (eventlog, predict, register)\n", sub, branch(false))
	case hasEventlog && hasPredict:
		fmt.Printf("%s%sMode: mixed (eventlog, predict)\n", sub, branch(false))
	case hasEventlog && hasRegister:
		fmt.Printf("%s%sMode: mixed (eventlog, register)\n", sub, branch(false))
	case hasPredict && hasRegister:
		fmt.Printf("%s%sMode: mixed (predict, register)\n", sub, branch(false))
	case hasEventlog:
		fmt.Printf("%s%sMode: all eventlog-based\n", sub, branch(false))
	case hasPredict:
		fmt.Printf("%s%sMode: all predict-based\n", sub, branch(false))
	default:
		fmt.Printf("%s%sMode: all register-based\n", sub, branch(false))
	}

	// Count remaining detail items so we know which is last.
	remaining := 0
	if hasEventlog {
		remaining++
	}
	if hasPredict {
		remaining++
	}
	if hasRegister {
		remaining++
	}
	if !hasEventlog && !hasPredict && !hasRegister {
		// Already printed mode, nothing else.
		return
	}

	printed := 0

	if hasEventlog {
		printed++
		isLast := printed == remaining
		fmt.Printf("%s%sEventlog PCRs: %v\n", sub, branch(isLast), blob.GetEventlogPCRIndices())
		if blob.EventlogInfo != nil && !isLast {
			// Print eventlog details nested under eventlog line.
			esub := sub + cont(isLast)
			_ = esub // eventlog detail is shown inline to keep tree compact
		}
	}
	if hasPredict {
		printed++
		isLast := printed == remaining
		indices := blob.GetPredictPCRIndices()
		fmt.Printf("%s%sPredict PCRs: %v\n", sub, branch(isLast), indices)
	}
	if hasRegister {
		printed++
		isLast := printed == remaining
		fmt.Printf("%s%sRegister PCRs: %v\n", sub, branch(isLast), regPCRs)
	}
}

func formatNVAttributes(nvPub *tpm2.TPMSNVPublic) string {
	var attrs []string
	if nvPub.Attributes.OwnerWrite {
		attrs = append(attrs, "OwnerWrite")
	}
	if nvPub.Attributes.OwnerRead {
		attrs = append(attrs, "OwnerRead")
	}
	if nvPub.Attributes.AuthWrite {
		attrs = append(attrs, "AuthWrite")
	}
	if nvPub.Attributes.AuthRead {
		attrs = append(attrs, "AuthRead")
	}
	if nvPub.Attributes.Written {
		attrs = append(attrs, "Written")
	}
	if len(attrs) == 0 {
		return "(none)"
	}
	result := attrs[0]
	for _, a := range attrs[1:] {
		result += ", " + a
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
