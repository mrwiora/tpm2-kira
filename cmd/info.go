package cmd

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
	Verify     blobVerification
	raw        []byte
	// GenState describes the slot's generation index as the TPM holds it.
	GenState string
}

// blobVerification is the outcome of checking a blob's signature with the
// local signing key. Until it succeeds, every blob field is untrusted.
type blobVerification struct {
	Verified bool
	Key      crypto.Signer // the key that verified the blob, if Verified
	KeyPath  string        // where that key was loaded from, or tried
	Reason   string        // why the blob is not verified
}

// SlotInfoJSON is used for JSON multi-slot output.
type SlotInfoJSON struct {
	SlotNumber        int             `json:"slot_number"`
	NVRAMIndex        string          `json:"nvram_index"`
	SignatureVerified bool            `json:"signature_verified"`
	Blob              json.RawMessage `json:"blob"`
}

// ── entry point ─────────────────────────────────────────────────────────

// InfoCommand is the top-level entry point for the info CLI command.
// When nvramIndex is 0 it scans every default slot; otherwise it shows
// only the requested index.
//
// Each blob's signature is checked with privKeyPath, or the default key when
// it is empty. A blob that cannot be verified is still shown, marked as
// untrusted, and no file it names is opened.
func InfoCommand(tpmPath string, nvramIndex uint32, privKeyPath string, debug bool, jsonOutput bool) error {
	tpmDev, err := OpenTPM(tpmPath)
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

	verifier := newBlobVerifier(privKeyPath)
	for i := range slots {
		slots[i].Verify = verifier.verify(slots[i].raw, slots[i].Blob)
	}

	if jsonOutput {
		return printJSON(slots)
	}
	printTree(slots)
	return nil
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
		raw:        sealedData,
		GenState:   generationState(tpmDev, nvramIndex, sealedBlob.Payload.Generation),
	}, nil
}

// generationState compares the slot's generation index with the generation
// the blob's approval requires.
func generationState(tpmDev transport.TPM, nvramIndex uint32, blobGen uint64) string {
	gen, err := ReadGeneration(tpmDev, GenerationIndex(nvramIndex))
	switch {
	case errors.Is(err, ErrCodesLocked):
		return "read-locked until reboot ('tpm2-kira cap' ran): no codes in this boot"
	case err != nil:
		return fmt.Sprintf("unavailable (%v): no codes until reseal", err)
	case gen != blobGen:
		return fmt.Sprintf("%d — does NOT match the blob: this approval is revoked; reseal", gen)
	}
	return fmt.Sprintf("%d (matches)", gen)
}

// blobVerifier loads the local signing key once and checks blobs with it.
type blobVerifier struct {
	keyPath string
	key     crypto.Signer
	loadErr error
}

func newBlobVerifier(privKeyPath string) *blobVerifier {
	v := &blobVerifier{keyPath: privKeyPath}
	if v.keyPath == "" {
		v.keyPath = DefaultPrivateKeyPath
	}
	v.key, v.loadErr = LoadCheckedSigningPrivateKey(v.keyPath)
	return v
}

func (v *blobVerifier) verify(raw []byte, blob *SealedBlob) blobVerification {
	if v.loadErr != nil {
		return blobVerification{KeyPath: v.keyPath, Reason: fmt.Sprintf("no signing key to check it with (%v)", v.loadErr)}
	}
	if err := VerifyBlobSignature(raw, blob, v.key.Public()); err != nil {
		return blobVerification{KeyPath: v.keyPath, Reason: fmt.Sprintf("signature does not verify with %s (%v)", v.keyPath, err)}
	}
	return blobVerification{Verified: true, Key: v.key, KeyPath: v.keyPath}
}

// ── JSON output ─────────────────────────────────────────────────────────

func printJSON(slots []slotInfo) error {
	// Always an array of annotated objects, so consumers never have to branch
	// on the slot count.
	items := make([]SlotInfoJSON, 0, len(slots))
	for _, si := range slots {
		raw, err := json.Marshal(si.Blob)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON for slot #%d: %w", si.SlotNumber, err)
		}
		items = append(items, SlotInfoJSON{
			SlotNumber:        si.SlotNumber,
			NVRAMIndex:        fmt.Sprintf("0x%08X", si.Index),
			SignatureVerified: si.Verify.Verified,
			Blob:              json.RawMessage(raw),
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

	// ── 0. Signature: first, because it decides how to read the rest ──
	if si.Verify.Verified {
		fmt.Printf("%s%sSignature: valid (verified with %s)\n", prefix, branch(false), si.Verify.KeyPath)
	} else {
		fmt.Printf("%s%sSignature: NOT VERIFIED — the fields below are untrusted\n", prefix, branch(false))
		fmt.Printf("%s%s%sReason: %s\n", prefix, cont(false), branch(true), si.Verify.Reason)
	}

	// ── 1. Blob Format ──────────────────────────────────────────────
	fmt.Printf("%s%sBlob Format\n", prefix, branch(false))
	sub := prefix + cont(false)
	fmt.Printf("%s%sVersion: %d\n", sub, branch(false), blob.Version)
	fmt.Printf("%s%sApp Version: %s\n", sub, branch(false), quoteUntrusted(blob.Payload.AppVersion))
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
	fmt.Printf("%s%sCount: %d\n", sub, branch(false), len(blob.Payload.PCRDigests))
	for j, pd := range blob.Payload.PCRDigests {
		isLast := j == len(blob.Payload.PCRDigests)-1
		fmt.Printf("%s%sPCR %-2d (%s): %s\n", sub, branch(isLast), pd.Index, pd.Source.String(), GetPCRDescription(pd.Index))
	}

	// ── 4. Authentication ───────────────────────────────────────────
	fmt.Printf("%s%sAuthentication: PolicyAuthorize (PCR values + generation, approved by the signing key)\n", prefix, branch(false))
	sub = prefix + cont(false)
	fmt.Printf("%s%sTOTP Key: HMAC-%s, inside the TPM\n", sub, branch(false), totpAlgorithmName(blob.Payload.TOTPAlgorithm))
	fmt.Printf("%s%sApproved Generation: %d\n", sub, branch(false), blob.Payload.Generation)
	fmt.Printf("%s%sGeneration Index: 0x%08X = %s\n", sub, branch(false), GenerationIndex(si.Index), si.GenState)
	printSigningKeyInfo(sub, blob, si.Verify)

	// ── 5. TPM Objects ──────────────────────────────────────────────
	fmt.Printf("%s%sTPM Objects\n", prefix, branch(false))
	sub = prefix + cont(false)
	fmt.Printf("%s%sPublic Blob: %d bytes\n", sub, branch(false), len(blob.Payload.Public))
	fmt.Printf("%s%sPrivate Blob: %d bytes\n", sub, branch(true), len(blob.Payload.Private))

	// ── 6. PCR Sources ──────────────────────────────────────────────
	fmt.Printf("%s%sPCR Sources\n", prefix, branch(false))
	sub = prefix + cont(false)
	printPCRSources(sub, blob)

	// ── 7. PCR Digests (last section) ───────────────────────────────
	fmt.Printf("%s%sPCR Digests\n", prefix, branch(true))
	sub = prefix + cont(true)
	for j, pd := range blob.Payload.PCRDigests {
		isLast := j == len(blob.Payload.PCRDigests)-1
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

// printSigningKeyInfo describes the signing key. Only the key that verified
// the blob is described and checked; key paths recorded in the blob are
// printed quoted and never opened, since the blob may have been planted.
// Closes the branch.
func printSigningKeyInfo(sub string, blob *SealedBlob, v blobVerification) {
	if v.Verified {
		pubKey := v.Key.Public()
		fmt.Printf("%s%sSigning Key: %s (fingerprint: %s)\n", sub, branch(false), PublicKeyDescription(pubKey), PublicKeyFingerprint(pubKey))
		if desc, ok := YubiKeyDescription(v.Key); ok {
			fmt.Printf("%s%sSigning Key Location: %s\n", sub, branch(false), desc)
		}
	} else {
		fmt.Printf("%s%sSigning Key: unknown (blob not verified)\n", sub, branch(false))
	}

	recorded := "recorded"
	if !v.Verified {
		recorded = "recorded, unverified, not opened"
	}
	for _, p := range []struct{ label, path string }{
		{"Private Key Path", blob.Payload.PrivateKeyPath},
		{"Public Key Path", blob.Payload.PublicKeyPath},
	} {
		if p.path != "" {
			fmt.Printf("%s%s%s: %s (%s)\n", sub, branch(false), p.label, quoteUntrusted(p.path), recorded)
		}
	}

	fmt.Printf("%s%sKey File Check: %s: %s\n", sub, branch(true), v.KeyPath, keyFileStatus(v.KeyPath))
}

// keyFileStatus reports whether seal and reseal would accept a key file.
func keyFileStatus(path string) string {
	if err := CheckSigningKeyFile(path); err != nil {
		return "WARNING: " + strings.ReplaceAll(err.Error(), "\n", " ")
	}
	return "ok (mode 0400, trusted owner and directory)"
}

func printPCRSources(sub string, blob *SealedBlob) {
	hasEventlog := blob.HasEventlogPCRs()
	hasUKI := blob.HasUKIPCRs()
	regPCRs := blob.GetRegisterPCRIndices()
	hasRegister := len(regPCRs) > 0

	if info := blob.Payload.EventlogInfo; info != nil && info.MeasurePointExtends != "" {
		fmt.Printf("%s%sMeasure-point extends: %s\n", sub, branch(false), quoteUntrusted(info.MeasurePointExtends))
		if info.MeasurePointDetection != "" {
			fmt.Printf("%s%s  detected via: %s\n", sub, branch(false), quoteUntrusted(info.MeasurePointDetection))
		}
	}

	// Summary line
	switch {
	case hasEventlog && hasUKI && hasRegister:
		fmt.Printf("%s%sMode: mixed (eventlog, uki, register)\n", sub, branch(false))
	case hasEventlog && hasUKI:
		fmt.Printf("%s%sMode: mixed (eventlog, uki)\n", sub, branch(false))
	case hasEventlog && hasRegister:
		fmt.Printf("%s%sMode: mixed (eventlog, register)\n", sub, branch(false))
	case hasUKI && hasRegister:
		fmt.Printf("%s%sMode: mixed (uki, register)\n", sub, branch(false))
	case hasEventlog:
		fmt.Printf("%s%sMode: all eventlog-based\n", sub, branch(false))
	case hasUKI:
		fmt.Printf("%s%sMode: all uki-based\n", sub, branch(false))
	default:
		fmt.Printf("%s%sMode: all register-based\n", sub, branch(false))
	}

	// Count remaining detail items so we know which is last.
	remaining := 0
	if hasEventlog {
		remaining++
	}
	if hasUKI {
		remaining++
	}
	if hasRegister {
		remaining++
	}
	if remaining == 0 {
		// Already printed mode, nothing else.
		return
	}

	printed := 0

	if hasEventlog {
		printed++
		fmt.Printf("%s%sEventlog PCRs: %v\n", sub, branch(printed == remaining), blob.GetEventlogPCRIndices())
	}
	if hasUKI {
		printed++
		fmt.Printf("%s%sUKI PCRs: %v\n", sub, branch(printed == remaining), blob.GetUKIPCRIndices())
	}
	if hasRegister {
		printed++
		fmt.Printf("%s%sRegister PCRs: %v\n", sub, branch(printed == remaining), regPCRs)
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
