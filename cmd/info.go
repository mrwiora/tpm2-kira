package cmd

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/attest"
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
	// CounterState describes the slot's record counter against the count
	// in the blob's attestation part; empty without one.
	CounterState string
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
	RevisionCounter   string          `json:"revision_counter,omitempty"` // only with an attestation part
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

	si := &slotInfo{
		Index:      nvramIndex,
		SlotNumber: SlotNumber(nvramIndex),
		NVPublic:   nvPublic,
		Blob:       sealedBlob,
		raw:        sealedData,
		GenState:   generationState(tpmDev, nvramIndex, sealedBlob.Payload.Generation),
	}
	if att := sealedBlob.Payload.Attestation; att != nil && nvramIndex >= NVRAMSlotStart && nvramIndex <= NVRAMSlotEnd {
		si.CounterState = counterState(tpmDev, nvramIndex, att.Count)
	}
	return si, nil
}

// counterState compares the slot's record counter with the count in the
// blob's attestation part.
func counterState(tpmDev transport.TPM, nvramIndex uint32, count uint64) string {
	counter, err := readAttestCounter(tpmDev, AttestCounterIndex(nvramIndex))
	switch {
	case err != nil:
		return fmt.Sprintf("unavailable (%v): the gate serves no verifier until you enrol again", err)
	case counter != count:
		return fmt.Sprintf("%d — does NOT match the blob's revision %d: an older blob was put back, or the counter was raised; enrol again", counter, count)
	}
	return fmt.Sprintf("%d (matches: this is the current blob)", counter)
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
			RevisionCounter:   si.CounterState,
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

	// ── Remote attestation (optional part of the blob) ───────────────
	printAttestationTree(prefix, si)

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

	if extends := blob.MeasurePointExtends(); extends != "" {
		fmt.Printf("%s%sMeasure-point extends: %s\n", sub, branch(false), extends)
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

// printAttestationTree renders the blob's remote-attestation part: who the
// machine is to its verifiers, which key signs its quotes, which PCRs are
// quoted, and the methods by which a verifier reaches it.
func printAttestationTree(prefix string, si *slotInfo) {
	att := si.Blob.Payload.Attestation
	if att == nil {
		fmt.Printf("%s%sRemote attestation: not set up (tpm2-kira attest enrol)\n", prefix, branch(false))
		return
	}
	fmt.Printf("%s%sRemote attestation\n", prefix, branch(false))
	sub := prefix + cont(false)
	fmt.Printf("%s%sMachine name: %s\n", sub, branch(false), quoteUntrusted(att.FriendlyName))
	fmt.Printf("%s%sDevice ID: %x\n", sub, branch(false), att.DeviceID)
	fmt.Printf("%s%sAttestation key (signs the quotes; private part wrapped by this TPM)\n", sub, branch(false))
	ak := sub + cont(false)
	fmt.Printf("%s%sName: %x\n", ak, branch(false), att.AKName)
	fmt.Printf("%s%sPublic: %d bytes, private: %d bytes\n", ak, branch(false), len(att.AKPublic), len(att.AKPrivate))
	fmt.Printf("%s%sEndorsement key used at enrolment: %s\n", ak, branch(true), ekAlgName(att.EKAlg))
	if sel, err := att.Selection(); err == nil {
		fmt.Printf("%s%sPCRs quoted: %s\n", sub, branch(false), sel)
	} else {
		fmt.Printf("%s%sPCRs quoted: invalid selection (%v)\n", sub, branch(false), err)
	}
	// Not a count of attestations: it moves only when the verifiers of the
	// slot change, and says which blob is the current one.
	fmt.Printf("%s%sRevision: %d (changes when verifiers are added or removed, not when the machine is attested)\n", sub, branch(false), att.Count)
	if si.CounterState != "" {
		fmt.Printf("%s%sRevision counter in the TPM (0x%08X): %s\n", sub, branch(false), AttestCounterIndex(si.Index), si.CounterState)
	}
	fmt.Printf("%s%sMethods\n", sub, branch(true))
	methods := sub + cont(true)
	if !att.Phone.Enabled() {
		fmt.Printf("%s%s(none set up)\n", methods, branch(true))
		return
	}
	phones := att.Phone.Verifiers
	fmt.Printf("%s%sPhones over Bluetooth LE: %d enrolled (channel and advertising keys present, not shown)\n", methods, branch(true), len(phones))
	list := methods + cont(true)
	for i, v := range phones {
		last := i == len(phones)-1
		fmt.Printf("%s%s%s\n", list, branch(last), verifierName(&v))
		d := list + cont(last)
		fmt.Printf("%s%sID: %s\n", d, branch(false), quoteUntrusted(v.ID))
		fmt.Printf("%s%sAnchor key (signs its verdicts): SHA-256 %x\n", d, branch(false), attest.AnchorDigest(v.AnchorPub))
		fmt.Printf("%s%sChannel key: %x\n", d, branch(v.PolicyID == ""), v.NoisePub)
		if v.PolicyID != "" {
			fmt.Printf("%s%sPolicy: %s\n", d, branch(true), quoteUntrusted(v.PolicyID))
		}
	}
}
