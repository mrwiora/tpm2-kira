package cmd

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// ErrPhoneSlot: the slot is attested by its phones and has no TOTP code.
var ErrPhoneSlot = errors.New("the slot is attested by its phone and has no TOTP code")

// SlotCode reads the blob at nvramIndex and computes its current TOTP code.
//
// Before asking the TPM it compares the blob with the live state, purely to
// explain a failure: a PCRMismatchError when the registers differ from the
// sealed values, ErrSeparatorLocked when they differ only by the OS
// separator that ran after the measure point, a GenerationMismatchError
// when a later reseal revoked this blob's approval, ErrCodesLocked after
// 'tpm2-kira cap'. None of these checks is the gate; the TPM is.
func SlotCode(tpmDev transport.TPM, nvramIndex uint32, t time.Time, debug bool) (string, *nvslot.SealedBlob, error) {
	sealedData, err := tpmdev.ReadFromNVRAM(tpmDev, nvramIndex)
	if err != nil {
		return "", nil, tpmdev.HandleNVRAMNotFoundError(err, debug)
	}
	sealedBlob, err := nvslot.UnmarshalSealedBlob(sealedData)
	if err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal sealed data: %w", err)
	}
	if !sealedBlob.HasTOTPKey() {
		return "", sealedBlob, ErrPhoneSlot
	}

	gen, err := nvslot.ReadGeneration(tpmDev, nvslot.GenerationIndex(nvramIndex))
	switch {
	case errors.Is(err, nvslot.ErrCodesLocked):
		return "", sealedBlob, nvslot.ErrCodesLocked
	case err != nil:
		return "", sealedBlob, &nvslot.GenerationMismatchError{BlobGeneration: sealedBlob.Payload.Generation, IndexMissing: true}
	case gen != sealedBlob.Payload.Generation:
		return "", sealedBlob, &nvslot.GenerationMismatchError{BlobGeneration: sealedBlob.Payload.Generation, IndexGeneration: gen}
	}

	currentPCRValues, err := nvslot.GetCurrentPCRValuesFromRegisters(tpmDev, sealedBlob, debug)
	if err != nil {
		return "", sealedBlob, err
	}
	if !measure.VerifyPCRValues(sealedBlob.GetPCRDigestValues(), currentPCRValues) {
		mismatch := newPCRMismatchError(sealedBlob, currentPCRValues)
		if mismatch.SeparatorLocked() {
			return "", sealedBlob, measure.ErrSeparatorLocked
		}
		return "", sealedBlob, mismatch
	}

	code, err := TOTPCode(tpmDev, sealedBlob, nvramIndex, t)
	return code, sealedBlob, err
}

func newPCRMismatchError(sealedBlob *nvslot.SealedBlob, current []tpm2.TPM2BDigest) *measure.PCRMismatchError {
	expectedDigests := make([][]byte, len(sealedBlob.Payload.PCRDigests))
	pcrSources := make([]measure.PCRSource, len(sealedBlob.Payload.PCRDigests))
	for i, d := range sealedBlob.Payload.PCRDigests {
		expectedDigests[i] = d.Digest.Buffer
		pcrSources[i] = d.Source
	}
	currentDigests := make([][]byte, len(current))
	for i, d := range current {
		currentDigests[i] = d.Buffer
	}
	return &measure.PCRMismatchError{
		Message:         "PCR values have changed. Use 'slot approve' with the signing key to approve the new values",
		PCRIndices:      sealedBlob.GetPCRIndices(),
		ExpectedDigests: expectedDigests,
		CurrentDigests:  currentDigests,
		PCRSources:      pcrSources,
	}
}

// LoadSealedObjectResponse contains the result of loading a sealed object
type LoadSealedObjectResponse struct {
	ObjectHandle tpm2.TPMHandle
	Name         tpm2.TPM2BName
}

// LoadSealedObject loads the blob's key object into the TPM
func LoadSealedObject(tpmDev transport.TPM, primaryKey *tpmdev.PrimaryKeyResponse, sealedBlob *nvslot.SealedBlob) (*LoadSealedObjectResponse, error) {
	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](sealedBlob.Payload.Public),
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: sealedBlob.Payload.Private,
		},
	}

	loadRsp, err := loadCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to load sealed object: %w", err)
	}

	return &LoadSealedObjectResponse{
		ObjectHandle: loadRsp.ObjectHandle,
		Name:         loadRsp.Name,
	}, nil
}

// NVRAMSlot represents a TOTP secret stored in an NVRAM slot
type NVRAMSlot struct {
	SlotNumber int
	Index      uint32
	Code       string // TOTP code for the time of the scan, computed in the TPM
	Error      error  // Why no code could be computed (if any)
	Available  bool   // Whether the slot has data (even if no code could be computed)

	// AfterSeparator marks a slot that got its first code only after the
	// boot display released the boot (tpm2-kira run), i.e. a blob whose
	// policy holds after the OS separator: its codes are computed live for
	// as long as the policy holds, and the display says so.
	AfterSeparator bool

	// Phone marks a slot attested by its phones: it has no TOTP key, so
	// no code, and the display shows the phone's state instead.
	Phone bool
}

// phoneSlotDefault is a phone slot's line where no gate reports on it.
const phoneSlotDefault = "mobile attestation (a phone is enrolled; no TOTP code)"

// ScanNVRAMSlots scans all NVRAM indices from 0x01803010 to 0x0180301F
// and returns a list of slots containing valid TOTP secrets
func ScanNVRAMSlots(tpmDev transport.TPM, debug bool) []NVRAMSlot {
	return ScanNVRAMSlotsRange(tpmDev, nvslot.NVRAMSlotStart, nvslot.NVRAMSlotEnd, debug)
}

// ScanNVRAMSlot scans a single NVRAM index and returns it as a slot if valid
func ScanNVRAMSlot(tpmDev transport.TPM, nvramIndex uint32, debug bool) []NVRAMSlot {
	return ScanNVRAMSlotsRange(tpmDev, nvramIndex, nvramIndex, debug)
}

// ScanNVRAMSlotsRange scans NVRAM indices from startIndex to endIndex
// and returns a list of slots containing valid TOTP secrets.
// A lightweight existence check is performed first so that empty indices
// are skipped without incurring the cost of a full unseal attempt.
func ScanNVRAMSlotsRange(tpmDev transport.TPM, startIndex, endIndex uint32, debug bool) []NVRAMSlot {
	// Pre-filter: discover which indices actually hold data.
	populated := nvslot.FindPopulatedSlotsInRange(tpmDev, startIndex, endIndex, debug)
	if len(populated) == 0 {
		return nil
	}

	var slots []NVRAMSlot

	for _, i := range populated {
		slotNumber := nvslot.SlotNumber(i)

		if debug {
			fmt.Printf("Scanning NVRAM slot %d (0x%08X)...\n", slotNumber, i)
		}

		// Cleanup TPM state before each unseal attempt
		tpmdev.Cleanup(tpmDev, debug)

		// In debug mode, peek at the raw NVRAM data before attempting full unseal
		if debug {
			rawData, peekErr := tpmdev.ReadFromNVRAM(tpmDev, i)
			if peekErr == nil {
				peek := nvslot.PeekBlobVersion(rawData)
				fmt.Printf("  Slot %d: NVRAM data found (%d bytes), blob version: %d\n", slotNumber, peek.DataSize, peek.Version)
			} else if debug {
				fmt.Printf("  Slot %d: no NVRAM data (%v)\n", slotNumber, peekErr)
			}
			// Re-cleanup after the peek read
			tpmdev.Cleanup(tpmDev, debug)
		}

		code, _, err := SlotCode(tpmDev, i, time.Now(), debug)
		if errors.Is(err, ErrPhoneSlot) {
			slots = append(slots, NVRAMSlot{SlotNumber: slotNumber, Index: i, Available: true, Phone: true})
			continue
		}
		if err != nil {
			if debug {
				fmt.Printf("  Slot %d: no code (%v)\n", slotNumber, err)
			}
			// The slot was confirmed to exist by the pre-filter, so it
			// is reported with the reason, whatever it is.
			slots = append(slots, NVRAMSlot{SlotNumber: slotNumber, Index: i, Available: true, Error: err})
			continue
		}
		if debug {
			fmt.Printf("  Slot %d: code computed\n", slotNumber)
		}
		slots = append(slots, NVRAMSlot{SlotNumber: slotNumber, Index: i, Code: code, Available: true})
	}

	return slots
}

// GenerateTOTPCodesForSlots collects the codes of the slots that have one,
// keyed by slot number. The codes were computed by the TPM during the scan.
func GenerateTOTPCodesForSlots(slots []NVRAMSlot) (map[int]string, error) {
	codes := make(map[int]string)
	for _, slot := range slots {
		if slot.Error == nil && slot.Code != "" {
			codes[slot.SlotNumber] = slot.Code
		}
	}
	return codes, nil
}

// slotErrorLine describes why a slot has no code, for the boot console.
// It returns "" for a PCR mismatch, which is shown with its details.
func slotErrorLine(err error) string {
	var genErr *nvslot.GenerationMismatchError
	switch {
	case errors.Is(err, nvslot.ErrCodesLocked):
		return "Locked until reboot (codes are only shown before the disk is unlocked)"
	case errors.Is(err, measure.ErrSeparatorLocked):
		return "Locked until the next boot (the OS separator ran after the measure point)"
	case errors.As(err, &genErr):
		if genErr.IndexMissing {
			return "Generation index missing - slot approve"
		}
		return fmt.Sprintf("Approval revoked (blob generation %d, slot at %d) - slot approve", genErr.BlobGeneration, genErr.IndexGeneration)
	}
	if bve, ok := nvslot.IsBlobVersionError(err); ok {
		return fmt.Sprintf("Incompatible blob version (found v%d, requires v%d) - re-seal with: tpm2-kira slot add", bve.FoundVersion, bve.RequiredVersion)
	}
	if _, ok := err.(*measure.PCRMismatchError); ok || tpmdev.IsTPMPolicyFailure(err) {
		return ""
	}
	return fmt.Sprintf("No code: %v", err)
}

// PrintKIRASlots prints TOTP codes in the unified KIRA format with timestamps and PCR details
func PrintKIRASlots(tpmDev transport.TPM, slots []NVRAMSlot, codes map[int]string) {
	FprintKIRASlots(os.Stdout, tpmDev, slots, codes)
}

// FprintKIRASlots is PrintKIRASlots onto w: the console, or an SSH session.
func FprintKIRASlots(w io.Writer, tpmDev transport.TPM, slots []NVRAMSlot, codes map[int]string) {
	now := time.Now().UTC()
	timestamp := now.Format("15:04:05")

	// Yellow color for KIRA
	fmt.Fprintf(w, "[ \033[1;33mKIRA\033[0m ] Time UTC %s\n", timestamp)

	for _, slot := range slots {
		if slot.Error != nil {
			if line := slotErrorLine(slot.Error); line != "" {
				fmt.Fprintf(w, "\033[0;31m#%d\033[0m: %s\n", slot.SlotNumber, line)
				continue
			}

			// This slot has a PCR mismatch or policy failure - red slot number
			fmt.Fprintf(w, "\033[0;31m#%d\033[0m: PCR Mismatch\n", slot.SlotNumber)

			// Try to read the sealed blob to get PCR details
			// Read the sealed blob and current register values for comparison
			sealedData, err := tpmdev.ReadFromNVRAM(tpmDev, slot.Index)
			if err == nil {
				sealedBlob, err := nvslot.UnmarshalSealedBlob(sealedData)
				if err == nil {
					// Read current PCR values from TPM registers only
					// (no eventlog or UKI dependency)
					currentPCRValues, err := nvslot.GetCurrentPCRValuesFromRegisters(tpmDev, sealedBlob, false)
					if err == nil {
						pcrIndices := sealedBlob.GetPCRIndices()
						expectedDigests := sealedBlob.GetPCRDigestValues()

						for idx, pcrIndex := range pcrIndices {
							if idx >= len(expectedDigests) || idx >= len(currentPCRValues) {
								break
							}

							expected := expectedDigests[idx].Buffer
							current := currentPCRValues[idx].Buffer

							status := measure.PCRStatus(expected, current)

							source := sealedBlob.Payload.PCRDigests[idx].Source
							fmt.Fprintf(w, "  PCR%-2d (%s): %s - %s\n", pcrIndex, source.String(), measure.GetPCRDescription(pcrIndex), status)
							fmt.Fprintf(w, "    Expected (blob):    %x\n", expected)
							fmt.Fprintf(w, "    Current (register): %x\n", current)
						}
					}
				}
			}
		} else if slot.Phone {
			fmt.Fprintf(w, "\033[0;33m#%d\033[0m: %s\n", slot.SlotNumber, phoneSlotText(codes, slot))
		} else if code, exists := codes[slot.SlotNumber]; exists {
			// Green slot number for successful reveal
			fmt.Fprintf(w, "\033[0;32m#%d\033[0m: %s", slot.SlotNumber, code)
			if slot.AfterSeparator {
				fmt.Fprint(w, "  (computed after the boot was released: approve to lock it before the OS separator)")
			}
			fmt.Fprintln(w)
		}
	}
}

// phoneSlotText is a phone slot's line: what the boot screen put in codes
// for it, or phoneSlotDefault.
func phoneSlotText(codes map[int]string, slot NVRAMSlot) string {
	if line, ok := codes[slot.SlotNumber]; ok {
		return line
	}
	return phoneSlotDefault
}

// PrintPlainSlots prints TOTP codes in plain format (no KIRA header)
func PrintPlainSlots(slots []NVRAMSlot, codes map[int]string) {
	for _, slot := range slots {
		if slot.Error != nil {
			if line := slotErrorLine(slot.Error); line != "" {
				fmt.Printf("#%d: %s\n", slot.SlotNumber, line)
				continue
			}
			// For plain output with errors, show slot number
			fmt.Printf("#%d: PCR Mismatch\n", slot.SlotNumber)
		} else if slot.Phone {
			fmt.Printf("#%d: %s\n", slot.SlotNumber, phoneSlotText(codes, slot))
		} else if code, exists := codes[slot.SlotNumber]; exists {
			// For plain output with codes, only show the code without prefix if single slot
			if len(slots) == 1 {
				fmt.Printf("%s\n", code)
			} else {
				fmt.Printf("#%d: %s\n", slot.SlotNumber, code)
			}
		}
	}
}

// HasValidSlots returns true if there are any slots with valid TOTP codes
func HasValidSlots(slots []NVRAMSlot) bool {
	for _, slot := range slots {
		if slot.Error == nil && slot.Code != "" {
			return true
		}
	}
	return false
}

// RevealCommand implements the reveal command functionality
func RevealCommand(tpmPath string, nvramIndex uint32, debug bool, plain bool) {
	// Open TPM
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		PrintKIRAError(fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err))
		return
	}
	defer tpmDev.Close()

	// Cleanup TPM memory
	tpmdev.Cleanup(tpmDev, debug)

	// Determine if we should scan all slots or just one
	var slots []NVRAMSlot
	if nvramIndex == 0 {
		// Scan all slots in the default range when nvramIndex is 0
		slots = ScanNVRAMSlots(tpmDev, debug)
		if len(slots) == 0 {
			PrintKIRAError(fmt.Errorf("no TOTP secrets found in NVRAM slots 0x%08X - 0x%08X", nvslot.NVRAMSlotStart, nvslot.NVRAMSlotEnd))
			return
		}
	} else {
		// Scan only the specified index
		slots = ScanNVRAMSlot(tpmDev, nvramIndex, debug)
		if len(slots) == 0 {
			PrintKIRAError(fmt.Errorf("no TOTP secret found at NVRAM index 0x%08X", nvramIndex))
			return
		}
	}

	// Generate TOTP codes for valid slots
	codes, _ := GenerateTOTPCodesForSlots(slots)

	// Display codes (including slots with PCR mismatches)
	if plain {
		PrintPlainSlots(slots, codes)
	} else {
		PrintKIRASlots(tpmDev, slots, codes)
	}
}

// ErrNoTOTPKeyAlgorithm means the TPM supports neither SHA-1 nor SHA-256 HMAC.
var ErrNoTOTPKeyAlgorithm = errors.New("the TPM supports neither SHA-1 nor SHA-256 for HMAC")

// totpKeySize is the size of a fresh TOTP key: the output size of the HMAC
// hash, as RFC 4226 recommends for SHA-1.
func totpKeySize(alg tpm2.TPMAlgID) int {
	if alg == tpm2.TPMAlgSHA256 {
		return sha256.Size
	}
	return 20
}

// ChooseTOTPAlgorithm returns HMAC-SHA1, the TOTP default every authenticator
// supports, or HMAC-SHA256 when the TPM has no SHA-1.
func ChooseTOTPAlgorithm(tpmDev transport.TPM) (tpm2.TPMAlgID, error) {
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapAlgs,
		Property:      uint32(tpm2.TPMAlgSHA1),
		PropertyCount: 64,
	}.Execute(tpmDev)
	if err != nil {
		return 0, fmt.Errorf("failed to read the TPM's algorithms: %w", err)
	}
	algs, err := rsp.CapabilityData.Data.Algorithms()
	if err != nil {
		return 0, fmt.Errorf("failed to parse the TPM's algorithms: %w", err)
	}
	has := map[tpm2.TPMAlgID]bool{}
	for _, a := range algs.AlgProperties {
		has[a.Alg] = true
	}
	switch {
	case has[tpm2.TPMAlgSHA1]:
		return tpm2.TPMAlgSHA1, nil
	case has[tpm2.TPMAlgSHA256]:
		return tpm2.TPMAlgSHA256, nil
	}
	return 0, ErrNoTOTPKeyAlgorithm
}

// CreateTOTPKey creates the HMAC key object for key under the primary key.
// The key is sent to the TPM in a salted, parameter-encrypted session, so it
// does not cross the bus in the clear.
func CreateTOTPKey(tpmDev transport.TPM, primary *tpmdev.PrimaryKeyResponse, key []byte, alg tpm2.TPMAlgID, authPolicy []byte) (*tpmdev.CreateSealedObjectResponse, error) {
	session := tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
		tpm2.Salted(primary.ObjectHandle, primary.Public),
		tpm2.AESEncryption(128, tpm2.EncryptIn))
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: session},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: key}),
			},
		},
		InPublic: tpm2.New2B(totpKeyTemplate(alg, authPolicy)),
	}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to create the TOTP key in the TPM: %w", err)
	}
	return &tpmdev.CreateSealedObjectResponse{Public: rsp.OutPublic.Bytes(), Private: rsp.OutPrivate.Buffer}, nil
}

func totpKeyTemplate(alg tpm2.TPMAlgID, authPolicy []byte) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:    true,
			FixedParent: true,
			SignEncrypt: true,
			// UserWithAuth deliberately NOT set: policy only.
			// SensitiveDataOrigin is clear because tpm2-kira supplies the
			// key, which it must show once for enrolment.
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{
				Scheme:  tpm2.TPMAlgHMAC,
				Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{HashAlg: alg}),
			},
		}),
	}
}

// TOTPCode computes the TOTP code of the slot whose blob is at blobIndex, for
// time t, inside the TPM.
//
// The policy session satisfies the approved policy (PolicyPCR against the
// live registers, PolicyNV against the generation index), then PolicyAuthorize
// with a ticket for the approval signature in the blob. The TPM decides; the
// blob is not trusted for anything it could not also have done itself:
// PolicyAuthorize only accepts the signing key whose Name the key object's
// policy binds.
func TOTPCode(tpmDev transport.TPM, blob *nvslot.SealedBlob, blobIndex uint32, t time.Time) (string, error) {
	p := &blob.Payload
	if p.TOTPAlgorithm != tpm2.TPMAlgSHA1 && p.TOTPAlgorithm != tpm2.TPMAlgSHA256 {
		return "", fmt.Errorf("blob has unknown TOTP algorithm 0x%04x", uint16(p.TOTPAlgorithm))
	}
	session, done, err := nvslot.ApprovedSession(tpmDev, blob, blobIndex)
	if err != nil {
		return "", err
	}
	defer done()
	primary, err := tpmdev.CreatePrimaryKey(tpmDev)
	if err != nil {
		return "", err
	}
	defer tpmdev.FlushHandle(tpmDev, primary.ObjectHandle)
	key, err := LoadSealedObject(tpmDev, primary, blob)
	if err != nil {
		return "", err
	}
	defer tpmdev.FlushHandle(tpmDev, key.ObjectHandle)

	counter := binary.BigEndian.AppendUint64(nil, uint64(t.Unix()/30))
	rsp, err := tpm2.Hmac{
		Handle:  tpm2.AuthHandle{Handle: key.ObjectHandle, Name: key.Name, Auth: session},
		Buffer:  tpm2.TPM2BMaxBuffer{Buffer: counter},
		HashAlg: p.TOTPAlgorithm,
	}.Execute(tpmDev)
	if err != nil {
		if errors.Is(err, nvslot.ErrCodesLocked) {
			return "", nvslot.ErrCodesLocked
		}
		return "", fmt.Errorf("failed to compute the code in the TPM: %w", err)
	}
	return hotpTruncate(rsp.OutHMAC.Buffer), nil
}

// CapCommand implements 'tpm2-kira cap': it read-locks every generation
// index, so that no TOTP code can be computed until the next reboot. Run it
// when leaving the initrd; the systemd unit and the initramfs-tools script do.
func CapCommand(tpmPath string) error {
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	n, err := nvslot.CapCodes(tpmDev)
	if err != nil {
		return fmt.Errorf("locked %d generation index(es), but not all: %w", n, err)
	}
	fmt.Printf("tpm2-kira: locked %d generation index(es); no codes until the next reboot\n", n)
	return nil
}
