package measure

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"   // the SHA-1 bank's Authenticode hash
	_ "crypto/sha256" // the SHA-256 bank's
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/google/go-attestation/attest"
	"github.com/tpm2-trust/go-uefi-slim/authenticode"
)

// PCR 4 holds what the firmware loaded: EV_EFI_BOOT_SERVICES_APPLICATION, the
// Authenticode hash of each image (systemd-boot and the UKI; shim and GRUB).
// It moves at every loader and kernel update, so it is predicted for the next
// boot ("4u"), never taken as it was: this boot's log, with each of those
// events' digests replaced by the hash of the file as it will be booted,
// every other event of PCR 4 as it is.

// TPM2PCRBootLoader is the PCR the firmware measures what it loads into.
const TPM2PCRBootLoader = 4

// evBootServicesApplication is EV_EFI_BOOT_SERVICES_APPLICATION.
const evBootServicesApplication = 0x80000003

// evNoAction is EV_NO_ACTION, which extends nothing.
const evNoAction = 0x03

// espRoots are where the EFI system partition is mounted. A var: the tests
// point it elsewhere.
var espRoots = []string{"/boot", "/efi", "/boot/efi"}

// ukiLoaderDir is where the boot loader finds unified kernel images: an image
// loaded from there is the UKI of the next boot, whatever this boot's was
// called.
const ukiLoaderDir = `\efi\linux\`

// PCR4Prediction is the next boot's PCR 4 and how it came about.
type PCR4Prediction struct {
	Value []byte
	// Replaced names the images whose digest differs from this boot's.
	Replaced []string
	// Kept names the images whose digest stays this boot's: no file to hash.
	Kept []string
}

// PredictPCR4 is the next boot's PCR 4 from the event log at eventlogPath;
// ukiPath is the image that replaces what the firmware loaded from
// \EFI\Linux\.
func PredictPCR4(eventlogPath, ukiPath string, algo PCRHashAlgo) (*PCR4Prediction, error) {
	raw, err := ReadRawEventLogFromPath(eventlogPath)
	if err != nil {
		return nil, fmt.Errorf("PCR 4 is predicted from the event log: %w", err)
	}
	log, err := attest.ParseEventLog(raw)
	if err != nil {
		return nil, fmt.Errorf("PCR 4 is predicted from the event log: %w", err)
	}
	return predictPCR4(log.Events(AttestHash(algo)), ukiPath, algo)
}

func predictPCR4(events []attest.Event, ukiPath string, algo PCRHashAlgo) (*PCR4Prediction, error) {
	p := &PCR4Prediction{Value: make([]byte, algo.DigestSize())}
	seen := 0
	for _, e := range events {
		if e.Index != TPM2PCRBootLoader || e.Type == evNoAction {
			continue
		}
		digest := e.Digest
		if uint32(e.Type) == evBootServicesApplication {
			seen++
			path := imageLoadPath(e.Data)
			file := espFile(path, ukiPath)
			next, err := fileAuthenticode(file, algo)
			switch {
			case err != nil:
				p.Kept = append(p.Kept, fmt.Sprintf("%q: %v", path, err))
			case !bytes.Equal(next, digest):
				p.Replaced = append(p.Replaced, file)
				digest = next
			}
		}
		p.Value = ExtendDigest(algo, p.Value, digest)
	}
	if seen == 0 {
		return nil, fmt.Errorf("the event log has no image the firmware loaded in PCR 4")
	}
	return p, nil
}

// espFile is the file on the EFI system partition for path from an event, the
// UKI for one under \EFI\Linux\; "" when there is none.
func espFile(path, ukiPath string) string {
	if path == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(path), ukiLoaderDir) && ukiPath != "" {
		return ukiPath
	}
	rel := strings.ReplaceAll(strings.TrimPrefix(path, `\`), `\`, "/")
	for _, root := range espRoots {
		f := filepath.Join(root, filepath.FromSlash(rel))
		if st, err := os.Stat(f); err == nil && st.Mode().IsRegular() {
			return f
		}
	}
	return ""
}

// fileAuthenticode is the file's Authenticode hash in the bank's hash.
func fileAuthenticode(path string, algo PCRHashAlgo) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("not on the EFI system partition")
	}
	img, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	h := crypto.SHA256
	if algo == PCRHashAlgoSHA1 {
		h = crypto.SHA1
	}
	return authenticode.HashWith(img, h)
}

// imageLoadPath is the file path in a UEFI_IMAGE_LOAD_EVENT's device path
// (TCG PC Client Platform Firmware Profile): location, length and link address
// of the image, the device path's length and the path, whose media file path
// nodes (type 4, subtype 4) hold the file, in UTF-16. "" when it names none.
func imageLoadPath(data []byte) string {
	const header = 32
	if len(data) < header {
		return ""
	}
	length := binary.LittleEndian.Uint64(data[24:])
	if length > uint64(len(data)-header) {
		return ""
	}
	dp := data[header : header+int(length)]
	var path strings.Builder
	for len(dp) >= 4 {
		nodeLen := int(binary.LittleEndian.Uint16(dp[2:]))
		if nodeLen < 4 || nodeLen > len(dp) {
			return ""
		}
		if dp[0] == 4 && dp[1] == 4 {
			units := make([]uint16, 0, (nodeLen-4)/2)
			for b := dp[4:nodeLen]; len(b) >= 2 && (b[0] != 0 || b[1] != 0); b = b[2:] {
				units = append(units, binary.LittleEndian.Uint16(b))
			}
			path.WriteString(string(utf16.Decode(units)))
		}
		dp = dp[nodeLen:]
	}
	return path.String()
}
