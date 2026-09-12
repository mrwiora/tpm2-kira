package cmd

import (
	"bytes"
	"debug/pe"
	"io"
	"testing"
)

// systemd-stub measures the unpadded section contents. debug/pe's Section.Size
// is SizeOfRawData, which is padded to the file alignment, so measuring it
// silently produces a PCR 11 value the machine will never present.
func TestPredictPCR11UsesUnpaddedSections(t *testing.T) {
	file, err := pe.Open(DefaultUKIPath)
	if err != nil {
		t.Skipf("no unified kernel image at %s: %v", DefaultUKIPath, err)
	}
	defer file.Close()

	measure := func(padded bool) []byte {
		pcr := make([]byte, 32)
		for _, name := range ukiMeasuredSections {
			section := file.Section(name)
			if section == nil {
				continue
			}
			size := int64(section.VirtualSize)
			if size == 0 || size > int64(section.Size) {
				size = int64(section.Size)
			}
			if padded {
				size = int64(section.Size)
			}
			if size == 0 {
				continue
			}
			pcr = ExtendDigest(PCRHashAlgoSHA256, pcr,
				DigestOf(PCRHashAlgoSHA256, append([]byte(name), 0)))
			hasher := newHashFor(PCRHashAlgoSHA256)
			if _, err := io.CopyN(hasher, section.Open(), size); err != nil {
				t.Fatalf("section %s: %v", name, err)
			}
			pcr = ExtendDigest(PCRHashAlgoSHA256, pcr, hasher.Sum(nil))
		}
		return ExtendDigest(PCRHashAlgoSHA256, pcr,
			DigestOf(PCRHashAlgoSHA256, []byte(EnterInitrdWord)))
	}

	unpadded, paddedValue := measure(false), measure(true)
	if bytes.Equal(unpadded, paddedValue) {
		t.Skip("no measured section is padded in this image; the test cannot distinguish")
	}

	got, err := PredictPCR11FromUKI(DefaultUKIPath, MeasurePointPhases, PCRHashAlgoSHA256, false)
	if err != nil {
		t.Fatalf("PredictPCR11FromUKI: %v", err)
	}
	if bytes.Equal(got, paddedValue) {
		t.Fatalf("PCR 11 was computed over padded sections (SizeOfRawData); got %x", got)
	}
	if !bytes.Equal(got, unpadded) {
		t.Errorf("PCR 11 mismatch:\n got  %x\n want %x", got, unpadded)
	}
}
