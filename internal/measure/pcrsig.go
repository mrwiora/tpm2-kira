package measure

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/mrwiora/tpm2-kira/core/attest"
)

// The PCR key's signatures as systemd writes them (systemd-measure sign --json,
// a UKI's .pcrsig; systemd-stub hands them over to the initrd):
//
//	{"sha256": [{"pcrs": [11], "pkfp": "...", "pol": "<hex>", "sig": "<base64>"}], ...}

// PCRSignatures are those signatures, by the bank's name.
type PCRSignatures map[string][]struct {
	PCRs []int  `json:"pcrs"`
	Pkfp string `json:"pkfp"`
	Pol  string `json:"pol"`
	Sig  string `json:"sig"`
}

// BootPCRSignaturePaths are where the initrd finds the booted image's
// signatures: systemd-stub's file, and systemd's copy of it. A var: the tests
// point it elsewhere.
var BootPCRSignaturePaths = []string{"/run/systemd/tpm2-pcr-signature.json", "/.extra/tpm2-pcr-signature.json"}

// ParsePCRSignatures reads systemd's JSON (trailing NULs allowed, as a section
// has them).
func ParsePCRSignatures(b []byte) (PCRSignatures, error) {
	var p PCRSignatures
	if err := json.Unmarshal(bytes.TrimRight(b, "\x00"), &p); err != nil {
		return nil, fmt.Errorf("not systemd's PCR signatures: %w", err)
	}
	return p, nil
}

// ReadBootPCRSignatures reads the booted image's signatures from the first of
// BootPCRSignaturePaths that is there.
func ReadBootPCRSignatures() (PCRSignatures, error) {
	var last error
	for _, path := range BootPCRSignaturePaths {
		b, err := os.ReadFile(path)
		if err != nil {
			last = err
			continue
		}
		return ParsePCRSignatures(b)
	}
	return nil, fmt.Errorf("no signatures of PCR 11 from the image: %w", last)
}

// Find is the signature by the key in PKIX DER, for pcrs in bank, over pol;
// nil when there is none. It is checked here.
func (p PCRSignatures) Find(key []byte, bank PCRHashAlgo, pcrs []int, pol []byte) []byte {
	for _, e := range p[string(bank)] {
		if !slices.Equal(e.PCRs, pcrs) {
			continue
		}
		if got, err := hex.DecodeString(e.Pol); err != nil || !bytes.Equal(got, pol) {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(e.Sig)
		if err != nil {
			continue
		}
		if attest.VerifyPCRSignature(key, pol, sig) == nil {
			return sig
		}
	}
	return nil
}

// SignedPolicy is what the PCR key signs for one PCR's value: the PolicyPCR
// digest of a fresh SHA-256 session.
func SignedPolicy(pcr int, value []byte, bank PCRHashAlgo) []byte {
	composite := sha256.Sum256(value)
	h := sha256.New()
	h.Write(make([]byte, sha256.Size))
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(tpm2.TPMCCPolicyPCR)))
	h.Write(tpm2.Marshal(CreatePCRSelection([]int{pcr}, bank)))
	h.Write(composite[:])
	return h.Sum(nil)
}

// UKIPCRSignatures reads the .pcrsig section of the image at path.
func UKIPCRSignatures(path string) (PCRSignatures, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer f.Close()
	s := f.Section(".pcrsig")
	if s == nil {
		return nil, fmt.Errorf("%s has no .pcrsig section", path)
	}
	b, err := s.Data()
	if err != nil {
		return nil, fmt.Errorf("%s: .pcrsig: %w", path, err)
	}
	return ParsePCRSignatures(b)
}

// CheckUKIPCRSig checks that the image's .pcrsig holds what the slots need and
// nothing else: exactly one signature per bank, by the key in PKIX DER, and for
// the banks tpm2-kira computes, the image's PCR 11 at enter-initrd. A signature
// of a later phase too would let the running system meet the policy.
func CheckUKIPCRSig(path string, key []byte) error {
	sigs, err := UKIPCRSignatures(path)
	if err != nil {
		return err
	}
	if len(sigs) == 0 {
		return fmt.Errorf("%s: .pcrsig holds no signature", path)
	}
	for bank, entries := range sigs {
		if len(entries) != 1 {
			return fmt.Errorf("%s: .pcrsig holds %d signatures for %s, not exactly one for enter-initrd", path, len(entries), bank)
		}
	}
	for _, algo := range []PCRHashAlgo{PCRHashAlgoSHA256, PCRHashAlgoSHA1} {
		if _, ok := sigs[string(algo)]; !ok {
			if algo == PCRHashAlgoSHA256 {
				return fmt.Errorf("%s: .pcrsig has no signature for sha256", path)
			}
			continue
		}
		value, err := PredictPCR11FromUKI(path, MeasurePointPhases, algo, false)
		if err != nil {
			return err
		}
		if sigs.Find(key, algo, []int{TPM2PCRKernelBoot}, SignedPolicy(TPM2PCRKernelBoot, value, algo)) == nil {
			return fmt.Errorf("%s: .pcrsig holds no signature by the PCR key of PCR 11 at enter-initrd (%s)", path, algo)
		}
	}
	return nil
}
