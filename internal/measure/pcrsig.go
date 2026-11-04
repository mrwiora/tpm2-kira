package measure

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/tpm2-trust/go-uefi-slim/uki"
	"github.com/tpm2-trust/tpm2-kira/core/attest"
)

// BootPCRSignaturePaths are where the initrd finds the booted image's
// signatures: systemd-stub's file, and systemd's copy of it. A var: the tests
// point it elsewhere.
var BootPCRSignaturePaths = []string{"/run/systemd/tpm2-pcr-signature.json", "/.extra/tpm2-pcr-signature.json"}

// ReadBootPCRSignatures reads the booted image's signatures from the first of
// BootPCRSignaturePaths that is there.
func ReadBootPCRSignatures() (uki.PCRSignatures, error) {
	var last error
	for _, path := range BootPCRSignaturePaths {
		b, err := os.ReadFile(path)
		if err != nil {
			last = err
			continue
		}
		return uki.ParsePCRSignatures(b)
	}
	return nil, fmt.Errorf("no signatures of PCR 11 from the image: %w", last)
}

// FindPCRSignature is the signature in p by the PCR key in PKIX DER, for pcrs in
// bank, over pol; nil when there is none. It is checked here.
func FindPCRSignature(p uki.PCRSignatures, key []byte, bank PCRHashAlgo, pcrs []int, pol []byte) []byte {
	return p.Find(string(bank), pcrs, pol, func(sig []byte) error {
		return attest.VerifyPCRSignature(key, pol, sig)
	})
}

// SignedPolicy is what the PCR key signs for one PCR's value: the PolicyPCR
// digest of a fresh SHA-256 session.
func SignedPolicy(pcr int, value []byte, bank PCRHashAlgo) []byte {
	composite := sha256.Sum256(value)
	return attest.PolicyDigest(tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{Buffer: composite[:]},
		Pcrs:      CreatePCRSelection([]int{pcr}, bank),
	}.Update)
}

// UKIPCRSignatures reads the .pcrsig section of the image at path.
func UKIPCRSignatures(path string) (uki.PCRSignatures, error) {
	i, err := uki.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer i.Close()
	p, err := i.PCRSignatures()
	if errors.Is(err, uki.ErrNoSection) {
		return nil, fmt.Errorf("%s has no .pcrsig section", path)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: .pcrsig: %w", path, err)
	}
	return p, nil
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
		if FindPCRSignature(sigs, key, algo, []int{TPM2PCRKernelBoot}, SignedPolicy(TPM2PCRKernelBoot, value, algo)) == nil {
			return fmt.Errorf("%s: .pcrsig holds no signature by the PCR key of PCR 11 at enter-initrd (%s)", path, algo)
		}
	}
	return nil
}
