package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// NVRAMRestore puts a blob that WriteToNVRAM stashed under NVRAMRecoveryDir
// back into its slot. The file holds the sealed object the TPM can still
// load, so the secret survives the lost index; what the file cannot carry
// is a current approval - the slot's generation index has moved on, or the
// PCRs have - so the blob is approved and written as reseal does it, with
// the PCR selection it was sealed to. The slot must be empty: restoring
// over a blob would destroy one to bring back another, which is a delete
// and a restore, said so. Index from --nvram, else from the file's name.
// The file is removed once the write has been read back.
func NVRAMRestore(tpmPath, file string, nvramIndex uint32, pubKeyPath, privKeyPath string, debug bool) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("cannot restore: %w", err)
	}
	if nvramIndex == 0 {
		nvramIndex, err = recoveryFileIndex(file)
		if err != nil {
			return fmt.Errorf("cannot restore: %w", err)
		}
	}
	if err := ValidateBlobIndex(nvramIndex); err != nil {
		return fmt.Errorf("cannot restore: %w", err)
	}
	blob, err := UnmarshalSealedBlob(data)
	if err != nil {
		if bve, ok := IsBlobVersionError(err); ok {
			return fmt.Errorf("cannot restore: %s holds a version %d blob and this build writes version %d; seal again (new TOTP secret, re-enrol)",
				file, bve.FoundVersion, bve.RequiredVersion)
		}
		return fmt.Errorf("cannot restore: %s is not a tpm2-kira blob: %w", file, err)
	}

	keys, err := resolveResealKeys(data, blob, privKeyPath, pubKeyPath, debug)
	if err != nil {
		return err
	}
	signer := keys.signer
	if err := checkObjectSigningKey(blob, signer.Public()); err != nil {
		return fmt.Errorf("cannot restore: %w", err)
	}
	if err := PrepareSigningKey(signer); err != nil {
		return fmt.Errorf("cannot restore: %w", err)
	}

	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	CleanupTPM(tpmDev, debug)

	if existing, err := ReadFromNVRAM(tpmDev, nvramIndex); err == nil {
		if _, err := UnmarshalSealedBlob(existing); err == nil {
			return fmt.Errorf("cannot restore: slot #%d (0x%08X) holds a blob already.\n"+
				"  Restoring would replace it. If that is what you want: tpm2-kira nvram delete --nvram %d, then restore again",
				SlotNumber(nvramIndex), nvramIndex, SlotNumber(nvramIndex))
		}
		return fmt.Errorf("cannot restore: NVRAM index 0x%08X exists and holds something that is not a tpm2-kira blob; delete it first", nvramIndex)
	}

	specs := blob.GetPCRSpecs()
	hashAlgo := blob.GetHashAlgo()
	fmt.Printf("Restoring slot #%d (0x%08X) from %s\n", SlotNumber(nvramIndex), nvramIndex, file)
	fmt.Printf("PCR selection as sealed: %s, %s\n", PCRSpecsToString(specs), hashAlgo.DisplayString())
	pub := signer.Public()
	fmt.Printf("Signing key: %s (%s, fingerprint: %s)\n", keys.privKeyPath, PublicKeyDescription(pub), PublicKeyFingerprint(pub))

	blob.Payload.PrivateKeyPath = keys.privKeyPath
	blob.Payload.PublicKeyPath = pubKeyPath
	if pubKeyPath == "" && keys.privKeyPath == DefaultPrivateKeyPath {
		blob.Payload.PublicKeyPath = DefaultPublicKeyPath
	}
	if err := approveAndWrite(tpmDev, nvramIndex, blob, specs, hashAlgo, false, signer, debug); err != nil {
		return fmt.Errorf("failed to restore: %w", err)
	}

	phones := "no phone"
	if a := blob.Payload.Attestation; a != nil && a.Phone.Enabled() {
		phones = "its phone"
	}
	fmt.Printf("\nRestored slot #%d: the TOTP key and %s, approved for PCRs %s at generation %d\n",
		SlotNumber(nvramIndex), phones, PCRSpecsToString(specs), blob.Payload.Generation)
	if err := os.Remove(file); err != nil {
		fmt.Printf("The slot holds the blob again; %s could not be removed (%v) and may be deleted\n", file, err)
	} else {
		fmt.Printf("%s removed: the slot holds the blob again\n", file)
	}
	return nil
}

// recoveryFileIndex reads the NV index out of a stashed blob's file name,
// slot-0x<index>-<time>.blob, as stashUnwrittenBlobFile wrote it.
func recoveryFileIndex(file string) (uint32, error) {
	name := filepath.Base(file)
	rest, ok := strings.CutPrefix(name, "slot-0x")
	if !ok {
		return 0, errors.New("the file is not named slot-0x<index>-<time>.blob; pass --nvram")
	}
	hex, _, ok := strings.Cut(rest, "-")
	if !ok {
		return 0, errors.New("the file is not named slot-0x<index>-<time>.blob; pass --nvram")
	}
	v, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("no NV index in the file's name (%q); pass --nvram", hex)
	}
	return uint32(v), nil
}
