package cmd

// The machine's boot settings: one small NV index the code screen and the
// phone check read at boot. Today it holds one switch, debug, which makes
// both log every step they take and put the phone check's narrative on
// the console. It lives in the TPM, not in the boot image or on the kernel
// command line, so switching it changes neither the image nor PCR 11 - a
// unified kernel image under Secure Boot has a command line nobody can
// edit at boot - and takes effect at the next boot.
//
// Only 'tpm2-kira control' writes it, with the signing key (PolicySigned,
// as the slots' blobs): nobody else can turn on verbose output on the
// console. Anyone with TPM access can read it; it holds nothing secret.
// It is not measured: it changes how much is logged, not what is trusted.

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
)

// BootSettingsIndex is the boot settings' NV index: the free start of
// tpm2-kira's range, below the slots.
const BootSettingsIndex = 0x01803000

// bootSettingsVersion is the format: [version:1][flags:1].
const bootSettingsVersion = 1

const bootFlagDebug = 1 << 0

// BootSettings are the switches the boot reads.
type BootSettings struct {
	Debug bool // the code screen and the phone check log every step
}

func (s BootSettings) marshal() []byte {
	var flags byte
	if s.Debug {
		flags |= bootFlagDebug
	}
	return []byte{bootSettingsVersion, flags}
}

func parseBootSettings(b []byte) (BootSettings, error) {
	if len(b) != 2 || b[0] != bootSettingsVersion {
		return BootSettings{}, fmt.Errorf("the boot settings at 0x%08X are not in this version's format", BootSettingsIndex)
	}
	if b[1]&^bootFlagDebug != 0 {
		return BootSettings{}, fmt.Errorf("the boot settings at 0x%08X carry flags this version does not know", BootSettingsIndex)
	}
	return BootSettings{Debug: b[1]&bootFlagDebug != 0}, nil
}

// ReadBootSettings reads the boot settings; no index means all off.
func ReadBootSettings(tpmDev transport.TPM) (BootSettings, error) {
	if !NVRAMIndexExists(tpmDev, BootSettingsIndex) {
		return BootSettings{}, nil
	}
	data, err := ReadFromNVRAM(tpmDev, BootSettingsIndex)
	if err != nil {
		return BootSettings{}, err
	}
	return parseBootSettings(data)
}

// WriteBootSettings writes the boot settings with the signing key. With
// every switch off the index is removed: nothing left behind to explain.
func WriteBootSettings(tpmDev transport.TPM, s BootSettings, signer crypto.Signer) error {
	if signer == nil {
		return errors.New("the boot settings are written with the signing key")
	}
	if s == (BootSettings{}) {
		if !NVRAMIndexExists(tpmDev, BootSettingsIndex) {
			return nil
		}
		return undefineIndex(tpmDev, BootSettingsIndex)
	}
	return WriteToNVRAM(tpmDev, BootSettingsIndex, s.marshal(), signer.Public(), signer)
}

// BootDebug reports the debug switch, read through the TPM at tpmPath (the
// resource manager when there is one: the code screen holds the TPM too).
// Any failure is "off": debug only adds output.
func BootDebug(tpmPath string) bool {
	tpmDev, err := OpenTPM(preferResourceManager(tpmPath))
	if err != nil {
		return false
	}
	defer tpmDev.Close()
	s, err := ReadBootSettings(tpmDev)
	return err == nil && s.Debug
}
