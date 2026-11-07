//go:build integration
// +build integration

package main

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/totp"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"
)

// slotCode asks the TPM for a slot's code now (totp.SlotCode, what the boot's code screen asks):
// the six digits, or "#N: why" as the code screen says it ("PCR Mismatch" where it shows the
// registers). No command shows a code on the running system, where the boot is closed; the
// suite's swtpm never is, so the tests ask the TPM directly. err is set only when the TPM
// cannot be opened or the slot named is no slot.
func slotCode(t *testing.T, tpmPath, nvram string) (stdout, stderr string, err error) {
	t.Helper()
	n, err := strconv.ParseUint(nvram, 0, 32)
	if err != nil {
		return "", "", err
	}
	idx := nvslot.ResolveNVRAMIndex(uint32(n))
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return "", "", err
	}
	defer tpmDev.Close()
	tpmdev.Cleanup(tpmDev, false)
	code, _, err := totp.SlotCode(tpmDev, idx, time.Now(), false)
	if err == nil {
		return code + "\n", "", nil
	}
	line := totp.SlotErrorLine(err)
	if line == "" {
		line = "PCR Mismatch"
	}
	return fmt.Sprintf("#%d: %s\n", nvslot.SlotNumber(idx), line), err.Error(), nil
}
