package tpmdev

import "os"

// PreferResourceManager returns /dev/tpmrm0 for a /dev/tpm0 path when the
// kernel's resource manager is available. The gate runs next to the OTP
// display in the initrd; on the raw device only one process may open the TPM,
// and the display's per-cycle cleanup would flush the gate's loaded AK.
func PreferResourceManager(path string) string {
	if path != "/dev/tpm0" {
		return path
	}
	if st, err := os.Stat("/dev/tpmrm0"); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		return "/dev/tpmrm0"
	}
	return path
}
