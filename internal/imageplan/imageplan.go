// Package imageplan is what a boot image carries: its parts, named in
// Dir, and what run starts from them.
package imageplan

import (
	"os"
	"path/filepath"
	"time"
)

// TPMWait is how long run waits for the TPM's device to appear.
const TPMWait = 5 * time.Second

// ImagePlanDir is where the image names its parts.
const Dir = "/etc/tpm2-kira/plan"

// Planned is what 'run' starts, from the image's ImagePlanDir.
type Planned struct {
	Codes, Phone, Vault bool
	// TPM: a part needs the TPM, and run waits for its device first.
	TPM bool
}

// AllPlanned is 'run' without a plan, by hand: everything it finds.
var All = Planned{Codes: true, Phone: true, Vault: true, TPM: true}

// ReadPlanned reads the parts an image names in dir.
func Read(dir string) Planned {
	has := func(name string) bool {
		st, err := os.Stat(filepath.Join(dir, name))
		return err == nil && st.IsDir()
	}
	return Planned{Codes: has(PartCodes), Phone: has(PartPhone), Vault: has(PartVault), TPM: has(PartTPM)}
}

// The parts, in the order they are told.
const (
	PartUnlock = "unlock" // the key provider: always
	PartCodes  = "codes"  // the TOTP code screen
	PartPhone  = "phone"  // the Bluetooth gate for an enrolled phone
	PartVault  = "vault"  // a slot's key from the vault
	PartNet    = "net"    // the image's network
	PartSSH    = "ssh"    // tpm2-kira's SSH server
	// PartTPM is derived: run waits for the TPM's device (TPMWait) when a
	// part needs it. It is a marker, not a part of its own.
	PartTPM = "tpm"
)
