// Package efivars is where tpm2-kira keeps its own EFI variables (the
// slots' records, the sealed machine-id): under tpm2-kira's vendor GUID,
// through the workspace's go-uefi-slim module. aSSH's variable (the SSH CA's) is
// aSSH's, through its persist; both live in the same efivarfs.
package efivars

import (
	"errors"
	"os"

	"github.com/tpm2-trust/assh/persist"
	"github.com/tpm2-trust/go-uefi-slim/efivar"
)

// GUIDText is the vendor GUID of tpm2-kira's EFI variables.
const GUIDText = "67f474ef-94a1-4412-88df-d62349d430a9"

// GUID is GUIDText's binary form.
var GUID = efivar.MustParseGUID(GUIDText)

// attributes: non-volatile, boot service and runtime access; no
// authenticated write - what is kept is signed or sealed, the TPM checks it.
const attributes = efivar.NonVolatile | efivar.BootServiceAccess | efivar.RuntimeAccess

// Dir is where efivarfs is mounted; SetDir points it elsewhere.
var Dir = efivar.DefaultDir

// SetDir points every EFI variable tpm2-kira reads or writes - its own and
// aSSH's - at dir: the tests, and the binaries run by them.
func SetDir(dir string) {
	Dir = dir
	persist.VarDir = dir
}

func store() efivar.Store { return efivar.Store{Dir: Dir} }

// Name is the variable's file name: NAME-GUID.
func Name(name string) string { return name + "-" + GUIDText }

// Read is the variable's data; an error os.IsNotExist knows when there is
// none.
func Read(name string) ([]byte, error) {
	_, data, err := store().Read(name, GUID)
	return data, err
}

// Write replaces the variable, in one write; an empty one is refused.
func Write(name string, data []byte) error {
	return store().Write(name, GUID, attributes, data)
}

// Remove removes the variable and reports whether there was one.
func Remove(name string) (bool, error) {
	err := store().Remove(name, GUID)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Readable says whether the EFI variables are there to read: a mounted
// efivarfs always holds the firmware's own, so an empty or missing
// directory is one that is not mounted.
func Readable() bool {
	entries, err := os.ReadDir(Dir)
	return err == nil && len(entries) > 0
}
