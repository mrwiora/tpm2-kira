package kira

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// KeyReferencePEMType marks a file that names where the signing key lives
// instead of containing it.
//
// The private key path is a fixed, well-known location: the default for
// --privkey, what the reseal hook passes, and what the documentation tells
// people to back up. When the key lives on a hardware token there is no key
// material to put there, and leaving the file absent broke the step between
// 'setup' and the first 'seal' — setup recorded the operator's choice nowhere,
// so seal fell back to the default path and failed on a file that was never
// going to exist.
//
// So the file is always written, and its PEM block type says which kind of key
// it is. sbctl does the same thing for a TPM-held Secure Boot key: db.key keeps
// its name and carries a "TSS2 PRIVATE KEY" block rather than a "PRIVATE KEY"
// one. The benefit is that one path resolves for both variants, so every script,
// hook and flag keeps working, and an older tool reading this file reports an
// unsupported block type rather than a mangled key.
const KeyReferencePEMType = "TPM2-KIRA KEY REFERENCE"

// ErrRealKeyPresent is returned when a reference would overwrite a file that
// holds actual key material. Replacing it would destroy the only copy of a key
// that cannot be regenerated, so callers must decide, never the writer.
var ErrRealKeyPresent = errors.New("a private key is already stored at this path")

// referenceFilePreamble explains the file to whoever cats it. pem.Decode skips
// everything before the BEGIN line, so this is free.
func referenceFilePreamble(ref KeyRef) string {
	return fmt.Sprintf(`# tpm2-kira signing key reference — this file is NOT a private key.
#
# The signing key lives on a hardware token:
#
#     %s
#
# The token has to be connected to seal, to reseal after a firmware or kernel
# update, and to write the recovery NV index. It is never needed at boot.
#
# Deleting this file loses only the pointer, not the key: pass the reference
# above to --privkey, or run 'tpm2-kira yubikey adopt' to write it again.
`, ref)
}

// MarshalKeyReference encodes a token reference in PEM form.
func MarshalKeyReference(ref KeyRef) ([]byte, error) {
	if ref.Kind != KeyRefYubiKey {
		return nil, fmt.Errorf("only a token-held key can be recorded as a reference, got %v", ref)
	}

	block := pem.EncodeToMemory(&pem.Block{
		Type:  KeyReferencePEMType,
		Bytes: []byte(ref.String()),
	})
	if block == nil {
		return nil, fmt.Errorf("failed to encode the key reference for %v", ref)
	}

	return append([]byte(referenceFilePreamble(ref)), block...), nil
}

// ReadKeyReference reports whether path holds a reference rather than a key,
// and to what. A file that is absent, unreadable or a genuine key yields
// ok=false with no error: the caller is asking a question, not demanding a
// reference, and the ordinary key path handles all three.
func ReadKeyReference(path string) (ref KeyRef, ok bool, err error) {
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		return KeyRef{}, false, nil
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != KeyReferencePEMType {
		return KeyRef{}, false, nil
	}

	// Past this point the file says it is a reference, so a problem with it is
	// a real error: silently treating it as a key would produce a far more
	// confusing failure further down.
	parsed, parseErr := ParseKeyRef(string(block.Bytes))
	if parseErr != nil {
		return KeyRef{}, false, fmt.Errorf("%s is a key reference file, but its contents are unusable: %w", path, parseErr)
	}

	if parsed.Kind != KeyRefYubiKey {
		return KeyRef{}, false, fmt.Errorf("%s is a key reference file, but it names %q rather than a token slot", path, string(block.Bytes))
	}

	return parsed, true, nil
}

// InstallKeyReference records ref at path, refusing to overwrite key material.
//
// Replacing an existing reference is fine — it is only a pointer, and a key
// moved to another token or slot has to be repointed somewhere. Replacing a
// private key is not: that file may be the only copy, so it returns
// ErrRealKeyPresent and leaves it untouched.
func InstallKeyReference(path string, ref KeyRef) error {
	if _, err := os.Stat(path); err == nil {
		if _, isRef, refErr := ReadKeyReference(path); refErr != nil {
			return refErr
		} else if !isRef {
			return fmt.Errorf("%w: %s", ErrRealKeyPresent, path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot examine %s: %w", path, err)
	}

	pemBytes, err := MarshalKeyReference(ref)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("failed to create %s: %w", filepath.Dir(path), err)
	}

	// 0644, unlike the 0400 of a real key: a slot number is not a secret, and
	// marking it as one would have WarnAboutKeyPermissions nagging about a file
	// that has nothing to protect.
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		return fmt.Errorf("failed to write the key reference to %s: %w", path, err)
	}

	return nil
}
