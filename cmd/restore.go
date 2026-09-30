package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/go-tpm/tpm2/transport"
)

// Restoring a sealed blob that could not be committed to NVRAM.
//
// Replacing an NV index means undefining it first, and TPM 2.0 has no atomic
// replace. WriteToNVRAM does everything that can fail before that point — see
// its comment — but a TPM error or a token pulled mid-write can still leave the
// index empty. It then writes the blob to NVRAMRecoveryDir, because the sealed
// object's private area is wrapped by this TPM's deterministically re-derived
// primary key: the secret survives in those bytes even though the index is gone.
//
// This is what writes them back.

// NVRAMRestore writes a stashed blob back to an NVRAM index.
//
// fromPath may be empty, in which case the newest stash recorded for this index
// is used. keyRefStr overrides the key reference the blob itself names.
func NVRAMRestore(tpmPath string, index uint32, fromPath, keyRefStr string, force, debug bool) error {
	if err := ValidateNVRAMIndex(index); err != nil {
		return fmt.Errorf("invalid NVRAM index: %w", err)
	}

	path, err := resolveStashPath(index, fromPath)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}

	fmt.Printf("Restoring NVRAM index 0x%08X (slot #%d) from:\n    %s\n",
		index, SlotNumber(index), path)
	fmt.Printf("Blob size: %d bytes\n\n", len(data))

	blob, err := UnmarshalSealedBlob(data)
	if err != nil {
		if bve, ok := IsBlobVersionError(err); ok {
			return fmt.Errorf(
				"cannot restore: the stashed blob is version %d but this build writes version %d.\n"+
					"  There is no migration between blob versions, so it cannot be written back.\n"+
					"  Run 'tpm2-kira seal' to start over; the TOTP secret in this file cannot be recovered\n"+
					"  by this build, so you will need to re-enrol your authenticator",
				bve.FoundVersion, bve.RequiredVersion)
		}
		return fmt.Errorf("failed to parse the stashed blob: %w", err)
	}

	// ── Resolve the signing key ──
	// The write policy on the index is PolicySigned, so restoring needs the
	// key just as sealing did. The blob names it, which is why v9 stores a
	// reference rather than a bare path.
	effectiveRef := keyRefStr
	if effectiveRef == "" && !blob.Payload.PrivateKeyRef.IsZero() {
		effectiveRef = blob.Payload.PrivateKeyRef.String()
		if debug {
			fmt.Printf("Using the key reference recorded in the blob: %s\n", effectiveRef)
		}
	}
	if effectiveRef == "" {
		if _, statErr := os.Stat(DefaultPrivateKeyPath); statErr == nil {
			effectiveRef = DefaultPrivateKeyPath
		}
	}

	keyRef, err := ParseKeyRef(effectiveRef)
	if err != nil {
		return err
	}

	signingKey, err := OpenSigningKey(keyRef, NewPINProvider(PINFileSetting), debug)
	if err != nil {
		return fmt.Errorf("cannot restore: the signing key is needed to authorise the NVRAM write: %w", err)
	}
	defer signingKey.Close()

	fmt.Printf("Signing key: %s\n", signingKey.Description())

	// ── Trust the file only after checking it ──
	// A stash file is an ordinary file on disk. Writing it back unverified
	// would make editing it a way to plant a blob in NVRAM.
	if err := checkKeyIdentity(signingKey, blob); err != nil {
		return err
	}
	if err := VerifyBlobSignature(data, blob, signingKey.Public()); err != nil {
		return fmt.Errorf("refusing to restore: the blob's signature does not verify — the file has been\n"+
			"  modified since it was written, or it belongs to a different signing key: %w", err)
	}
	fmt.Println("Blob signature verified.")

	tpmDev, err := OpenTPMDevice(tpmPath)
	if err != nil {
		return err
	}
	defer tpmDev.Close()

	CleanupTPM(tpmDev, debug)

	// ── Do not clobber a good blob ──
	// By now the user may already have re-sealed, and that newer secret is
	// the live one. Overwriting it would destroy a working setup to recover
	// an older one.
	if existing, readErr := ReadFromNVRAM(tpmDev, index); readErr == nil {
		if bytes.Equal(existing, data) {
			fmt.Printf("\nNVRAM index 0x%08X already holds exactly this blob. Nothing to do.\n", index)
			return nil
		}

		if !force {
			return fmt.Errorf("refusing to restore: NVRAM index 0x%08X already holds a different blob.\n"+
				"  It may be a newer secret you sealed after this file was written, and overwriting\n"+
				"  it would destroy that secret irrecoverably.\n"+
				"  Inspect it first:   tpm2-kira info --nvram 0x%08X\n"+
				"  Then, if you are sure this file is the one you want:\n"+
				"      tpm2-kira nvram restore --nvram 0x%08X --from %s --force",
				index, index, index, path)
		}

		fmt.Printf("\nWARNING: overwriting the different blob already in 0x%08X, as --force was given.\n", index)
	}

	// ── Prove this TPM can actually use the blob ──
	// A blob from another TPM writes without complaint and then fails at
	// reveal, long after the evidence is gone. Loading the sealed object now
	// turns that into an accurate error while the file is still in hand.
	if err := verifySealedObjectLoads(tpmDev, blob, debug); err != nil {
		return err
	}
	fmt.Println("This TPM can load the sealed object.")

	if err := WriteToNVRAM(tpmDev, index, data, signingKey.Public(), signingKey); err != nil {
		return fmt.Errorf("failed to write the blob back to NVRAM: %w", err)
	}

	fmt.Printf("\nSuccessfully restored NVRAM index 0x%08X.\n", index)
	fmt.Printf("The stash file was left in place: %s\n", path)
	fmt.Println("\nThe restored policy binds the PCR values from when this blob was written, which")
	fmt.Println("is probably not the current state. Check, and reseal if there is a mismatch:")
	fmt.Printf("    tpm2-kira info --nvram 0x%08X\n", index)
	fmt.Println("    sudo tpm2-kira reseal")

	return nil
}

// verifySealedObjectLoads checks that the sealed object in the blob belongs to
// this TPM, by re-deriving the primary key and loading it.
func verifySealedObjectLoads(tpmDev transport.TPM, blob *SealedBlob, debug bool) error {
	primaryKey, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return fmt.Errorf("failed to derive the storage primary key: %w", err)
	}
	defer FlushHandle(tpmDev, primaryKey.ObjectHandle)

	loaded, err := LoadSealedObject(tpmDev, primaryKey, blob)
	if err != nil {
		return fmt.Errorf("refusing to restore: this TPM cannot load the sealed object in that file.\n"+
			"  The private area is wrapped by the TPM that created it and cannot be moved to\n"+
			"  another one, so this blob is almost certainly from a different machine or from\n"+
			"  before the TPM was cleared. Writing it would produce an index that never unseals.\n"+
			"  Underlying error: %w", err)
	}
	FlushHandle(tpmDev, loaded.ObjectHandle)

	if debug {
		fmt.Println("Sealed object loaded successfully; the blob belongs to this TPM")
	}

	return nil
}

// resolveStashPath picks the file to restore from.
//
// An explicit path is used as given. Otherwise the newest stash recorded for
// this index wins, since stash names carry the index and a timestamp, and the
// chosen file is always printed so the decision is visible.
func resolveStashPath(index uint32, fromPath string) (string, error) {
	if fromPath != "" {
		if _, err := os.Stat(fromPath); err != nil {
			return "", fmt.Errorf("cannot read %s: %w", fromPath, err)
		}
		return fromPath, nil
	}

	pattern := fmt.Sprintf("%s/slot-0x%08X-*.blob", NVRAMRecoveryDir, index)

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("failed to search %s: %w", NVRAMRecoveryDir, err)
	}

	if len(matches) == 0 {
		others, _ := filepath.Glob(NVRAMRecoveryDir + "/*.blob")
		if len(others) > 0 {
			return "", fmt.Errorf("no stashed blob for NVRAM index 0x%08X in %s.\n"+
				"  Files present for other slots:\n    %s\n"+
				"  Pass one explicitly with --from if that is the file you want",
				index, NVRAMRecoveryDir, joinLines(others))
		}
		return "", fmt.Errorf("no stashed blob found in %s.\n"+
			"  That directory is only written when an NVRAM write fails part way through,\n"+
			"  so there is nothing to restore. Pass --from <path> to name a file directly",
			NVRAMRecoveryDir)
	}

	// Names embed a Unix timestamp, so a lexical sort is chronological for
	// every timestamp of the same width — which covers the next few centuries.
	sort.Strings(matches)
	newest := matches[len(matches)-1]

	if len(matches) > 1 {
		fmt.Printf("Found %d stashed blobs for this slot; using the newest.\n", len(matches))
	}

	return newest, nil
}

func joinLines(paths []string) string {
	var out bytes.Buffer
	for i, path := range paths {
		if i > 0 {
			out.WriteString("\n    ")
		}
		out.WriteString(path)
	}
	return out.String()
}
