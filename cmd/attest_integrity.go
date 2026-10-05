package cmd

// Integrity of the attestation blob (TODO-SEC.md S2, in the marify app
// repository).
//
// The blob's NV index refuses in-place writes without the signing key
// (PolicySigned), but the owner hierarchy can undefine it and define a new
// one with any content: root on this system, or any other OS booted on this
// machine. The initrd cannot tell, because it has no copy of the signing key;
// that is why the gate's console verdict is advisory and the phone's screen
// is authoritative.
//
// On the booted, unlocked system the key's public half is available. There
// the blob is checked twice:
//
//   - its signature must verify with this machine's signing key, which
//     catches a blob written by anyone else;
//   - it must equal the copy recorded when tpm2-kira last wrote or accepted
//     it, stored on the encrypted root file system, which also catches an
//     older, genuinely signed blob put back (re-enrolling a removed phone).

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"
)

// DefaultAttestStateDir holds the recorded digest of each slot's blob.
const DefaultAttestStateDir = "/var/lib/tpm2-kira"

// VerifyAttestBlobSignature checks the signature of a stored attestation
// blob (the raw NV contents) against pubKey, which must come from the
// machine's own key files, never from the blob.
func VerifyAttestBlobSignature(signed []byte, pubKey crypto.PublicKey) error {
	b, err := UnmarshalAttestBlob(signed)
	if err != nil {
		return err
	}
	plen := binary.LittleEndian.Uint32(signed[4:8])
	return verifySignedRegion(signed[:8+plen], b.Signature, pubKey)
}

// attestPublicKey finds the signing public key for a slot: an explicit path,
// else the one recorded in the slot's sealed blob, else the default.
func attestPublicKey(tpmDev transport.TPM, idx uint32, explicit string) (crypto.PublicKey, string, error) {
	path := explicit
	if path == "" {
		sealIndex := NVRAMSlotStart + (idx - AttestNVRAMStart)
		if sealed := readSealedSlot(tpmDev, sealIndex); sealed != nil && sealed.Payload.PublicKeyPath != "" {
			path = sealed.Payload.PublicKeyPath
		}
	}
	if path == "" {
		path = DefaultPublicKeyPath
	}
	pub, _, err := LoadSigningPublicKeyFromPEM(path)
	if err != nil {
		return nil, path, err
	}
	return pub, path, nil
}

func attestStateFile(dir string, idx uint32) string {
	return filepath.Join(dir, fmt.Sprintf("attest-slot%d.sha256", idx-AttestNVRAMStart))
}

func blobDigest(signed []byte) string {
	d := sha256.Sum256(signed)
	return hex.EncodeToString(d[:])
}

// recordAttestState remembers signed as the slot's accepted blob.
func recordAttestState(dir string, idx uint32, signed []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(attestStateFile(dir, idx), []byte(blobDigest(signed)+"\n"), 0o600)
}

func forgetAttestState(dir string, idx uint32) {
	_ = os.Remove(attestStateFile(dir, idx))
}

// Outcomes of checking one slot.
type slotIntegrity int

const (
	integrityOK        slotIntegrity = iota
	integrityFirstSeen               // no recorded state yet; recorded now
	integrityBadSig                  // not signed by this machine's key
	integrityChanged                 // signed, but not the blob recorded last
	integrityNoBlob                  // nothing enrolled / unreadable
)

// checkSlotIntegrity verifies signed against pubKey and the recorded state in
// dir. With accept, a validly signed blob becomes the recorded state.
func checkSlotIntegrity(signed []byte, pubKey crypto.PublicKey, dir string, idx uint32, accept bool) (slotIntegrity, error) {
	if err := VerifyAttestBlobSignature(signed, pubKey); err != nil {
		return integrityBadSig, err
	}
	want, err := os.ReadFile(attestStateFile(dir, idx))
	switch {
	case errors.Is(err, os.ErrNotExist) || accept:
		if err := recordAttestState(dir, idx, signed); err != nil {
			return integrityOK, fmt.Errorf("blob is valid, but its state could not be recorded: %w", err)
		}
		if accept {
			return integrityOK, nil
		}
		return integrityFirstSeen, nil
	case err != nil:
		return integrityOK, err
	}
	if strings.TrimSpace(string(want)) != blobDigest(signed) {
		return integrityChanged, nil
	}
	return integrityOK, nil
}

// CheckOptions configures `attest check`.
type CheckOptions struct {
	TPMPath    string
	SealIndex  uint32 // 0 = every enrolled slot
	PubKeyPath string // "" = the slot's, else DefaultPublicKeyPath
	StateDir   string
	Accept     bool // record the current (validly signed) blob as accepted
	Debug      bool
}

// AttestCheck verifies the attestation blobs on the booted system and
// returns an exit code: 0, ExitTampered, or ExitUsage/ExitInternal.
func AttestCheck(o CheckOptions) int {
	tpmDev, err := transport.OpenTPM(o.TPMPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm2-kira: failed to open TPM at %s: %v\n", o.TPMPath, err)
		return ExitInternal
	}
	defer tpmDev.Close()
	return checkSlots(tpmDev, o, os.Stdout)
}

func checkSlots(tpmDev transport.TPM, o CheckOptions, out io.Writer) int {
	if o.StateDir == "" {
		o.StateDir = DefaultAttestStateDir
	}
	var indices []uint32
	if o.SealIndex != 0 {
		idx, err := AttestIndexForSlot(o.SealIndex)
		if err != nil {
			fmt.Fprintln(out, "tpm2-kira:", err)
			return ExitUsage
		}
		indices = []uint32{idx}
	} else {
		indices = FindPopulatedSlotsInRange(tpmDev, AttestNVRAMStart, AttestNVRAMEnd, o.Debug)
	}
	code := 0
	for _, idx := range indices {
		slot := idx - AttestNVRAMStart
		signed, err := ReadFromNVRAM(tpmDev, idx)
		if err != nil {
			fmt.Fprintf(out, "tpm2-kira: slot %d: cannot read the attestation blob: %v\n", slot, err)
			code = ExitInternal
			continue
		}
		pub, path, err := attestPublicKey(tpmDev, idx, o.PubKeyPath)
		if err != nil {
			fmt.Fprintf(out, "tpm2-kira: slot %d: NOT CHECKED: no signing public key at %s (%v)\n", slot, path, err)
			if code == 0 {
				code = ExitUsage
			}
			continue
		}
		res, err := checkSlotIntegrity(signed, pub, o.StateDir, idx, o.Accept)
		switch res {
		case integrityOK:
			if err != nil {
				fmt.Fprintf(out, "tpm2-kira: slot %d: %v\n", slot, err)
				code = ExitInternal
				continue
			}
			fmt.Fprintf(out, "tpm2-kira: slot %d: OK: attestation blob signed by %s and unchanged\n", slot, path)
		case integrityFirstSeen:
			fmt.Fprintf(out, "tpm2-kira: slot %d: OK: attestation blob signed by %s; state recorded for future checks\n", slot, path)
		case integrityBadSig:
			fmt.Fprintf(out, "tpm2-kira: slot %d: TAMPERED: the attestation blob is not signed by this machine's signing key (%s): %v\n", slot, path, err)
			fmt.Fprintln(out, "tpm2-kira:   It was replaced outside tpm2-kira. The phones it lists, and the gate's console")
			fmt.Fprintln(out, "tpm2-kira:   verdict, cannot be trusted. Trust only your phone's screen; re-enrol with")
			fmt.Fprintf(out, "tpm2-kira:   'tpm2-kira attest unenrol --nvram %d' and 'tpm2-kira attest enrol'.\n", slot)
			code = ExitTampered
		case integrityChanged:
			fmt.Fprintf(out, "tpm2-kira: slot %d: CHANGED: the attestation blob is signed by %s but differs from the one\n", slot, path)
			fmt.Fprintln(out, "tpm2-kira:   tpm2-kira wrote or accepted last. An older blob may have been put back (re-enrolling")
			fmt.Fprintln(out, "tpm2-kira:   a removed phone). Check 'tpm2-kira attest status'; if the listed phones are right, run")
			fmt.Fprintf(out, "tpm2-kira:   'tpm2-kira attest check --accept --nvram %d'.\n", slot)
			code = ExitTampered
		}
	}
	if len(indices) == 0 {
		fmt.Fprintln(out, "tpm2-kira: no slot is enrolled for attestation")
	}
	return code
}

// verifyBeforeExtending refuses to add a phone to a blob that this machine's
// signing key did not write: extending it would sign the attacker's entries.
func verifyBeforeExtending(signed []byte, pubKey crypto.PublicKey, slot uint32) error {
	if err := VerifyAttestBlobSignature(signed, pubKey); err != nil {
		return fmt.Errorf("the attestation blob in slot %d is not signed by your signing key (%v): "+
			"it was replaced outside tpm2-kira. Inspect it with 'tpm2-kira attest status'; to start over, "+
			"run 'tpm2-kira attest unenrol --nvram %d' and enrol again", slot, err, slot)
	}
	return nil
}
