package cmd

// Integrity of the attestation record (SECURITY.md, "Remote attestation with a
// phone: what it does not protect against").
//
// The record's NV index refuses in-place writes without the signing key
// (PolicySigned), but the owner hierarchy can undefine it and define a new
// one with any content: root on this system, or any other OS booted on this
// machine. That could name an attacker's phone, or put back an older record
// that still names a phone you removed.
//
// The gate therefore serves only the record its initramfs was built for.
// When the image is built - on the unlocked system, where this machine's
// signing key is - 'attest fingerprint' verifies each record's signature and
// writes its SHA-256 into the image. At boot the gate compares the record in
// the TPM with that fingerprint before it advertises: a foreign record and a rolled-back
// one both differ, before any passphrase is typed and whether or not a phone
// is there. Enrolling or removing a phone changes the record, so the image
// has to be rebuilt afterwards.
//
// The fingerprint is not a secret (the record itself is readable from the
// TPM) and it is as trustworthy as the initramfs that carries it: a unified
// kernel image signed for Secure Boot, or PCRs covering the initrd in what
// the TOTP seal or the phone checks. Where neither holds, whoever can
// replace the record can replace the image and the fingerprint in it too.

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/matthias/tpm2-kira/attest"
)

// DefaultRecordFingerprintPath is the fingerprint file inside the initramfs.
const DefaultRecordFingerprintPath = "/etc/tpm2-kira/attest-record.sha256"

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

// attestPublicKey loads this machine's signing public key: an explicit
// path, else the default. A path recorded in a blob is never used to find it.
func attestPublicKey(explicit string) (crypto.PublicKey, string, error) {
	path := explicit
	if path == "" {
		path = DefaultPublicKeyPath
	}
	pub, _, err := LoadSigningPublicKeyFromPEM(path)
	if err != nil {
		return nil, path, err
	}
	return pub, path, nil
}

func blobDigest(signed []byte) string {
	d := sha256.Sum256(signed)
	return hex.EncodeToString(d[:])
}

// RecordFingerprints lists, per attestation NV index, the SHA-256 of the record an
// initramfs was built for.
type RecordFingerprints map[uint32]string

// FormatRecordFingerprints renders the file: one "0xINDEX digest" line per slot.
func FormatRecordFingerprints(fps RecordFingerprints) []byte {
	idxs := make([]uint32, 0, len(fps))
	for i := range fps {
		idxs = append(idxs, i)
	}
	slices.Sort(idxs)
	var b strings.Builder
	b.WriteString("# tpm2-kira: the attestation records this initramfs serves (NV index, SHA-256).\n")
	b.WriteString("# Not a secret. Written by 'tpm2-kira attest fingerprint' when the image is built.\n")
	for _, i := range idxs {
		fmt.Fprintf(&b, "0x%08X %s\n", i, fps[i])
	}
	return []byte(b.String())
}

// ParseRecordFingerprints reads a fingerprint file.
func ParseRecordFingerprints(data []byte) (RecordFingerprints, error) {
	fps := RecordFingerprints{}
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("fingerprint line %d: want \"0xINDEX digest\"", n+1)
		}
		idx, err := strconv.ParseUint(strings.TrimPrefix(f[0], "0x"), 16, 32)
		if err != nil || uint32(idx) < AttestNVRAMStart || uint32(idx) > AttestNVRAMEnd {
			return nil, fmt.Errorf("fingerprint line %d: %q is not an attestation NV index", n+1, f[0])
		}
		if d, err := hex.DecodeString(f[1]); err != nil || len(d) != sha256.Size {
			return nil, fmt.Errorf("fingerprint line %d: not a SHA-256 digest", n+1)
		}
		fps[uint32(idx)] = strings.ToLower(f[1])
	}
	return fps, nil
}

// LoadRecordFingerprints reads the file at path; (nil, nil) when there is
// none, as in an image built before fingerprints existed.
func LoadRecordFingerprints(path string) (RecordFingerprints, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseRecordFingerprints(data)
}

// What the initramfs's fingerprint says about the record in the TPM.
type fingerprintState int

const (
	fingerprintAbsent  fingerprintState = iota // the image carries no fingerprint
	fingerprintMatches                         // the record is the one the image was built for
	fingerprintDiffers                         // it is another one, or the image does not know the slot
)

func checkRecordFingerprint(fps RecordFingerprints, idx uint32, signed []byte) fingerprintState {
	if fps == nil {
		return fingerprintAbsent
	}
	if want, ok := fps[idx]; ok && want == blobDigest(signed) {
		return fingerprintMatches
	}
	return fingerprintDiffers
}

// AttestFingerprintCommand implements 'attest fingerprint', run by the
// initramfs hooks: it verifies every enrolled record against this machine's
// signing key and prints the fingerprints for the image. Exit ExitTampered when a record does not
// verify, ExitUsage when nothing is enrolled; nothing is printed then.
func AttestFingerprintCommand(tpmPath, pubKeyPath string, out io.Writer, debug bool) int {
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm2-kira: failed to open TPM at %s: %v\n", tpmPath, err)
		return ExitInternal
	}
	defer tpmDev.Close()
	fps, code := fingerprintSlots(tpmDev, pubKeyPath, os.Stderr, debug)
	if code != 0 {
		return code
	}
	_, _ = out.Write(FormatRecordFingerprints(fps))
	return 0
}

func fingerprintSlots(tpmDev transport.TPM, pubKeyPath string, errOut io.Writer, debug bool) (RecordFingerprints, int) {
	found := FindPopulatedSlotsInRange(tpmDev, AttestNVRAMStart, AttestNVRAMEnd, debug)
	if len(found) == 0 {
		fmt.Fprintln(errOut, "tpm2-kira: no phone is enrolled for attestation; nothing to fingerprint")
		return nil, ExitUsage
	}
	fps := RecordFingerprints{}
	for _, idx := range found {
		slot := idx - AttestNVRAMStart
		raw, err := ReadFromNVRAM(tpmDev, idx)
		if err != nil {
			fmt.Fprintf(errOut, "tpm2-kira: slot %d: cannot read the attestation record: %v\n", slot, err)
			return nil, ExitInternal
		}
		pub, path, err := attestPublicKey(pubKeyPath)
		if err != nil {
			fmt.Fprintf(errOut, "tpm2-kira: slot %d: no signing public key at %s: %v\n", slot, path, err)
			return nil, ExitInternal
		}
		if err := VerifyAttestBlobSignature(raw, pub); err != nil {
			fmt.Fprintf(errOut, "tpm2-kira: slot %d: TAMPERED: the attestation record is not signed by this machine's\n", slot)
			fmt.Fprintf(errOut, "tpm2-kira:   signing key (%s): %v.\n", path, err)
			fmt.Fprintf(errOut, "tpm2-kira:   It was written outside tpm2-kira and is not accepted. Inspect it with\n")
			fmt.Fprintf(errOut, "tpm2-kira:   'tpm2-kira attest status'; to start over: 'tpm2-kira attest unenrol --nvram %d'.\n", slot)
			return nil, ExitTampered
		}
		fps[idx] = blobDigest(raw)
	}
	return fps, 0
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

// AttestEKCert shows what the phone will conclude about this TPM at
// enrolment: which EK is offered, whether it has a vendor certificate, and
// whether that certificate verifies against the roots embedded in the core.
func AttestEKCert(tpmPath string, debug bool) error {
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	defer CleanupTPM(tpmDev, debug)

	alg, ek, pub, err := pickCertifiedEK(tpmDev)
	if err != nil {
		return err
	}
	FlushHandle(tpmDev, ek.handle)
	cert := readEKCert(tpmDev, alg)
	chain := readEKCertChain(tpmDev)
	fmt.Printf("EK offered at enrolment: %s\n", ekAlgName(alg))
	fmt.Printf("EK certificate:          %s\n", presentBytes(cert))
	n := 0
	if certs, err := attest.SplitDERChain(chain); err == nil {
		n = len(certs)
	}
	fmt.Printf("Certificate chain (NV 0x%08X): %s, %d certificate(s)\n", attest.EKCertChainNVIndex, presentBytes(chain), n)
	by, err := attest.VerifyEKCertificate(pub, cert, chain, time.Now())
	if err != nil {
		fmt.Printf("Result:                  NOT VERIFIED: %s\n", attest.EKCertNote(err))
		fmt.Println("The phone will show this TPM as \"not verified as genuine hardware\".")
		return nil
	}
	fmt.Printf("Result:                  verified: %s\n", by)
	return nil
}

func presentBytes(b []byte) string {
	if len(b) == 0 {
		return "absent"
	}
	return fmt.Sprintf("present (%d bytes)", len(b))
}
