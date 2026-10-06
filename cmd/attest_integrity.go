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
// The gate therefore checks the record before it advertises, in the initrd,
// before any passphrase is typed and whether or not a phone is there:
//
//   - its signature must verify with this machine's signing public key, a
//     copy of which the hooks put into the image ('attest signer'). That
//     catches a record written by anyone else;
//   - its count must equal the slot's TPM counter (attest_counter.go), which
//     catches an older, genuinely signed record put back.
//
// Enrolling or removing a phone writes a newly signed record with the next
// count; the image does not change, so nothing has to be rebuilt.
//
// The public key in the image is not a secret, and it is as trustworthy as
// the initramfs that carries it: a unified kernel image signed for Secure
// Boot, or PCRs covering the initrd in what the TOTP seal or the phone
// checks. Where neither holds, whoever can replace the record can replace
// the image and the key in it too.

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/matthias/tpm2-kira/attest"
)

// DefaultAttestSignerPath is the signing public key inside the initramfs.
const DefaultAttestSignerPath = "/etc/tpm2-kira/attest-signer.pem"

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

// checkAttestRecord applies both checks to the raw record of a slot.
func checkAttestRecord(tpmDev transport.TPM, idx uint32, raw []byte, pubKey crypto.PublicKey) error {
	if err := VerifyAttestBlobSignature(raw, pubKey); err != nil {
		return &recordError{foreign: true, detail: err.Error()}
	}
	b, err := UnmarshalAttestBlob(raw)
	if err != nil {
		return &recordError{foreign: true, detail: err.Error()}
	}
	counter, err := readAttestCounter(tpmDev, AttestCounterIndex(idx))
	if err != nil {
		return &recordError{detail: err.Error()}
	}
	if b.Count != counter {
		return &recordError{detail: fmt.Sprintf("the record has count %d, the TPM counter is at %d", b.Count, counter)}
	}
	return nil
}

// recordError says why a record is not served: written by someone else, or
// not the current one.
type recordError struct {
	foreign bool
	detail  string
}

func (e *recordError) Error() string {
	if e.foreign {
		return "it is not signed by this machine's signing key (" + e.detail + ")"
	}
	return "it is not the current record (" + e.detail + ")"
}

// AttestSignerCommand implements 'attest signer', run by the initramfs
// hooks: it checks every enrolled record against this machine's signing
// public key and the record counters, and prints that key (PEM) for the
// image. Exit ExitTampered when a record does not pass, ExitUsage when
// nothing is enrolled; nothing is printed then.
func AttestSignerCommand(tpmPath, pubKeyPath string, out io.Writer, debug bool) int {
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm2-kira: failed to open TPM at %s: %v\n", tpmPath, err)
		return ExitInternal
	}
	defer tpmDev.Close()
	pemBytes, code := signerForImage(tpmDev, pubKeyPath, os.Stderr, debug)
	if code != 0 {
		return code
	}
	_, _ = out.Write(pemBytes)
	return 0
}

func signerForImage(tpmDev transport.TPM, pubKeyPath string, errOut io.Writer, debug bool) ([]byte, int) {
	found := FindPopulatedSlotsInRange(tpmDev, AttestNVRAMStart, AttestNVRAMEnd, debug)
	if len(found) == 0 {
		fmt.Fprintln(errOut, "tpm2-kira: no phone is enrolled for attestation")
		return nil, ExitUsage
	}
	pub, path, err := attestPublicKey(pubKeyPath)
	if err != nil {
		fmt.Fprintf(errOut, "tpm2-kira: no signing public key at %s: %v\n", path, err)
		return nil, ExitInternal
	}
	for _, idx := range found {
		slot := idx - AttestNVRAMStart
		raw, err := ReadFromNVRAM(tpmDev, idx)
		if err != nil {
			fmt.Fprintf(errOut, "tpm2-kira: slot %d: cannot read the attestation record: %v\n", slot, err)
			return nil, ExitInternal
		}
		if err := checkAttestRecord(tpmDev, idx, raw, pub); err != nil {
			fmt.Fprintf(errOut, "tpm2-kira: slot %d: TAMPERED: the attestation record is not accepted:\n", slot)
			fmt.Fprintf(errOut, "tpm2-kira:   %v.\n", err)
			fmt.Fprintf(errOut, "tpm2-kira:   Signing key: %s. Inspect the record with 'tpm2-kira attest status';\n", path)
			fmt.Fprintf(errOut, "tpm2-kira:   to start over: 'tpm2-kira attest unenrol --nvram %d', then enrol again.\n", slot)
			return nil, ExitTampered
		}
	}
	pemBytes, err := PublicKeyToPEM(pub)
	if err != nil {
		fmt.Fprintf(errOut, "tpm2-kira: cannot encode the signing public key: %v\n", err)
		return nil, ExitInternal
	}
	return pemBytes, 0
}

// verifyBeforeExtending refuses to add a phone to a blob that this machine's
// signing key did not write: extending it would sign the attacker's entries.
func verifyBeforeExtending(signed []byte, pubKey crypto.PublicKey, slot uint32) error {
	if err := VerifyAttestBlobSignature(signed, pubKey); err != nil {
		return fmt.Errorf("the attestation blob in slot %d is not signed by your signing key (%v): "+
			"it was replaced outside tpm2-kira, or is left over from an installation with another signing key. "+
			"Inspect it with 'tpm2-kira attest status'; to start over, run 'tpm2-kira attest unenrol --nvram %d' "+
			"(or 'tpm2-kira nvram delete' to remove everything tpm2-kira keeps in the TPM) and enrol again", slot, err, slot)
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
