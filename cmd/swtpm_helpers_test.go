//go:build integration || apptest

package cmd

// Software-TPM helpers shared by the swtpm integration suite (tag
// integration) and the app test machine (tag apptest, attest_app_test.go).

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/attest"
)

// swtpmProc is one swtpm process over a state directory. Stopping and
// starting it again on the same directory is a power cycle of the same TPM.
type swtpmProc struct {
	dir  string
	sock string
	cmd  *exec.Cmd
}

// startSWTPMProc starts swtpm on dir and waits for its socket.
func startSWTPMProc(dir string) (*swtpmProc, error) {
	if _, err := exec.LookPath("swtpm"); err != nil {
		return nil, fmt.Errorf("swtpm not installed: %w", err)
	}
	sock := filepath.Join(dir, "swtpm.sock")
	os.Remove(sock)
	os.Remove(sock + ".ctrl")
	cmd := exec.Command("swtpm", "socket", "--tpm2",
		"--tpmstate", "dir="+dir,
		"--server", "type=unixio,path="+sock,
		"--ctrl", "type=unixio,path="+sock+".ctrl",
		"--flags", "not-need-init,startup-clear")
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			time.Sleep(100 * time.Millisecond)
			return &swtpmProc{dir: dir, sock: sock, cmd: cmd}, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	cmd.Process.Kill()
	cmd.Wait()
	return nil, fmt.Errorf("swtpm did not start")
}

// stop ends the process. With an open TPM connection it first sends
// TPM2_Shutdown(CLEAR), as an operating system does before a reboot:
// without it the next start is a non-orderly reset and the TPM reports its
// clock as unsafe.
func (p *swtpmProc) stop(tpm transport.TPMCloser) {
	if tpm != nil {
		tpm2.Shutdown{ShutdownType: tpm2.TPMSUClear}.Execute(tpm)
		tpm.Close()
	}
	p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { p.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		p.cmd.Process.Kill()
		<-done
	}
}

// startSWTPM runs a software TPM for the duration of the test and returns
// its socket path.
func startSWTPM(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed")
	}
	p, err := startSWTPMProc(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.stop(nil) })
	return p.sock
}

type swtpmSetup struct {
	sock string
	tpm  transport.TPMCloser
	blob *Attestation
	be   *tpmBackend
}

// sealRealSlot seals a real TOTP key into the slot at idx, the way 'seal'
// does, bound to PCR 23 (a register tests can extend to leave the approved
// boot state). It returns the signing key and its public key file. A phone
// enrolment needs such a slot: the boot key shares the slot's policy.
func sealRealSlot(t *testing.T, sock string, idx uint32) (crypto.Signer, string) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privPath, pubPath := filepath.Join(dir, "seal.key"), filepath.Join(dir, "seal.pub")
	if err := WriteSigningKeyFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	pubPEM, err := PublicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteSigningKeyFile(pubPath, pubPEM); err != nil {
		t.Fatal(err)
	}
	if err := Seal(sock, "23", idx, pubPath, privPath, false, PCRHashAlgoSHA256, false); err != nil {
		t.Fatalf("sealing the test slot: %v", err)
	}
	signer, err := LoadCheckedSigningPrivateKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pubPath
}

func newSWTPMSetup(t *testing.T) *swtpmSetup {
	return newSWTPMSetupAt(t, startSWTPM(t), "swtpm-box")
}

// newSWTPMSetupAt creates an attestation key in the TPM at sock and the
// machine's attestation blob around it.
func newSWTPMSetupAt(t *testing.T, sock, name string) *swtpmSetup {
	tpmDev, err := transport.OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	s := &swtpmSetup{sock: sock, tpm: tpmDev}
	t.Cleanup(func() { s.tpm.Close() })

	pub, priv, akName, err := CreateAK(tpmDev)
	if err != nil {
		t.Fatalf("CreateAK: %v", err)
	}
	if _, err := attest.ParseAKPublic(pub, akName); err != nil {
		t.Fatalf("TPM-created AK fails the verifier's own checks: %v", err)
	}
	noise, _ := attest.GenerateNoiseKeypair(nil)
	sel, _ := attest.NewPCRSelection(attest.AlgSHA256, []int{0, 2, 4, 7, 8, 9, 10, 11, 14})
	s.blob = &Attestation{
		DeviceID:     randBytes(16),
		FriendlyName: name,
		AKPublic:     pub,
		AKPrivate:    priv,
		AKName:       akName,
		PCRAlg:       sel.Alg,
		PCRSelection: sel.Indices,
		Phone:        PhoneAttestation{NoisePrivate: noise.Private, AdvKey: randBytes(32)},
	}
	s.be = &tpmBackend{tpm: tpmDev, blob: s.blob, sealIndex: NVRAMSlotStart}
	return s
}

func (s *swtpmSetup) extend(t *testing.T, pcr int, data string) {
	if err := extendPCR(s.tpm, pcr, data); err != nil {
		t.Fatal(err)
	}
}

// extendPCR extends one PCR in the SHA-1 and SHA-256 banks, as firmware
// extends every active bank, with digests made of data's first byte.
func extendPCR(tpm transport.TPM, pcr int, data string) error {
	_, err := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcr), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{
			{HashAlg: tpm2.TPMAlgSHA1, Digest: bytes.Repeat([]byte(data[:1]), 20)},
			{HashAlg: tpm2.TPMAlgSHA256, Digest: bytes.Repeat([]byte(data[:1]), 32)},
		}},
	}.Execute(tpm)
	return err
}

func testSigner(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
