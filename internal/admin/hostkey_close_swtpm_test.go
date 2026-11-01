//go:build integration

package admin

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/config"
	"github.com/tpm2-trust/assh/hostkey"

	"github.com/mrwiora/tpm2-kira/internal/sshscreen"
)

// swtpmBoots is a software TPM that can be rebooted (TPM2_Startup(CLEAR)
// on a TPM that keeps its state): what a boot of the machine does to it.
type swtpmBoots struct {
	t   *testing.T
	p   *swtpmProc
	dev transport.TPMCloser
}

func startBoots(t *testing.T) *swtpmBoots {
	t.Helper()
	p, err := startSWTPMProc(t.TempDir())
	if err != nil {
		t.Skip(err)
	}
	dev, err := transport.OpenTPM(p.sock)
	if err != nil {
		t.Fatal(err)
	}
	b := &swtpmBoots{t: t, p: p, dev: dev}
	t.Cleanup(func() { b.p.stop(b.dev) })
	return b
}

func (b *swtpmBoots) reboot() {
	b.t.Helper()
	b.p.stop(b.dev)
	var err error
	if b.p, err = startSWTPMProc(b.p.dir); err != nil {
		b.t.Fatal(err)
	}
	if b.dev, err = transport.OpenTPM(b.p.sock); err != nil {
		b.t.Fatal(err)
	}
}

func (b *swtpmBoots) pcr15() []byte {
	b.t.Helper()
	v, err := hostkey.ReadPCRs(b.dev, hostkey.SHA256, []int{15})
	if err != nil {
		b.t.Fatal(err)
	}
	return v[15]
}

// closeTestCA makes the SSH CA as control does (slot 0 PCR 7), approved for
// the PCRs as they are, saved at path.
func closeTestCA(t *testing.T, b *swtpmBoots, path string) *hostkey.CA {
	t.Helper()
	key := testSigner(t)
	ca, err := hostkey.CreateCA(b.dev, key.Public(), hostkey.CAOptions{Type: hostkey.P256, Bank: hostkey.SHA256, PCRs: []int{7}, PolicyRef: []byte(sshCARef)})
	if err != nil {
		t.Fatal(err)
	}
	values, err := ca.ReadPCRs(b.dev)
	if err != nil {
		t.Fatal(err)
	}
	if err := approveSSHCASlots(ca, key, values); err != nil {
		t.Fatal(err)
	}
	if err := ca.Save(path); err != nil {
		t.Fatal(err)
	}
	return ca
}

// The code screen closes the SSH CA however it ends: after a host key it
// could not make, and with a CA file it could not read, the CA certifies
// nothing more in that boot; the next boot opens it again.
func TestHostKeyClosedOnError(t *testing.T) {
	b := startBoots(t)
	caPath := filepath.Join(t.TempDir(), "ca.json")
	ca := closeTestCA(t, b, caPath)
	conf := config.Default()
	conf.CA = caPath
	open := func() bool {
		t.Helper()
		o, err := ca.IsOpen(b.dev)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	if open() {
		t.Fatal("the CA is open in the boot of its creation")
	}

	// A host key type the TPM is not asked for: an error, the CA closed.
	b.reboot()
	if !open() {
		t.Fatal("the CA is closed in the boot after the creation")
	}
	bad := conf
	bad.HostKeyType = "nonsense"
	if _, err := sshscreen.PrepareHostKey(b.p.sock, bad); err == nil {
		t.Fatal("a host key of an unknown type")
	}
	if open() {
		t.Fatal("a failed code screen left the CA open")
	}

	// A CA file that does not parse: a temporary key, the CA closed.
	b.reboot()
	good, _ := os.ReadFile(caPath)
	if err := os.WriteFile(caPath, []byte("{not a CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hk, err := sshscreen.PrepareHostKey(b.p.sock, conf); err != nil || hk.Temporary == "" {
		t.Fatalf("an unreadable CA file: %+v %v", hk, err)
	}
	if open() {
		t.Fatal("an unreadable CA file left the CA open")
	}

	// The next boot certifies, and closes it after.
	b.reboot()
	os.WriteFile(caPath, good, 0o600)
	if hk, err := sshscreen.PrepareHostKey(b.p.sock, conf); err != nil || hk.Slot != 0 {
		t.Fatalf("the next boot: %+v %v", hk, err)
	}
	if open() {
		t.Fatal("the CA is open after the host key")
	}
}

// tpm2-kira-boot close (the end of the code screen, the resume from
// hibernation): it closes the CA with PCR 15 - with no CA file and no
// assh.conf - after which the code screen gets no certificate; a code
// screen that closed it already leaves it closed; the next boot opens it.
// PCR 15 holds aSSH's close event, measured as systemd-pcrextend measures
// a word: the same value at every boot of the same image.
func TestHostKeyClose(t *testing.T) {
	b := startBoots(t)
	dir := t.TempDir()

	// No CA at all: the close extends PCR 15 all the same, no error.
	if err := sshscreen.Close(b.p.sock); err != nil {
		t.Fatalf("without a CA: %v", err)
	}
	ev := sha256.Sum256([]byte(hostkey.CloseEvent))
	once := sha256.Sum256(append(make([]byte, 32), ev[:]...))
	if !bytes.Equal(b.pcr15(), once[:]) {
		t.Fatalf("PCR 15 after the close: %x", b.pcr15())
	}

	caPath := filepath.Join(dir, "ca.json")
	ca := closeTestCA(t, b, caPath)
	conf := config.Default()
	conf.CA = caPath

	// A boot as a resume meets it: the CA open, closed by the close alone;
	// the code screen after it gets a temporary key.
	b.reboot()
	if o, _ := ca.IsOpen(b.dev); !o {
		t.Fatal("the CA is closed in the boot after the creation")
	}
	if err := sshscreen.Close(b.p.sock); err != nil {
		t.Fatal(err)
	}
	if o, _ := ca.IsOpen(b.dev); o {
		t.Fatal("the CA is open after the close")
	}
	if hk, err := sshscreen.PrepareHostKey(b.p.sock, conf); err != nil || !strings.Contains(hk.Temporary, "the CA is closed until the next boot") {
		t.Fatalf("the code screen after the close: %+v %v", hk, err)
	}

	// A normal boot: the code screen certifies and closes (one event); the
	// image's close after it extends once more; a second code screen gets a
	// temporary key. Two boots alike end with PCR 15 alike.
	var ends [][]byte
	for range 2 {
		b.reboot()
		if hk, err := sshscreen.PrepareHostKey(b.p.sock, conf); err != nil || hk.Slot != 0 {
			t.Fatalf("the code screen: %+v %v", hk, err)
		}
		if !bytes.Equal(b.pcr15(), once[:]) {
			t.Fatalf("PCR 15 after the code screen: %x", b.pcr15())
		}
		if err := sshscreen.Close(b.p.sock); err != nil {
			t.Fatalf("the close after the code screen: %v", err)
		}
		if hk, err := sshscreen.PrepareHostKey(b.p.sock, conf); err != nil || hk.Temporary == "" {
			t.Fatalf("a second code screen: %+v %v", hk, err)
		}
		ends = append(ends, b.pcr15())
	}
	if !bytes.Equal(ends[0], ends[1]) {
		t.Fatal("two boots alike end with PCR 15 apart")
	}
}
