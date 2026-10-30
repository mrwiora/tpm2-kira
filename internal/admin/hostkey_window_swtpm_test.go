//go:build integration

package admin

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/config"
	"github.com/tpm2-trust/assh/hostkey"

	"github.com/mrwiora/tpm2-kira/internal/sshscreen"
)

// The code screen closes the SSH CA's window however it ends: after a host
// key it could not make, and with a CA file it could not read, the CA
// certifies nothing more in that boot; the next boot opens it again.
func TestHostKeyWindowClosedOnError(t *testing.T) {
	p, err := startSWTPMProc(t.TempDir())
	if err != nil {
		t.Skip(err)
	}
	tpmDev, err := transport.OpenTPM(p.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.stop(tpmDev) })
	reboot := func() {
		t.Helper()
		p.stop(tpmDev)
		if p, err = startSWTPMProc(p.dir); err != nil {
			t.Fatal(err)
		}
		if tpmDev, err = transport.OpenTPM(p.sock); err != nil {
			t.Fatal(err)
		}
	}
	key := testSigner(t)
	caPath := filepath.Join(t.TempDir(), "ca.json")
	ca, err := hostkey.CreateCA(tpmDev, key.Public(), hostkey.CAOptions{Type: hostkey.P256, Bank: hostkey.SHA256, PCRs: []int{7}, PolicyRef: []byte(sshCARef)})
	if err != nil {
		t.Fatal(err)
	}
	values, err := ca.ReadPCRs(tpmDev)
	if err != nil {
		t.Fatal(err)
	}
	if err := approveSSHCASlots(ca, key, values); err != nil {
		t.Fatal(err)
	}
	if err := ca.Save(caPath); err != nil {
		t.Fatal(err)
	}
	conf := config.Default()
	conf.CA = caPath
	open := func() bool {
		t.Helper()
		o, err := ca.WindowOpen(tpmDev)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}

	// A host key type the TPM is not asked for: an error, the window closed.
	reboot()
	if !open() {
		t.Fatal("the window is closed in the boot after the creation")
	}
	bad := conf
	bad.HostKeyType = "nonsense"
	if _, err := sshscreen.PrepareHostKey(p.sock, bad); err == nil {
		t.Fatal("a host key of an unknown type")
	}
	if open() {
		t.Fatal("a failed code screen left the window open")
	}

	// A CA file that does not parse: a temporary key, the window closed.
	reboot()
	good, _ := os.ReadFile(caPath)
	if err := os.WriteFile(caPath, []byte("{not a CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hk, err := sshscreen.PrepareHostKey(p.sock, conf); err != nil || hk.Temporary == "" {
		t.Fatalf("an unreadable CA file: %+v %v", hk, err)
	}
	if open() {
		t.Fatal("an unreadable CA file left the window open")
	}

	// The next boot certifies, and closes it after.
	reboot()
	os.WriteFile(caPath, good, 0o600)
	if hk, err := sshscreen.PrepareHostKey(p.sock, conf); err != nil || hk.Slot != 0 {
		t.Fatalf("the next boot: %+v %v", hk, err)
	}
	if open() {
		t.Fatal("the window is open after the host key")
	}
}

// The close before a resume from hibernation (tpm2-kira-boot close): it
// closes an open window, after which the code screen gets no certificate;
// it does nothing without a CA; it leaves an index that is not a window and
// fails, so that the resume stops; the next boot opens the window again.
// The code screen's own close extends no PCR.
func TestHostKeyClose(t *testing.T) {
	p, err := startSWTPMProc(t.TempDir())
	if err != nil {
		t.Skip(err)
	}
	tpmDev, err := transport.OpenTPM(p.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.stop(tpmDev) })
	reboot := func() {
		t.Helper()
		p.stop(tpmDev)
		if p, err = startSWTPMProc(p.dir); err != nil {
			t.Fatal(err)
		}
		if tpmDev, err = transport.OpenTPM(p.sock); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	confPath := filepath.Join(dir, "assh.conf")

	// No CA, no assh.conf: nothing to close, no error.
	if err := sshscreen.Close(p.sock, confPath); err != nil {
		t.Fatalf("without a CA: %v", err)
	}

	key := testSigner(t)
	caPath := filepath.Join(dir, "ca.json")
	ca, err := hostkey.CreateCA(tpmDev, key.Public(), hostkey.CAOptions{Type: hostkey.P256, Bank: hostkey.SHA256, PCRs: []int{7}, PolicyRef: []byte(sshCARef)})
	if err != nil {
		t.Fatal(err)
	}
	values, err := ca.ReadPCRs(tpmDev)
	if err != nil {
		t.Fatal(err)
	}
	if err := approveSSHCASlots(ca, key, values); err != nil {
		t.Fatal(err)
	}
	if err := ca.Save(caPath); err != nil {
		t.Fatal(err)
	}
	conf := config.Default()
	conf.CA = caPath
	if err := os.WriteFile(confPath, []byte("ASSH_CA="+caPath+"\nASSH_CA_SLOT_0=7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	open := func() bool {
		t.Helper()
		o, err := ca.WindowOpen(tpmDev)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	pcr15 := func() []byte {
		t.Helper()
		v, err := hostkey.ReadPCRs(tpmDev, hostkey.SHA256, []int{15})
		if err != nil {
			t.Fatal(err)
		}
		return v[15]
	}

	// A boot as a resume meets it: the window open, closed by the close
	// alone; the code screen after it gets a temporary key.
	reboot()
	if !open() {
		t.Fatal("the window is closed in the boot after the creation")
	}
	if err := sshscreen.Close(p.sock, confPath); err != nil {
		t.Fatal(err)
	}
	if open() {
		t.Fatal("the window is open after the close")
	}
	if hk, err := sshscreen.PrepareHostKey(p.sock, conf); err != nil || hk.Temporary == "" {
		t.Fatalf("the code screen after the close: %+v %v", hk, err)
	}

	// A normal boot: the code screen certifies and closes; the close after
	// it does nothing; a second code screen gets a temporary key; PCR 15 is
	// as the boot left it.
	reboot()
	before := pcr15()
	if hk, err := sshscreen.PrepareHostKey(p.sock, conf); err != nil || hk.Slot != 0 {
		t.Fatalf("the code screen: %+v %v", hk, err)
	}
	if err := sshscreen.Close(p.sock, confPath); err != nil {
		t.Fatalf("the close after the code screen: %v", err)
	}
	if hk, err := sshscreen.PrepareHostKey(p.sock, conf); err != nil || hk.Temporary == "" {
		t.Fatalf("a second code screen: %+v %v", hk, err)
	}
	if !bytes.Equal(before, pcr15()) {
		t.Fatal("the close extended PCR 15")
	}

	// An index at the handle assh.conf names that is no window: left as it
	// is, and an error.
	const foreign tpm2.TPMHandle = 0x01802917
	if _, err := (tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
		NVIndex: foreign, NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{OwnerWrite: true, OwnerRead: true, AuthRead: true, NT: tpm2.TPMNTOrdinary, NoDA: true},
		DataSize:   8,
	})}).Execute(tpmDev); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.conf")
	os.WriteFile(other, []byte("ASSH_CA="+filepath.Join(dir, "none.json")+"\nASSH_WINDOW_HANDLE=0x01802917\n"), 0o644)
	if err := sshscreen.Close(p.sock, other); err == nil {
		t.Fatal("a foreign index at the window's handle: no error")
	}
	if _, err := (tpm2.NVReadPublic{NVIndex: foreign}).Execute(tpmDev); err != nil {
		t.Fatalf("the foreign index is gone: %v", err)
	}
}
