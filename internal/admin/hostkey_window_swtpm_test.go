//go:build integration

package admin

import (
	"os"
	"path/filepath"
	"testing"

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
