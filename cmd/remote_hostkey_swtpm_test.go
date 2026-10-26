//go:build integration

package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/hostkey"
)

// The SSH CA is approved, in both slots, for the PCRs as the code screen
// meets them: the end-of-firmware values replayed from the event log, the
// window empty. Slot 0 is what 'seal' would bind slot 0 to - here, with
// neither a unified kernel image nor GRUB in the log, PCR 0, 2 and 7 -
// slot 1 PCR 7. At the code screen it certifies this boot's host key
// through slot 0, and the window closes: a second key of this boot is
// temporary, and the error names the window in every slot. After a reboot
// with a firmware update (PCR 0) and a new option ROM (PCR 2) slot 1
// certifies, and the signing key approves the new state in both slots
// again, which keeps the CA. The slots control worked out are in
// assh.conf; one added there is the CA's at the next reseal, approved.
func TestSSHCAApprovedForTheCodeScreen(t *testing.T) {
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed")
	}
	p, err := startSWTPMProc(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tpmDev, err := transport.OpenTPM(p.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.stop(tpmDev) })
	logPath := filepath.Join(t.TempDir(), "binary_bios_measurements")
	old := DefaultEventlogPath
	DefaultEventlogPath = logPath
	defer func() { DefaultEventlogPath = old }()
	// boot measures the firmware, an option ROM and the Secure Boot state,
	// and writes the event log of it.
	boot := func(fw, rom byte) {
		t.Helper()
		entries := []struct {
			pcr    int
			digest []byte
		}{
			{0, bytes.Repeat([]byte{fw}, 32)},
			{2, bytes.Repeat([]byte{rom}, 32)},
			{7, bytes.Repeat([]byte{0xC3}, 32)},
		}
		for _, e := range entries {
			extendSHA256(t, tpmDev, e.pcr, e.digest)
		}
		if err := os.WriteFile(logPath, tcg2Log(entries), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	boot(0xA1, 0xB2)

	controlPath := filepath.Join(t.TempDir(), "control.conf")
	conf, err := loadSSHConf(sshConfPath(controlPath), controlPath)
	if err != nil {
		t.Fatal(err)
	}
	path := conf.CA
	_, keyPath := writeTestKeyPair(t)
	signer, err := LoadCheckedSigningPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := createSSHCA(&conf, p.sock, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSSHConf(controlPath, conf); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(sshConfPath(controlPath)); !strings.Contains(string(b), "ASSH_CA_SLOT_0=0,2,7,15\nASSH_CA_SLOT_1=7,15\nASSH_CA_WINDOW=15\n") {
		t.Fatalf("the slots in assh.conf:\n%s", b)
	}
	if pub, err := os.ReadFile(path + ".pub"); err != nil || !strings.HasPrefix(string(pub), "ecdsa-sha2-nistp256 ") {
		t.Fatalf("the CA's public key: %q %v", pub, err)
	}
	if ca.Window != 15 || len(ca.Slots) != 2 || !slices.Equal(ca.Slots[0].PCRs, []int{0, 2, 7, 15}) || !slices.Equal(ca.Slots[1].PCRs, []int{7, 15}) {
		t.Fatalf("the CA: %s", ca.Describe())
	}
	if st := readSSHCA(conf, p.sock); len(st.Approvals) != 2 || st.Unapproved() != nil || st.CA.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("not approved for the next boot: %+v", st)
	}
	hk, err := prepareHostKey(p.sock, conf)
	if err != nil || hk.CA != ca.Fingerprint() || hk.Slot != 0 || hk.Temporary != "" {
		t.Fatalf("at the code screen: %+v %v", hk, err)
	}

	// The window is closed: the CA certifies nothing more in this boot,
	// and a temporary key is served, made in the TPM.
	if hk, err := prepareHostKey(p.sock, conf); err != nil || hk.CA != "" || !strings.Contains(hk.Temporary, "slot 0: PCR 15 not as approved; slot 1: PCR 15 not as approved") {
		t.Fatalf("after the window closed: %+v %v", hk, err)
	}
	none := conf
	none.CA = filepath.Join(t.TempDir(), "none.json")
	if hk, err := prepareHostKey(p.sock, none); err != nil || !strings.Contains(hk.Temporary, "no SSH CA at") {
		t.Fatalf("without a CA: %+v %v", hk, err)
	}
	// The approvals are still the next boot's: made from the event log,
	// the window empty.
	if st := readSSHCA(conf, p.sock); len(st.Approvals) != 2 {
		t.Fatalf("the closed window took approvals away: %+v", st)
	}

	// A reboot after a firmware update and with a new option ROM: slot 0
	// is not met, slot 1 is.
	p.stop(tpmDev)
	if p, err = startSWTPMProc(p.dir); err != nil {
		t.Fatal(err)
	}
	if tpmDev, err = transport.OpenTPM(p.sock); err != nil {
		t.Fatal(err)
	}
	boot(0xA2, 0xB3)
	st := readSSHCA(conf, p.sock)
	if len(st.Approvals) != 1 || st.Approvals[0].Slot != 1 || len(st.Unapproved()) != 1 || st.Unapproved()[0] != 0 {
		t.Fatalf("a firmware update: %+v", st)
	}
	if hk, err := prepareHostKey(p.sock, conf); err != nil || hk.CA != ca.Fingerprint() || hk.Slot != 1 {
		t.Fatalf("a firmware update: %+v %v", hk, err)
	}

	// reseal approves the new state in both slots, with the signing key
	// alone: the CA stays the same, and keeps those approvals alone.
	_, otherKey := writeTestKeyPair(t)
	if err := resealSSHCA(controlPath, p.sock, otherKey); err == nil || !strings.Contains(err.Error(), "its authority is another key") {
		t.Fatalf("reseal with another key: %v", err)
	}
	if err := resealSSHCA(controlPath, p.sock, keyPath); err != nil {
		t.Fatal(err)
	}
	again, err := hostkey.LoadCA(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Fingerprint() != ca.Fingerprint() || len(again.Approvals) != 2 {
		t.Fatalf("approved again: %s, %d approvals", again.Fingerprint(), len(again.Approvals))
	}
	if st := readSSHCA(conf, p.sock); len(st.Approvals) != 2 || st.Approvals[0].Slot != 0 {
		t.Fatalf("not approved after reseal: %+v", st)
	}
	// Nothing to approve: reseal leaves the CA as it is.
	if err := resealSSHCA(controlPath, p.sock, otherKey); err != nil {
		t.Fatalf("reseal with every slot approved: %v", err)
	}

	// A slot added in assh.conf: reseal gives it to the CA and approves it.
	f, _ := os.OpenFile(sshConfPath(controlPath), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("ASSH_CA_SLOT_2=0,7,15\n")
	f.Close()
	if err := resealSSHCA(controlPath, p.sock, keyPath); err != nil {
		t.Fatal(err)
	}
	if again, err = hostkey.LoadCA(path); err != nil || len(again.Slots) != 3 || len(again.Approvals) != 3 || again.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("a slot added in assh.conf: %v %s", err, again.Describe())
	}
	// Taken away again: reseal takes it from the CA with its approval,
	// though every slot left is approved and nothing is signed.
	b, _ := os.ReadFile(sshConfPath(controlPath))
	os.WriteFile(sshConfPath(controlPath), bytes.ReplaceAll(b, []byte("ASSH_CA_SLOT_2=0,7,15\n"), nil), 0o644)
	if err := resealSSHCA(controlPath, p.sock, otherKey); err != nil {
		t.Fatal(err)
	}
	if again, err = hostkey.LoadCA(path); err != nil || len(again.Slots) != 2 || len(again.Approvals) != 2 {
		t.Fatalf("a slot taken away in assh.conf: %v %s", err, again.Describe())
	}
}
