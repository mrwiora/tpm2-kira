//go:build integration

package cmd

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tpm2-trust/assh/hostkey"
)

// The SSH CA is approved for PCR 0 and 7 as the code screen meets them:
// the end-of-firmware values replayed from the event log, even when the
// approval is made after the OS separator. At the code screen it certifies
// this boot's host key; after the separator, or with another Secure Boot
// state, it does not, and the error names the register that moved. A new
// state is approved again with the signing key, which keeps the CA.
func TestSSHCAApprovedForTheCodeScreen(t *testing.T) {
	s := newSWTPMSetup(t)
	entries := []struct {
		pcr    int
		digest []byte
	}{
		{0, bytes.Repeat([]byte{0xA1}, 32)},
		{7, bytes.Repeat([]byte{0xC3}, 32)},
	}
	for _, e := range entries {
		extendSHA256(t, s.tpm, e.pcr, e.digest)
	}
	logPath := filepath.Join(t.TempDir(), "binary_bios_measurements")
	if err := os.WriteFile(logPath, tcg2Log(entries), 0o600); err != nil {
		t.Fatal(err)
	}
	old := DefaultEventlogPath
	DefaultEventlogPath = logPath
	defer func() { DefaultEventlogPath = old }()

	path := filepath.Join(t.TempDir(), "ssh_ca.json")
	signer := testSigner(t)
	ca, err := createSSHCA(path, s.sock, hostkey.P256, signer)
	if err != nil {
		t.Fatal(err)
	}
	if pub, err := os.ReadFile(path + ".pub"); err != nil || !strings.HasPrefix(string(pub), "ecdsa-sha2-nistp256 ") {
		t.Fatalf("the CA's public key: %q %v", pub, err)
	}
	if st := readSSHCA(path, s.sock); st.Approval == nil || st.CA.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("not approved for the next boot: %+v", st)
	}
	// The image's copy: the CA with that approval.
	hk, why := certifiedHostKey(s.sock, path)
	if hk == nil || hk.CA != ca.Fingerprint() || hk.Throwaway != "" {
		t.Fatalf("at the code screen: %v %s", hk, why)
	}

	// The OS separator: PCR 0-7 move on, the CA certifies nothing more,
	// and a throwaway key is served.
	sep := sha256.Sum256([]byte(OSSeparatorWord))
	for _, pcr := range []int{0, 7} {
		extendSHA256(t, s.tpm, pcr, sep[:])
	}
	if hk, why := certifiedHostKey(s.sock, path); hk != nil || !strings.Contains(why, "PCR 0 and 7 not as approved") {
		t.Fatalf("after the separator: %v %q", hk, why)
	}
	if hk, err := prepareHostKey(s.sock, path); err != nil || hk.Throwaway == "" || hk.CA != "" {
		t.Fatalf("throwaway: %+v %v", hk, err)
	}
	// The approval is still the next boot's: made from the event log.
	if st := readSSHCA(path, s.sock); st.Approval == nil {
		t.Fatal("the separator took the approval away")
	}

	// A state without an approval (as after a firmware or Secure Boot
	// update): the signing key approves it, and the CA stays the same.
	bare := ca.Only(func(hostkey.Approval) bool { return false })
	if err := saveSSHCA(bare, path); err != nil {
		t.Fatal(err)
	}
	if st := readSSHCA(path, s.sock); st.CA == nil || st.Approval != nil {
		t.Fatalf("no approval, yet approved: %+v", st)
	}
	again, err := approveSSHCA(path, s.sock, signer)
	if err != nil {
		t.Fatal(err)
	}
	if again.Fingerprint() != ca.Fingerprint() || len(again.Approvals) != 1 {
		t.Fatalf("approved again: %s, %d approvals", again.Fingerprint(), len(again.Approvals))
	}
	if st := readSSHCA(path, s.sock); st.Approval == nil {
		t.Fatal("not approved after approveSSHCA")
	}
}
