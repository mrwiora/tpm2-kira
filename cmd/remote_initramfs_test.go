package cmd

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The image build: the networkd file, the sealed host key, the ed25519 keys
// that may log in and the drop-in, written into the build root; the
// matched interface's driver for the hook to add. Settings that cannot
// work are an error before anything is written.
func TestRemoteInitramfs(t *testing.T) {
	fakeNet(t, map[string]string{"enp1s0": "aa:bb:cc:dd:ee:01"})
	dir := t.TempDir()
	keys, auth, conf, root := filepath.Join(dir, "keys"), filepath.Join(dir, "authorized_keys"), filepath.Join(dir, "control.conf"), filepath.Join(dir, "root")
	write := func(content string) {
		os.WriteFile(conf, []byte(content+"TPM2_KIRA_SSH_HOSTKEY="+keys+"\nTPM2_KIRA_SSH_AUTHORIZED_KEYS="+auth+"\n"), 0o644)
	}
	run := func() (string, error) {
		var out bytes.Buffer
		err := RemoteInitramfsCommand(conf, root, "/dev/null", &out)
		return out.String(), err
	}
	// The sealing itself is tried on a software TPM (remote_hostkey_swtpm_test.go).
	var sealedKey ed25519.PrivateKey
	old := sealForImage
	sealForImage = func(key ed25519.PrivateKey, _ string) ([]byte, error) {
		sealedKey = key
		return []byte("SEALED"), nil
	}
	t.Cleanup(func() { sealForImage = old })

	write("")
	if out, err := run(); err != nil || out != "net off\n" {
		t.Fatalf("off: %q %v", out, err)
	}
	write("TPM2_KIRA_NET=dhcp\nTPM2_KIRA_SSH=on\n")
	login := func(comment string) string {
		_, k, _ := ed25519.GenerateKey(nil)
		s, _ := ssh.NewSignerFromKey(k)
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " " + comment
	}
	limited, admin := `from="10.0.0.1" `+login("limited"), login("admin@desk")
	os.WriteFile(auth, []byte("ssh-rsa AAAA broken\n"+limited+"\n"), 0o600)
	if _, err := run(); err == nil || !strings.Contains(err.Error(), "holds no key without options") {
		t.Fatalf("no usable key: %v", err)
	}
	os.WriteFile(auth, []byte("# keys\nssh-rsa AAAA broken\n"+limited+"\n"+admin+"\n"), 0o600)
	if _, err := run(); err == nil || !strings.Contains(err.Error(), "no SSH host key at") {
		t.Fatalf("no host key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, imageNetworkFile)); err == nil {
		t.Fatal("a refused setting wrote into the image")
	}
	if err := createHostKey(keys); err != nil {
		t.Fatal(err)
	}
	sk, _ := loadHostKey(keys)
	pub := sk.Public().(ed25519.PublicKey)
	out, err := run()
	if err != nil || out != "net dhcp\nmodule drv_enp1s0\nssh 22\nhostkey "+hostKeyFingerprint(pub)+" from "+keys+", sealed to PCR 0+7\n"+
		"warning 2 line(s) of "+auth+" left out: options in front of the key are not honoured, and what does not parse is no key\n" {
		t.Fatalf("dhcp with ssh: %q %v", out, err)
	}
	if !sealedKey.Equal(sk) {
		t.Fatal("another key was sealed")
	}
	for path, want := range map[string]string{
		imageNetworkFile:    "DHCP=yes",
		ImageSealedHostKey:  "SEALED",
		ImageAuthorizedKeys: admin + "\n",
		imageRunDropIn:      `"TPM2_KIRA_REMOTE=--ssh=22 --ssh-hold=0 --ssh-hostkey=/etc/tpm2-kira/ssh/ed25519.sealed"`,
	} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || !strings.Contains(string(data), want) {
			t.Errorf("%s: %q %v, want %q", path, data, err, want)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(root, ImageAuthorizedKeys)); strings.Contains(string(b), "broken") || strings.Contains(string(b), "limited") {
		t.Errorf("a line that does not let anyone in went into the image:\n%s", b)
	}
	if st, _ := os.Stat(filepath.Join(root, ImageSealedHostKey)); st.Mode().Perm() != 0o600 {
		t.Errorf("sealed host key mode %v", st.Mode().Perm())
	}
	if b, _ := os.ReadFile(filepath.Join(root, imageRunDropIn)); !strings.Contains(string(b), "TimeoutStartSec=infinity") {
		t.Errorf("an unlimited hold times out:\n%s", b)
	}

	// A MAC this machine does not have: every driver, and the hook says so.
	write("TPM2_KIRA_NET=static\nTPM2_KIRA_NET_MATCH=aa:bb:cc:dd:ee:09\nTPM2_KIRA_NET_ADDRESS=192.0.2.10/24\nTPM2_KIRA_SSH_HOLD=60\n")
	if out, err := run(); err != nil || !strings.Contains(out, "modules-all\nwarning no interface aa:bb:cc:dd:ee:09") || strings.Contains(out, "ssh") {
		t.Fatalf("unknown MAC: %q %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(root, imageNetworkFile)); err != nil {
		t.Fatal(err)
	}
	if d := runDropIn(SSHConfig{Port: 2222, Hold: 60}); !strings.Contains(d, "TimeoutStartSec=150") || !strings.Contains(d, "--ssh=2222 --ssh-hold=60") {
		t.Fatalf("a limited hold:\n%s", d)
	}
}
