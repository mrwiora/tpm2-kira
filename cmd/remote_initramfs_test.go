package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The image build: the networkd file, the host keys, the ed25519 keys
// that may log in and the drop-in, written into the build root; the
// matched interface's driver for the hook to add. Settings that cannot
// work are an error before anything is written.
func TestRemoteInitramfs(t *testing.T) {
	fakeNet(t, map[string]string{"enp1s0": "aa:bb:cc:dd:ee:01"})
	dir := t.TempDir()
	keys, auth, conf, root := filepath.Join(dir, "keys"), filepath.Join(dir, "authorized_keys"), filepath.Join(dir, "control.conf"), filepath.Join(dir, "root")
	write := func(content string) {
		os.WriteFile(conf, []byte(content+"TPM2_KIRA_SSH_HOSTKEYS="+keys+"\nTPM2_KIRA_SSH_AUTHORIZED_KEYS="+auth+"\n"), 0o644)
	}
	run := func() (string, error) {
		var out bytes.Buffer
		err := RemoteInitramfsCommand(conf, root, &out)
		return out.String(), err
	}

	write("")
	if out, err := run(); err != nil || out != "net off\n" {
		t.Fatalf("off: %q %v", out, err)
	}
	write("TPM2_KIRA_NET=dhcp\nTPM2_KIRA_SSH=on\n")
	if _, err := run(); err == nil || !strings.Contains(err.Error(), "tinysshd-makekey") {
		t.Fatalf("no host key: %v", err)
	}
	os.MkdirAll(keys, 0o700)
	os.WriteFile(filepath.Join(keys, "ed25519.pk"), []byte("PK"), 0o644)
	os.WriteFile(filepath.Join(keys, ".ed25519.sk"), []byte("SK"), 0o600)
	os.WriteFile(auth, []byte("ssh-rsa AAAA rsa\n"), 0o600)
	if _, err := run(); err == nil || !strings.Contains(err.Error(), "no ssh-ed25519 key") {
		t.Fatalf("no ed25519 key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, imageNetworkFile)); err == nil {
		t.Fatal("a refused setting wrote into the image")
	}
	os.WriteFile(auth, []byte("ssh-rsa AAAA rsa\nssh-ed25519 AAAAC3 admin@desk\n"), 0o600)
	out, err := run()
	if err != nil || out != "net dhcp\nmodule drv_enp1s0\nssh 22\n" {
		t.Fatalf("dhcp with ssh: %q %v", out, err)
	}
	for path, want := range map[string]string{
		imageNetworkFile: "DHCP=yes",
		filepath.Join(imageSSHHostKeys, ".ed25519.sk"): "SK",
		imageAuthorizedKey: "ssh-ed25519 AAAAC3 admin@desk\n",
		imageRunDropIn:     `"TPM2_KIRA_REMOTE=--ssh=22 --ssh-hold=0 --ssh-hostkeys=/etc/tpm2-kira/ssh"`,
	} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || !strings.Contains(string(data), want) {
			t.Errorf("%s: %q %v, want %q", path, data, err, want)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(root, imageAuthorizedKey)); strings.Contains(string(b), "ssh-rsa") {
		t.Error("a key tinysshd does not take went into the image")
	}
	if st, _ := os.Stat(filepath.Join(root, imageSSHHostKeys, ".ed25519.sk")); st.Mode().Perm() != 0o600 {
		t.Errorf("secret host key mode %v", st.Mode().Perm())
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
