package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/tpm2-trust/assh/hostkey"
	"golang.org/x/crypto/ssh"
)

// planConfig is control.conf's content as the plan reads it.
func planConfig(t *testing.T, content string) ControlConfig {
	t.Helper()
	cfg, err := ParseControlConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// testSSHCA is an SSH CA as the plan reads it, made without a TPM: a CA
// key's public part and an authority's approval of values, or none.
func testSSHCA(t *testing.T, approved bool) sshCAState {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	auth, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	authDER, _ := x509.MarshalPKIXPublicKey(auth.Public())
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme:  tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: k.X.FillBytes(make([]byte, 32))},
			Y: tpm2.TPM2BECCParameter{Buffer: k.Y.FillBytes(make([]byte, 32))},
		}),
	}
	ca := &hostkey.CA{Version: 1, Type: hostkey.P256, Bank: hostkey.SHA256, PCRs: []int{0, 7},
		Public: tpm2.Marshal(pub), Authority: authDER, PolicyRef: []byte(sshCARef)}
	values := map[int][]byte{0: bytes.Repeat([]byte{0xA1}, 32), 7: bytes.Repeat([]byte{0xC3}, 32)}
	st := sshCAState{CA: ca, Values: values}
	if approved {
		if err := ca.Approve(auth, values); err != nil {
			t.Fatal(err)
		}
		st.Approval = ca.Approved(values)
	}
	return st
}

func loginKey(t *testing.T, comment string) string {
	t.Helper()
	_, k, _ := ed25519.GenerateKey(nil)
	s, _ := ssh.NewSignerFromKey(k)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " " + comment
}

func partsOn(p *BootPlan) string {
	var on []string
	for _, pt := range p.Parts {
		if pt.On {
			on = append(on, pt.Name)
		}
	}
	return strings.Join(on, " ")
}

// The rules: the disk unlock always; every other part only when something
// uses it, and what needs the TPM stays out without one - a machine that
// unlocks by password and salt alone gets nothing else, whatever
// control.conf asks for.
func TestDecidePlan(t *testing.T) {
	bt := &BTDeps{Adapter: "hci0", Modules: []string{"btusb", "bluetooth"}, Firmware: []string{"intel/ibt.sfi"}}

	// No TPM, Bluetooth packed always, a phone's worth of settings: the
	// disk unlock alone, and each part says why.
	p := decidePlan(planInputs{TPMErr: "no /dev/tpmrm0", Config: planConfig(t, "TPM2_KIRA_ATTEST_BLUETOOTH=always\n")})
	if got := partsOn(p); got != "unlock" || p.TPM {
		t.Fatalf("no TPM: %q, TPM %v", got, p.TPM)
	}
	if why := p.Part(PartPhone).Why; !strings.Contains(why, "no TPM") || !strings.Contains(why, "a phone cannot attest") {
		t.Errorf("the phone without a TPM: %q", why)
	}
	if why := p.Part(PartCodes).Why; !strings.Contains(why, "no /dev/tpmrm0") {
		t.Errorf("the codes without a TPM: %q", why)
	}

	// A TPM with nothing sealed: still the disk unlock alone.
	p = decidePlan(planInputs{Config: DefaultControlConfig()})
	if got := partsOn(p); got != "unlock" || p.TPM || !strings.Contains(p.Part(PartCodes).Why, "nothing is sealed") {
		t.Fatalf("nothing sealed: %q %+v", got, p.Part(PartCodes))
	}
	if why := p.Part(PartPhone).Why; why != "no phone is enrolled" {
		t.Errorf("no phone: %q", why)
	}

	// Slots and an enrolled phone: the codes and the gate, and the TPM.
	in := planInputs{Config: DefaultControlConfig(), Slots: 2, Phones: 1, BT: bt, Signer: []byte("PEM")}
	p = decidePlan(in)
	if got := partsOn(p); got != "unlock codes phone" || !p.TPM {
		t.Fatalf("a phone: %q", got)
	}
	// The record not accepted, or no adapter: the gate stays out.
	in.SignerErr = "slot 0: TAMPERED"
	if p := decidePlan(in); p.Has(PartPhone) || !strings.Contains(p.Part(PartPhone).Why, "TAMPERED") {
		t.Errorf("a refused record: %+v", p.Part(PartPhone))
	}
	in.SignerErr, in.BT, in.BTErr = "", nil, "no Bluetooth adapter hci0 on this machine"
	if p := decidePlan(in); p.Has(PartPhone) || !strings.Contains(p.Part(PartPhone).Why, "no Bluetooth adapter") {
		t.Errorf("no adapter: %+v", p.Part(PartPhone))
	}
	// Packed ahead of any enrolment.
	p = decidePlan(planInputs{Config: planConfig(t, "TPM2_KIRA_ATTEST_BLUETOOTH=always\n"), BT: bt, Signer: []byte("PEM")})
	if !p.Has(PartPhone) || !strings.Contains(p.Part(PartPhone).Why, "every image") || p.Has(PartCodes) || !p.TPM {
		t.Errorf("always: %+v", p.Parts)
	}

	// The vault is asked over the network; SSH needs it too.
	in = planInputs{Config: DefaultControlConfig(), Slots: 1, Vaults: 1}
	if p := decidePlan(in); p.Has(PartVault) || !strings.Contains(p.Part(PartVault).Why, "network") {
		t.Errorf("a vault without a network: %+v", p.Part(PartVault))
	}
	in.Config = planConfig(t, "TPM2_KIRA_NET=dhcp\nTPM2_KIRA_SSH=on\n")
	in.KeysErr = "authorized_keys holds no key without options: nobody could log in"
	p = decidePlan(in)
	if got := partsOn(p); got != "unlock codes vault net" || !strings.Contains(p.Part(PartSSH).Why, "nobody could log in") {
		t.Fatalf("a vault, SSH without keys: %q %+v", got, p.Part(PartSSH))
	}
	in.KeysErr, in.Keys, in.SSHCA = "", []string{loginKey(t, "admin")}, sshCAState{Err: "no SSH CA: tpm2-kira control creates it in the TPM"}
	if p := decidePlan(in); p.Has(PartSSH) || !strings.Contains(p.Part(PartSSH).Why, "control creates it") {
		t.Fatalf("SSH without a CA: %+v", p.Part(PartSSH))
	}
	in.SSHCA = testSSHCA(t, false)
	if p := decidePlan(in); p.Has(PartSSH) || p.Part(PartSSH).Why != sshCAUnapproved {
		t.Fatalf("SSH with a CA not approved for the next boot: %+v", p.Part(PartSSH))
	}
	in.SSHCA = testSSHCA(t, true)
	p = decidePlan(in)
	if got := partsOn(p); got != "unlock codes vault net ssh" || !strings.Contains(p.Part(PartSSH).Why, "certified by the SSH CA SHA256:") {
		t.Fatalf("SSH: %q %+v", got, p.Part(PartSSH))
	}
	// The digest names the settings: the same twice, another with another
	// port.
	if again := decidePlan(in); again.Part(PartSSH).Digest != p.Part(PartSSH).Digest || again.Part(PartNet).Digest != p.Part(PartNet).Digest {
		t.Error("the same settings, another digest")
	}
	in.Config.Remote.SSH.Port = 2222
	if other := decidePlan(in); other.Part(PartSSH).Digest == p.Part(PartSSH).Digest || other.Part(PartNet).Digest != p.Part(PartNet).Digest {
		t.Error("another port, the same digest")
	}
	// No busybox on initramfs-tools: no network, and nothing that needs it.
	in.NoBusybox = true
	if got := partsOn(decidePlan(in)); got != "unlock codes" {
		t.Errorf("no busybox: %q", got)
	}
	// A new approval (a firmware update) is another digest.
	approved := in.SSHCA
	in.SSHCA.CA.Approvals[0].Signature = append([]byte{1}, in.SSHCA.CA.Approvals[0].Signature...)
	in.SSHCA.Approval = &in.SSHCA.CA.Approvals[0]
	if other := decidePlan(in); other.Part(PartSSH).Digest == p.Part(PartSSH).Digest {
		t.Error("another approval, the same digest")
	}
	in.SSHCA = approved
	// SSH without a TPM: its host keys are made in it.
	in.NoBusybox, in.TPMErr = false, "gone"
	if p := decidePlan(in); p.Has(PartSSH) || !strings.Contains(p.Part(PartSSH).Why, "made and certified in it") || !p.Has(PartNet) {
		t.Errorf("SSH without a TPM: %+v", p.Parts)
	}

	// A file that does not load: built with the defaults, and said.
	p = decidePlan(planInputs{Config: DefaultControlConfig(), ConfigErr: "line 1: expected KEY=VALUE"})
	if len(p.Warnings) == 0 || !strings.Contains(p.Warnings[0], "does not load") {
		t.Errorf("a broken file: %q", p.Warnings)
	}
}

// writePlan writes the plan into a fresh build root and returns its lines.
func writePlan(t *testing.T, p *BootPlan, format string) (string, string) {
	t.Helper()
	root := t.TempDir()
	var out bytes.Buffer
	if err := p.WriteImage(root, format, &out); err != nil {
		t.Fatal(err)
	}
	return out.String(), root
}

func readImage(t *testing.T, root, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return string(b)
}

// The image's files: the parts it names, and for each part in it its own
// files - the drop-ins, the gate's signer, module list and rule, the
// network file, the SSH CA, the keys that may log in - and the
// lines the hook adds by. A part that is out writes nothing.
func TestWriteImageMkinitcpio(t *testing.T) {
	fakeNet(t, map[string]string{"enp1s0": "aa:bb:cc:dd:ee:01"})

	// The disk unlock alone: the plan names it, nothing else is written.
	out, root := writePlan(t, decidePlan(planInputs{TPMErr: "none", Config: DefaultControlConfig()}), FormatMkinitcpio)
	entries, _ := os.ReadDir(filepath.Join(root, ImagePlanDir))
	if len(entries) != 1 || entries[0].Name() != PartUnlock {
		t.Fatalf("the plan names %v", entries)
	}
	for _, p := range []string{imageTPMDropIn, "/" + btModulesLoadConf, DefaultAttestSignerPath, imageNetworkFile, ImageSSHCA} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			t.Errorf("%s in an image of the disk unlock alone", p)
		}
	}
	if !strings.Contains(out, "say Phone (Bluetooth): out - no TPM (none): a phone cannot attest this machine") || strings.Contains(out, "module") {
		t.Errorf("the lines:\n%s", out)
	}

	admin := loginKey(t, "admin@desk")
	ca := testSSHCA(t, true)
	// An approval of other values stays on this machine.
	other := map[int][]byte{0: bytes.Repeat([]byte{1}, 32), 7: bytes.Repeat([]byte{2}, 32)}
	ca.CA.Approvals = append(ca.CA.Approvals, hostkey.Approval{PCRs: other, Signature: []byte("old")})
	ca.Approval = &ca.CA.Approvals[0]
	bt := &BTDeps{Adapter: "hci0", Modules: []string{"btusb", "btintel", "bluetooth"}, Firmware: []string{"intel/ibt-0180-0041.sfi"},
		Authorize: &USBDevice{Port: "3-10", Vendor: "8087", Product: "0033"}}
	in := planInputs{Config: planConfig(t, "TPM2_KIRA_NET=dhcp\nTPM2_KIRA_SSH=on\n"), Slots: 2, Phones: 1, BT: bt,
		Signer: []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"), Keys: []string{admin}, KeysSkipped: 2, SSHCA: ca}
	in.Config.Remote.SSH.AuthorizedKeys = "/etc/tpm2-kira/authorized_keys"
	p := decidePlan(in)
	out, root = writePlan(t, p, FormatMkinitcpio)
	for _, want := range []string{
		"say TOTP codes:        in  - 2 slots sealed\n",
		"say Phone (Bluetooth): in  - 1 phone enrolled, via hci0\n",
		"bt-module btusb\nbt-module btintel\nbt-module bluetooth\nbt-firmware intel/ibt-0180-0041.sfi\n",
		"net-module drv_enp1s0\n",
		"warning 2 line(s) of /etc/tpm2-kira/authorized_keys left out",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, name := range []string{PartUnlock, PartCodes, PartPhone, PartNet, PartSSH, partTPM} {
		digest := planDigest(partTPM)
		if name != partTPM {
			digest = p.Part(name).Digest
		}
		if _, err := os.Stat(filepath.Join(root, ImagePlanDir, name, digest)); err != nil {
			t.Errorf("the plan does not name %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ImagePlanDir, PartVault)); err == nil {
		t.Error("the vault is named, and no slot has one")
	}
	for path, want := range map[string]string{
		imageTPMDropIn:          "Wants=dev-tpmrm0.device",
		imageTPMWaitDropIn:      "JobTimeoutSec=5",
		"/" + btModulesLoadConf: "btusb\nbtintel\nbluetooth\n",
		DefaultAttestSignerPath: "BEGIN PUBLIC KEY",
		"/" + BTUdevRuleFile:    `KERNEL=="3-10"`,
		imageNetworkFile:        "DHCP=yes",
		ImageAuthorizedKeys:     admin + "\n",
		imageRunDropIn:          `"TPM2_KIRA_REMOTE=--ssh=22 --ssh-hold=0 --ssh-ca=/etc/tpm2-kira/ssh/ca.json"`,
	} {
		if got := readImage(t, root, path); !strings.Contains(got, want) {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
	imageCA, err := hostkey.ParseCA([]byte(readImage(t, root, ImageSSHCA)))
	if err != nil {
		t.Fatal(err)
	}
	if imageCA.Fingerprint() != ca.CA.Fingerprint() || len(imageCA.Approvals) != 1 || imageCA.Approved(ca.Values) == nil {
		t.Errorf("the image's CA: %s, %d approvals", imageCA.Fingerprint(), len(imageCA.Approvals))
	}
	if st, _ := os.Stat(filepath.Join(root, ImageSSHCA)); st.Mode().Perm() != 0o600 {
		t.Errorf("SSH CA mode %v", st.Mode().Perm())
	}
	if d := readImage(t, root, imageRunDropIn); !strings.Contains(d, "TimeoutStartSec=infinity") {
		t.Errorf("an unlimited hold times out:\n%s", d)
	}
	if d := runDropIn(SSHConfig{Port: 2222, Hold: 60}); !strings.Contains(d, "TimeoutStartSec=150") || !strings.Contains(d, "--ssh=2222 --ssh-hold=60") {
		t.Errorf("a limited hold:\n%s", d)
	}

	// A MAC this machine does not have: every driver, and the hook says so.
	in.Config = planConfig(t, "TPM2_KIRA_NET=static\nTPM2_KIRA_NET_MATCH=aa:bb:cc:dd:ee:09\nTPM2_KIRA_NET_ADDRESS=192.0.2.10/24\n")
	if out, _ := writePlan(t, decidePlan(in), FormatMkinitcpio); !strings.Contains(out, "net-modules-all\nwarning no interface aa:bb:cc:dd:ee:09") {
		t.Errorf("unknown MAC:\n%s", out)
	}
}

// initramfs-tools: the network and the SSH flags in remote.conf for the
// boot scripts, the adapter's modules in a list of their own; no
// systemd-networkd file and no drop-ins.
func TestWriteImageInitramfsTools(t *testing.T) {
	fakeNet(t, map[string]string{"enp1s0": "aa:bb:cc:dd:ee:01"})
	in := planInputs{Config: planConfig(t, "TPM2_KIRA_NET=static\nTPM2_KIRA_NET_MATCH=aa:bb:cc:dd:ee:01\nTPM2_KIRA_NET_ADDRESS=\"192.0.2.10/24 2001:db8::10/64\"\nTPM2_KIRA_NET_GATEWAY=192.0.2.1\nTPM2_KIRA_SSH=on\nTPM2_KIRA_SSH_PORT=2222\n"),
		Slots: 1, Phones: 1, BT: &BTDeps{Adapter: "hci0", Modules: []string{"btusb"}}, Signer: []byte("PEM"),
		Keys: []string{loginKey(t, "admin")}, SSHCA: testSSHCA(t, true)}
	out, root := writePlan(t, decidePlan(in), FormatInitramfsTools)
	if !strings.Contains(out, "net-module drv_enp1s0\n") || !strings.Contains(out, "bt-module btusb\n") {
		t.Errorf("the lines:\n%s", out)
	}
	conf := readImage(t, root, imageRemoteConf)
	for _, want := range []string{
		`TPM2_KIRA_NET="static"`, `TPM2_KIRA_NET_MATCH="aa:bb:cc:dd:ee:01"`,
		`TPM2_KIRA_NET_ADDRESS="192.0.2.10/24 2001:db8::10/64"`, `TPM2_KIRA_NET_GATEWAY="192.0.2.1"`,
		`TPM2_KIRA_REMOTE="--ssh=2222 --ssh-hold=0 --ssh-ca=/etc/tpm2-kira/ssh/ca.json"`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("remote.conf lacks %s:\n%s", want, conf)
		}
	}
	if got := readImage(t, root, btModulesList); got != "btusb\n" {
		t.Errorf("the module list: %q", got)
	}
	for _, p := range []string{imageNetworkFile, imageRunDropIn, imageTPMDropIn, "/" + btModulesLoadConf} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			t.Errorf("%s in an initramfs-tools image", p)
		}
	}
	for _, p := range []string{ImageSSHCA, ImageAuthorizedKeys, filepath.Join(ImagePlanDir, partTPM)} {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Error(err)
		}
	}
	// The network alone: no SSH flags.
	in.Config = planConfig(t, "TPM2_KIRA_NET=dhcp\n")
	_, root = writePlan(t, decidePlan(in), FormatInitramfsTools)
	if conf := readImage(t, root, imageRemoteConf); strings.Contains(conf, "TPM2_KIRA_REMOTE") || !strings.Contains(conf, `TPM2_KIRA_NET="dhcp"`) {
		t.Errorf("network alone:\n%s", conf)
	}
}

// control reads the plan an image names from its listing: a part in use
// now and not in the image, or in it with other settings, is a reason to
// rebuild; a part the image carries for nothing is not.
func TestImagePlanPending(t *testing.T) {
	fakeNet(t, map[string]string{"enp1s0": "aa:bb:cc:dd:ee:01"})
	in := planInputs{Config: planConfig(t, "TPM2_KIRA_NET=dhcp\nTPM2_KIRA_SSH=on\n"), Slots: 1, Keys: []string{loginKey(t, "admin")}, SSHCA: testSSHCA(t, true)}
	_, root := writePlan(t, decidePlan(in), FormatMkinitcpio)

	img := filepath.Join(t.TempDir(), "initramfs-linux.img")
	os.WriteFile(img, nil, 0o644)
	oldList := listImage
	t.Cleanup(func() { listImage = oldList })
	listImage = func(string) ([]string, error) {
		var files []string
		filepath.Walk(root, func(p string, info os.FileInfo, _ error) error {
			name := "./" + strings.TrimPrefix(p, root+"/")
			if info.IsDir() {
				name += "/"
			}
			files = append(files, name)
			return nil
		})
		return files, nil
	}
	parts, err := imagePlan(img)
	if err != nil || len(parts) != 5 || parts[PartSSH] != decidePlan(in).Part(PartSSH).Digest {
		t.Fatalf("the image's plan: %v %v", parts, err)
	}
	if p := planPending(decidePlan(in), parts, img); len(p) != 0 {
		t.Errorf("just built: %q", p)
	}
	// A key added: the SSH server's settings changed.
	in.Keys = append(in.Keys, loginKey(t, "laptop"))
	if p := planPending(decidePlan(in), parts, img); len(p) != 1 || !strings.Contains(p[0], "SSH server: its settings changed after initramfs-linux.img was built") {
		t.Errorf("a key added: %q", p)
	}
	// A phone enrolled: a part in use and not in the image.
	in.Phones, in.BT, in.Signer = 1, &BTDeps{Adapter: "hci0", Modules: []string{"btusb"}}, []byte("PEM")
	if p := planPending(decidePlan(in), parts, img); !strings.Contains(strings.Join(p, "\n"), "Phone (Bluetooth): in use now, not in initramfs-linux.img yet (1 phone enrolled, via hci0)") {
		t.Errorf("a phone enrolled: %q", p)
	}
	// SSH switched off: the image carries it for nothing, no reason to rebuild.
	in = planInputs{Config: planConfig(t, "TPM2_KIRA_NET=dhcp\n"), Slots: 1}
	if p := planPending(decidePlan(in), parts, img); len(p) != 0 {
		t.Errorf("SSH off: %q", p)
	}
	if u := planUnused(decidePlan(in), parts); strings.Join(u, ",") != "SSH server" {
		t.Errorf("unused: %q", u)
	}
	// An image of no plan at all: everything in use is missing.
	listImage = func(string) ([]string, error) { return []string{"./usr/bin/tpm2-kira"}, nil }
	st, _ := os.Stat(img)
	os.Chtimes(img, st.ModTime().Add(1e9), st.ModTime().Add(1e9)) // a new build: the listing is cached by time
	parts, _ = imagePlan(img)
	if p := planPending(decidePlan(in), parts, img); len(p) != 3 {
		t.Errorf("no plan in the image: %q", p)
	}
}

// 'run --plan' starts what the image names, and nothing else.
func TestReadPlanned(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, PartUnlock), 0o755)
	if got := ReadPlanned(dir); got != (Planned{}) {
		t.Errorf("the disk unlock alone: %+v", got)
	}
	os.MkdirAll(filepath.Join(dir, PartCodes, "abc"), 0o755)
	os.MkdirAll(filepath.Join(dir, PartPhone), 0o755)
	if got := ReadPlanned(dir); got != (Planned{Codes: true, Phone: true}) {
		t.Errorf("codes and phone: %+v", got)
	}
	if got := ReadPlanned(filepath.Join(dir, "none")); got != (Planned{}) {
		t.Errorf("no plan: %+v", got)
	}
}
