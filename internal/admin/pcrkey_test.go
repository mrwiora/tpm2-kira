package admin

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tpm2-trust/assh/config"
	"github.com/tpm2-trust/tpm2-kira/internal/measure"
)

// usePCRKey points the PCR key's paths into a temporary directory and makes it.
func usePCRKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	a, b, c := pcrKeyPath, pcrPubPath, ukiConfPath
	t.Cleanup(func() { pcrKeyPath, pcrPubPath, ukiConfPath = a, b, c })
	pcrKeyPath, pcrPubPath, ukiConfPath = filepath.Join(dir, "pcr.key"), filepath.Join(dir, "pcr.pem"), filepath.Join(dir, "kernel", "uki.conf")
	if err := ensurePCRKey(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// buildSignedUKI builds an image with ukify, as mkinitcpio does, from conf.
func buildSignedUKI(t *testing.T, dir, name, cmdline, conf string) string {
	t.Helper()
	for _, tool := range []string{"ukify"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	if _, err := os.Stat("/usr/lib/systemd/systemd-measure"); err != nil {
		t.Skip("systemd-measure not installed")
	}
	if _, err := os.Stat("/usr/lib/systemd/boot/efi/linuxx64.efi.stub"); err != nil {
		t.Skip("systemd's stub not installed")
	}
	linux, initrd := filepath.Join(dir, "linux"), filepath.Join(dir, "initrd")
	if err := os.WriteFile(linux, append([]byte("MZ"), make([]byte, 4094)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(initrd, []byte("an initrd "+name), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, name+".efi")
	cmd := exec.Command("ukify", "build", "--config="+conf, "--linux="+linux, "--initrd="+initrd, "--cmdline="+cmdline,
		"--uname=6.0.0-test", "--os-release=ID=test", "--output="+out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ukify: %v\n%s", err, b)
	}
	return out
}

// uki.conf is appended to and nothing else of it changes; the lines say
// enter-initrd alone; asked twice it is written once.
func TestAdoptUKIConf(t *testing.T) {
	usePCRKey(t)
	if ukiConfSigns() {
		t.Fatal("no file signs")
	}
	if err := os.MkdirAll(filepath.Dir(ukiConfPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ukiConfPath, []byte("[UKI]\nCmdline=x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := adoptUKIConf(); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(ukiConfPath)
	want := "[UKI]\nCmdline=x\n\n[PCRSignature:tpm2-kira]\nPCRPrivateKey=" + pcrKeyPath + "\nPCRPublicKey=" + pcrPubPath + "\nPhases=enter-initrd\n"
	if string(b) != want {
		t.Fatalf("%q", b)
	}
	if !ukiConfSigns() {
		t.Fatal("the lines are not seen")
	}
	st, err := os.Stat(pcrKeyPath)
	if err != nil || st.Mode().Perm() != 0o400 {
		t.Fatalf("the PCR key's mode: %v %v", st, err)
	}
}

// A built image's .pcrsig: exactly one signature per bank, by the PCR key, of
// PCR 11 at enter-initrd. Not by another key, not a second phase as well.
func TestCheckUKIPCRSig(t *testing.T) {
	dir := usePCRKey(t)
	if err := adoptUKIConf(); err != nil {
		t.Fatal(err)
	}
	good := buildSignedUKI(t, dir, "good", "x=y", ukiConfPath)
	if why := ukiSignedReason(good); why != "" {
		t.Fatalf("a good image: %s", why)
	}

	all := filepath.Join(dir, "all.conf")
	os.WriteFile(all, []byte("[PCRSignature:all]\nPCRPrivateKey="+pcrKeyPath+"\nPCRPublicKey="+pcrPubPath+"\n"), 0o644)
	if why := ukiSignedReason(buildSignedUKI(t, dir, "all", "x=y", all)); !strings.Contains(why, "not exactly one") {
		t.Fatalf("an image signed for every phase: %q", why)
	}

	none := filepath.Join(dir, "none.conf")
	os.WriteFile(none, []byte("[UKI]\n"), 0o644)
	if why := ukiSignedReason(buildSignedUKI(t, dir, "none", "x=y", none)); !strings.Contains(why, "no .pcrsig") {
		t.Fatalf("an image without: %q", why)
	}

	pcrPubPath = filepath.Join(dir, "other.pem")
	pcrKeyPath = filepath.Join(dir, "other.key")
	if err := ensurePCRKey(); err != nil {
		t.Fatal(err)
	}
	if why := ukiSignedReason(good); !strings.Contains(why, "no signature by the PCR key") {
		t.Fatalf("another key's: %q", why)
	}
}

// Conf's PCR 11 goes to the PCR key where the machine signs; the others stay,
// and so does a conf without 11.
func TestSignSlots(t *testing.T) {
	usePCRKey(t)
	conf := config.Config{Slots: map[int][]int{0: {0, 2, 4, 7, 11}, 1: {7, 11}}}
	signSlots(&conf)
	if conf.Signed != nil {
		t.Fatalf("without uki.conf: %v", conf.Signed)
	}
	if err := adoptUKIConf(); err != nil {
		t.Fatal(err)
	}
	signSlots(&conf)
	if len(conf.Slots[0]) != 4 || conf.Slots[0][3] != 7 || len(conf.Slots[1]) != 1 || conf.Slots[1][0] != 7 ||
		conf.Signed[0][0] != 11 || conf.Signed[1][0] != 11 || conf.PCRKey != pcrPubPath || conf.PCRSigs != measure.BootPCRSignaturePaths[0] {
		t.Fatalf("%+v", conf)
	}
	grub := config.Config{Slots: map[int][]int{0: {0, 2, 4, 7, 8, 9}, 1: {7, 8, 9}}}
	signSlots(&grub)
	if grub.Signed != nil {
		t.Fatalf("GRUB's: %v", grub.Signed)
	}
	if _, err := sshCASlotSpecs(conf); err != nil {
		t.Fatal(err)
	}
}

// 11s parses, for PCR 11 alone, and the selection's string reads back.
func TestSignedSpec(t *testing.T) {
	specs, err := measure.ParsePCRSpecs("0e,2e,4u,7e,11s")
	if err != nil || specs[4].Source != measure.PCRSourceSigned || specs[4].Command != measure.DefaultUKIPath {
		t.Fatalf("%v %v", specs, err)
	}
	if !strings.Contains(measure.PCRSpecsToString(specs), "11s:") {
		t.Fatal(measure.PCRSpecsToString(specs))
	}
	if specs, err := measure.ParsePCRSpecs("11s:/x.efi"); err != nil || specs[0].Command != "/x.efi" {
		t.Fatalf("%v %v", specs, err)
	}
	if _, err := measure.ParsePCRSpecs("7s"); err == nil {
		t.Fatal("7s")
	}
}
