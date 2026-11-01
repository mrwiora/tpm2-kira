//go:build integration

package admin

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/totp"
	"github.com/tpm2-trust/assh/hostkey"
)

// bootUKI makes PCR 11 what the image's boot makes it (SHA-256) and hands over
// its signatures as systemd-stub does.
func bootUKI(t *testing.T, tpm transport.TPM, uki, sigFile string) {
	t.Helper()
	digests, err := measure.UKIMeasurementDigests(uki, measure.MeasurePointPhases, measure.PCRHashAlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range digests {
		if _, err := (tpm2.PCRExtend{
			PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(11), Auth: tpm2.PasswordAuth(nil)},
			Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: d}}},
		}).Execute(tpm); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command("objcopy", "-O", "binary", "--only-section=.pcrsig", uki, sigFile).CombinedOutput()
	if err != nil {
		t.Fatalf("objcopy: %v\n%s", err, out)
	}
}

// A slot with PCR 11 signed by the PCR key: the TOTP key opens in a boot of any
// image the key signed for enter-initrd, without an approval; the rest of the
// policy holds as before (PCR 23, the close). The policy computed in software is
// the TPM's: else no session would open.
func TestSlotWithSignedPCR11(t *testing.T) {
	if _, err := exec.LookPath("objcopy"); err != nil {
		t.Skip("objcopy not installed")
	}
	dir := usePCRKey(t)
	if err := adoptUKIConf(); err != nil {
		t.Fatal(err)
	}
	oldPaths := measure.BootPCRSignaturePaths
	sigFile := filepath.Join(dir, "tpm2-pcr-signature.json")
	measure.BootPCRSignaturePaths = []string{sigFile}
	defer func() { measure.BootPCRSignaturePaths = oldPaths }()

	uki1 := buildSignedUKI(t, dir, "uki1", "first", ukiConfPath)
	uki2 := buildSignedUKI(t, dir, "uki2", "second", ukiConfPath)
	other := filepath.Join(dir, "unsigned.conf")
	os.WriteFile(other, []byte("[UKI]\n"), 0o644)
	unsigned := buildSignedUKI(t, dir, "unsigned", "third", other)

	b := startBoots(t)
	idx := nvslot.ResolveNVRAMIndex(3)
	pubPath, privPath := writeTestKeyPair(t)
	if err := Seal(b.p.sock, "23,11s:"+uki1, idx, pubPath, privPath, false, measure.PCRHashAlgoSHA256, false, true); err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, err := nvslot.ReadRecord(idx)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := nvslot.UnmarshalSealedBlob(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(sb.Payload.PCRKey) == 0 || len(sb.SignedPCRIndices()) != 1 || len(sb.PlainPCRIndices()) != 1 {
		t.Fatalf("the blob: key %d bytes, signed %v, plain %v", len(sb.Payload.PCRKey), sb.SignedPCRIndices(), sb.PlainPCRIndices())
	}
	if name, err := attest.PCRKeyName(sb.Payload.PCRKey); err != nil || len(name) != 34 {
		t.Fatalf("the PCR key's Name: %x %v", name, err)
	}

	when := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	code := func() error {
		_, _, err := totp.SlotCode(b.dev, idx, when, false)
		return err
	}
	// Not booted yet: PCR 11 has no signature.
	if _, err := os.Stat(sigFile); err == nil {
		t.Fatal("a signature before the boot")
	}
	if err := code(); err == nil {
		t.Fatal("a code before the image's boot")
	}

	// The image approved with.
	bootUKI(t, b.dev, uki1, sigFile)
	if err := code(); err != nil {
		t.Fatalf("the image approved with: %v", err)
	}
	// PCR 11 past enter-initrd (leave-initrd measured): no signature for it.
	if err := extendPCR(b.dev, 11, "leave-initrd"); err != nil {
		t.Fatal(err)
	}
	if err := code(); !errors.Is(err, nvslot.ErrNotSigned) {
		t.Fatalf("past enter-initrd: %v", err)
	}

	b.reboot()
	// Another image the key signed: no approval needed.
	bootUKI(t, b.dev, uki2, sigFile)
	if err := code(); err != nil {
		t.Fatalf("a new signed image: %v", err)
	}
	// PCR 23 moved: the approval does not hold, whatever the PCR key signed.
	if err := extendPCR(b.dev, 23, "x"); err != nil {
		t.Fatal(err)
	}
	if err := code(); err == nil {
		t.Fatal("PCR 23 moved")
	}

	b.reboot()
	// An image without a signature, its signature file another image's.
	keep, _ := os.ReadFile(sigFile)
	bootUKI(t, b.dev, unsigned, filepath.Join(dir, "unsigned.sig"))
	os.WriteFile(sigFile, keep, 0o600)
	if err := code(); !errors.Is(err, nvslot.ErrNotSigned) {
		t.Fatalf("an unsigned image: %v", err)
	}

	b.reboot()
	bootUKI(t, b.dev, uki1, sigFile)
	if err := code(); err != nil {
		t.Fatalf("after the reboot: %v", err)
	}
	// The close ends it, as every slot's.
	if err := hostkey.Close(b.dev); err != nil {
		t.Fatal(err)
	}
	if err := code(); err == nil {
		t.Fatal("a code after the close")
	}
}
