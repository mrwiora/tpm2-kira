//go:build kira_vm_fixture

package admin

import (
	"crypto/sha256"
	"os"
	"strconv"
	"testing"

	"github.com/tpm2-trust/go-uefi-slim/efivar"
	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/internal/efivars"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/phonegate"
	"github.com/tpm2-trust/tpm2-kira/internal/signing"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"
)

// TestVMChannelFixture is no test: tools/vmtest.py builds it (go test -c) and runs it
// on a test machine, which has no phone and no radio, to give the slot $FIXTURE_SLOT
// a phone channel sealed to a PCR 7 of another day - what a db update leaves behind.
// A register extended by hand would not do: the channel compares with the next boot's
// value, and that comes from the event log, not from the register. It never goes into
// a package.
func TestVMChannelFixture(t *testing.T) {
	slot, err := strconv.Atoi(os.Getenv("FIXTURE_SLOT"))
	if err != nil {
		t.Skip("FIXTURE_SLOT is not set")
	}
	efivars.SetDir(efivar.DefaultDir)
	idx := nvslot.ResolveNVRAMIndex(uint32(slot))
	tpm, err := tpmdev.Open("/dev/tpmrm0")
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	signer, err := signing.LoadCheckedSigningPrivateKey(signing.DefaultPrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	sb := phonegate.ReadSealedSlot(tpm, idx)
	if sb == nil {
		t.Fatalf("no slot %d", slot)
	}
	public, private, name, err := phonegate.CreateAK(tpm)
	if err != nil {
		t.Fatal(err)
	}
	sel, err := attest.NewPCRSelection(attest.AlgSHA256, []int{0, 2, 4, 7, 8, 9, 10, 11, 14})
	if err != nil {
		t.Fatal(err)
	}
	noise, err := attest.GenerateNoiseKeypair(nil)
	if err != nil {
		t.Fatal(err)
	}
	blob := &nvslot.Attestation{DeviceID: phonegate.RandBytes(16), FriendlyName: "vm fixture", AKPublic: public, AKPrivate: private, AKName: name,
		PCRAlg: sel.Alg, PCRSelection: sel.Indices}
	old := sha256.Sum256([]byte("a PCR 7 of another day"))
	channel := &nvslot.ChannelSecrets{NoisePrivate: noise.Private, AdvKey: phonegate.RandBytes(32)}
	if err := nvslot.SealChannelTo(tpm, sb, &blob.Phone, channel, []nvslot.ChannelPCR{{Index: 7, Digest: old[:]}}); err != nil {
		t.Fatal(err)
	}
	blob.Phone.Verifiers = []attest.EnrolledVerifier{{ID: "vm-fixture", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(tpm, idx, blob, signer); err != nil {
		t.Fatal(err)
	}
	if moved, err := nvslot.ChannelMoved(tpm, phonegate.ReadSealedSlot(tpm, idx)); err != nil || !moved {
		t.Fatalf("the fixture's channel has not moved: %v %v", moved, err)
	}
}
