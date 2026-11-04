//go:build integration

package admin

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
)

// sealTestChannel makes the slot's channel and writes the record. It returns the
// record as read back and the secrets.
func sealTestChannel(t *testing.T, s *swtpmSetup, idx uint32, signer crypto.Signer) (*nvslot.SealedBlob, *nvslot.ChannelSecrets) {
	t.Helper()
	sb := phonegate.ReadSealedSlot(s.tpm, idx)
	s.blob.Phone = nvslot.PhoneAttestation{}
	channel, err := enrolmentChannel(s.tpm, sb, s.blob, signer)
	if err != nil {
		t.Fatal(err)
	}
	s.blob.Phone.Verifiers = []attest.EnrolledVerifier{{ID: "my-phone", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(s.tpm, idx, s.blob, signer); err != nil {
		t.Fatal(err)
	}
	return phonegate.ReadSealedSlot(s.tpm, idx), channel
}

// A moved PCR 7 - a db or dbx update, another signed system, Secure Boot off - is
// no gate: the first branch refuses, not as closed, and the signed branch still
// opens. Status says so, and a person's slot approve seals the same secrets to the
// new value, so that the phones keep what they pinned. The close then still closes.
func TestChannelFollowsPCR7(t *testing.T) {
	s := newSWTPMSetup(t)
	idx := uint32(nvslot.NVRAMSlotStart + 4)
	signer, pubPath := sealRealSlot(t, s.sock, idx)
	sb, channel := sealTestChannel(t, s, idx, signer)
	same := func(c *nvslot.ChannelSecrets) bool {
		return c != nil && bytes.Equal(c.NoisePrivate, channel.NoisePrivate) && bytes.Equal(c.AdvKey, channel.AdvKey)
	}
	moved := func() bool {
		t.Helper()
		m, err := nvslot.ChannelMoved(s.tpm, sb)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}

	if c, err := nvslot.UnsealChannel(s.tpm, sb); err != nil || !same(c) {
		t.Fatalf("with PCR 7 as sealed and PCR 15 zero: %v", err)
	}
	if moved() {
		t.Fatal("moved, with PCR 7 as sealed")
	}

	s.extend(t, 7, "a dbx update")
	if !moved() {
		t.Fatal("not moved, with PCR 7 extended")
	}
	if _, err := nvslot.UnsealChannel(s.tpm, sb); !errors.Is(err, nvslot.ErrChannelMoved) {
		t.Fatalf("with PCR 7 moved: %v, want ErrChannelMoved", err)
	}
	gate := phonegate.NewGateService(s.tpm, idx, pubPath, false)
	<-gate.Ready
	if gate.Code == 0 || !errors.Is(gate.Reason, nvslot.ErrChannelMoved) {
		t.Fatalf("the boot's gate with PCR 7 moved: %d %v", gate.Code, gate.Reason)
	}
	if c, err := nvslot.UnsealChannelSigned(s.tpm, sb, signer); err != nil || !same(c) {
		t.Fatalf("the signing key with PCR 7 moved: %v", err)
	}

	// Status and control read the same note.
	notes := statusNotes(StatusReport{Slots: []StatusSlot{{Slot: 4, Signed: true, ChannelMoved: moved()}}})
	if !strings.Contains(strings.Join(notes, "\n"), "tpm2-kira slot approve --nvram 4") {
		t.Fatalf("no advice in %v", notes)
	}

	// Slot approve, by the way a person says yes: what it writes opens again.
	public := bytes.Clone(sb.Payload.Attestation.Phone.ChannelPublic)
	specs, err := measure.ParsePCRSpecs("23")
	if err != nil {
		t.Fatal(err)
	}
	if err := approveAndWrite(s.tpm, idx, sb, specs, measure.PCRHashAlgoSHA256, false, signer, ChannelSeal, false); err != nil {
		t.Fatal(err)
	}
	sb = phonegate.ReadSealedSlot(s.tpm, idx)
	if sb == nil || sb.Payload.Attestation == nil || bytes.Equal(sb.Payload.Attestation.Phone.ChannelPublic, public) {
		t.Fatal("slot approve did not seal the channel again")
	}
	if len(sb.Payload.Attestation.Phone.Verifiers) != 1 {
		t.Fatal("slot approve lost the phones")
	}
	if moved() {
		t.Fatal("moved, after slot approve")
	}
	if c, err := nvslot.UnsealChannel(s.tpm, sb); err != nil || !same(c) {
		t.Fatalf("after slot approve: %v", err)
	}

	// Approving again with nothing moved keeps the object.
	public = bytes.Clone(sb.Payload.Attestation.Phone.ChannelPublic)
	if err := approveAndWrite(s.tpm, idx, sb, specs, measure.PCRHashAlgoSHA256, false, signer, ChannelSeal, false); err != nil {
		t.Fatal(err)
	}
	if sb = phonegate.ReadSealedSlot(s.tpm, idx); !bytes.Equal(sb.Payload.Attestation.Phone.ChannelPublic, public) {
		t.Fatal("slot approve sealed the channel again with nothing moved")
	}

	// The close: refused as closed, with PCR 7 as sealed and moved.
	s.extend(t, 15, "close")
	if _, err := nvslot.UnsealChannel(s.tpm, sb); !errors.Is(err, nvslot.ErrClosed) {
		t.Fatalf("after the close: %v, want ErrClosed", err)
	}
	s.extend(t, 7, "and moved")
	if _, err := nvslot.UnsealChannel(s.tpm, sb); !errors.Is(err, nvslot.ErrClosed) {
		t.Fatalf("after the close with PCR 7 moved: %v, want ErrClosed", err)
	}
	if c, err := nvslot.UnsealChannelSigned(s.tpm, sb, signer); err != nil || !same(c) {
		t.Fatalf("the signing key after the close: %v", err)
	}

	// Another key does not reseal: slot approve's way of opening is the signature.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := nvslot.ResealChannelIfMoved(s.tpm, sb, other); err == nil {
		t.Fatal("another key sealed the channel again")
	}
}

// A phone enrolled on the running system, where the separator has moved PCR 7,
// opens at the next boot: the value sealed is the event log's, not the register's.
func TestChannelSealedForTheNextBoot(t *testing.T) {
	dir := t.TempDir()
	useTestVars(t)
	p, err := startSWTPMProc(dir)
	if err != nil {
		t.Skip(err)
	}
	defer func() { p.stop(nil) }()

	firmware := []struct {
		pcr    int
		digest []byte
	}{{7, bytes.Repeat([]byte{0xC3}, 32)}, {7, bytes.Repeat([]byte{0xC4}, 32)}}
	logPath := filepath.Join(dir, "binary_bios_measurements")
	if err := os.WriteFile(logPath, tcg2Log(firmware), 0o600); err != nil {
		t.Fatal(err)
	}
	old := measure.DefaultEventlogPath
	measure.DefaultEventlogPath = logPath
	defer func() { measure.DefaultEventlogPath = old }()

	s := newSWTPMSetupAt(t, p.sock, "box")
	boot := func() {
		for _, e := range firmware {
			extendSHA256(t, s.tpm, e.pcr, e.digest)
		}
	}
	boot()
	beforeSeparator, err := measure.ReadPCRRegisters(s.tpm, []int{7}, measure.PCRHashAlgoSHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	// systemd-pcrosseparator has run: this is the running system.
	extendSHA256(t, s.tpm, 7, measure.DigestOf(measure.PCRHashAlgoSHA256, []byte(measure.OSSeparatorWord)))
	running, err := measure.ReadPCRRegisters(s.tpm, []int{7}, measure.PCRHashAlgoSHA256, false)
	if err != nil {
		t.Fatal(err)
	}

	idx := uint32(nvslot.NVRAMSlotStart + 4)
	signer, _ := sealRealSlot(t, p.sock, idx)
	sb, channel := sealTestChannel(t, s, idx, signer)
	pcrs := sb.Payload.Attestation.Phone.ChannelPCRs
	if len(pcrs) != 1 || pcrs[0].Index != 7 || !bytes.Equal(pcrs[0].Digest, beforeSeparator[7]) || bytes.Equal(pcrs[0].Digest, running[7]) {
		t.Fatalf("sealed to %+v: want the event log's %x, not the register's %x", pcrs, beforeSeparator[7], running[7])
	}
	if m, err := nvslot.ChannelMoved(s.tpm, sb); err != nil || m {
		t.Fatalf("a running system's own separator counts as moved: %v %v", m, err)
	}
	// Here the first branch refuses, and the running system has the signing key.
	if _, err := nvslot.UnsealChannel(s.tpm, sb); !errors.Is(err, nvslot.ErrChannelMoved) {
		t.Fatalf("after the separator: %v, want ErrChannelMoved", err)
	}
	if c, err := nvslot.UnsealChannelSigned(s.tpm, sb, signer); err != nil || !bytes.Equal(c.NoisePrivate, channel.NoisePrivate) {
		t.Fatalf("the signing key on the running system: %v", err)
	}

	// The next boot: the firmware's events again, no separator yet.
	s.tpm.Close()
	p.stop(nil)
	if p, err = startSWTPMProc(dir); err != nil {
		t.Fatal(err)
	}
	if s.tpm, err = transport.OpenTPM(p.sock); err != nil {
		t.Fatal(err)
	}
	boot()
	if c, err := nvslot.UnsealChannel(s.tpm, sb); err != nil || !bytes.Equal(c.NoisePrivate, channel.NoisePrivate) || !bytes.Equal(c.AdvKey, channel.AdvKey) {
		t.Fatalf("at the next boot: %v", err)
	}
}
