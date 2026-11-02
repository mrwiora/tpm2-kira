//go:build integration || apptest

package admin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
)

// The channel's secrets: never in the record; open before the close in a boot of
// the PCR 7 they are sealed to, approved or not; after the close only with the
// slot's signing key; a further phone gets the same ones.
func TestChannelSecretsSealed(t *testing.T) {
	s := newSWTPMSetup(t)
	idx := uint32(nvslot.NVRAMSlotStart + 4)
	signer, pubPath := sealRealSlot(t, s.sock, idx)

	// A slot's first phone: the secrets are made here and sealed.
	sb := phonegate.ReadSealedSlot(s.tpm, idx)
	s.blob.Phone = nvslot.PhoneAttestation{}
	channel, err := enrolmentChannel(s.tpm, sb, s.blob, signer)
	if err != nil {
		t.Fatal(err)
	}
	want := &nvslot.ChannelSecrets{NoisePrivate: bytes.Clone(channel.NoisePrivate), AdvKey: bytes.Clone(channel.AdvKey)}
	same := func(c *nvslot.ChannelSecrets) bool {
		return bytes.Equal(c.NoisePrivate, want.NoisePrivate) && bytes.Equal(c.AdvKey, want.AdvKey)
	}
	s.blob.Phone.Verifiers = []attest.EnrolledVerifier{{ID: "my-phone", AnchorPub: []byte{1}, NoisePub: make([]byte, 32)}}
	if err := writeAttestBlob(s.tpm, idx, s.blob, signer); err != nil {
		t.Fatal(err)
	}

	t.Logf("the channel's object: %d + %d bytes", len(s.blob.Phone.ChannelPublic), len(s.blob.Phone.ChannelPrivate))
	// The record holds neither, in any encoding of the bytes: the object is
	// wrapped by the TPM.
	raw, err := nvslot.ReadRecord(idx)
	if err != nil {
		t.Fatal(err)
	}
	for what, secret := range map[string][]byte{"NoisePrivate": want.NoisePrivate, "AdvKey": want.AdvKey} {
		for at := 0; at+8 <= len(secret); at++ {
			if bytes.Contains(raw, secret[at:at+8]) {
				t.Fatalf("the record holds bytes of %s in the clear", what)
			}
		}
	}

	sb = phonegate.ReadSealedSlot(s.tpm, idx)
	if sb.Payload.Attestation == nil || !sb.Payload.Attestation.Phone.Enabled() {
		t.Fatal("the record lost the channel")
	}

	// Before the close, with PCR 7 as sealed, whether or not the boot is approved:
	// PCR 23, what the slot was approved for, moved, and the gate still has its
	// channel, so the phone can show the boot as changed.
	if c, err := nvslot.UnsealChannel(s.tpm, sb); err != nil || !same(c) {
		t.Fatalf("before the close: %v", err)
	}
	s.extend(t, 23, "tampered")
	if c, err := nvslot.UnsealChannel(s.tpm, sb); err != nil || !same(c) {
		t.Fatalf("before the close, in a boot not approved: %v", err)
	}
	svc := phonegate.NewGateService(s.tpm, idx, pubPath, false)
	<-svc.Ready
	if svc.Code != 0 || !same(svc.Channel) {
		t.Fatalf("the boot's gate: %d %v", svc.Code, svc.Reason)
	}

	// The close.
	if _, err := (tpm2.PCREvent{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(15), Auth: tpm2.PasswordAuth(nil)},
		EventData: tpm2.TPM2BEvent{Buffer: []byte("close")},
	}).Execute(s.tpm); err != nil {
		t.Fatal(err)
	}
	if _, err := nvslot.UnsealChannel(s.tpm, sb); !errors.Is(err, nvslot.ErrClosed) {
		t.Fatalf("after the close: %v, want ErrClosed", err)
	}
	closed := phonegate.NewGateService(s.tpm, idx, pubPath, false)
	<-closed.Ready
	if closed.Code == 0 || !errors.Is(closed.Reason, nvslot.ErrClosed) {
		t.Fatalf("the boot's gate after the close: %d %v", closed.Code, closed.Reason)
	}

	// Another key does not open them, and neither does the slot's signature for
	// another nonce: it signs each session's.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nvslot.UnsealChannelSigned(s.tpm, sb, other); err == nil {
		t.Fatal("another key opened the channel's secrets")
	}
	if c, err := nvslot.UnsealChannelSigned(s.tpm, sb, signer); err != nil || !same(c) {
		t.Fatalf("the signing key after the close: %v", err)
	}

	// A further phone, on the closed system: the same secrets, the object kept.
	public := bytes.Clone(s.blob.Phone.ChannelPublic)
	further, err := enrolmentChannel(s.tpm, sb, s.blob, signer)
	if err != nil || !same(further) {
		t.Fatalf("a further phone: %v", err)
	}
	if !bytes.Equal(s.blob.Phone.ChannelPublic, public) {
		t.Fatal("a further phone sealed the secrets anew")
	}

	// The phone salt's hand-over: a whole gate on the closed system.
	signedGate := phonegate.NewGateServiceOpening(phonegate.OpenChannelSigned(signer), s.tpm, idx, pubPath, false)
	<-signedGate.Ready
	if signedGate.Code != 0 || !same(signedGate.Channel) {
		t.Fatalf("the gate with the signing key: %d %v", signedGate.Code, signedGate.Reason)
	}
}
