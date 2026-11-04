//go:build integration

package admin

import (
	"crypto"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/totp"
)

// failingSigner is a signing key that does not sign: a YubiKey whose PIN is
// wrong, or that was pulled.
type failingSigner struct{ crypto.Signer }

func (s failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("the key does not sign")
}

func loadedHandles(t *testing.T, tpm transport.TPM, kind tpm2.TPMHT) int {
	t.Helper()
	rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapHandles, Property: uint32(kind) << 24, PropertyCount: 32}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	handles, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		t.Fatal(err)
	}
	return len(handles.Handle)
}

// Failures on one connection leave nothing in the TPM, however many there are:
// a TPM holds three sessions, and the fourth would be TPM_RC_SESSION_MEMORY.
func TestFailuresLeaveNoSession(t *testing.T) {
	sock := startSWTPM(t)
	const slot = nvslot.NVRAMSlotStart + 1
	signer, _ := sealRealSlot(t, sock, slot) // sealed to PCR 23
	s := newSWTPMSetupAt(t, sock, "box")
	tpm := s.tpm
	s.blob.EKAlg = uint16(tpm2.TPMAlgECC)
	_, sealed, err := phonegate.ReadSlot(tpm, slot)
	if err != nil {
		t.Fatal(err)
	}
	if s.blob.ReleaseKeyPublic, s.blob.ReleaseKeyPrivate, err = phonegate.CreateReleaseKey(tpm, sealed); err != nil {
		t.Fatal(err)
	}
	if err := writeAttestBlob(tpm, slot, s.blob, signer); err != nil {
		t.Fatal(err)
	}
	_, sb, err := phonegate.ReadSlot(tpm, slot)
	if err != nil {
		t.Fatal(err)
	}
	att := sb.Payload.Attestation
	_, wrapped, err := phonegate.WrapFactor(tpm, att, nil)
	if err != nil {
		t.Fatal(err)
	}

	clean := func(t *testing.T, what string) {
		t.Helper()
		if n := loadedHandles(t, tpm, tpm2.TPMHTLoadedSession); n != 0 {
			t.Fatalf("%s: %d sessions left", what, n)
		}
		if n := loadedHandles(t, tpm, tpm2.TPMHTTransient); n != 0 {
			t.Fatalf("%s: %d objects left", what, n)
		}
	}
	// Not one of them may be the TPM's lack of memory.
	refused := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("no failure")
		}
		if errors.Is(err, tpm2.TPMRCSessionMemory) || errors.Is(err, tpm2.TPMRCObjectMemory) {
			t.Fatalf("out of the TPM's memory: %v", err)
		}
	}
	const failures = 8

	// In the approved state a session goes with its done, and what the policy
	// needed is gone before the command: a caller keeps its two objects beside it.
	session, done, err := nvslot.ApprovedSession(tpm, sb, slot)
	if err != nil {
		t.Fatal(err)
	}
	if session == nil || loadedHandles(t, tpm, tpm2.TPMHTLoadedSession) != 1 || loadedHandles(t, tpm, tpm2.TPMHTTransient) != 0 {
		t.Fatal("not one session, and no object, while the policy holds")
	}
	done()
	clean(t, "after done")
	if _, err := phonegate.UnwrapFactor(tpm, sb, slot, att, wrapped); err != nil {
		t.Fatalf("the approved state: %v", err)
	}
	clean(t, "an opened factor")

	t.Run("a policy that fails afterwards", func(t *testing.T) {
		for i := 0; i < failures; i++ {
			_, _, err := nvslot.ApprovedSessionThen(tpm, sb, slot, func(transport.TPM, tpm2.TPMISHPolicy) error {
				return errors.New("the object's own part")
			})
			if !errors.Is(err, nvslot.ErrPolicyRefused) {
				t.Fatalf("failure %d: %v", i, err)
			}
			clean(t, "a failing policy")
		}
	})

	t.Run("the signing key does not sign", func(t *testing.T) {
		index := nvslot.GenerationIndex(slot)
		for i := 0; i < failures; i++ {
			_, err := nvslot.WriteGeneration(tpm, index, sb.Payload.Generation, signer.Public(), failingSigner{signer})
			refused(t, err)
			clean(t, "an NV write unsigned")
		}
	})

	t.Run("the endorsement hierarchy has a password", func(t *testing.T) {
		if _, err := (tpm2.HierarchyChangeAuth{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
			NewAuth:    tpm2.TPM2BAuth{Buffer: []byte("not empty")},
		}).Execute(tpm); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := (tpm2.HierarchyChangeAuth{
				AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth([]byte("not empty"))},
			}).Execute(tpm); err != nil {
				t.Fatal(err)
			}
		}()
		for i := 0; i < failures; i++ {
			_, _, err := phonegate.EndorsementSession(tpm)
			refused(t, err)
			clean(t, "an endorsement session")
		}
	})

	// The boot state moves: everything bound to the slot is refused, again and again.
	s.extend(t, 23, "something else booted")
	t.Run("a boot not approved", func(t *testing.T) {
		for i := 0; i < failures; i++ {
			_, _, err := nvslot.ApprovedSession(tpm, sb, slot)
			if !errors.Is(err, nvslot.ErrPolicyRefused) {
				t.Fatalf("failure %d: %v", i, err)
			}
			clean(t, "ApprovedSession")

			_, err = phonegate.UnwrapFactor(tpm, sb, slot, att, wrapped)
			if !errors.Is(err, phonegate.ErrFactorRefused) {
				t.Fatalf("failure %d: %v", i, err)
			}
			refused(t, err)
			clean(t, "UnwrapFactor")

			_, err = totp.Code(tpm, sb, slot, time.Now())
			if !errors.Is(err, nvslot.ErrPolicyRefused) {
				t.Fatalf("failure %d: %v", i, err)
			}
			clean(t, "the code")
		}
	})
}
