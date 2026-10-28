package admin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/piv"
	"github.com/mrwiora/tpm2-kira/internal/piv/pivtest"
	"github.com/mrwiora/tpm2-kira/internal/signing"
)

func testBlob() *nvslot.SealedBlob {
	return &nvslot.SealedBlob{Payload: nvslot.SealedBlobPayload{PCRDigests: []nvslot.PCRDigestPair{{Index: 0}, {Index: 7}}}}
}

func TestAsResealSkipped(t *testing.T) {
	cause := &signing.TokenUnavailableError{Token: "YubiKey 1, slot 9a", Reason: "no YubiKey with serial 1 is present"}
	blob := testBlob()

	// Token missing before anything was written: a skip.
	err := asResealSkipped(fmt.Errorf("failed to reseal data: %w", cause), 0x01803010, "/k/seal.key", blob)
	var skip *ResealSkippedError
	if !errors.As(err, &skip) || !errors.Is(err, ErrResealSkipped) || skip.Cause != cause || skip.KeyFile != "/k/seal.key" {
		t.Fatalf("token error before the write: %v", err)
	}

	// The same cause after the index was replaced: never a skip.
	replaced := stashUnwrittenBlobMarker(fmt.Errorf("failed to write: %w", cause))
	if err := asResealSkipped(replaced, 0x01803010, "/k/seal.key", blob); errors.Is(err, ErrResealSkipped) {
		t.Fatal("an error after the NV index was replaced was reported as a skip")
	}

	// Anything that is not an unavailable token stays a failure.
	plain := errors.New("TPM_RC_POLICY_FAIL")
	if err := asResealSkipped(plain, 0x01803010, "", blob); err != plain {
		t.Fatalf("plain error changed: %v", err)
	}
	if asResealSkipped(nil, 0, "", blob) != nil {
		t.Fatal("nil error changed")
	}
}

// stashUnwrittenBlobMarker wraps like stashUnwrittenBlob without writing.
func stashUnwrittenBlobMarker(err error) error { return &nvslot.NvReplacedError{Err: err} }

func TestPrintResealSkipped(t *testing.T) {
	cause := &signing.TokenUnavailableError{Token: "YubiKey 12345678, slot 9a", Reason: "no YubiKey with serial 12345678 is present"}
	var buf bytes.Buffer
	PrintResealSkipped(&buf, []*ResealSkippedError{
		{NVIndex: 0x01803010, KeyFile: "/etc/tpm2-kira/keys/seal.key", Cause: cause, SealedPCRs: testBlob().GetPCRSpecs()},
		{NVIndex: 0x01803011, KeyFile: "/etc/tpm2-kira/keys/seal.key", Cause: cause},
	})
	out := buf.String()
	t.Logf("block:\n%s", out)
	if !strings.HasPrefix(out, "tpm2-kira: SKIPPED: ") {
		t.Errorf("block does not start with the hook marker:\n%s", out)
	}
	for _, want := range []string{"(YubiKey 12345678, slot 9a)", "no YubiKey with serial 12345678 is present",
		"#0, #1", "nothing was written", "PCR MISMATCH", "sudo tpm2-kira slot approve", signing.PINEnvVar} {
		if !strings.Contains(out, want) {
			t.Errorf("block lacks %q", want)
		}
	}
}

func TestPrepareSigningKey(t *testing.T) {
	card := pivtest.New(1)
	card.AddECKey(piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyNever, false)
	fake := &fakeTokens{cards: []*pivtest.Card{card}}
	fake.install(t)
	path := writeStub(t, 1, probeSlot(t, 1, piv.SlotAuthentication))
	signer, _ := signing.LoadSigningPrivateKey(path)

	// Software keys are always ready.
	software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.PrepareSigningKey(software); err != nil {
		t.Fatal(err)
	}

	// No PIN: unavailable, and no attempt spent.
	os.Unsetenv(signing.PINEnvVar)
	if err := signing.PrepareSigningKey(signer); !errors.Is(err, signing.ErrTokenUnavailable) || card.Retries != 3 {
		t.Fatalf("no PIN: %v, retries %d", err, card.Retries)
	}
	signing.CloseTokenSessions()
	fake.install(t)

	// Token unplugged: unavailable, with the reason the SKIPPED block shows.
	fake.cards = nil
	err = signing.PrepareSigningKey(signer)
	var tu *signing.TokenUnavailableError
	if !errors.As(err, &tu) || !strings.Contains(tu.Reason, "no YubiKey with serial 1") {
		t.Fatalf("unplugged: %v", err)
	}

	// Present with the PIN: verified up front, then signing needs no new PIN.
	fake.cards = []*pivtest.Card{card}
	t.Setenv(signing.PINEnvVar, "123456")
	if err := signing.PrepareSigningKey(signer); err != nil {
		t.Fatal(err)
	}
	if !card.Sent(0x20) {
		t.Fatal("the PIN was not verified up front")
	}
}
