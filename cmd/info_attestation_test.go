//go:build unit || !integration

package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// 'info' reads the blob's attestation part for a human: the machine as an
// attester, and the phones of the Bluetooth method. The keys of the channel
// are present in the blob and are not printed.
func TestInfoShowsTheAttestationPart(t *testing.T) {
	sb := testSlotBlob()
	sb.Payload.Attestation = testEnrolment("my laptop")
	sb.Payload.Attestation.Count = 4
	si := &slotInfo{
		Index: NVRAMSlotStart, SlotNumber: 0, Blob: sb, NVPublic: &tpm2.TPMSNVPublic{},
		CounterState: "4 (matches: this is the current blob)",
	}
	out := captureStdout(t, func() { printAttestationTree("", si) })
	for _, want := range []string{
		"Remote attestation",
		`Machine name: "my laptop"`,
		"Device ID: d1d1d1d1",
		"Attestation key",
		"PCRs quoted: sha256:[0 7]",
		"Revision: 4",
		"not when the machine is attested",
		"Revision counter in the TPM (0x01803820): 4 (matches",
		"Methods",
		"Phones over Bluetooth LE: 1 enrolled",
		"└── Pixel",
		"ID: phone",
		"Anchor key",
		"Policy: p",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("info does not show %q:\n%s", want, out)
		}
	}
	// The channel key (0x11...) and the advertising key (0x22...) stay out.
	for _, secret := range []string{strings.Repeat("11", 32), strings.Repeat("22", 32)} {
		if strings.Contains(out, secret) {
			t.Errorf("info prints a key of the channel:\n%s", out)
		}
	}

	// Without the part, and with the part but no method.
	si.Blob = testSlotBlob()
	if out := captureStdout(t, func() { printAttestationTree("", si) }); !strings.Contains(out, "not set up") {
		t.Errorf("info without attestation:\n%s", out)
	}
	bare := testSlotBlob()
	bare.Payload.Attestation = testEnrolment("x")
	bare.Payload.Attestation.Phone = PhoneAttestation{}
	si.Blob = bare
	if out := captureStdout(t, func() { printAttestationTree("", si) }); !strings.Contains(out, "(none set up)") {
		t.Errorf("info with an attestation part without methods:\n%s", out)
	}

	// A phone's name is chosen on the phone: it cannot drive the terminal.
	evil := testSlotBlob()
	evil.Payload.Attestation = testEnrolment("x\x1b[2J")
	evil.Payload.Attestation.Phone.Verifiers[0].Name = "ok\x1b[31m\nSignature: valid"
	si.Blob = evil
	if out := captureStdout(t, func() { printAttestationTree("", si) }); strings.Contains(out, "\x1b") || strings.Contains(out, "\nSignature: valid") {
		t.Errorf("an escape sequence or a forged line reached the terminal:\n%q", out)
	}
}

func TestInfoJSONShowsTheAttestationPart(t *testing.T) {
	sb := testSlotBlob()
	sb.Payload.Attestation = testEnrolment("my laptop")
	sb.Payload.Attestation.Count = 4
	raw, err := json.Marshal(sb)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Version     uint32 `json:"version"`
		Attestation *struct {
			FriendlyName string `json:"friendly_name"`
			PCRSelection string `json:"pcr_selection"`
			Revision     uint64 `json:"revision"`
			Methods      struct {
				Phone *struct {
					Transport string `json:"transport"`
					Verifiers []struct {
						ID, Name     string
						AnchorDigest string `json:"anchor_digest"`
					} `json:"verifiers"`
				} `json:"phone"`
			} `json:"methods"`
		} `json:"attestation"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	a := got.Attestation
	if got.Version != CurrentBlobVersion || a == nil || a.FriendlyName != "my laptop" || a.Revision != 4 || a.PCRSelection != "sha256:[0 7]" ||
		a.Methods.Phone == nil || a.Methods.Phone.Transport != "bluetooth-le" || len(a.Methods.Phone.Verifiers) != 1 ||
		a.Methods.Phone.Verifiers[0].Name != "Pixel" || len(a.Methods.Phone.Verifiers[0].AnchorDigest) != 64 {
		t.Fatalf("attestation in JSON: %s", raw)
	}
	for _, secret := range []string{strings.Repeat("11", 32), strings.Repeat("22", 32), "noise_private", "adv_key", "ak_private"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the JSON carries %q", secret)
		}
	}
	plain, _ := json.Marshal(testSlotBlob())
	if strings.Contains(string(plain), `"attestation"`) {
		t.Errorf("a blob without the part shows one: %s", plain)
	}
}
