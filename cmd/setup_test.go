package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

func testSlots(t *testing.T, n int) []TokenSlotInfo {
	t.Helper()

	slots := make([]TokenSlotInfo, 0, n)
	for i := 0; i < n; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		slots = append(slots, TokenSlotInfo{
			Serial:      uint32(12345670 + i),
			Slot:        []byte{0x9A, 0x9C, 0x9D}[i%3],
			PublicKey:   &key.PublicKey,
			HasPolicies: true,
		})
	}
	return slots
}

// TestSelectSlot covers the menu answer handling. An empty answer must mean the
// documented default, and anything unrecognised must be an error rather than a
// quiet fall back to it — someone who typed "9a" or "yes" meant something.
func TestSelectSlot(t *testing.T) {
	slots := testSlots(t, 2)

	tests := []struct {
		name      string
		answer    string
		wantLocal bool
		wantIndex int
		wantErr   bool
	}{
		{name: "empty means a key file", answer: "", wantLocal: true},
		{name: "whitespace means a key file", answer: "   ", wantLocal: true},
		{name: "first slot", answer: "1", wantIndex: 0},
		{name: "second slot", answer: "2", wantIndex: 1},
		{name: "answer is trimmed", answer: " 2 ", wantIndex: 1},
		{name: "zero is not a choice", answer: "0", wantErr: true},
		{name: "beyond the list", answer: "3", wantErr: true},
		{name: "negative", answer: "-1", wantErr: true},
		{name: "a slot name is not a menu number", answer: "9a", wantErr: true},
		{name: "yes is not a choice", answer: "yes", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectSlot(slots, tc.answer)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %+v", got)
				}
				// The message has to say what the valid answers are.
				if !strings.Contains(err.Error(), "1-2") {
					t.Errorf("the error should name the valid range, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("selectSlot failed: %v", err)
			}

			if tc.wantLocal {
				if got != nil {
					t.Errorf("expected the key-file default, got %+v", got)
				}
				return
			}

			if got == nil {
				t.Fatal("expected a slot, got the key-file default")
			}
			if want := slots[tc.wantIndex]; got.Serial != want.Serial || got.Slot != want.Slot {
				t.Errorf("got slot %d/%02x, want %d/%02x", got.Serial, got.Slot, want.Serial, want.Slot)
			}
		})
	}
}

// TestResolveSetupKeyLocationFlags checks the non-interactive paths, which are
// the ones packaging scripts and the mkinitcpio hook take.
func TestResolveSetupKeyLocationFlags(t *testing.T) {
	t.Run("--local never asks and never uses a token", func(t *testing.T) {
		ref, abort, err := resolveSetupKeyLocation("/dev/null", SetupKeyChoice{Local: true}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if abort {
			t.Error("--local should not abort")
		}
		if !ref.IsZero() {
			t.Errorf("expected the key-file default, got %+v", ref)
		}
	})

	t.Run("--yubikey with a reference is honoured", func(t *testing.T) {
		ref, abort, err := resolveSetupKeyLocation("/dev/null",
			SetupKeyChoice{TokenRef: "yubikey:serial=12345678;slot=9c"}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if abort {
			t.Error("--yubikey should not abort")
		}
		want := KeyRef{Kind: KeyRefYubiKey, Serial: 12345678, Slot: 0x9C}
		if ref != want {
			t.Errorf("got %+v, want %+v", ref, want)
		}
	})

	t.Run("--yubikey rejects a filesystem path", func(t *testing.T) {
		if _, _, err := resolveSetupKeyLocation("/dev/null",
			SetupKeyChoice{TokenRef: "/var/lib/tpm2-kira/keys/seal.key"}, false); err == nil {
			t.Error("a path is not a token reference and should be refused")
		}
	})

	t.Run("--yubikey rejects a slot that holds no key", func(t *testing.T) {
		if _, _, err := resolveSetupKeyLocation("/dev/null",
			SetupKeyChoice{TokenRef: "yubikey:slot=9b"}, false); err == nil {
			t.Error("slot 9b is not a PIV key slot and should be refused")
		}
	})
}

// TestTokenSlotInfoRendering checks the strings the menu is built from, since a
// wrong one would send someone to the wrong slot.
func TestTokenSlotInfoRendering(t *testing.T) {
	slots := testSlots(t, 1)
	slot := slots[0]
	slot.Serial = 12345678
	slot.Slot = 0x9A

	if got := slot.Describe(); !strings.Contains(got, "12345678") || !strings.Contains(got, "9a") {
		t.Errorf("Describe() = %q, want it to name the serial and slot", got)
	}
	if got := slot.Ref().String(); got != "yubikey:serial=12345678;slot=9a" {
		t.Errorf("Ref() = %q", got)
	}

	// A slot that needs a touch per signature cannot serve an unattended
	// reseal, and the menu has to say so.
	slot.HasPolicies = true
	slot.TouchPolicy = 0x02 // always
	if got := slot.UnattendedWarning(); !strings.Contains(got, "touch") {
		t.Errorf("UnattendedWarning() = %q, want it to mention the touch requirement", got)
	}

	slot.TouchPolicy = 0x01 // never
	if got := slot.UnattendedWarning(); got != "" {
		t.Errorf("a touch-never slot needs no warning, got %q", got)
	}

	// Firmware that cannot report policies must not invent them.
	slot.HasPolicies = false
	if got := slot.DescribePolicies(); got != "" {
		t.Errorf("DescribePolicies() = %q, want empty when unknown", got)
	}
	if got := slot.UnattendedWarning(); got != "" {
		t.Errorf("UnattendedWarning() = %q, want empty when policies are unknown", got)
	}
}
