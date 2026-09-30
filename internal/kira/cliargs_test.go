package kira

import (
	"strings"
	"testing"
)

// TestPositionalArgErrorGuessesTheOption covers the message that turns the
// mistake into a correction. The case that matters is the one that caused data
// loss: "nvram delete 0" has to be pointed at --nvram.
func TestPositionalArgErrorGuessesTheOption(t *testing.T) {
	tests := []struct {
		name    string
		command string
		extra   []string
		want    string
	}{
		{
			name:    "a bare slot number suggests --nvram",
			command: "nvram delete",
			extra:   []string{"0"},
			want:    `tpm2-kira nvram delete --nvram 0`,
		},
		{
			name:    "a full index suggests --nvram",
			command: "nvram delete",
			extra:   []string{"0x01803011"},
			want:    `tpm2-kira nvram delete --nvram 0x01803011`,
		},
		{
			name:    "a PCR list suggests --pcrs",
			command: "seal",
			extra:   []string{"0,7"},
			want:    `tpm2-kira seal --pcrs "0,7"`,
		},
		{
			name:    "a PCR list with sources suggests --pcrs",
			command: "seal",
			extra:   []string{"0e,7e,11u"},
			want:    `tpm2-kira seal --pcrs "0e,7e,11u"`,
		},
		{
			name:    "anything else points at help",
			command: "info",
			extra:   []string{"nonsense"},
			want:    "see 'tpm2-kira help'",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := PositionalArgError(tc.command, tc.extra)
			if err == nil {
				t.Fatal("expected an error")
			}

			message := err.Error()
			if !strings.Contains(message, tc.want) {
				t.Errorf("message should contain %q, got:\n%s", tc.want, message)
			}
			// The rejected argument has to be quoted back, or the reader
			// cannot tell which of several words was the problem.
			if !strings.Contains(message, tc.extra[0]) {
				t.Errorf("message should quote the argument, got:\n%s", message)
			}
			if !strings.Contains(message, tc.command) {
				t.Errorf("message should name the command, got:\n%s", message)
			}
		})
	}
}

func TestLooksLikeSlot(t *testing.T) {
	for _, arg := range []string{"0", "1", "15", "0x01803010", "0X01803010", " 7 "} {
		if !LooksLikeSlot(arg) {
			t.Errorf("%q should read as a slot or index", arg)
		}
	}

	for _, arg := range []string{"", "abc", "0,7", "0e", "--nvram", "0x", "0xZZ", "-1"} {
		if LooksLikeSlot(arg) {
			t.Errorf("%q should not read as a slot or index", arg)
		}
	}
}

func TestLooksLikePCRSpec(t *testing.T) {
	for _, arg := range []string{"0,7", "0,2,7", "0e,7e", "0e,7e,11u"} {
		if !LooksLikePCRSpec(arg) {
			t.Errorf("%q should read as a PCR selection", arg)
		}
	}

	// A bare number parses as a PCR selection too, but --nvram is the likelier
	// intent, so it must not be claimed here.
	for _, arg := range []string{"0", "7", "0x01803010", "nonsense", "0,99", ""} {
		if LooksLikePCRSpec(arg) {
			t.Errorf("%q should not be treated as a PCR selection", arg)
		}
	}
}
