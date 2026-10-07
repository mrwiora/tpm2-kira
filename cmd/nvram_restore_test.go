package cmd

import "testing"

func TestRecoveryFileIndex(t *testing.T) {
	for _, tc := range []struct {
		file string
		want uint32
		bad  bool
	}{
		{"/etc/tpm2-kira/recovery/slot-0x01803012-1759823456.blob", 0x01803012, false},
		{"slot-0x01803010-1.blob", 0x01803010, false},
		{"copy.blob", 0, true},
		{"slot-0xZZ-1.blob", 0, true},
		{"slot-0x01803010.blob", 0, true},
	} {
		got, err := recoveryFileIndex(tc.file)
		if tc.bad {
			if err == nil {
				t.Errorf("%s: no error", tc.file)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: 0x%08X, %v; want 0x%08X", tc.file, got, err, tc.want)
		}
	}
}
