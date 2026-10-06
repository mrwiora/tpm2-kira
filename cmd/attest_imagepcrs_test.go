package cmd

import "testing"

func TestImagePCRs(t *testing.T) {
	for _, c := range []struct {
		sel  []uint8
		want string
	}{
		{[]uint8{0, 2, 7}, ""},
		{[]uint8{0, 2, 7, 11}, "11"},
		{[]uint8{0, 2, 4, 7}, "4"},
		{[]uint8{0, 4, 7, 9, 11, 14}, "4, 9, 11"},
	} {
		if got := imagePCRs(c.sel); got != c.want {
			t.Errorf("%v: %q, want %q", c.sel, got, c.want)
		}
	}
}
