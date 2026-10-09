//go:build unit || !integration

package cmd

import (
	"strings"
	"testing"
)

func TestWarnAboutBootChainCoverage(t *testing.T) {
	for _, tc := range []struct {
		pcrs string
		uki  bool
		warn string // "" means no boot-chain warning
	}{
		{"0,7", false, "measure neither the kernel and initrd nor the kernel command line"},
		{"0,7,9e", false, "do not measure the kernel command line"},
		{"0,7,8e", false, "measure neither the kernel nor the initrd"},
		{"0,7,11u", false, ""},
		{"0,7,8e,9e", false, ""},
		{"0,7,9,12", false, ""},
		{"0,7", true, `tpm2-kira seal --pcrs "0,7,11u"`},
	} {
		specs, err := ParsePCRSpecs(tc.pcrs)
		if err != nil {
			t.Fatal(err)
		}
		old := bootedViaSystemdStub
		bootedViaSystemdStub = func() bool { return tc.uki }
		out := captureStdout(t, func() { WarnAboutPCRSelection(specs) })
		bootedViaSystemdStub = old

		gotWarning := strings.Contains(out, "WARNING: the selected PCRs")
		switch {
		case tc.warn == "" && gotWarning:
			t.Errorf("--pcrs %s: unexpected boot-chain warning:\n%s", tc.pcrs, out)
		case tc.warn != "" && !strings.Contains(out, tc.warn):
			t.Errorf("--pcrs %s: output lacks %q:\n%s", tc.pcrs, tc.warn, out)
		}
	}
}

// control switches the advisory warnings off: its overview judges the
// same, in red, and nothing is said twice.
func TestAdvisoryWarningsSwitch(t *testing.T) {
	specs, err := ParsePCRSpecs("0,7")
	if err != nil {
		t.Fatal(err)
	}
	defer func(old bool) { AdvisoryWarnings = old }(AdvisoryWarnings)
	AdvisoryWarnings = false
	out := captureStdout(t, func() {
		WarnAboutPCRSelection(specs)
		WarnAboutHashAlgo(PCRHashAlgoSHA1)
	})
	if out != "" {
		t.Fatalf("advisories although switched off:\n%s", out)
	}
	AdvisoryWarnings = true
	out = captureStdout(t, func() { WarnAboutHashAlgo(PCRHashAlgoSHA1) })
	if !strings.Contains(out, "SHA-1") {
		t.Fatalf("the SHA-1 note is gone:\n%s", out)
	}
}
