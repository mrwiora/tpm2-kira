package cmd

import (
	"bufio"
	"errors"
	"strings"
	"testing"

	"github.com/mrwiora/tpm2-kira/attest"
)

func judge(policy HWCheckPolicy, answer string, revoked map[string]string, rerr error) (*phoneJudge, *strings.Builder) {
	out := &strings.Builder{}
	j := &phoneJudge{policy: policy, console: bufio.NewReader(strings.NewReader(answer)), out: out}
	if revoked != nil || rerr != nil {
		j.revoked = func() (map[string]string, error) { return revoked, rerr }
	}
	return j, out
}

var (
	goodPhone = attest.PhoneAttestation{Verified: true, Root: "Google", SecurityLevel: "StrongBox", Unlock: "fingerprint/face or PIN", BootState: "verified", DeviceLocked: true, Serials: []string{"1", "abc"}}
	romPhone  = attest.PhoneAttestation{Root: "Google", SecurityLevel: "TEE", BootState: "self-signed", Problems: []string{"the phone did not boot a verified system (self-signed, e.g. a custom ROM)"}}
)

func TestPhoneJudgePolicies(t *testing.T) {
	j, out := judge(CheckWarn, "", map[string]string{}, nil)
	if ok, _ := j.JudgePhone(goodPhone); !ok || !strings.Contains(out.String(), "verified by Google: StrongBox") {
		t.Fatalf("verified phone: %v %s", ok, out)
	}
	if j, out := judge(CheckWarn, "\n", nil, nil); func() bool { ok, _ := j.JudgePhone(romPhone); return ok }() {
		t.Fatalf("custom ROM accepted on Enter: %s", out)
	}
	if j, _ := judge(CheckWarn, "y\n", nil, nil); func() bool { ok, _ := j.JudgePhone(romPhone); return !ok }() {
		t.Fatal("explicit yes refused")
	}
	if j, out := judge(CheckRequire, "y\n", nil, nil); func() bool { ok, _ := j.JudgePhone(romPhone); return ok }() || !strings.Contains(out.String(), "required") {
		t.Fatal("require accepted an unverified phone")
	}
	if j, out := judge(CheckOff, "", nil, nil); func() bool { ok, _ := j.JudgePhone(romPhone); return !ok }() || out.Len() != 0 {
		t.Fatal("off still checked")
	}
	// A revoked certificate turns a verified phone into an unverified one.
	j, out = judge(CheckWarn, "n\n", map[string]string{"abc": "REVOKED KEY_COMPROMISE"}, nil)
	if ok, _ := j.JudgePhone(goodPhone); ok || !strings.Contains(out.String(), "revoked by Google (REVOKED KEY_COMPROMISE)") {
		t.Fatalf("revoked: %s", out)
	}
	// An unreachable list is said, not hidden.
	j, out = judge(CheckWarn, "", nil, errors.New("no network"))
	if ok, _ := j.JudgePhone(goodPhone); !ok || !strings.Contains(out.String(), "revocation not checked (no network)") {
		t.Fatalf("offline: %s", out)
	}
}

func TestParseHWCheckPolicy(t *testing.T) {
	for in, want := range map[string]HWCheckPolicy{"": CheckWarn, "warn": CheckWarn, "require": CheckRequire, "off": CheckOff} {
		if got, err := ParseHWCheckPolicy(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseHWCheckPolicy("ask"); err == nil {
		t.Error("unknown policy accepted")
	}
}
