package phonegate

// Enrolment checks of the other side's hardware, on the machine: is this
// machine's own TPM genuine (EK certificate), and is the phone's anchor key
// inside genuine secure hardware (Android Key Attestation)? Each is
// reported, and according to its policy enrolment continues, asks, or stops.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/attest"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// HWCheckPolicy says what enrolment does when a hardware check fails.
type HWCheckPolicy string

const (
	CheckWarn    HWCheckPolicy = "warn"    // show the result and ask (default)
	CheckRequire HWCheckPolicy = "require" // refuse unless verified
	CheckOff     HWCheckPolicy = "off"     // do not check
)

// ParseHWCheckPolicy reads a --verify-* option.
func ParseHWCheckPolicy(s string) (HWCheckPolicy, error) {
	switch p := HWCheckPolicy(s); p {
	case CheckWarn, CheckRequire, CheckOff:
		return p, nil
	case "":
		return CheckWarn, nil
	}
	return "", fmt.Errorf("check policy must be warn, require or off, not %q", s)
}

// askContinue asks on the console; anything but y/yes is no.
func askContinue(console *bufio.Reader, out io.Writer) (bool, error) {
	for {
		fmt.Fprint(out, "    Continue anyway? [y/N]: ")
		line, err := console.ReadString('\n')
		if err != nil && line == "" {
			return false, fmt.Errorf("no answer on the console: %w", err)
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true, nil
		case "", "n", "no":
			return false, nil
		}
	}
}

// decide applies policy to a check that did not verify.
func decide(policy HWCheckPolicy, console *bufio.Reader, out io.Writer) (bool, error) {
	switch policy {
	case CheckRequire:
		fmt.Fprintln(out, "    Refused: this check is required (--verify-*=require).")
		return false, nil
	case CheckOff:
		return true, nil
	}
	return askContinue(console, out)
}

// CheckOwnTPM runs the phone's EK verification on this machine before
// enrolling, so a problem shows up here first.
func CheckOwnTPM(tpmDev transport.TPM, policy HWCheckPolicy, console *bufio.Reader, out io.Writer) (bool, error) {
	if policy == CheckOff {
		return true, nil
	}
	by, note, err := ownEKVerdict(tpmDev)
	if err != nil {
		return false, err
	}
	if by != "" {
		fmt.Fprintf(out, "TPM:           verified as genuine (%s)\n", by)
		return true, nil
	}
	fmt.Fprintf(out, "TPM:           NOT VERIFIED as genuine hardware: %s\n", note)
	fmt.Fprintln(out, "               The phone will show the same. A machine that is already compromised")
	fmt.Fprintln(out, "               could present a software TPM; enrol only if you trust its current state.")
	return decide(policy, console, out)
}

func ownEKVerdict(tpmDev transport.TPM) (vendor, note string, err error) {
	alg, ek, pub, err := PickCertifiedEK(tpmDev)
	if err != nil {
		return "", "", err
	}
	tpmdev.FlushHandle(tpmDev, ek.Handle)
	leaf := ReadEKCert(tpmDev, alg)
	by, verr := attest.VerifyEKCertificate(pub, leaf, ReadEKCertChain(tpmDev, leaf), time.Now())
	return by, attest.EKCertNote(verr), nil
}

// AttestationStatusURL is Google's revocation list for attestation certificates.
const AttestationStatusURL = "https://android.googleapis.com/attestation/status"

// RevokedSerials fetches the revocation list; an error means "not checked".
func RevokedSerials(client *http.Client) (map[string]string, error) {
	resp, err := client.Get(AttestationStatusURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var st struct {
		Entries map[string]struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&st); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for serial, e := range st.Entries {
		out[strings.ToLower(serial)] = strings.TrimSpace(e.Status + " " + e.Reason)
	}
	return out, nil
}

// PhoneJudge decides on the phone's key attestation at enrolment.
type PhoneJudge struct {
	Policy  HWCheckPolicy
	Console *bufio.Reader
	Out     io.Writer
	Revoked func() (map[string]string, error) // nil: not checked
}

func (j *PhoneJudge) JudgePhone(a attest.PhoneAttestation) (bool, error) {
	if j.Policy == CheckOff {
		return true, nil
	}
	fmt.Fprintln(j.Out, "Checking the phone's key attestation in the background (its certificate")
	fmt.Fprintln(j.Out, "chain against Google's roots, its serials against the revocation list) ...")
	if j.Revoked != nil && a.Root != "" {
		if list, err := j.Revoked(); err != nil {
			fmt.Fprintf(j.Out, "Phone key:     revocation not checked (%v)\n", err)
		} else {
			for _, s := range a.Serials {
				if why, bad := list[s]; bad {
					a.Problems = append(a.Problems, "a certificate in its attestation was revoked by Google ("+why+")")
					a.Verified = false
				}
			}
		}
	}
	if a.Verified {
		fmt.Fprintf(j.Out, "Phone key:     verified by %s: %s\n", a.Root, a.Summary())
		return true, nil
	}
	fmt.Fprintf(j.Out, "Phone key:     NOT VERIFIED (%s)\n", a.Summary())
	for _, p := range a.Problems {
		fmt.Fprintf(j.Out, "               - %s\n", p)
	}
	fmt.Fprintln(j.Out, "               Its receipts then prove only that this phone's key signed them, not that")
	fmt.Fprintln(j.Out, "               the key is protected by secure hardware on an untampered phone.")
	return decide(j.Policy, j.Console, j.Out)
}
