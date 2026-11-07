package admin

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/tpm2-kira/internal/measure"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
)

// bootThroughKira says whether this boot passed the code screen: the boot
// image closed it (PCR 15 is not zero), so the slots' objects answer
// "closed until the next boot".
func bootThroughKira(tpmDev transport.TPM) bool {
	return nvslot.Closed(tpmDev)
}

// verifiedBootRequired: a phone is enrolled only in a boot that was
// verified before it, because enrolment pins this boot as the good one.
// The phone takes the machine's identity on first use and records its
// boot state as the baseline every later boot is compared with; nothing
// the phone can check itself says that this state is clean. The person's
// earlier check says so: for a slot's first phone, its TOTP code at this
// boot's code screen, compared with the authenticator (the code exists
// only while the PCRs are the ones the signing key approved); for a
// further phone, an enrolled phone's verdict on this boot. That is why a
// slot starts with a TOTP key, the setup is two parts with a reboot
// between them, and the TOTP key is retired only by the first phone,
// never before (docs/SECURITY-BACKGROUND.md §3.1).
//
// requireVerifiedBoot refuses a boot that cannot have been verified: one
// that never passed tpm2-kira's code screen (PCR 15 not closed), and, for a slot with a TOTP key, one whose PCR values
// at the code screen were not the approved ones, so no code was shown for
// the slot. It reports whether that match was established; when the event
// log cannot tell, the person's answer is what is left.
func requireVerifiedBoot(tpmDev transport.TPM, sealed *nvslot.SealedBlob, slot uint32) (bool, error) {
	if !bootThroughKira(tpmDev) {
		return false, fmt.Errorf("this boot did not pass tpm2-kira's code screen, so nothing verified it, and enrolling\n" +
			"would pin an unverified boot on the phone. Reboot through the code screen, compare the\n" +
			"code with your authenticator, then enrol")
	}
	if !sealed.HasTOTPKey() {
		return false, nil // a phone verified the boot, or did not: confirmVerifiedBoot asks
	}
	differ, err := bootMatchesApproval(tpmDev, sealed)
	switch {
	case err != nil:
		fmt.Printf("NOTE: whether this boot was the state slot %d is approved for cannot be told from the\n", slot)
		fmt.Printf("      event log (%v); your answer below decides.\n\n", err)
		return false, nil
	case len(differ) > 0:
		return false, fmt.Errorf("this boot is not the state slot %d's code is approved for (PCR %s differ), so the\n"+
			"code screen showed no code for it and nothing verified this boot. Approve the current\n"+
			"boot chain ('tpm2-kira slot approve', after a kernel update the hook does it), reboot, compare the\n"+
			"code with your authenticator, then enrol", slot, joinInts(differ))
	}
	return true, nil
}

// bootMatchesApproval recomputes, from this boot's event log, the values
// the slot's PCRs had at the code screen (before the OS separator, with
// systemd's enter-initrd on PCR 11, as the seal predicts them) and lists
// the PCRs that differ from the approved ones. A PCR the event log does not
// describe is read from its register, which only works for one that has
// not changed since; for one that has (9, 11, 15 above 12) it cannot tell.
func bootMatchesApproval(tpmDev transport.TPM, sealed *nvslot.SealedBlob) ([]int, error) {
	specs := make([]measure.PCRSpec, 0, len(sealed.Payload.PCRDigests))
	for _, pd := range sealed.Payload.PCRDigests {
		spec := measure.PCRSpec{Index: pd.Index, Source: measure.PCRSourceRegister}
		switch {
		case pd.Index <= 12:
			spec.Source = measure.PCRSourceEventlog
		default:
			if reason, volatile := measure.IsVolatileAfterMeasurePoint(pd.Index); volatile {
				return nil, fmt.Errorf("PCR %d is not in the event log and changes after the code screen: %s", pd.Index, reason)
			}
		}
		specs = append(specs, spec)
	}
	res, err := measure.ReadPCRValues(tpmDev, specs, sealed.GetHashAlgo(), measure.MeasurePointOn, measure.MeasurePointBeforeSeparator, false)
	if err != nil {
		return nil, err
	}
	if res.AfterSeparator != "" {
		return nil, errors.New(res.AfterSeparator)
	}
	var differ []int
	for _, pd := range sealed.Payload.PCRDigests {
		// A signed PCR is the PCR key's, not the approval's.
		if pd.Source != measure.PCRSourceSigned && !bytes.Equal(res.Values[pd.Index], pd.Digest.Buffer) {
			differ = append(differ, pd.Index)
		}
	}
	return differ, nil
}

// warnUnclosedBoot says, before a session with the phone, what its boot
// key verdict will read in a boot that never passed the code screen:
// refused, not the designed "locked until the next boot". control blocks
// its steps on this; by hand the note is the warning.
func warnUnclosedBoot(tpmDev transport.TPM) {
	if bootThroughKira(tpmDev) {
		return
	}
	fmt.Println("NOTE: this boot did not pass tpm2-kira's code screen, so the TPM cannot answer")
	fmt.Println("      with the boot key and the phone will call it refused. In a boot through")
	fmt.Println("      the wired image it reads \"locked until the next boot\", by design.")
	fmt.Println()
}

// confirmVerifiedBoot asks the person whether they verified this boot: the
// machine knows the code screen ran and, with a TOTP key, that it showed a
// valid code, but not that anyone compared it.
func confirmVerifiedBoot(in *bufio.Reader, sealed *nvslot.SealedBlob, slot uint32, matched bool) (bool, error) {
	fmt.Println()
	if sealed.HasTOTPKey() {
		if matched {
			fmt.Printf("    This boot showed slot %d's code at the code screen (its PCRs were the approved ones).\n", slot)
		}
		fmt.Printf("    Did slot %d's code at this boot's code screen match your authenticator?\n", slot)
		fmt.Println("    The phone takes this boot as the good one; only a boot you verified may be.")
		fmt.Printf("    After the enrolment slot %d has no TOTP code; the phone checks its boots.\n", slot)
	} else {
		fmt.Printf("    Did an enrolled phone attest this boot (\"mobile attestation passed\" for slot %d)?\n", slot)
		fmt.Println("    The new phone takes this boot as the good one; only a verified boot may be.")
	}
	fmt.Println()
	for {
		fmt.Print("    [y] yes, I verified this boot   [n] no — abort: ")
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return false, fmt.Errorf("no answer on the console: %w", err)
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
	}
}
