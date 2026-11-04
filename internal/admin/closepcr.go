package admin

import (
	"fmt"

	"github.com/tpm2-trust/tpm2-kira/internal/measure"
)

// The close (PCR 15 extended) ends what every slot object and the SSH CA
// require: PCR 15 at zero. So PCR 15 has to be zero at the code screen, which
// is checked, not assumed: an event of the firmware's or the boot loader's in
// it, in the log of this boot, means it is not, at any boot.

// closeEventlogPath is the event log the check reads ("" for the default).
// A var: the tests point it elsewhere.
var closeEventlogPath = ""

// closePCRWhy is the finding, for status and for the refusal.
const closePCRWhy = "PCR 15 is measured by the firmware or the boot loader (risk: nothing of tpm2-kira's opens on this machine: every slot and the SSH CA need it at zero at the code screen)"

// firmwareClosePCREvents counts the events in PCR 15 in the event log at
// path ("" for the default), in the bank that has any events of it.
func firmwareClosePCREvents(path string) (int, error) {
	if path == "" {
		path = measure.DefaultEventlogPath
	}
	var firstErr error
	for _, algo := range []measure.PCRHashAlgo{measure.PCRHashAlgoSHA256, measure.PCRHashAlgoSHA1} {
		digests, err := measure.EventDigestsForPCR(path, 15, algo)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(digests) > 0 {
			return len(digests), nil
		}
	}
	return 0, firstErr
}

// checkClosePCRZero refuses an approval on a machine whose PCR 15 is not zero
// at the code screen. No log to read (a software TPM, a boot without one) says
// nothing: it passes.
func checkClosePCRZero() error {
	n, err := firmwareClosePCREvents(closeEventlogPath)
	if err != nil || n == 0 {
		return nil
	}
	return fmt.Errorf("this boot's event log has %d event(s) in PCR 15: %s", n, closePCRWhy)
}
