package kira

import (
	"fmt"
	"strconv"
	"strings"
)

// Rejecting arguments a command does not take.
//
// Go's flag package stops at the first non-flag and leaves the rest in Args(),
// which is easy to discard by accident. Doing so turned a natural mistake into a
// dangerous one: "tpm2-kira nvram delete 0" reads as naming slot 0, but the 0 was
// dropped, --nvram went unset, and the command fell through to its
// delete-everything path.

// PositionalArgError explains that a command was given arguments it does not
// take, and guesses which option was meant.
func PositionalArgError(command string, extra []string) error {
	message := fmt.Sprintf("'tpm2-kira %s' does not take positional arguments, but got %q.",
		command, strings.Join(extra, " "))

	switch {
	case LooksLikePCRSpec(extra[0]):
		message += fmt.Sprintf("\n  Did you mean:  tpm2-kira %s --pcrs %q", command, extra[0])
	case LooksLikeSlot(extra[0]):
		message += fmt.Sprintf("\n  Did you mean:  tpm2-kira %s --nvram %s", command, extra[0])
	default:
		message += fmt.Sprintf("\n  Every option is named; see 'tpm2-kira help' for what %s takes.", command)
	}

	return fmt.Errorf("%s", message)
}

// LooksLikeSlot reports whether an argument could have been meant as a slot
// number or a full NVRAM index.
func LooksLikeSlot(arg string) bool {
	lower := strings.ToLower(strings.TrimSpace(arg))

	if strings.HasPrefix(lower, "0x") {
		_, err := strconv.ParseUint(lower[2:], 16, 32)
		return err == nil
	}

	_, err := strconv.ParseUint(lower, 10, 32)
	return err == nil
}

// LooksLikePCRSpec reports whether an argument looks like a PCR selection, so
// that "tpm2-kira seal 0,7" is pointed at --pcrs rather than --nvram.
//
// A single number is a slot as far as this is concerned: it is a valid PCR
// selection too, but --nvram is the likelier intent for a bare number, and the
// suggestion only has to be the better guess.
func LooksLikePCRSpec(arg string) bool {
	if !strings.Contains(arg, ",") {
		return false
	}

	_, err := ParsePCRSpecs(arg)
	return err == nil
}
