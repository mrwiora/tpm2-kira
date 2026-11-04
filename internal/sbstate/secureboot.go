// Package sbstate reads the firmware's Secure Boot state from its EFI
// variables and says, in one line, what is wrong with it. It needs no TPM: the
// boot's lines come from here as well. It never stops anything: tpm2-kira informs,
// and has no enforced mode.
package sbstate

import (
	"fmt"
	"strings"

	"github.com/tpm2-trust/go-uefi-slim/efivar"
	"github.com/tpm2-trust/tpm2-kira/internal/efivars"
)

// State is what the firmware says. Known is false when either variable cannot be
// read, Why says what went wrong; the other fields then hold what could be read.
type State struct {
	Enabled   bool
	SetupMode bool
	Known     bool
	Why       string
}

// Read is the state now, from the variables under efivars.Dir.
func Read() State {
	var s State
	var problems []string
	var err error
	if s.Enabled, err = readBool("SecureBoot"); err != nil {
		problems = append(problems, err.Error())
	}
	if s.SetupMode, err = readBool("SetupMode"); err != nil {
		problems = append(problems, err.Error())
	}
	s.Known = len(problems) == 0
	s.Why = strings.Join(problems, "; ")
	return s
}

// readBool reads a one-byte variable of the UEFI specification's namespace.
func readBool(name string) (bool, error) {
	_, data, err := efivar.Store{Dir: efivars.Dir}.Read(name, efivar.GlobalVariable)
	if efivar.IsNotExist(err) {
		return false, fmt.Errorf("no %s variable: no UEFI, or efivarfs not mounted", name)
	}
	if err != nil {
		return false, err
	}
	if len(data) != 1 {
		return false, fmt.Errorf("%s: %d bytes, not one", name, len(data))
	}
	return data[0] == 1, nil
}

// Risk says in one line what is wrong with this state, without a prefix; empty
// when Secure Boot is on and out of Setup Mode.
func (s State) Risk() string {
	switch {
	case !s.Known:
		return "Secure Boot's state could not be read (" + s.Why + "): whether anything checks the boot loader and the kernel is unknown"
	case s.SetupMode:
		return "Secure Boot is in Setup Mode: nothing checks the boot loader and the kernel, and any root user can replace its keys"
	case !s.Enabled:
		return "Secure Boot is off: nothing checks the boot loader and the kernel, and PCR 7 records only that"
	}
	return ""
}

// WarningPrefix starts a Warning's line: a hook that has said it already finds it by this.
const WarningPrefix = "WARNING: Secure Boot"

// Warning is Risk as a line of a command's output; empty when there is no risk.
func (s State) Warning() string {
	if r := s.Risk(); r != "" {
		return "WARNING: " + r
	}
	return ""
}
