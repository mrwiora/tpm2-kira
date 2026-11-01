// Package bootclose is what a boot does with aSSH's close (hostkey.Close, the
// ladder of PCR 15, the kill switch and PCR 7): the closes of the boot image and
// what follows from each outcome. docs/SSH.md, "The close".
//
//	the close succeeded, some way          go on; degraded: say so, control red
//	no device and no sign of a TPM         nothing to close: go on
//	a TPM the firmware measured into       one hard reboot, counted in an EFI
//	does not answer                        variable; then go on, passphrase only,
//	                                       with the late closer
//	the TPM answers, all ways refused      hard reboot, not counted
//
// A resume from hibernation goes on only through PCR 15 itself, or without a TPM.
package bootclose

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/hostkey"

	"github.com/mrwiora/tpm2-kira/internal/efivars"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// CounterVar counts the hard reboots for a TPM that did not answer, under
// tpm2-kira's GUID; a close that succeeds removes it. Nothing trusts it: whoever
// writes it can spare a boot that reboot, not a close.
const CounterVar = "KIRAcloseReboot"

// State is what this boot's close came to, in RunDir's stateFile.
type State string

const (
	StateClosed      State = "closed"      // PCR 15 moved
	StateHierarchies State = "hierarchies" // the kill switch
	StatePCR7        State = "pcr7"        // PCR 7 moved
	StateNoTPM       State = "no-tpm"      // no TPM in this boot, by any sign
	StatePending     State = "pending"     // the late closer is waiting for the TPM
)

const (
	stateFile   = "close-state"
	pendingFile = "close-pending"
)

// Paths and times; vars for the tests.
var (
	// Wait is how long a close waits for the TPM's device.
	Wait = 30 * time.Second
	// LateEvery is how often the late closer asks.
	LateEvery = 2 * time.Second
	// RunDir survives the change to the real root on both distributions.
	RunDir     = "/run/tpm2-kira"
	ACPITables = "/sys/firmware/acpi/tables"
	EventLog   = "/sys/kernel/security/tpm0/binary_bios_measurements"
	// out is where a close speaks: the console, by the unit or the script.
	out io.Writer = os.Stderr
	// openTPM asks the TPM a few times, and says what it answered.
	openTPM = tpmdev.Open
)

// stubMeasured is systemd-stub's variable for what it measured into a TPM.
const stubMeasured = "StubPcrKernelImage-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

// TestPaths points what this package reads and writes at a test's directory
// when TPM2_KIRA_TEST_DIR is set, as machineid.TestPaths.
func TestPaths() {
	dir := os.Getenv("TPM2_KIRA_TEST_DIR")
	if dir == "" {
		return
	}
	RunDir = dir + "/run"
	ACPITables = dir + "/acpi"
	EventLog = dir + "/binary_bios_measurements"
}

// ErrReboot is a boot that must not go on: the unit's FailureAction, the script's
// reboot -f. The exit status of 'close'.
var ErrReboot = errors.New("the boot is not closed (PCR 15)")

// ErrNoResume is a resume that must not go on.
var ErrNoResume = errors.New("the boot is not closed by PCR 15: no resume from hibernation this boot")

// outcome is what one attempt met.
type outcome int

const (
	closed outcome = iota // result holds how
	noTPM
	silent
	refused
)

// attempt waits for the device up to wait and runs the ladder.
func attempt(tpmPath string, wait time.Duration) (outcome, hostkey.CloseResult, error) {
	if !tpmdev.AwaitNode(tpmPath, wait) {
		if sign := FirmwareSign(); sign != "" {
			return silent, hostkey.CloseResult{}, fmt.Errorf("%s did not appear within %s, and %s", tpmPath, wait, sign)
		}
		return noTPM, hostkey.CloseResult{}, nil
	}
	dev, err := openTPM(tpmPath)
	if err != nil {
		return silent, hostkey.CloseResult{}, err
	}
	defer dev.Close()
	return run(dev)
}

// run is the ladder on an open TPM.
func run(dev transport.TPM) (outcome, hostkey.CloseResult, error) {
	res, err := hostkey.Close(dev)
	if err == nil {
		return closed, res, nil
	}
	var ce *hostkey.CloseError
	if errors.As(err, &ce) && ce.Answers {
		return refused, res, err
	}
	return silent, res, err
}

// FirmwareSign says what shows that the firmware had a TPM in this boot; "" for
// nothing that does. The ACPI table holds for a device the kernel did not bind,
// the stub's variable for what it measured; the event log comes with a bound
// device (and securityfs).
func FirmwareSign() string {
	for _, table := range []string{"TPM2", "TCPA"} {
		if _, err := os.Stat(filepath.Join(ACPITables, table)); err == nil {
			return "the firmware has the ACPI table " + table
		}
	}
	if _, err := os.Stat(EventLog); err == nil {
		return "the firmware kept an event log"
	}
	if _, err := os.Stat(filepath.Join(efivars.Dir, stubMeasured)); err == nil {
		return "the stub measured into a TPM"
	}
	return ""
}

// Boot is the close of a boot on its way to the real root: nil goes on, ErrReboot
// (wrapped) is the hard reboot.
func Boot(tpmPath string) error {
	how, res, err := attempt(tpmPath, Wait)
	switch how {
	case closed:
		succeeded(res)
		return nil
	case noTPM:
		writeState(StateNoTPM, "no TPM device and no sign of one in the firmware: nothing to close")
		return nil
	case refused:
		return fmt.Errorf("%w: %w: rebooting", ErrReboot, err)
	}
	// A TPM that does not answer: one reboot, then on.
	if n := rebootsCounted(); n == 0 {
		if werr := efivars.Write(CounterVar, []byte{1}); werr == nil {
			return fmt.Errorf("%w: %w: rebooting once", ErrReboot, err)
		} else {
			fmt.Fprintf(out, "tpm2-kira: the reboot cannot be counted (%v): no reboot\n", werr)
		}
	}
	fmt.Fprintf(out, "\033[0;31mtpm2-kira: the TPM does not answer (%v): this boot goes on with the passphrase alone, and closes the moment the TPM answers. Nothing of a slot or of the SSH CA works. tpm2-kira control says more.\033[0m\n", err)
	writeState(StatePending, err.Error())
	if werr := touchPending(); werr != nil {
		fmt.Fprintf(out, "tpm2-kira: the late closer will not start: %v\n", werr)
	}
	return nil
}

// Resume is the close right before a resume from hibernation: nil resumes. It
// closes as far as it can, leaves the counter to the boot's own close, and only
// PCR 15 itself lets a resume go on: a resumed system expects its own state.
func Resume(tpmPath string) error {
	wait := Wait
	if pending() {
		wait = 0 // the boot's close has waited
	}
	how, res, err := attempt(tpmPath, wait)
	switch how {
	case noTPM:
		return nil
	case closed:
		succeeded(res)
		if !res.Degraded() {
			return nil
		}
		return ErrNoResume
	}
	return fmt.Errorf("%w: %w", ErrNoResume, err)
}

// Now is run's close at the end of the code screen, which has waited for the
// device at its start: what it cannot do is left to the image's close, which
// decides.
func Now(tpmPath string) error {
	how, res, err := attempt(tpmPath, 0)
	if how == closed {
		succeeded(res)
		return nil
	}
	if how == noTPM {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrReboot, err)
}

// Late waits for a TPM that did not answer at boot and closes the moment it does:
// the rest of the initrd, then the real root (tpm2-kira-late-close.service in
// both). Best effort: root can kill it. It ends when the close succeeded, and
// when stop is closed.
func Late(tpmPath string, stop <-chan struct{}) error {
	said := ""
	for {
		how, res, err := lateAttempt(tpmPath)
		if how == closed {
			succeeded(res)
			fmt.Fprintf(out, "tpm2-kira: the TPM answers: the boot is closed late (%s)\n", res)
			return nil
		}
		if err != nil && err.Error() != said {
			said = err.Error()
			fmt.Fprintf(out, "tpm2-kira: the late close waits: %v\n", err)
		}
		select {
		case <-stop:
			return errors.New("stopped before the TPM answered")
		case <-time.After(LateEvery):
		}
	}
}

func lateAttempt(tpmPath string) (outcome, hostkey.CloseResult, error) {
	if !tpmdev.AwaitNode(tpmPath, 0) {
		return silent, hostkey.CloseResult{}, nil
	}
	dev, err := openTPM(tpmPath)
	if err != nil {
		return silent, hostkey.CloseResult{}, err
	}
	defer dev.Close()
	return run(dev)
}

// succeeded is a close that holds, some way: the counter goes, the state is
// written, a degraded one is said.
func succeeded(res hostkey.CloseResult) {
	if _, err := efivars.Remove(CounterVar); err != nil {
		fmt.Fprintf(out, "tpm2-kira: the reboot's counter stays: %v\n", err)
	}
	os.Remove(filepath.Join(RunDir, pendingFile))
	state := StateClosed
	switch res.How {
	case hostkey.ClosedHierarchies:
		state = StateHierarchies
	case hostkey.ClosedPCR7:
		state = StatePCR7
	}
	writeState(state, res.String())
	if res.Degraded() {
		fmt.Fprintf(out, "\033[0;31mtpm2-kira: the close went another way: %s. The boot goes on: passphrase and temporary host key work, no slot and no SSH CA, until the next boot.\033[0m\n", res)
	}
}

func rebootsCounted() int {
	b, err := efivars.Read(CounterVar)
	if err != nil || len(b) == 0 {
		return 0
	}
	return int(b[0])
}

func pending() bool {
	_, err := os.Stat(filepath.Join(RunDir, pendingFile))
	return err == nil
}

func touchPending() error {
	if err := os.MkdirAll(RunDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(RunDir, pendingFile), nil, 0o644)
}

func writeState(s State, detail string) {
	if err := os.MkdirAll(RunDir, 0o755); err == nil {
		err = os.WriteFile(filepath.Join(RunDir, stateFile), []byte(string(s)+"\n"+detail+"\n"), 0o644)
		if err == nil {
			return
		}
		fmt.Fprintf(out, "tpm2-kira: the close's state is not kept: %v\n", err)
	}
}

// ReadState is what this boot's close left, and its detail; "" when none did.
func ReadState() (State, string) {
	b, err := os.ReadFile(filepath.Join(RunDir, stateFile))
	if err != nil {
		return "", ""
	}
	s, detail, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return State(s), detail
}

// Finding is what status and control say in red of this boot's close; "" for
// nothing wrong. It looks at the TPM as well as the state (dev nil: at the state
// alone): the hierarchies off are that, whoever turned them off.
func Finding(dev transport.TPM) string {
	state, detail := ReadState()
	if pending() {
		state = StatePending
	}
	switch state {
	case StatePending:
		return "the TPM did not answer at boot: passphrase only, and a process waits to close the moment it answers (" + detail + ") (risk: a TPM that answers later in this boot, while that process is killed by root, has every slot and the SSH CA open: reboot once the TPM is mended)"
	case StatePCR7:
		return "the close did not move PCR 15, PCR 7 instead (" + detail + ") (risk: a TPM that refused its PCR: no slot and no SSH CA until the next boot, and a slot that does not read PCR 7 stays open)"
	}
	if dev != nil {
		if h, err := hostkey.ReadHierarchies(dev); err == nil && !h.Storage {
			if detail == "" || state != StateHierarchies {
				detail = "TPM2_HierarchyControl, by someone"
			}
			return "the owner hierarchy of the TPM is off until the next boot: the close's kill switch (" + detail + ") (risk: a TPM that refused PCR 15: no slot and no SSH CA, and nothing of tpm2-kira's can be set up, until the next boot)"
		}
	}
	if state == StateHierarchies {
		return "the close turned the owner hierarchy off (" + detail + ") (risk: a TPM that refused PCR 15: no slot and no SSH CA until the next boot)"
	}
	if rebootsCounted() > 0 {
		return "the last boots rebooted for a TPM that did not answer, and no close has succeeded since (risk: a TPM that comes and goes: the close may fail again)"
	}
	return ""
}
