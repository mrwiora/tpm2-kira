package phonegate

// The radio worker at boot: 'tpm2-kira-boot gate-child', started by the
// coordinator (tpm2-kira-boot run) as the SSH server starts ssh-child - the
// same on every distribution, with nothing of it in a unit or a script.
//
// It is the process that parses what anyone in range sends, before the
// disk is unlocked, so it starts with nothing: as nobody, with the two
// capabilities the adapter needs (CAP_NET_ADMIN for the HCI user channel,
// CAP_NET_RAW for the raw HCI socket) and no others, in IPC, PID, mount
// and UTS namespaces of its own - not a network namespace: Bluetooth
// sockets exist only in the first one - and with the connection to the
// coordinator and /dev/rfkill as its only open files. Then it takes from
// itself what assh's sandbox takes, on every thread: new privileges,
// executable memory, every file but /sys (Landlock; it reads the adapter's
// and rfkill's state there), and the system calls that administer the
// machine (seccomp). No TPM: while the code screen is up, a TPM would
// compute codes for whoever asks.
//
// Its narrative goes to stdout, which the coordinator puts into its own
// (the journal, or Debian's log file); what needs eyes goes to stderr,
// which is the coordinator's and reaches the console.

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tpm2-trust/assh/sandbox"

	"github.com/mrwiora/tpm2-kira/internal/journal"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/core/transport/ble"
)

// The worker's files, as the coordinator hands them over (ExtraFiles).
const (
	workerConnFD   = 3
	workerWatchFD  = 4
	workerRFKillFD = 5 // closed when the coordinator has no /dev/rfkill
)

// workerNamespaces are the worker's namespaces of its own.
const workerNamespaces = syscall.CLONE_NEWIPC | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS

// workerCommand starts the worker; a var for the tests.
var workerCommand = func(debug bool) *exec.Cmd {
	self, err := os.Executable()
	if err != nil {
		self = "/usr/bin/tpm2-kira-boot"
	}
	args := []string{"gate-child"}
	if debug {
		args = append(args, "--debug")
	}
	return exec.Command(self, args...)
}

// workerStopWait is how long a stopped worker gets to bring the adapter
// back before it is killed; a var for the tests.
var workerStopWait = 3 * time.Second

// StartRadioWorker starts the radio worker for host. stop ends the phone
// check: the worker learns that the coordinator is gone, closes the radio
// and exits; one that does not is killed.
func StartRadioWorker(host GateHost, debug bool) (stop func(), err error) {
	server, files, err := LinkGate(host)
	if err != nil {
		return nil, err
	}
	defer files[0].Close()
	defer files[1].Close()
	extra := []*os.File{files[0], files[1], nil}
	// The worker cannot open /dev/rfkill; it may need to clear a soft
	// block, so it gets the device open for writing.
	if rf, err := os.OpenFile("/dev/rfkill", os.O_WRONLY|unix.O_CLOEXEC, 0); err == nil {
		defer rf.Close()
		extra[2] = rf
	}

	build := func(ns bool) *exec.Cmd {
		cmd := workerCommand(debug)
		cmd.Env = []string{"PATH=/usr/bin"}
		cmd.Stdout = journal.Narrator{Prio: journal.PrioInfo}
		cmd.Stderr = os.Stderr
		cmd.ExtraFiles = extra
		attr := &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if os.Geteuid() == 0 {
			attr.Credential = &syscall.Credential{Uid: workerUID, Gid: workerUID, Groups: []uint32{}}
			attr.AmbientCaps = []uintptr{unix.CAP_NET_ADMIN, unix.CAP_NET_RAW}
			if ns {
				attr.Cloneflags = workerNamespaces
			}
		}
		cmd.SysProcAttr = attr
		return cmd
	}
	cmd := build(true)
	if err := cmd.Start(); err != nil && os.Geteuid() == 0 {
		// A kernel without one of the namespaces: the other user and the
		// sandbox still hold.
		fmt.Fprintf(os.Stderr, "tpm2-kira: the phone's radio worker runs without namespaces of its own: %v\n", err)
		cmd = build(false)
		err = cmd.Start()
		if err != nil {
			server.Close()
			return nil, err
		}
	} else if err != nil {
		server.Close()
		return nil, err
	}
	exited := make(chan struct{})
	go func() {
		err := cmd.Wait()
		if code := cmd.ProcessState.ExitCode(); err != nil && code != ExitUnavailable {
			journal.Narrate("tpm2-kira: the phone's radio worker ended: %v", err)
		}
		close(exited)
	}()
	return func() {
		server.Close()
		select {
		case <-exited:
		case <-time.After(workerStopWait):
			cmd.Process.Kill()
			<-exited
		}
	}, nil
}

// workerUID is nobody's.
const workerUID = 65534

// RadioWorkerMain is 'gate-child', the radio worker, started by
// StartRadioWorker. It returns the exit status.
func RadioWorkerMain(debug bool) int {
	journal.NarrateDebug = debug
	step := GateSteps(debug)
	if os.Geteuid() == 0 {
		GateFail("the phone's radio worker refuses to run as root: it is started by 'tpm2-kira-boot run'")
		return ExitUsage
	}
	client, err := GateClientFromFiles(os.NewFile(workerConnFD, "gate"), os.NewFile(workerWatchFD, "gate-watch"))
	if err != nil {
		GateFail("no coordinator (the radio worker is started by 'tpm2-kira-boot run'): %v", err)
		return ExitUsage
	}
	defer client.Close()
	var rfkill *os.File
	if _, err := unix.FcntlInt(workerRFKillFD, unix.F_GETFD, 0); err == nil {
		rfkill = os.NewFile(workerRFKillFD, "/dev/rfkill")
		defer rfkill.Close()
	}
	confined, err := sandbox.Apply(sandbox.Policy{ReadBeneath: []string{"/sys"}})
	if err != nil {
		GateFail("the radio worker cannot confine itself: %v", err)
		return ExitInternal
	}
	step("version %s; radio worker, uid %d, %s", nvslot.AppVersion, os.Geteuid(), confined)
	// Nothing is configured: the worker takes the adapter that comes up and
	// waits for it, and for a phone, as long as the code screen holds.
	return RunGateRadio(client, GateOptions{Adapter: ble.AnyAdapter, AdapterWait: GateAdapterWait,
		Debug: debug, Worker: true, RFKill: rfkill}, step, client.Gone())
}
