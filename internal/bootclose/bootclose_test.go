package bootclose

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/hostkey"
	"golang.org/x/sys/unix"

	"github.com/mrwiora/tpm2-kira/internal/bootwait"
	"github.com/mrwiora/tpm2-kira/internal/efivars"
)

// setup gives a test its own paths, and a device path with nothing there.
func setup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	was := []string{RunDir, ACPITables, EventLog, efivars.Dir, bootwait.Dir}
	w, o, every, open := Wait, out, LateEvery, openTPM
	t.Cleanup(func() {
		RunDir, ACPITables, EventLog = was[0], was[1], was[2]
		efivars.SetDir(was[3])
		bootwait.Dir = was[4]
		Wait, out, LateEvery, openTPM = w, o, every, open
	})
	RunDir, ACPITables, EventLog = dir+"/run", dir+"/acpi", dir+"/log"
	bootwait.Dir = RunDir
	efivars.SetDir(dir + "/efivars")
	for _, d := range []string{ACPITables, dir + "/efivars"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	Wait, out, LateEvery = 10*time.Millisecond, io.Discard, 10*time.Millisecond
	return "/dev/tpm2-kira-test-none"
}

func firmwareHasTPM(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(ACPITables, "TPM2"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func counted(t *testing.T) int {
	t.Helper()
	return rebootsCounted()
}

// Step 5: no device and no sign of one: nothing to close, no error, no reboot; a
// resume goes on too.
func TestNoTPMAtAll(t *testing.T) {
	path := setup(t)
	if err := Boot(path); err != nil {
		t.Fatal(err)
	}
	if s, _ := ReadState(); s != StateNoTPM || pending() || counted(t) != 0 {
		t.Fatalf("state %q pending %v counted %d", s, pending(), counted(t))
	}
	if f := Finding(nil); f != "" {
		t.Fatalf("a finding without a TPM: %s", f)
	}
	if err := Resume(path); err != nil {
		t.Fatal(err)
	}
}

// Step 6: a TPM the firmware had does not answer: one hard reboot, counted; the
// next boot, and those after it, go on with the late closer.
func TestSilentTPM(t *testing.T) {
	for _, sign := range []string{"acpi", "stub"} {
		t.Run(sign, func(t *testing.T) {
			path := setup(t)
			if sign == "acpi" {
				firmwareHasTPM(t)
			} else {
				os.WriteFile(filepath.Join(efivars.Dir, stubMeasured), nil, 0o644)
			}
			if err := Boot(path); !errors.Is(err, ErrReboot) || !strings.Contains(err.Error(), "rebooting once") {
				t.Fatalf("the first boot: %v", err)
			}
			if counted(t) != 1 || pending() {
				t.Fatalf("counted %d pending %v", counted(t), pending())
			}
			for boot := 2; boot <= 3; boot++ {
				if err := Boot(path); err != nil {
					t.Fatalf("boot %d: %v", boot, err)
				}
				if s, _ := ReadState(); s != StatePending || !pending() || counted(t) != 1 {
					t.Fatalf("boot %d: state %q pending %v counted %d", boot, s, pending(), counted(t))
				}
			}
			if f := Finding(nil); !strings.Contains(f, "did not answer") || !strings.Contains(f, "risk:") {
				t.Fatalf("the finding: %s", f)
			}
			// A resume in that boot: none, and the count is the boot's.
			if err := Resume(path); !errors.Is(err, ErrNoResume) {
				t.Fatalf("the resume: %v", err)
			}
			if counted(t) != 1 {
				t.Fatalf("the resume counted: %d", counted(t))
			}
		})
	}
}

// A count that cannot be written is no reboot loop: the boot goes on.
func TestSilentTPMUncounted(t *testing.T) {
	path := setup(t)
	firmwareHasTPM(t)
	efivars.SetDir(filepath.Join(t.TempDir(), "a file"))
	os.WriteFile(efivars.Dir, nil, 0o644)
	if err := Boot(path); err != nil {
		t.Fatal(err)
	}
	if !pending() {
		t.Fatal("no late closer")
	}
}

// A resume whose boot has not closed does not count a reboot either.
func TestResumeLeavesTheCount(t *testing.T) {
	path := setup(t)
	firmwareHasTPM(t)
	if err := Resume(path); !errors.Is(err, ErrNoResume) || counted(t) != 0 {
		t.Fatalf("%v, counted %d", err, counted(t))
	}
}

// swtpm for the test.
func swtpm(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed")
	}
	dir, err := os.MkdirTemp("", "kc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	cmd := exec.Command("swtpm", "socket", "--tpm2", "--tpmstate", "dir="+dir,
		"--server", "type=unixio,path="+sock, "--ctrl", "type=unixio,path="+sock+".c",
		"--flags", "not-need-init,startup-clear")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if c, err := transport.OpenTPM(sock); err == nil {
			c.Close()
			return sock
		}
		if time.Now().After(deadline) {
			t.Fatal("swtpm did not start")
		}
	}
}

// faulty refuses PCR_Event of the PCRs named, as a TPM would answer.
type faulty struct {
	transport.TPMCloser
	pcrs []uint32
}

func (f faulty) Send(cmd []byte) ([]byte, error) {
	if tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:])) == tpm2.TPMCCPCREvent {
		h := binary.BigEndian.Uint32(cmd[10:])
		for _, p := range f.pcrs {
			if p == h {
				rsp := binary.BigEndian.AppendUint16(nil, uint16(tpm2.TPMSTNoSessions))
				rsp = binary.BigEndian.AppendUint32(rsp, 10)
				return binary.BigEndian.AppendUint32(rsp, uint32(tpm2.TPMRCBadAuth)), nil
			}
		}
	}
	return f.TPMCloser.Send(cmd)
}

func refusing(pcrs ...uint32) func(string) (transport.TPMCloser, error) {
	return func(p string) (transport.TPMCloser, error) {
		c, err := transport.OpenTPM(p)
		if err != nil {
			return nil, err
		}
		return faulty{c, pcrs}, nil
	}
}

func pcr15(t *testing.T, sock string) []byte {
	t.Helper()
	c, err := transport.OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	v, err := hostkey.ReadPCRs(c, hostkey.SHA256, []int{hostkey.ClosePCR})
	if err != nil {
		t.Fatal(err)
	}
	return v[hostkey.ClosePCR]
}

func lock(t *testing.T, sock string, handles ...tpm2.TPMHandle) {
	t.Helper()
	c, err := transport.OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, h := range handles {
		if _, err := (tpm2.HierarchyChangeAuth{
			AuthHandle: tpm2.AuthHandle{Handle: h, Auth: tpm2.PasswordAuth(nil)},
			NewAuth:    tpm2.TPM2BAuth{Buffer: []byte("not ours")},
		}).Execute(c); err != nil {
			t.Fatal(err)
		}
	}
}

// The close that holds removes the count of an earlier boot.
func TestClosedClearsTheCount(t *testing.T) {
	setup(t)
	sock := swtpm(t)
	efivars.Write(CounterVar, []byte{1})
	if err := Boot(sock); err != nil {
		t.Fatal(err)
	}
	if s, _ := ReadState(); s != StateClosed || counted(t) != 0 {
		t.Fatalf("state %q counted %d", s, counted(t))
	}
	if bytes.Equal(pcr15(t, sock), make([]byte, 32)) {
		t.Fatal("PCR 15 did not move")
	}
	if f := Finding(nil); f != "" {
		t.Fatalf("a finding: %s", f)
	}
	if err := Resume(sock); err != nil {
		t.Fatalf("the resume: %v", err)
	}
}

// Step 4: the kill switch, and PCR 7: the boot goes on and says so; the resume
// does not.
func TestDegraded(t *testing.T) {
	t.Run("hierarchies", func(t *testing.T) {
		setup(t)
		sock := swtpm(t)
		openTPM = refusing(15)
		if err := Resume(sock); !errors.Is(err, ErrNoResume) {
			t.Fatalf("the resume: %v", err)
		}
		if err := Boot(sock); err != nil {
			t.Fatal(err)
		}
		if s, d := ReadState(); s != StateHierarchies || !strings.Contains(d, "shEnable clear") {
			t.Fatalf("state %q %q", s, d)
		}
		c, err := transport.OpenTPM(sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if f := Finding(c); !strings.Contains(f, "owner hierarchy") || !strings.Contains(f, "risk:") {
			t.Fatalf("the finding: %s", f)
		}
	})
	t.Run("pcr7", func(t *testing.T) {
		setup(t)
		sock := swtpm(t)
		lock(t, sock, tpm2.TPMRHOwner, tpm2.TPMRHPlatform)
		openTPM = refusing(15)
		if err := Boot(sock); err != nil {
			t.Fatal(err)
		}
		if s, _ := ReadState(); s != StatePCR7 {
			t.Fatalf("state %q", s)
		}
		if f := Finding(nil); !strings.Contains(f, "PCR 7") {
			t.Fatalf("the finding: %s", f)
		}
	})
}

// Step 7: the TPM answers and refuses every way: a hard reboot, not counted.
func TestRefusedReboots(t *testing.T) {
	setup(t)
	sock := swtpm(t)
	lock(t, sock, tpm2.TPMRHOwner, tpm2.TPMRHPlatform)
	openTPM = refusing(15, 7)
	for i := 0; i < 2; i++ {
		if err := Boot(sock); !errors.Is(err, ErrReboot) || !strings.Contains(err.Error(), "answers and refuses") {
			t.Fatalf("%v", err)
		}
		if counted(t) != 0 || pending() {
			t.Fatalf("counted %d pending %v", counted(t), pending())
		}
	}
}

// The late closer: it waits for the device, closes the moment the TPM answers,
// and leaves no count and nothing pending.
func TestLate(t *testing.T) {
	path := setup(t)
	firmwareHasTPM(t)
	efivars.Write(CounterVar, []byte{1})
	Wait = time.Hour // a counted boot does not wait: the closer takes a device that comes
	if err := Boot(path); err != nil {
		t.Fatal(err)
	}
	sock := swtpm(t)
	link := filepath.Join(t.TempDir(), "tpm")
	done := make(chan error, 1)
	stop := make(chan struct{})
	go func() { done <- Late(link, stop) }()
	select {
	case err := <-done:
		t.Fatalf("closed without a TPM: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if !bytes.Equal(pcr15(t, sock), make([]byte, 32)) {
		t.Fatal("PCR 15 moved before the close")
	}
	if err := os.Symlink(sock, link); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		close(stop)
		t.Fatal("the late close did not come")
	}
	if bytes.Equal(pcr15(t, sock), make([]byte, 32)) {
		t.Fatal("PCR 15 did not move")
	}
	if s, _ := ReadState(); s != StateClosed || pending() || counted(t) != 0 {
		t.Fatalf("state %q pending %v counted %d", s, pending(), counted(t))
	}
}

// bootBy runs Boot and fails when it takes longer than a boot that does not wait would.
func bootBy(t *testing.T, path string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- Boot(path) }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the close waited")
		return nil
	}
}

// The first wait of a boot counts for the close: machine-id's and run's are spent.
func TestCloseWaitsOnlyWhatIsLeft(t *testing.T) {
	path := setup(t)
	firmwareHasTPM(t)
	Wait = waitBeganAtBoot(t)
	if err := bootBy(t, path); !errors.Is(err, ErrReboot) {
		t.Fatalf("no wait left, the first time: the one reboot, got %v", err)
	}
	if counted(t) != 1 {
		t.Fatalf("counted %d", counted(t))
	}
}

// The first boot gives a late device all of its wait.
func TestFirstBootWaits(t *testing.T) {
	path := setup(t)
	firmwareHasTPM(t)
	Wait = 50 * time.Millisecond
	start := time.Now()
	if err := Boot(path); !errors.Is(err, ErrReboot) {
		t.Fatal(err)
	}
	if d := time.Since(start); d < Wait {
		t.Fatalf("waited %s of %s", d, Wait)
	}
}

// The boot after the one reboot: no wait, the passphrase, the late closer.
func TestCountedBootDoesNotWait(t *testing.T) {
	path := setup(t)
	firmwareHasTPM(t)
	efivars.Write(CounterVar, []byte{1})
	Wait = time.Hour
	if err := bootBy(t, path); err != nil {
		t.Fatal(err)
	}
	if s, _ := ReadState(); s != StatePending || !pending() {
		t.Fatalf("state %q pending %v: no late closer", s, pending())
	}
}

// The count is plain: without a sign of the firmware's, where no late closer would
// follow, it spares no wait.
func TestCountWithoutFirmwareSignWaits(t *testing.T) {
	path := setup(t)
	efivars.Write(CounterVar, []byte{1})
	Wait = 50 * time.Millisecond
	start := time.Now()
	if err := Boot(path); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < Wait {
		t.Fatalf("waited %s of %s", d, Wait)
	}
	if s, _ := ReadState(); s != StateNoTPM {
		t.Fatalf("state %q", s)
	}
}

// What /run/tpm2-kira and the count say never skips a close: a TPM that is there is
// closed, whatever they say.
func TestNothingWrittenSkipsTheClose(t *testing.T) {
	setup(t)
	firmwareHasTPM(t)
	efivars.Write(CounterVar, []byte{1})
	waitBeganAtBoot(t)
	if err := touchPending(); err != nil {
		t.Fatal(err)
	}
	sock := swtpm(t)
	if err := bootBy(t, sock); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pcr15(t, sock), make([]byte, 32)) {
		t.Fatal("PCR 15 did not move")
	}
	if s, _ := ReadState(); s != StateClosed || pending() || counted(t) != 0 {
		t.Fatalf("state %q pending %v counted %d", s, pending(), counted(t))
	}
}

// A silent TPM with nothing left of the wait, in a resume: no resume, at once.
func TestResumeOfACountedBootDoesNotWait(t *testing.T) {
	path := setup(t)
	firmwareHasTPM(t)
	efivars.Write(CounterVar, []byte{1})
	Wait = time.Hour
	done := make(chan error, 1)
	go func() { done <- Resume(path) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNoResume) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the resume's close waited")
	}
}

// waitBegan is a step of this boot that began to wait ago.
func waitBegan(t *testing.T, ago time.Duration) {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bootwait.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	began := strconv.FormatInt(ts.Nano()-int64(ago), 10)
	if err := os.WriteFile(filepath.Join(bootwait.Dir, bootwait.SinceFile), []byte(began), 0o600); err != nil {
		t.Fatal(err)
	}
}

// AwaitRun in a goroutine, and whether it returned within the wait.
func awaitRunReturns(t *testing.T, ready, pid string, within time.Duration) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		AwaitRun(ready, pid)
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(within):
		return false
	}
}

// The close before a volume waits as long as the code screen holds, and goes on with
// the file made or with run gone: After=tpm2-kira.service, ready or gone.
func TestAwaitRun(t *testing.T) {
	dir := t.TempDir()
	ready, pidFile := dir+"/ready", dir+"/pid"
	if !awaitRunReturns(t, ready, pidFile, 5*time.Second) {
		t.Fatal("no pid file, no run: it should not wait")
	}

	run := exec.Command("sleep", "60")
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { run.Process.Kill(); run.Wait() })
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(run.Process.Pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		AwaitRun(ready, pidFile)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("it went on while run holds")
	case <-time.After(300 * time.Millisecond):
	}
	if err := os.WriteFile(ready, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the file is there and it still waits")
	}
}

// The image's init does not reap run: one that ended is a zombie, and gone to AwaitRun.
func TestAwaitRunTakesAZombieForGone(t *testing.T) {
	dir := t.TempDir()
	run := exec.Command("true")
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { run.Wait() })
	if err := os.WriteFile(dir+"/pid", []byte(strconv.Itoa(run.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	if !awaitRunReturns(t, dir+"/ready", dir+"/pid", 5*time.Second) {
		t.Fatal("it waits for a zombie")
	}
}

// waitBeganAtBoot has the first wait begin at the boot's start and gives how long ago that
// was: a machine up for less than an hour (a CI runner) has no time of an hour ago.
func waitBeganAtBoot(t *testing.T) time.Duration {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Fatal(err)
	}
	waitBegan(t, time.Duration(ts.Nano()))
	return time.Duration(ts.Nano())
}
