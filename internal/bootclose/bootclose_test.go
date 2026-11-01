package bootclose

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/hostkey"

	"github.com/mrwiora/tpm2-kira/internal/efivars"
)

// setup gives a test its own paths, and a device path with nothing there.
func setup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	was := []string{RunDir, ACPITables, EventLog, efivars.Dir}
	w, o, every, open := Wait, out, LateEvery, openTPM
	t.Cleanup(func() {
		RunDir, ACPITables, EventLog = was[0], was[1], was[2]
		efivars.SetDir(was[3])
		Wait, out, LateEvery, openTPM = w, o, every, open
	})
	RunDir, ACPITables, EventLog = dir+"/run", dir+"/acpi", dir+"/log"
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
