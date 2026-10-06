//go:build apptest

package cmd

// TestAppMachine serves a tpm2-kira machine on a software TPM to the Android
// app's instrumented test (marify android/: SwtpmMachineSessionTest, run by
// scripts/test-swtpm.sh). The machine side is the production code path —
// tpmBackend with a real EK, AK, quotes, ActivateCredential and PolicySigned
// NV writes on swtpm — with BLE replaced by TCP:
//
//	control  KIRA_APPTEST_ADDR   one text command per line, one reply line
//	data     control port + 1    8-byte INFO from the machine, then
//	                             fragments both ways, each prefixed by a
//	                             big-endian u16 length
//
// Commands: enrol <mtu> | attest <mtu> (serve the next data connection) |
// reboot | extend <pcr> | snapshot | rollback | sas | phone | outcome <ms> | quit.
// Replies: "ok", a value, or "error: …".
//
// It runs only when asked:
//
//	KIRA_APPTEST_ADDR=127.0.0.1:7317 go test -tags apptest -run '^TestAppMachine$' ./cmd

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/matthias/tpm2-kira/attest"
	"github.com/matthias/tpm2-kira/transport/frame"
)

func TestAppMachine(t *testing.T) {
	addr := os.Getenv("KIRA_APPTEST_ADDR")
	if addr == "" {
		t.Skip("set KIRA_APPTEST_ADDR (scripts/test-swtpm.sh in the app does)")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	m := newAppMachine(t)

	ctl, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	data, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port+1)))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	go m.acceptData(data)

	t.Logf("machine %q ready: control %s, data port %d", m.s.blob.FriendlyName, addr, port+1)
	quit := make(chan struct{})
	var once sync.Once
	go func() {
		for {
			c, err := ctl.Accept()
			if err != nil {
				return
			}
			go func() {
				if m.control(c) {
					once.Do(func() { close(quit) })
				}
			}()
		}
	}()
	<-quit
}

type appMachine struct {
	t      *testing.T
	mu     sync.Mutex // guards everything below except result
	proc   *swtpmProc
	s      *swtpmSetup
	signer *ecdsa.PrivateKey
	idx    uint32
	snap   string
	evlog  []byte
	mode   string // session to serve on the next data connection
	mtu    int
	sas    string
	phone  *attest.PhoneAttestation // what the machine concluded about the phone's key
	result chan string
}

func newAppMachine(t *testing.T) *appMachine {
	proc, err := startSWTPMProc(t.TempDir())
	if err != nil {
		t.Skip(err)
	}
	m := &appMachine{
		t:      t,
		proc:   proc,
		signer: testSigner(t),
		idx:    uint32(NVRAMSlotStart + 9),
		snap:   t.TempDir(),
		// A fixed event log: the host's own log is neither readable nor
		// reproducible here, and the app should transfer a real-sized one.
		evlog:  bytes.Repeat([]byte("swtpm event log "), 3000),
		result: make(chan string, 1),
	}
	t.Cleanup(func() { m.proc.stop(nil) })
	m.s = newSWTPMSetupAt(t, proc.sock, "swtpm-box")
	// The phones are stored in the slot's blob, next to its TOTP key.
	writeTestSlot(t, m.s.tpm, m.idx, m.signer)
	m.newBackend()
	return m
}

// newBackend builds the machine's TPM backend over the current connection.
func (m *appMachine) newBackend() {
	be := &tpmBackend{
		tpm:       m.s.tpm,
		blob:      m.s.blob,
		sealIndex: NVRAMSlotStart,
		evlogRead: true,
		evlog:     m.evlog,
	}
	// The console's "y": the machine user always confirms; the app test
	// compares the code it showed with this one.
	be.confirmSAS = func(code string) (bool, error) {
		m.mu.Lock()
		m.sas = code
		m.mu.Unlock()
		return true, nil
	}
	tpm := m.s.tpm
	be.commit = func(v attest.EnrolledVerifier) error {
		if err := m.s.blob.UpsertVerifier(v); err != nil {
			return err
		}
		return writeAttestBlob(tpm, m.idx, m.s.blob, m.signer)
	}
	be.phoneJudge = phoneRecorder{m}
	m.s.be = be
}

// phoneRecorder accepts every phone and keeps the verdict for the "phone"
// control command.
type phoneRecorder struct{ m *appMachine }

func (r phoneRecorder) JudgePhone(a attest.PhoneAttestation) (bool, error) {
	r.m.mu.Lock()
	r.m.phone = &a
	r.m.mu.Unlock()
	return true, nil
}

// powerCycle shuts the TPM down orderly, optionally saves or restores its
// state directory while it is off, and starts it again: a reboot, which
// advances the TPM's reset counter and clears the PCRs.
func (m *appMachine) powerCycle(save, restore string) error {
	m.proc.stop(m.s.tpm)
	if save != "" {
		if err := copyRegularFiles(m.proc.dir, save); err != nil {
			return err
		}
	}
	if restore != "" {
		if err := copyRegularFiles(restore, m.proc.dir); err != nil {
			return err
		}
	}
	p, err := startSWTPMProc(m.proc.dir)
	if err != nil {
		return err
	}
	m.proc = p
	tpm, err := transport.OpenTPM(p.sock)
	if err != nil {
		return err
	}
	m.s.tpm = tpm
	m.newBackend()
	return nil
}

func copyRegularFiles(from, to string) error {
	entries, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// control serves one control connection; it reports whether "quit" came.
func (m *appMachine) control(c net.Conn) bool {
	defer c.Close()
	in := bufio.NewScanner(c)
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 0 {
			continue
		}
		reply, quit := m.command(f)
		m.t.Logf("control: %s -> %s", in.Text(), reply)
		fmt.Fprintln(c, reply)
		if quit {
			return true
		}
	}
	return false
}

func (m *appMachine) command(f []string) (reply string, quit bool) {
	arg := func() (int, error) {
		if len(f) < 2 {
			return 0, fmt.Errorf("%s needs an argument", f[0])
		}
		return strconv.Atoi(f[1])
	}
	fail := func(err error) (string, bool) { return "error: " + err.Error(), false }
	switch f[0] {
	case "enrol", "attest":
		mtu, err := arg()
		if err != nil || mtu < 23 || mtu > 517 {
			return fail(fmt.Errorf("mtu must be 23-517"))
		}
		select { // forget an outcome nobody asked for
		case <-m.result:
		default:
		}
		m.mu.Lock()
		m.mode, m.mtu = f[0], mtu
		if f[0] == "enrol" {
			m.sas = ""
		}
		m.mu.Unlock()
		return "ok", false
	case "reboot", "snapshot", "rollback":
		m.mu.Lock()
		defer m.mu.Unlock()
		var err error
		switch f[0] {
		case "reboot":
			err = m.powerCycle("", "")
		case "snapshot":
			err = m.powerCycle(m.snap, "")
		case "rollback":
			err = m.powerCycle("", m.snap)
		}
		if err != nil {
			return fail(err)
		}
		return "ok", false
	case "extend":
		pcr, err := arg()
		if err != nil {
			return fail(err)
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if err := extendPCR(m.s.tpm, pcr, "x"); err != nil {
			return fail(err)
		}
		return "ok", false
	case "sas":
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.sas, false
	case "phone": // the machine's verdict on the phone's key attestation, as JSON
		m.mu.Lock()
		defer m.mu.Unlock()
		b, _ := json.Marshal(m.phone)
		return string(b), false
	case "outcome":
		ms, err := arg()
		if err != nil {
			return fail(err)
		}
		select {
		case r := <-m.result:
			return r, false
		case <-time.After(time.Duration(ms) * time.Millisecond):
			return "", false
		}
	case "quit":
		return "ok", true
	}
	return fail(fmt.Errorf("unknown command %q", f[0]))
}

func (m *appMachine) acceptData(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		m.mu.Lock()
		mode, mtu := m.mode, m.mtu
		m.mode = ""
		m.mu.Unlock()
		if mode == "" {
			c.Close() // like a machine that is not advertising
			continue
		}
		m.serve(c, mode, mtu)
	}
}

// serve runs one session over c, exactly as `attest enrol` / `attest gate`
// do over BLE, and posts the machine's outcome.
func (m *appMachine) serve(c net.Conn, mode string, mtu int) {
	defer c.Close()
	m.mu.Lock()
	tpm, be, blob := m.s.tpm, m.s.be, m.s.blob
	m.mu.Unlock()

	outcome := func() string {
		noise, err := attest.NoiseKeypairFromPrivate(blob.Phone.NoisePrivate)
		if err != nil {
			return "error: " + err.Error()
		}
		sel, err := blob.Selection()
		if err != nil {
			return "error: " + err.Error()
		}
		infoMode, caps, budget := uint8(infoModeEnrol), uint32(0),
			frame.Budget{MaxRecord: frame.MaxRecord, MaxBytes: 1 << 20, Deadline: 5 * time.Minute}
		if mode == "attest" {
			infoMode, caps, budget = infoModeAttest, attest.CapEventlog, frame.DefaultBudget
		}
		if _, err := c.Write(attestInfo(infoMode, caps)); err != nil {
			return "error: " + err.Error()
		}
		fc, err := frame.NewConn(&tcpLink{c: c, max: mtu - 3}, budget)
		if err != nil {
			return "error: " + err.Error()
		}
		defer fc.Close()
		go readFragments(c, fc)

		if mode == "enrol" {
			_, err := attest.ServeEnrolment(fc, &attest.EnrolIdentity{
				DeviceID: blob.DeviceID, FriendlyName: blob.FriendlyName,
				AKPub: blob.AKPublic, AKName: blob.AKName, NoiseStatic: noise,
				AdvKey: blob.Phone.AdvKey, Selection: sel, AppVersion: "apptest",
				Slot: uint8(SlotNumber(NVRAMSlotStart)),
			}, be, nil)
			if err != nil {
				return "error: " + err.Error()
			}
			return "enrolled"
		}
		stored, err := loadAttestBlob(tpm, m.idx)
		if err != nil {
			return "error: not enrolled: " + err.Error()
		}
		res, err := attest.ServeAttestation(fc, &attest.AttestIdentity{
			DeviceID: stored.DeviceID, AKName: stored.AKName, NoiseStatic: noise,
			Verifiers: stored.Phone.Verifiers, AppVersion: "apptest", Capabilities: attest.CapEventlog,
		}, be, nil)
		if res == nil || res.Receipt == nil {
			if err == nil {
				err = fmt.Errorf("no receipt")
			}
			return "error: " + err.Error()
		}
		return fmt.Sprintf("receipt: verdict=%s authentic=%t", res.Check.Verdict, res.Check.Authentic)
	}()
	m.t.Logf("%s session: %s", mode, outcome)
	select {
	case <-m.result:
	default:
	}
	m.result <- outcome
}

// tcpLink is the machine's side of the data connection, standing in for the
// GATT TX characteristic.
type tcpLink struct {
	mu  sync.Mutex
	c   net.Conn
	max int
}

func (l *tcpLink) SendFragment(f []byte) error {
	if len(f) > l.max {
		return fmt.Errorf("fragment of %d bytes exceeds %d", len(f), l.max)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(f)), uint16(len(f)))
	_, err := l.c.Write(append(b, f...))
	return err
}
func (l *tcpLink) MaxFragment() int { return l.max }
func (l *tcpLink) Close() error     { return l.c.Close() }

// readFragments plays the RX characteristic: every length-prefixed write
// from the app is one fragment.
func readFragments(c net.Conn, fc *frame.Conn) {
	defer fc.Close()
	var hdr [2]byte
	for {
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		f := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(c, f); err != nil {
			return
		}
		fc.Deliver(f)
	}
}
