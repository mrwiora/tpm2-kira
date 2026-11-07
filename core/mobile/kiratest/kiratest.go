// Package kiratest is a simulated tpm2-kira machine for app development and
// instrumented tests, built as a separate gomobile library:
//
//	gomobile bind -target=android -androidapi 28 -o kiratest.aar ./mobile/kiratest
//	gomobile bind -target=ios,iossimulator -o Kiratest.xcframework ./mobile/kiratest
//
// It runs the real machine-side protocol over a software TPM double, with
// the BLE link replaced by method calls: the app's RX writes go to Write and
// its TX notifications come from NextNotification. It lets UI tests reach
// every verdict state without Linux hardware.
//
// It is a test fixture. It MUST NOT be linked into release builds: it is an
// attester whose "TPM" is a software key.
package kiratest

import (
	"errors"
	"sync"
	"time"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/core/attest/attesttest"
	"github.com/tpm2-trust/tpm2-kira/core/transport/frame"
)

// DemoMachine is one simulated machine. It keeps its identity across
// sessions, so an enrolment followed by attestations behaves like a real box.
type DemoMachine struct {
	mu     sync.Mutex
	m      *attesttest.Machine
	conn   *frame.Conn
	notes  chan []byte
	result chan string
	sas    string

	// A phone salt with a keyboard (EnableKeyboard): handed over in the next attestation, then
	// released with a seed at every one after it; layout is what the last release opened.
	kb     *demoKeyboard
	layout string
}

// demoKeyboard is the machine's side of a phone salt with a pepper typed through the keyboard.
type demoKeyboard struct {
	keeping bool
	name    []byte
	keep    *attest.KeyboardKeep
	factor  *attest.FactorBlob
}

// keyboardBackend is the software TPM as the machine's gate is with such a keyslot: it offers the
// phone salt and the keyboard to keep once, and opens the seed of every release after.
type keyboardBackend struct {
	*attesttest.SoftTPM
	d *DemoMachine
}

func (b *keyboardBackend) FactorToKeep() *attest.FactorBlob {
	b.d.mu.Lock()
	defer b.d.mu.Unlock()
	if b.d.kb.keeping {
		return b.d.kb.factor
	}
	return nil
}

func (b *keyboardBackend) KeyboardToKeep() *attest.KeyboardKeep {
	b.d.mu.Lock()
	defer b.d.mu.Unlock()
	if b.d.kb.keeping {
		return b.d.kb.keep
	}
	return nil
}

func (b *keyboardBackend) TakeRelease(r *attest.Release) (uint8, string) {
	b.d.mu.Lock()
	defer b.d.mu.Unlock()
	if b.d.kb.keeping {
		b.d.kb.keeping = false
		return attest.ReleaseOK, "the phone keeps the phone salt"
	}
	if r.KeyboardCredential == nil {
		return attest.ReleaseOK, "the TPM opened the salt"
	}
	seed, err := b.ActivateCredentialFor(b.d.kb.name, r.KeyboardCredential, r.KeyboardSecret)
	if err != nil {
		return attest.ReleaseTPMRefused, "the TPM did not open the keyboard: " + err.Error()
	}
	l, err := attest.KeyboardLayoutOf(seed)
	if err != nil {
		return attest.ReleaseTPMRefused, err.Error()
	}
	b.d.layout = l.String()
	return attest.ReleaseOK, "the TPM opened the salt and the keyboard"
}

// EnableKeyboard gives the machine a keyslot of a phone salt with a pepper typed through the
// phone's one-time keyboard: the next attestation hands both over, every one after it releases the
// salt with a seed, and the phone shows the layout.
func (d *DemoMachine) EnableKeyboard() error {
	public, name, err := d.m.TPM.ReleaseKey(d.m.TPM.SigningPub, d.m.TPM.PolicyRef)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.kb = &demoKeyboard{keeping: true, name: name,
		keep:   &attest.KeyboardKeep{ReleaseKeyPublic: public, SigningPublic: d.m.TPM.SigningPub, PolicyRef: d.m.TPM.PolicyRef},
		factor: &attest.FactorBlob{CredentialBlob: []byte("demo credential"), EncryptedSecret: []byte("demo secret"), Label: "luks"}}
	return nil
}

// KeyboardLayout is the layout the machine's TPM opened in the last attestation, in the order of
// attest.KeyboardKeys, or "".
func (d *DemoMachine) KeyboardLayout() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.layout
}

// NewDemoMachine creates a machine named "Thinkpad-X1" quoting PCRs 0,2,4,7.
func NewDemoMachine() (*DemoMachine, error) {
	m, err := attesttest.NewMachine()
	if err != nil {
		return nil, err
	}
	return &DemoMachine{m: m}, nil
}

type link struct {
	max   int
	notes chan []byte
}

func (l *link) SendFragment(f []byte) error {
	if len(f) > l.max {
		return errors.New("kiratest: fragment exceeds MTU")
	}
	select {
	case l.notes <- append([]byte(nil), f...):
		return nil
	case <-time.After(30 * time.Second):
		return errors.New("kiratest: app is not reading notifications")
	}
}
func (l *link) MaxFragment() int { return l.max }
func (l *link) Close() error     { return nil }

func (d *DemoMachine) start(mtu int, serve func(conn *frame.Conn) string) error {
	if mtu < 23 || mtu > 517 {
		return errors.New("kiratest: mtu must be 23-517")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.notes = make(chan []byte, 8192)
	d.result = make(chan string, 1)
	c, err := frame.NewConn(&link{max: mtu - 3, notes: d.notes}, frame.DefaultBudget)
	if err != nil {
		return err
	}
	d.conn = c
	go func() {
		r := serve(c)
		c.Close()
		d.result <- r
	}()
	return nil
}

// StartEnrolment begins serving one enrolment, as `tpm2-kira phone enrol`.
// The console side confirms the code automatically; read it with LastSAS.
func (d *DemoMachine) StartEnrolment(mtu int) error {
	return d.start(mtu, func(c *frame.Conn) string {
		be := &attesttest.SoftEnrol{SoftTPM: d.m.TPM, SASAnswer: true}
		hook := &sasHook{SoftEnrol: be, d: d}
		v, err := attest.ServeEnrolment(c, d.m.EnrolIdentity(), hook, nil)
		if err != nil {
			return "error: " + err.Error()
		}
		d.m.Verifier = v
		return "enrolled"
	})
}

type sasHook struct {
	*attesttest.SoftEnrol
	d *DemoMachine
}

func (h *sasHook) ConfirmSAS(code string) (bool, error) {
	h.d.mu.Lock()
	h.d.sas = code
	h.d.mu.Unlock()
	return h.SoftEnrol.ConfirmSAS(code)
}

// StartAttestation begins serving one attestation, as `tpm2-kira phone gate`.
func (d *DemoMachine) StartAttestation(mtu int) error {
	if d.m.Verifier == nil {
		return errors.New("kiratest: enrol first")
	}
	return d.start(mtu, func(c *frame.Conn) string {
		var be attest.AttesterBackend = d.m.TPM
		d.mu.Lock()
		if d.kb != nil {
			be = &keyboardBackend{SoftTPM: d.m.TPM, d: d}
		}
		d.layout = ""
		d.mu.Unlock()
		res, err := attest.ServeAttestation(c, d.m.AttestIdentity(), be, nil)
		if res == nil || res.Receipt == nil {
			if err == nil {
				err = errors.New("no receipt")
			}
			return "error: " + err.Error()
		}
		return "receipt: verdict=" + res.Check.Verdict.String() + " authentic=" + boolStr(res.Check.Authentic)
	})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Write delivers one RX write from the app.
func (d *DemoMachine) Write(fragment []byte) {
	d.mu.Lock()
	c := d.conn
	d.mu.Unlock()
	if c != nil {
		c.Deliver(fragment)
	}
}

// NextNotification returns the next TX notification, or nil after timeoutMs.
func (d *DemoMachine) NextNotification(timeoutMs int) []byte {
	d.mu.Lock()
	ch := d.notes
	d.mu.Unlock()
	select {
	case n := <-ch:
		return n
	case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
		return nil
	}
}

// Outcome returns the machine's outcome of the current session ("enrolled",
// "receipt: verdict=ok authentic=true", "error: …"), or "" after timeoutMs.
func (d *DemoMachine) Outcome(timeoutMs int) string {
	d.mu.Lock()
	ch := d.result
	d.mu.Unlock()
	select {
	case r := <-ch:
		return r
	case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
		return ""
	}
}

// LastSAS returns the code the machine displayed at the last enrolment.
func (d *DemoMachine) LastSAS() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sas
}

// LastBootCode returns the code the machine's screen shows for the running
// (or last) attestation, as "ABCD-EFGH", or "" when its TPM refused the boot
// key. The phone must show the same.
func (d *DemoMachine) LastBootCode() string {
	code := d.m.TPM.ShownCode()
	if code == "" {
		return ""
	}
	return attest.FormatBootCode(code)
}

// RefuseBootKey makes the machine's TPM refuse the boot key from now on, as
// it does in a boot state its signing key has not approved.
func (d *DemoMachine) RefuseBootKey(refuse bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.m.TPM.BootRefuse = refuse
}

// ChangePCR simulates a boot-chain change (e.g. 4 = bootloader update,
// 7 = Secure Boot policy). The next attestation's verdict is "changed".
func (d *DemoMachine) ChangePCR(index int) {
	if index >= 0 && index < attest.MaxPCRIndex {
		d.m.TPM.Extend(uint8(index), "kiratest change")
	}
}

// SetInitrd boots the demo machine so that its event log shows the initrd: "uki", "grub"
// or "no_log"; and quotes the registers that hold them, as a machine of that boot does.
func (d *DemoMachine) SetInitrd(boot string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.m.TPM.SetInitrd(boot)
	pcrs := []int{0, 2, 4, 7}
	switch boot {
	case attesttest.InitrdUKI:
		pcrs = []int{0, 2, 4, 7, 11}
	case attesttest.InitrdGRUB:
		pcrs = []int{0, 2, 4, 7, 8, 9}
	}
	sel, err := attest.NewPCRSelection(attest.AlgSHA256, pcrs)
	if err != nil {
		return err
	}
	d.m.Sel = sel
	return nil
}

// SetSecureBoot boots the demo machine's firmware in a state: "on", "off" or
// "setup_mode" (attest.SecureBootOn and the others); "no_log" keeps PCR 7 and takes the
// events away, and "lying" keeps PCR 7 of its state and shows the events of "on"
// beside a value they do not replay to: neither is established.
func (d *DemoMachine) SetSecureBoot(state string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch state {
	case "no_log":
		d.m.TPM.PCR7Chain = nil
	case "lying":
		d.m.TPM.SetSecureBoot(attest.SecureBootOff)
		d.m.TPM.PCR7Chain = attesttest.SecureBootChain(attest.AlgSHA256, attest.SecureBootOn)
	default:
		d.m.TPM.SetSecureBoot(state)
	}
}

// NextBoot simulates a reboot (the TPM reset counter advances).
func (d *DemoMachine) NextBoot() { d.m.TPM.ResetCount++ }

// RollbackResetCount simulates a replayed or cleared TPM: the next verdict
// is "failed" with reset_count_decreased.
func (d *DemoMachine) RollbackResetCount() {
	if d.m.TPM.ResetCount > 0 {
		d.m.TPM.ResetCount = 0
	}
}

// ServiceData returns the 13-byte scan-response service data this machine
// would advertise in attestation mode, for testing MatchAdvertisement.
func (d *DemoMachine) ServiceData() []byte {
	return attest.BuildServiceData(attest.AdvFlagAttest, []byte{0x10, 0x20, 0x30, 0x40}, d.m.AdvKey)
}
