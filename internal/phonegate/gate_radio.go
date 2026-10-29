package phonegate

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/core/transport/ble"
	"github.com/mrwiora/tpm2-kira/core/transport/frame"
	"github.com/mrwiora/tpm2-kira/internal/journal"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// GateOptions configures `phone gate`.
type GateOptions struct {
	TPMPath     string
	SignerPath  string        // the signing public key in the initramfs; "" = DefaultAttestSignerPath
	SealIndex   uint32        // 0 = first enrolled slot
	Adapter     int           // hciN, or ble.AnyAdapter: the first that comes up
	Timeout     time.Duration // 0 = wait forever
	AdapterWait time.Duration // how long to wait for the adapter to appear; the code screen's end stops it earlier
	Debug       bool
	// Worker: the radio worker of a coordinator (gate_child.go), not one
	// process that holds the TPM itself.
	Worker bool
	// RFKill is /dev/rfkill, opened by whoever may: the worker cannot open
	// it. Nil: opened when a soft block is to be cleared.
	RFKill *os.File
}

// AttestGate is 'tpm2-kira phone gate': one process that holds the TPM
// and serves attestation requests until a phone returns a receipt, and
// reports the outcome as an exit code. At boot the gate is two processes
// instead (gate_child.go).
//
// The receipt is checked against the anchor in the attestation blob. In the
// initrd that blob cannot be authenticated (the signing key is not there), so
// on this machine the verdict line is advisory; the authoritative display is
// the phone's (PLAN-PHONE.md §10.2).
func AttestGate(o GateOptions) int {
	journal.NarrateDebug = o.Debug
	step := GateSteps(o.Debug)
	tpmPath := tpmdev.PreferResourceManager(o.TPMPath)
	step("version %s; opening the TPM at %s", nvslot.AppVersion, tpmPath)
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		GateFail("failed to open TPM at %s: %v", tpmPath, err)
		return ExitInternal
	}
	defer tpmDev.Close()
	defer tpmdev.Cleanup(tpmDev, o.Debug)
	return RunGateRadio(NewGateService(tpmDev, o.SealIndex, o.SignerPath, o.Debug), o, step, nil)
}

// runGateRadio is the radio half of the gate: advertise, serve the phone,
// print what it said. The TPM half is behind host; when ended is closed,
// that half is gone (the code screen has released the boot) and the radio
// stops.
func RunGateRadio(host GateHost, o GateOptions, step func(string, ...any), ended <-chan struct{}) int {
	ident, code, err := host.Identity()
	if code != 0 || err != nil {
		if code == 0 {
			code = ExitInternal
		}
		// A refused record was reported in full by whoever checked it.
		if code != ExitTampered || o.Worker {
			GateFail("%v", err)
		}
		return code
	}
	step("serving slot %d (record verified: %v), %d phone(s) enrolled", ident.Slot, ident.RecordVerified, len(ident.Verifiers))
	noise, err := attest.NoiseKeypairFromPrivate(ident.NoisePrivate)
	if err != nil {
		GateFail("%v", err)
		return ExitInternal
	}
	id := &attest.AttestIdentity{
		DeviceID:     ident.DeviceID,
		AKName:       ident.AKName,
		NoiseStatic:  noise,
		AppVersion:   nvslot.AppVersion,
		Capabilities: attest.CapEventlog,
	}
	for _, v := range ident.Verifiers {
		// No anchors here: the receipt is judged by the host.
		id.Verifiers = append(id.Verifiers, attest.EnrolledVerifier{ID: v.ID, NoisePub: v.NoisePub})
	}

	if o.Adapter == ble.AnyAdapter {
		step("waiting for the Bluetooth adapter (as long as the code screen holds)")
	} else {
		step("opening hci%d (waiting up to %s for it)", o.Adapter, o.AdapterWait)
	}
	p, err := ble.Open(ble.Config{Adapter: o.Adapter, UnblockRFKill: true, RFKill: o.RFKill, Wait: o.AdapterWait, Cancel: ended, Logf: DebugLogf(o.Debug)})
	if err != nil {
		GateFail("%v", err)
		host.Report(GateUnavailable)
		return ExitUnavailable
	}
	var closeOnce sync.Once
	closeRadio := func() { closeOnce.Do(func() { p.Close() }) }
	defer closeRadio()
	over := make(chan struct{})
	if ended != nil {
		finished := make(chan struct{})
		defer close(finished)
		go func() {
			select {
			case <-ended:
				close(over)
				closeRadio() // ends a pending wait for a phone
			case <-finished:
			}
		}()
	}
	isOver := func() bool {
		select {
		case <-over:
			return true
		default:
			return false
		}
	}
	step("hci%d is ready; advertising from here on (timeout %s, 0 = as long as the code screen is up)", o.Adapter, o.Timeout)

	adv := ble.Advertisement{
		ServiceData: attest.BuildServiceData(attest.AdvFlagAttest, RandBytes(4), ident.AdvKey),
		Info:        AttestInfo(InfoModeAttest, id.Capabilities),
	}
	journal.Narrate("tpm2-kira: waiting for attestation of %q (open the app on your phone)", ident.FriendlyName)
	host.Report(GateWaiting)

	res, err := WaitForReceipt(p, adv, o.Timeout, func(conn *frame.Conn) (*attest.AttestResult, error) {
		host.Report(GateSession)
		res, err := attest.ServeAttestation(conn, id, host, debugProgress(o.Debug))
		if svc, ok := host.(*GateService); ok {
			// No code screen next to a gate run by hand: say it here.
			if st, _ := svc.Status(); st.Code != "" {
				fmt.Printf("tpm2-kira: code for your phone: %s (the phone must show the same)\n", st.Code)
			}
		}
		if res == nil || res.Receipt == nil {
			host.Report(GateWaiting) // the gate advertises again
		} else {
			host.Report(GateSessionOver) // nothing more comes: no release to wait for
		}
		return res, err
	}, journal.Narrator{Prio: journal.PrioInfo}, time.Now)
	if errors.Is(err, ErrNoPhoneReachable) {
		GateFail("phone not reachable: no phone connected over Bluetooth within %s.\n"+
			"tpm2-kira:   This is not a TPM or boot-integrity failure. Check that the phone\n"+
			"tpm2-kira:   is close to this machine, Bluetooth is on and the Marify app is open.", o.Timeout)
		host.Report(GateUnavailable)
		return ExitUnavailable
	}
	if err != nil && isOver() {
		// The phone check lasts as long as the code screen.
		journal.Narrate("tpm2-kira: the code screen has ended; the phone was not asked in time for this boot")
		return ExitUnavailable
	}
	if err != nil {
		GateFail("%v", err)
		host.Report(GateUnavailable)
		return ExitUnavailable
	}
	return reportReceipt(res, ident.RecordVerified)
}

// gateSteps returns the gate's step log for debug runs: one line per step
// with the time since the gate started, so that a boot where the phone was
// never asked shows how far the gate got and where the time went.
func GateSteps(debug bool) func(string, ...any) {
	if !debug {
		return func(string, ...any) {}
	}
	start := time.Now()
	return func(format string, args ...any) {
		journal.NarrateAt(journal.PrioDebug, "tpm2-kira: gate +%.1fs: "+format, append([]any{time.Since(start).Seconds()}, args...)...)
	}
}

// attestInfo is the INFO characteristic: u8 protocol ‖ u8 mode ‖ u16le schema ‖ u32le capabilities.
func AttestInfo(mode uint8, caps uint32) []byte {
	b := []byte{1, mode, byte(attest.SchemaVersion), byte(attest.SchemaVersion >> 8), 0, 0, 0, 0}
	b[4], b[5], b[6], b[7] = byte(caps), byte(caps>>8), byte(caps>>16), byte(caps>>24)
	return b
}

const (
	InfoModeAttest = 2
)

func RandBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func DebugLogf(debug bool) func(string, ...any) {
	if !debug {
		return nil
	}
	return func(format string, args ...any) {
		journal.NarrateAt(journal.PrioDebug, "ble: %s "+format, append([]any{time.Now().Format("15:04:05.000")}, args...)...)
	}
}

// errNoPhoneReachable means no phone connected at all before the timeout,
// as opposed to a phone that connected and then failed.
var ErrNoPhoneReachable = errors.New("no phone reachable")

// waitForReceipt advertises in rounds of gateRetryInterval until a phone
// returns a receipt, reporting every round in which no phone was reachable.
// With timeout > 0 it gives up with errNoPhoneReachable. A session that ends
// without a receipt (a stranger's phone, a dropped link, a cancelled
// session) is reported and the wait goes on: one bad connection must not end
// it.
func WaitForReceipt(acc phoneAcceptor, adv ble.Advertisement, timeout time.Duration,
	serve func(*frame.Conn) (*attest.AttestResult, error), out io.Writer, now func() time.Time) (*attest.AttestResult, error) {
	start := now()
	for attempt := 1; ; attempt++ {
		wait := gateRetryInterval
		if timeout > 0 {
			left := timeout - now().Sub(start)
			if left <= 0 {
				return nil, ErrNoPhoneReachable
			}
			if left < wait {
				wait = left
			}
		}
		conn, err := acc.Accept(adv, frame.DefaultBudget, wait)
		if errors.Is(err, ble.ErrAcceptTimeout) {
			if attempt == 1 {
				fmt.Fprintln(out, "tpm2-kira: no phone reachable yet: nothing has connected over Bluetooth.")
				fmt.Fprintln(out, "tpm2-kira:   Open Marify on your phone, close to this machine, with Bluetooth on.")
			}
			if timeout <= 0 || now().Sub(start) < timeout {
				fmt.Fprintf(out, "tpm2-kira: phone not reachable yet (round %d), still waiting ...\n", attempt)
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		res, err := serve(conn)
		conn.Close()
		if res == nil || res.Receipt == nil {
			if err == nil {
				err = errors.New("no receipt")
			}
			fmt.Fprintf(out, "tpm2-kira: a phone connected, but the session ended without a receipt (%v); waiting again ...\n", err)
			continue
		}
		return res, nil
	}
}

func debugProgress(debug bool) attest.Progress {
	if !debug {
		return nil
	}
	return func(_ attest.ProgressLevel, format string, args ...any) {
		journal.NarrateAt(journal.PrioDebug, "tpm2-kira: "+format, args...)
	}
}

func reportReceipt(res *attest.AttestResult, recordVerified bool) int {
	// Even a verified record is only as good as the initramfs holding the
	// key it was verified with (SECURITY.md); the phone's screen is the verdict.
	if recordVerified {
		defer journal.Narrate("tpm2-kira:   (enrolment record verified: signed by this machine's key and current; your phone's screen is authoritative)")
	} else {
		defer journal.Narrate("tpm2-kira:   (not verified on this machine: your phone's screen is authoritative)")
	}
	who := "your phone"
	c := res.Check
	switch {
	case c.Authentic && c.Verdict == attest.VerdictOK:
		journal.Narrate("tpm2-kira: ATTESTED by %s: boot state matches a known-good profile", who)
		return ExitAttested
	case c.Authentic && c.Verdict == attest.VerdictApproved:
		journal.Narrate("tpm2-kira: APPROVED on %s: boot state changed and was approved by you", who)
		return ExitAttested
	case c.Verdict == attest.VerdictReject && (c.Authentic || c.Ack == attest.AckRejectNoted):
		fmt.Fprintf(os.Stderr, "tpm2-kira: REJECTED by %s: the phone does not trust this boot.\n", who)
		fmt.Fprintln(os.Stderr, "tpm2-kira: Do not type a passphrase before checking further (compare the TOTP code).")
		return ExitRejected
	case c.Ack == attest.AckBadSignature:
		fmt.Fprintf(os.Stderr, "tpm2-kira: ANCHOR MISMATCH: the receipt was not signed by the enrolled phone (%s).\n", c.Detail)
		fmt.Fprintln(os.Stderr, "tpm2-kira: This is either a wrong phone or an attack.")
		return ExitAnchor
	default:
		fmt.Fprintf(os.Stderr, "tpm2-kira: receipt not accepted: %s\n", c.Detail)
		return ExitInternal
	}
}

// gateRetryInterval is one advertising round of the gate: when no phone has
// connected within it, the gate says so and starts the next round. A phone
// can connect at any moment of a round; the length only sets how often the
// console is told (and advertising briefly restarts).
const gateRetryInterval = 30 * time.Second

// phoneAcceptor is the part of ble.Peripheral the gate waits on.
type phoneAcceptor interface {
	Accept(adv ble.Advertisement, budget frame.Budget, timeout time.Duration) (*frame.Conn, error)
}

// GateAdapterWait is how long the gate waits for its adapter: a bound for
// a gate without a code screen; in the image the screen's end stops the
// wait earlier (runGateRadio's ended).
const GateAdapterWait = 10 * time.Minute
