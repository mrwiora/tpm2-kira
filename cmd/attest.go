package cmd

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/matthias/tpm2-kira/attest"
	"github.com/matthias/tpm2-kira/transport/ble"
	"github.com/matthias/tpm2-kira/transport/frame"
)

// Remote attestation commands (PLAN-REMOTEATTESTATION.md §12, PLAN-BLE.md).
//
// Attestation stands on its own: the phone verifies the boot and returns a
// signed verdict, which the console shows. Releasing a factor (the hashpwd2
// salt, PLAN-FACTORRELEASE.md) is an optional step on top of a trusted
// receipt in the same session; this version of the attester answers such a
// request with "unsupported".

// Exit codes of the commands that do not follow the exit-0 rule
// (PLAN-REMOTEATTESTATION.md §12.1). They match PLAN-FACTORRELEASE.md §5.2.
const (
	ExitAttested    = 0 // a trusted receipt arrived and verified
	ExitInternal    = 1 // internal error
	ExitUsage       = 2 // usage error
	ExitUnavailable = 3 // no adapter, timeout, nobody in range
	ExitRejected    = 4 // the verifier rejected the attestation
	ExitAnchor      = 5 // receipt not signed by the enrolled phone
	ExitTampered    = 6 // attest check: the attestation blob was replaced or changed
)

// AttestInfo is the INFO characteristic: u8 protocol ‖ u8 mode ‖ u16le schema ‖ u32le capabilities.
func attestInfo(mode uint8, caps uint32) []byte {
	b := []byte{1, mode, byte(attest.SchemaVersion), byte(attest.SchemaVersion >> 8), 0, 0, 0, 0}
	b[4], b[5], b[6], b[7] = byte(caps), byte(caps>>8), byte(caps>>16), byte(caps>>24)
	return b
}

// INFO modes.
const (
	infoModeEnrol  = 1
	infoModeAttest = 2
)

func loadAttestBlob(tpmDev transport.TPM, idx uint32) (*AttestBlob, error) {
	data, err := ReadFromNVRAM(tpmDev, idx)
	if err != nil {
		return nil, err
	}
	return UnmarshalAttestBlob(data)
}

// writeAttestBlob signs and stores the blob with PolicySigned NV writes.
func writeAttestBlob(tpmDev transport.TPM, idx uint32, b *AttestBlob, priv crypto.Signer) error {
	unsigned, err := b.Marshal()
	if err != nil {
		return err
	}
	signed, err := SignBlobPayload(unsigned, priv)
	if err != nil {
		return err
	}
	return WriteToNVRAM(tpmDev, idx, signed, priv.Public(), priv)
}

// parseAttestPCRs reads a PCR list for quoting. Quotes always cover the
// live registers, so source suffixes from seal syntax are accepted and ignored.
// checkSamePCRs refuses a --pcrs that differs from an existing blob's
// selection. Further phones share the blob and its selection, so the option
// would otherwise be ignored without a word.
func checkSamePCRs(blob *AttestBlob, pcrs string, slot uint32) error {
	have, err := blob.Selection()
	if err != nil {
		return err
	}
	want, err := parseAttestPCRs(pcrs, have.Alg)
	if err != nil {
		return err
	}
	w, h := slices.Clone(want.Indices), slices.Clone(have.Indices)
	slices.Sort(w)
	slices.Sort(h)
	if slices.Equal(w, h) {
		return nil
	}
	return fmt.Errorf("slot %d is already enrolled with PCRs %s; --pcrs %s would be ignored.\n"+
		"Every phone enrolled on this machine checks the same PCRs. To change them, run\n"+
		"'tpm2-kira attest unenrol' (enrolled phones must then be enrolled again), or\n"+
		"enrol without --pcrs to keep %s", slot, have, pcrs, have)
}

func parseAttestPCRs(s string, alg uint16) (attest.PCRSelection, error) {
	var idx []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if i := strings.IndexFunc(f, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
			f = f[:i]
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			return attest.PCRSelection{}, fmt.Errorf("invalid PCR index %q", f)
		}
		idx = append(idx, n)
	}
	return attest.NewPCRSelection(alg, idx)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func readSealedSlot(tpmDev transport.TPM, sealIndex uint32) *SealedBlob {
	data, err := ReadFromNVRAM(tpmDev, sealIndex)
	if err != nil {
		return nil
	}
	sb, err := UnmarshalSealedBlob(data)
	if err != nil {
		return nil
	}
	return sb
}

// EnrolOptions configures `attest enrol`.
type EnrolOptions struct {
	TPMPath     string
	SealIndex   uint32
	Name        string
	PCRs        string
	Adapter     int
	PrivKeyPath string
	Timeout     time.Duration
	Debug       bool
	In          io.Reader // console input for the confirmation; default stdin
	// VerifyTPM / VerifyPhone: what to do when this machine's TPM, or the
	// phone's key, cannot be verified as genuine hardware (default warn).
	VerifyTPM   HWCheckPolicy
	VerifyPhone HWCheckPolicy
}

// AttestEnrol binds a phone to this machine over BLE. It runs on the booted,
// unlocked system: it writes NVRAM and needs the signing key, like `seal`.
func AttestEnrol(o EnrolOptions) error {
	tpmDev, err := transport.OpenTPM(o.TPMPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", o.TPMPath, err)
	}
	defer tpmDev.Close()
	defer CleanupTPM(tpmDev, o.Debug)

	sealIndex := ResolveNVRAMIndex(o.SealIndex)
	idx, err := AttestIndexForSlot(sealIndex)
	if err != nil {
		return err
	}
	sealed := readSealedSlot(tpmDev, sealIndex)

	// The signing key is needed to write the blob at the end; find out now,
	// before the radio is taken and a human has compared codes.
	// --privkey or the default key; a path recorded in a blob is never
	// used to find a key (a tampered blob could point anywhere).
	privPath := o.PrivKeyPath
	if privPath == "" {
		privPath = DefaultPrivateKeyPath
	}
	priv, err := LoadCheckedSigningPrivateKey(privPath)
	if err != nil {
		return fmt.Errorf("enrolment needs the signing key to write the attestation blob: %w", err)
	}

	blob, err := loadAttestBlob(tpmDev, idx)
	if err != nil {
		blob = nil
	}
	if blob != nil {
		raw, _ := ReadFromNVRAM(tpmDev, idx)
		if err := verifyBeforeExtending(raw, priv.Public(), idx-AttestNVRAMStart); err != nil {
			return err
		}
	}
	if blob != nil && o.PCRs != "" {
		if err := checkSamePCRs(blob, o.PCRs, idx-AttestNVRAMStart); err != nil {
			return err
		}
	}

	if blob == nil {
		alg := attest.AlgSHA256
		pcrs := o.PCRs
		if sealed != nil {
			if sealed.GetHashAlgo() == PCRHashAlgoSHA1 {
				alg = attest.AlgSHA1
			}
			if pcrs == "" {
				var parts []string
				for _, i := range sealed.GetPCRIndices() {
					parts = append(parts, strconv.Itoa(i))
				}
				pcrs = strings.Join(parts, ",")
			}
		}
		if pcrs == "" {
			pcrs = "0,2,4,7"
		}
		sel, err := parseAttestPCRs(pcrs, alg)
		if err != nil {
			return err
		}
		fmt.Println("Creating an attestation key in the TPM ...")
		akPub, akPriv, akName, err := CreateAK(tpmDev)
		if err != nil {
			return err
		}
		noise, err := attest.GenerateNoiseKeypair(nil)
		if err != nil {
			return err
		}
		name := o.Name
		if name == "" {
			name, _ = os.Hostname()
		}
		if len(name) > 64 {
			name = name[:64]
		}
		blob = &AttestBlob{
			DeviceID:     randBytes(attest.DeviceIDSize),
			FriendlyName: name,
			AKPublic:     akPub,
			AKPrivate:    akPriv,
			AKName:       akName,
			NoisePrivate: noise.Private,
			AdvKey:       randBytes(32),
			PCRAlg:       sel.Alg,
			PCRSelection: sel.Indices,
		}
	} else if o.Name != "" {
		blob.FriendlyName = o.Name
	}
	blob.AppVersion = AppVersion
	if blob.AppVersion == "" {
		blob.AppVersion = "unknown"
	}
	sel, err := blob.Selection()
	if err != nil {
		return err
	}
	noise, err := attest.NoiseKeypairFromPrivate(blob.NoisePrivate)
	if err != nil {
		return err
	}

	fmt.Println("=== tpm2-kira attest enrol ===")
	fmt.Printf("Machine:       %s (slot %d)\n", blob.FriendlyName, SlotNumber(sealIndex))
	fmt.Printf("PCRs quoted:   %s\n", sel)
	mp := predictMeasurePoint(tpmDev, sealed, sel, o.Debug)
	printMeasurePoint(mp, sel)
	fmt.Printf("Adapter:       hci%d\n", o.Adapter)
	fmt.Println()
	fmt.Println("NOTE: the adapter is taken over exclusively while enrolling. Bluetooth")
	fmt.Println("      mice, keyboards and headsets on it disconnect until this finishes.")
	fmt.Println("      Use --adapter N to enrol over a second adapter instead.")
	fmt.Println()

	in := o.In
	if in == nil {
		in = os.Stdin
	}
	console := bufio.NewReader(in)
	ok, err := confirmInitrdCoverage(console, sel, DefaultEventlogPath)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("enrolment cancelled: choose PCRs that cover the initrd with --pcrs")
	}
	if ok, err := checkOwnTPM(tpmDev, o.VerifyTPM, console, os.Stdout); err != nil {
		return err
	} else if !ok {
		return errors.New("enrolment cancelled: this machine's TPM is not verified as genuine (--verify-tpm)")
	}
	fmt.Println()

	p, err := ble.Open(ble.Config{Adapter: o.Adapter, Logf: debugLogf(o.Debug)})
	if err != nil {
		return err
	}
	defer p.Close()
	be := &tpmBackend{
		tpm:       tpmDev,
		blob:      blob,
		sealIndex: sealIndex,
		sealed:    sealed,
		debug:     o.Debug,
		mp:        mp,
		confirmSAS: func(code string) (bool, error) {
			return confirmCode(console, code)
		},
	}
	be.commit = func(v attest.EnrolledVerifier) error {
		if err := blob.UpsertVerifier(v); err != nil {
			return err
		}
		return writeAttestBlob(tpmDev, idx, blob, priv)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	be.phoneJudge = &phoneJudge{
		policy: o.VerifyPhone, console: console, out: os.Stdout,
		revoked: func() (map[string]string, error) { return revokedSerials(client) },
	}

	id := &attest.EnrolIdentity{
		DeviceID:     blob.DeviceID,
		FriendlyName: blob.FriendlyName,
		AKPub:        blob.AKPublic,
		AKName:       blob.AKName,
		NoiseStatic:  noise,
		AdvKey:       blob.AdvKey,
		Selection:    sel,
		AppVersion:   blob.AppVersion,
		Slot:         uint8(SlotNumber(sealIndex)),
	}
	adv := ble.Advertisement{
		ServiceData: attest.BuildServiceData(attest.AdvFlagEnrol, randBytes(4), nil),
		Info:        attestInfo(infoModeEnrol, 0),
	}
	budget := frame.Budget{MaxRecord: frame.MaxRecord, MaxBytes: 1 << 20, Deadline: 5 * time.Minute}

	deadline := time.Now().Add(o.Timeout)
	for {
		remaining := time.Until(deadline)
		if o.Timeout <= 0 {
			remaining = 0
		} else if remaining <= 0 {
			return errors.New("no phone completed enrolment in time")
		}
		fmt.Println("Advertising:   open the app and choose \"Enrol a machine\" ...")
		conn, err := p.Accept(adv, budget, remaining)
		if err != nil {
			return err
		}
		fmt.Println("Connected:     a phone (anonymous until the session is confirmed)")
		v, err := attest.ServeEnrolment(conn, id, be, progressf)
		conn.Close()
		if err != nil {
			var em *attest.ErrorMsg
			if errors.As(err, &em) || strings.Contains(err.Error(), "rejected") {
				return fmt.Errorf("enrolment aborted: %w", err)
			}
			fmt.Printf("Session failed: %v\nWaiting for another attempt ...\n\n", err)
			continue
		}
		fmt.Println()
		fmt.Printf("Enrolled:      %s (verifier id %s)\n", verifierName(v), v.ID)
		fmt.Printf("Stored:        attestation blob at NV 0x%08X\n", idx)
		if raw, err := ReadFromNVRAM(tpmDev, idx); err == nil {
			if err := recordAttestState(DefaultAttestStateDir, idx, raw); err != nil {
				fmt.Printf("Warning:       could not record the blob for 'attest check': %v\n", err)
			}
		}
		fmt.Println()
		fmt.Println("The phone can now attest this machine at boot. To serve attestation")
		fmt.Println("requests at the passphrase prompt, enable the gate in lazy mode:")
		fmt.Println("    echo 'TPM2_KIRA_ATTEST=lazy' | sudo tee /etc/tpm2-kira/attest.conf")
		fmt.Println("and rebuild the initramfs (the Bluetooth hook must find your adapter).")
		return nil
	}
}

func verifierName(v *attest.EnrolledVerifier) string {
	if v.Name != "" {
		return v.Name
	}
	return "phone"
}

func progressf(format string, args ...any) {
	fmt.Printf("               "+format+"\n", args...)
}

func debugLogf(debug bool) func(string, ...any) {
	if !debug {
		return nil
	}
	return func(format string, args ...any) {
		fmt.Printf("ble: %s "+format+"\n", append([]any{time.Now().Format("15:04:05.000")}, args...)...)
	}
}

// confirmCode shows the short authentication string and asks the person at
// the console to compare it with the phone.
func confirmCode(in *bufio.Reader, code string) (bool, error) {
	spaced := strings.Join(strings.Split(code, ""), " ")
	fmt.Println()
	fmt.Println("    Confirm this number matches the one shown in the app:")
	fmt.Println()
	fmt.Printf("                        %s\n", spaced)
	fmt.Println()
	for {
		fmt.Print("    [y] it matches   [n] it does not — abort: ")
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return false, fmt.Errorf("no answer on the console: %w", err)
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
	}
}

// GateOptions configures `attest gate`.
type GateOptions struct {
	TPMPath     string
	SealIndex   uint32 // 0 = first enrolled slot
	Adapter     int
	Timeout     time.Duration // 0 = wait forever
	AdapterWait time.Duration // how long to wait for the adapter to appear
	Debug       bool
}

// AttestGate serves attestation requests until a phone returns a receipt,
// and reports the outcome as an exit code. In lazy mode the unit that runs
// it does not hold the boot: the result is shown, and the passphrase prompt
// appears regardless.
//
// The receipt is checked against the anchor in the attestation blob. In the
// initrd that blob cannot be authenticated (the signing key is not there), so
// on this machine the verdict line is advisory; the authoritative display is
// the phone's. An image-pinned anchor comes with enforced mode
// (PLAN-REMOTEATTESTATION.md §10.2).
func AttestGate(o GateOptions) int {
	tpmPath := preferResourceManager(o.TPMPath)
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		gateFail("failed to open TPM at %s: %v", tpmPath, err)
		return ExitInternal
	}
	defer tpmDev.Close()
	defer CleanupTPM(tpmDev, o.Debug)

	var idx uint32
	if o.SealIndex != 0 {
		if idx, err = AttestIndexForSlot(o.SealIndex); err != nil {
			gateFail("%v", err)
			return ExitUsage
		}
	} else {
		found := FindPopulatedSlotsInRange(tpmDev, AttestNVRAMStart, AttestNVRAMEnd, o.Debug)
		if len(found) == 0 {
			gateFail("no slot is enrolled for attestation (run 'tpm2-kira attest enrol')")
			return ExitUsage
		}
		idx = found[0]
	}
	blob, err := loadAttestBlob(tpmDev, idx)
	if err != nil {
		gateFail("cannot read the attestation blob at 0x%08X: %v", idx, err)
		return ExitInternal
	}
	if len(blob.Verifiers) == 0 {
		gateFail("no phone is enrolled for slot %d", idx-AttestNVRAMStart)
		return ExitUsage
	}
	noise, err := attest.NoiseKeypairFromPrivate(blob.NoisePrivate)
	if err != nil {
		gateFail("%v", err)
		return ExitInternal
	}
	sealIndex := NVRAMSlotStart + (idx - AttestNVRAMStart)
	be := &tpmBackend{tpm: tpmDev, blob: blob, sealIndex: sealIndex, sealed: readSealedSlot(tpmDev, sealIndex), debug: o.Debug}
	id := &attest.AttestIdentity{
		DeviceID:     blob.DeviceID,
		AKName:       blob.AKName,
		NoiseStatic:  noise,
		Verifiers:    blob.Verifiers,
		AppVersion:   AppVersion,
		Capabilities: attest.CapEventlog,
	}

	p, err := ble.Open(ble.Config{Adapter: o.Adapter, UnblockRFKill: true, Wait: o.AdapterWait, Logf: debugLogf(o.Debug)})
	if err != nil {
		gateFail("%v", err)
		return ExitUnavailable
	}
	defer p.Close()

	adv := ble.Advertisement{
		ServiceData: attest.BuildServiceData(attest.AdvFlagAttest, randBytes(4), blob.AdvKey),
		Info:        attestInfo(infoModeAttest, id.Capabilities),
	}
	fmt.Printf("tpm2-kira: waiting for attestation of %q (open the app on your phone)\n", blob.FriendlyName)

	res, err := waitForReceipt(p, adv, o.Timeout, func(conn *frame.Conn) (*attest.AttestResult, error) {
		return attest.ServeAttestation(conn, id, be, debugProgress(o.Debug))
	}, os.Stdout, time.Now)
	if errors.Is(err, errNoPhoneReachable) {
		gateFail("phone not reachable: no phone connected over Bluetooth within %s.\n"+
			"tpm2-kira:   This is not a TPM or boot-integrity failure. Check that the phone\n"+
			"tpm2-kira:   is close to this machine, Bluetooth is on and the Kira app is open.", o.Timeout)
		return ExitUnavailable
	}
	if err != nil {
		gateFail("%v", err)
		return ExitUnavailable
	}
	return reportReceipt(blob, res)
}

// gateRetryInterval is one advertising round of the gate: when no phone has
// connected within it, the gate says so and starts the next round. A phone
// can connect at any moment of a round; the length only sets how often the
// console is told (and advertising briefly restarts).
const gateRetryInterval = 30 * time.Second

// errNoPhoneReachable means no phone connected at all before the timeout,
// as opposed to a phone that connected and then failed.
var errNoPhoneReachable = errors.New("no phone reachable")

// phoneAcceptor is the part of ble.Peripheral the gate waits on.
type phoneAcceptor interface {
	Accept(adv ble.Advertisement, budget frame.Budget, timeout time.Duration) (*frame.Conn, error)
}

// waitForReceipt advertises in rounds of gateRetryInterval until a phone
// returns a receipt, reporting every round in which no phone was reachable.
// With timeout > 0 it gives up with errNoPhoneReachable. A session that ends
// without a receipt (a stranger's phone, a dropped link, a cancelled
// session) is reported and the wait goes on: one bad connection must not end
// it.
func waitForReceipt(acc phoneAcceptor, adv ble.Advertisement, timeout time.Duration,
	serve func(*frame.Conn) (*attest.AttestResult, error), out io.Writer, now func() time.Time) (*attest.AttestResult, error) {
	start := now()
	for attempt := 1; ; attempt++ {
		wait := gateRetryInterval
		if timeout > 0 {
			left := timeout - now().Sub(start)
			if left <= 0 {
				return nil, errNoPhoneReachable
			}
			if left < wait {
				wait = left
			}
		}
		conn, err := acc.Accept(adv, frame.DefaultBudget, wait)
		if errors.Is(err, ble.ErrAcceptTimeout) {
			if attempt == 1 {
				fmt.Fprintln(out, "tpm2-kira: no phone reachable yet: nothing has connected over Bluetooth.")
				fmt.Fprintln(out, "tpm2-kira:   Open Kira on your phone, close to this machine, with Bluetooth on.")
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
	return func(format string, args ...any) { fmt.Printf("tpm2-kira: "+format+"\n", args...) }
}

func gateFail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "tpm2-kira: FAILED: "+format+"\n", args...)
}

func reportReceipt(blob *AttestBlob, res *attest.AttestResult) int {
	// The initrd cannot authenticate the blob that names the phone (SECURITY.md).
	defer fmt.Println("tpm2-kira:   (not verified on this machine: your phone's screen is authoritative)")
	who := verifierName(res.Verifier)
	c := res.Check
	switch {
	case c.Authentic && c.Verdict == attest.VerdictOK:
		fmt.Printf("tpm2-kira: ATTESTED by %s: boot state matches a known-good profile\n", who)
		return ExitAttested
	case c.Authentic && c.Verdict == attest.VerdictApproved:
		fmt.Printf("tpm2-kira: APPROVED on %s: boot state changed and was approved by you\n", who)
		return ExitAttested
	case c.Verdict == attest.VerdictReject && (c.Authentic || c.Ack == attest.AckRejectNoted):
		fmt.Printf("tpm2-kira: REJECTED by %s: the phone does not trust this boot.\n", who)
		fmt.Println("tpm2-kira: Do not type a passphrase before checking further (compare the TOTP code).")
		return ExitRejected
	case c.Ack == attest.AckBadSignature:
		fmt.Printf("tpm2-kira: ANCHOR MISMATCH: the receipt was not signed by the enrolled phone (%s).\n", c.Detail)
		fmt.Println("tpm2-kira: This is either a wrong phone or an attack.")
		return ExitAnchor
	default:
		fmt.Printf("tpm2-kira: receipt not accepted: %s\n", c.Detail)
		return ExitInternal
	}
}

// AttestStatus shows the enrolment of one slot or all slots.
func AttestStatus(tpmPath string, sealIndex uint32, jsonOut bool, debug bool) error {
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	var indices []uint32
	if sealIndex != 0 {
		idx, err := AttestIndexForSlot(sealIndex)
		if err != nil {
			return err
		}
		indices = []uint32{idx}
	} else {
		indices = FindPopulatedSlotsInRange(tpmDev, AttestNVRAMStart, AttestNVRAMEnd, debug)
	}
	type verifierJSON struct {
		ID           string `json:"id"`
		Name         string `json:"name,omitempty"`
		PolicyID     string `json:"policy_id,omitempty"`
		AnchorDigest string `json:"anchor_digest"`
	}
	type slotJSON struct {
		Slot         int            `json:"slot_number"`
		NVRAMIndex   string         `json:"nvram_index"`
		DeviceID     string         `json:"device_id"`
		FriendlyName string         `json:"friendly_name"`
		AKName       string         `json:"ak_name"`
		EKAlg        string         `json:"ek_alg"`
		PCRSelection string         `json:"pcr_selection"`
		AppVersion   string         `json:"app_version"`
		Signature    string         `json:"blob_signature"` // valid | invalid | unchecked
		SigningKey   string         `json:"signing_key,omitempty"`
		Verifiers    []verifierJSON `json:"verifiers"`
	}
	invalid := 0
	var out []slotJSON
	for _, idx := range indices {
		b, err := loadAttestBlob(tpmDev, idx)
		if err != nil {
			if sealIndex != 0 {
				return fmt.Errorf("slot is not enrolled for attestation: %w", err)
			}
			continue
		}
		sel, _ := b.Selection()
		s := slotJSON{
			Slot:         int(idx - AttestNVRAMStart),
			NVRAMIndex:   fmt.Sprintf("0x%08X", idx),
			DeviceID:     hex.EncodeToString(b.DeviceID),
			FriendlyName: b.FriendlyName,
			AKName:       hex.EncodeToString(b.AKName),
			EKAlg:        ekAlgName(b.EKAlg),
			PCRSelection: sel.String(),
			AppVersion:   b.AppVersion,
			Signature:    "unchecked",
		}
		if raw, err := ReadFromNVRAM(tpmDev, idx); err == nil {
			if pub, path, err := attestPublicKey(tpmDev, idx, ""); err == nil {
				s.SigningKey = path
				if VerifyAttestBlobSignature(raw, pub) == nil {
					s.Signature = "valid"
				} else {
					s.Signature = "invalid"
					invalid++
				}
			}
		}
		for _, v := range b.Verifiers {
			s.Verifiers = append(s.Verifiers, verifierJSON{ID: v.ID, Name: v.Name, PolicyID: v.PolicyID, AnchorDigest: hex.EncodeToString(attest.AnchorDigest(v.AnchorPub))})
		}
		out = append(out, s)
	}
	if jsonOut {
		if out == nil {
			out = []slotJSON{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return err
		}
		return tamperedErr(invalid)
	}
	if len(out) == 0 {
		fmt.Println("No slot is enrolled for attestation. Run: tpm2-kira attest enrol")
		return nil
	}
	for _, s := range out {
		fmt.Printf("Slot #%d (%s)\n", s.Slot, s.NVRAMIndex)
		fmt.Printf("├── Machine:    %s\n", s.FriendlyName)
		fmt.Printf("├── Device ID:  %s\n", s.DeviceID)
		fmt.Printf("├── AK Name:    %s\n", s.AKName)
		fmt.Printf("├── EK:         %s\n", s.EKAlg)
		fmt.Printf("├── PCRs:       %s\n", s.PCRSelection)
		switch s.Signature {
		case "valid":
			fmt.Printf("├── Signature:  valid (%s)\n", s.SigningKey)
		case "invalid":
			fmt.Printf("├── Signature:  INVALID: not written by this machine's signing key (%s). The blob was replaced; trust only the phone.\n", s.SigningKey)
		default:
			fmt.Printf("├── Signature:  not checked (signing public key not found)\n")
		}
		fmt.Printf("└── Verifiers:  %d\n", len(s.Verifiers))
		for i, v := range s.Verifiers {
			branch := "├──"
			if i == len(s.Verifiers)-1 {
				branch = "└──"
			}
			fmt.Printf("    %s %s (%s), anchor %s…\n", branch, v.Name, v.ID, v.AnchorDigest[:16])
		}
	}
	return tamperedErr(invalid)
}

func tamperedErr(invalid int) error {
	if invalid > 0 {
		return fmt.Errorf("%d attestation blob(s) are not signed by this machine's signing key", invalid)
	}
	return nil
}

// AttestQuote produces evidence without a peer, for carrying to another
// machine and judging there with `attest verify`.
func AttestQuote(tpmPath string, sealIndex uint32, nonceHex, pcrs, outPath string, debug bool) error {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) < 16 || len(nonce) > 64 {
		return fmt.Errorf("--nonce must be 16-64 bytes of hex, chosen by the verifier")
	}
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	defer CleanupTPM(tpmDev, debug)

	idx, err := AttestIndexForSlot(sealIndex)
	if err != nil {
		return err
	}
	blob, err := loadAttestBlob(tpmDev, idx)
	if err != nil {
		return fmt.Errorf("slot is not enrolled for attestation: %w", err)
	}
	sel, err := blob.Selection()
	if err != nil {
		return err
	}
	if pcrs != "" {
		if sel, err = parseAttestPCRs(pcrs, sel.Alg); err != nil {
			return err
		}
	}
	be := &tpmBackend{tpm: tpmDev, blob: blob, sealIndex: ResolveNVRAMIndex(sealIndex), sealed: readSealedSlot(tpmDev, ResolveNVRAMIndex(sealIndex)), debug: debug}
	q, err := be.Quote(attest.OfflineQualifyingData(nonce), sel)
	if err != nil {
		return err
	}
	ev := &attest.Evidence{
		Schema:      attest.SchemaVersion,
		DeviceID:    blob.DeviceID,
		AKName:      blob.AKName,
		Quoted:      q.Quoted,
		Signature:   q.Signature,
		PCRAlg:      sel.Alg,
		PCRValues:   q.Values,
		BootContext: be.BootContext(),
		AppVersion:  AppVersion,
	}
	data, err := ev.Encode()
	if err != nil {
		return err
	}
	if outPath == "" || outPath == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return err
	}
	fmt.Printf("Evidence written to %s (%d bytes, %s)\n", outPath, len(data), sel)
	return nil
}

// AttestVerify judges an evidence file against a machine record, with no
// TPM. Returns whether the evidence matched a known-good profile.
func AttestVerify(evidencePath, recordPath, nonceHex string, jsonOut bool) (bool, error) {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) < 16 || len(nonce) > 64 {
		return false, fmt.Errorf("--nonce must be the 16-64 bytes of hex given to 'attest quote'")
	}
	evData, err := os.ReadFile(evidencePath)
	if err != nil {
		return false, err
	}
	d, err := attest.Decode(evData)
	if err != nil {
		return false, err
	}
	ev, err := attest.DecodeEvidence(d)
	if err != nil {
		return false, err
	}
	recData, err := os.ReadFile(recordPath)
	if err != nil {
		return false, err
	}
	var rec attest.MachineRecord
	if err := json.Unmarshal(recData, &rec); err != nil {
		return false, fmt.Errorf("machine record: %w", err)
	}
	if err := rec.Validate(); err != nil {
		return false, err
	}
	pin := &attest.PinnedIdentity{DeviceID: rec.DeviceID, EKPub: rec.EKPub, AKPub: rec.AKPub, AKName: rec.AKName, ResetCount: rec.ResetCount, FirmwareVersion: rec.FirmwareVersion}
	pol := rec.Policy
	if sel := (attest.PCRSelection{Alg: ev.PCRAlg, Indices: pcrIndicesOf(ev)}); !sel.Equal(attest.PCRSelection{Alg: pol.PCRAlg, Indices: pol.Selection}) {
		fmt.Fprintf(os.Stderr, "note: evidence covers %s, the record's policy %s\n", sel, attest.PCRSelection{Alg: pol.PCRAlg, Indices: pol.Selection})
	}
	v := attest.Verify(ev, &pol, pin, attest.OfflineQualifyingData(nonce), time.Now())
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return v.OK, enc.Encode(v)
	}
	printVerdict(v)
	return v.OK, nil
}

func ekAlgName(alg uint16) string {
	switch tpm2.TPMAlgID(alg) {
	case tpm2.TPMAlgECC:
		return "ECC P-256"
	case tpm2.TPMAlgRSA:
		return "RSA-2048"
	}
	return fmt.Sprintf("0x%04x", alg)
}

func pcrIndicesOf(ev *attest.Evidence) []uint8 {
	var out []uint8
	for _, v := range ev.PCRValues {
		out = append(out, v.Index)
	}
	return out
}

func printVerdict(v *attest.Verdict) {
	switch v.State {
	case attest.StateMatch:
		fmt.Printf("MATCH: evidence matches profile %q\n", v.Profile)
	case attest.StateChanged:
		fmt.Println("CHANGED: evidence is authentic but matches no known-good profile")
	default:
		fmt.Println("FAILED: a hard check failed")
	}
	for _, r := range v.Reasons {
		kind := "soft"
		if r.Hard {
			kind = "HARD"
		}
		fmt.Printf("  [%s] %s: %s\n", kind, r.Code, r.Detail)
	}
	for _, w := range v.Warnings {
		fmt.Printf("  [warn] %s: %s\n", w.Code, w.Detail)
	}
	if v.Explanation != "" {
		fmt.Printf("  %s\n", v.Explanation)
	}
	for _, d := range v.PCRDiff {
		fmt.Printf("  PCR %2d  %s\n          expected %s\n          actual   %s\n", d.Index, d.Description, d.Expected, d.Actual)
	}
}

// AttestUnenrol deletes a slot's attestation blob. The sealed TOTP secret in
// the same slot is untouched.
func AttestUnenrol(tpmPath string, sealIndex uint32, debug bool) error {
	idx, err := AttestIndexForSlot(sealIndex)
	if err != nil {
		return err
	}
	if err := NVRAMDelete(tpmPath, idx, debug); err != nil {
		return err
	}
	forgetAttestState(DefaultAttestStateDir, idx)
	fmt.Printf("Attestation enrolment removed from slot %d (NV 0x%08X).\n", idx-AttestNVRAMStart, idx)
	fmt.Println("The phone still lists this machine; remove it there too.")
	return nil
}
