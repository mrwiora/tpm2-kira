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
	"sync"
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
	ExitTampered    = 6 // the attestation record was replaced or is not the current one
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

// errNotEnrolled: the slot's blob carries no phone enrolment.
var errNotEnrolled = errors.New("no phone is enrolled for this slot")

// readSlot returns a slot's blob as stored and parsed.
func readSlot(tpmDev transport.TPM, idx uint32) ([]byte, *SealedBlob, error) {
	raw, err := ReadFromNVRAM(tpmDev, idx)
	if err != nil {
		return nil, nil, err
	}
	sb, err := UnmarshalSealedBlob(raw)
	if err != nil {
		return raw, nil, err
	}
	return raw, sb, nil
}

// loadAttestBlob returns the phone enrolment a slot's blob carries.
func loadAttestBlob(tpmDev transport.TPM, idx uint32) (*AttestBlob, error) {
	_, sb, err := readSlot(tpmDev, idx)
	if err != nil {
		return nil, err
	}
	if sb.Payload.Attest == nil {
		return nil, errNotEnrolled
	}
	return sb.Payload.Attest, nil
}

// enrolledSlots returns the slots whose blob carries a phone enrolment.
func enrolledSlots(tpmDev transport.TPM, debug bool) []uint32 {
	var out []uint32
	for _, idx := range FindPopulatedSlots(tpmDev, debug) {
		if _, err := loadAttestBlob(tpmDev, idx); err == nil {
			out = append(out, idx)
		}
	}
	return out
}

// legacyAttestRecords returns the enrolments earlier versions stored as NV
// indices of their own. They are not read any more.
func legacyAttestRecords(tpmDev transport.TPM) []uint32 {
	return FindPopulatedSlotsInRange(tpmDev, AttestNVRAMStart, AttestNVRAMEnd, false)
}

// writeAttestBlob stores b as the slot's phone enrolment, or removes the
// enrolment when b is nil, by rewriting the slot's blob: the TOTP key and
// everything else in it are carried over as they are, and the whole is
// signed again.
//
// That is only done to a blob the same signing key wrote: signing somebody
// else's content would vouch for it. A new enrolment carries the next value
// of the slot's record counter, so an older blob can never pass as the
// current one (attest_counter.go). The counter is raised after the write:
// if the write fails, the previous blob is put back and is still current;
// between the two steps the new blob is merely not accepted yet.
func writeAttestBlob(tpmDev transport.TPM, idx uint32, b *AttestBlob, priv crypto.Signer) error {
	slot := attestSlot(idx)
	raw, sb, err := readSlot(tpmDev, idx)
	if err != nil {
		return fmt.Errorf("slot %d holds no sealed TOTP key (%v). A phone enrolment is stored with the slot's key: "+
			"run 'tpm2-kira seal --nvram %d' first", slot, err, slot)
	}
	if err := VerifyBlobSignature(raw, sb, priv.Public()); err != nil {
		return foreignSlotError(slot, err)
	}
	counterIdx := AttestCounterIndex(idx)
	current, err := readAttestCounter(tpmDev, counterIdx)
	if err != nil {
		// No counter yet, or not a counter: this makes one and counts once.
		if current, err = bumpAttestCounter(tpmDev, counterIdx); err != nil {
			return err
		}
	}
	if b != nil {
		b.Count = current + 1
	}
	sb.Payload.Attest = b
	unsigned, err := sb.Marshal()
	if err != nil {
		return err
	}
	signed, err := SignBlobPayload(unsigned, priv)
	if err != nil {
		return err
	}
	if err := WriteToNVRAM(tpmDev, idx, signed, priv.Public(), priv); err != nil {
		// The index was replaced for the write; the TOTP key lives in it.
		if rerr := WriteToNVRAM(tpmDev, idx, raw, priv.Public(), priv); rerr != nil {
			return fmt.Errorf("could not store the slot's blob (%w), and could not put the previous one back (%v); "+
				"a copy is in %s", err, rerr, NVRAMRecoveryDir)
		}
		return fmt.Errorf("could not store the slot's blob with the phone enrolment; the slot is as it was: %w", err)
	}
	if got, err := bumpAttestCounter(tpmDev, counterIdx); err != nil {
		return fmt.Errorf("the enrolment is written, but the record counter could not be raised, so it is not accepted yet: %w", err)
	} else if b != nil && got != b.Count {
		return fmt.Errorf("the record counter moved to %d while the enrolment was written with %d; enrol again", got, b.Count)
	}
	removeLegacyAttestRecord(tpmDev, idx)
	return nil
}

// nvIndexLimit is the largest NV index this TPM stores, or 0 if it does
// not say.
func nvIndexLimit(tpmDev transport.TPM) int {
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVIndexMax),
		PropertyCount: 1,
	}.Execute(tpmDev)
	if err != nil {
		return 0
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0
	}
	for _, p := range props.TPMProperty {
		if p.Property == tpm2.TPMPTNVIndexMax {
			return int(p.Value)
		}
	}
	return 0
}

// enrolmentSize is the size the slot's blob has with the given enrolment
// and one more phone of the largest size the format allows.
func enrolmentSize(slotBlob *SealedBlob, enrolment *AttestBlob) (int, error) {
	grown := *enrolment
	grown.Verifiers = append(append([]attest.EnrolledVerifier(nil), enrolment.Verifiers...), attest.EnrolledVerifier{
		ID: strings.Repeat("i", 64), Name: strings.Repeat("n", 64),
		AnchorPub: make([]byte, 91), NoisePub: make([]byte, 32), PolicyID: strings.Repeat("p", 64),
	})
	if len(grown.Verifiers) > MaxVerifiers {
		return 0, fmt.Errorf("slot already has %d verifiers enrolled", MaxVerifiers)
	}
	copyBlob := *slotBlob
	copyBlob.Payload.Attest = &grown
	unsigned, err := copyBlob.Marshal()
	if err != nil {
		return 0, err
	}
	sig := len(slotBlob.BlobSignature)
	if sig == 0 {
		sig = 512
	}
	return len(unsigned) + 2 + sig, nil
}

// checkEnrolmentFits refuses an enrolment that would not fit the slot's NV
// index, before a phone is involved.
func checkEnrolmentFits(tpmDev transport.TPM, slotBlob *SealedBlob, enrolment *AttestBlob, slot uint32) error {
	size, err := enrolmentSize(slotBlob, enrolment)
	if err != nil {
		return err
	}
	limit := nvIndexLimit(tpmDev)
	if limit > MaxNVRAMBlobSize || limit == 0 {
		limit = MaxNVRAMBlobSize
	}
	if size > limit {
		return fmt.Errorf("slot %d's blob would grow to about %d bytes with another phone, and this TPM stores at most %d per NV index.\n"+
			"Its phones share the blob with the TOTP key: remove one with 'tpm2-kira attest unenrol --nvram %d' "+
			"(that removes all phones of the slot) and enrol the ones you need", slot, size, limit, slot)
	}
	return nil
}

// foreignSlotError: the slot's blob was not written by this signing key.
func foreignSlotError(slot uint32, cause error) error {
	return fmt.Errorf("slot %d is not signed by your signing key (%v): it was replaced outside tpm2-kira, "+
		"or is left over from an installation with another signing key. Inspect it with 'tpm2-kira info --nvram %d'; "+
		"to start over, run 'tpm2-kira nvram delete --nvram %d' and seal again", slot, cause, slot, slot)
}

// removeLegacyAttestRecord deletes the slot's enrolment in the old place,
// if one is still there. Best effort: it is dead weight, not a danger.
func removeLegacyAttestRecord(tpmDev transport.TPM, idx uint32) {
	legacy := legacyAttestIndex(idx)
	if NVRAMIndexExists(tpmDev, legacy) {
		_ = undefineIndex(tpmDev, legacy)
	}
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
	SHA1        bool // quote the SHA-1 bank; never chosen without it
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

	// The enrolment is part of the slot's blob, next to the TOTP key, and
	// adding a phone signs that blob again: there has to be one, and this
	// signing key has to be the one that wrote it.
	raw, slotBlob, err := readSlot(tpmDev, idx)
	if err != nil {
		return fmt.Errorf("slot %d holds no sealed TOTP key (%v).\n"+
			"A phone enrolment is stored with the slot's key and checks the same boot: seal first with\n\n"+
			"    tpm2-kira seal --nvram %d", attestSlot(idx), err, attestSlot(idx))
	}
	if err := VerifyBlobSignature(raw, slotBlob, priv.Public()); err != nil {
		return foreignSlotError(attestSlot(idx), err)
	}
	blob := slotBlob.Payload.Attest
	sealed := slotBlob
	if legacy := legacyAttestIndex(idx); blob == nil && NVRAMIndexExists(tpmDev, legacy) {
		fmt.Printf("NOTE: slot %d has an enrolment in the old, separate format (NV 0x%08X). It is not used\n"+
			"      any more and is removed when this enrolment is stored; delete the machine in the\n"+
			"      phone app and enrol the phone again.\n\n", attestSlot(idx), legacy)
	}
	if blob != nil && o.PCRs != "" {
		if err := checkSamePCRs(blob, o.PCRs, attestSlot(idx)); err != nil {
			return err
		}
	}
	if blob != nil && o.SHA1 && blob.PCRAlg != attest.AlgSHA1 {
		return fmt.Errorf("slot %d is already enrolled with the SHA-256 bank, which every phone of the slot shares; "+
			"drop --sha1, or start over with 'tpm2-kira attest unenrol --nvram %d'", attestSlot(idx), attestSlot(idx))
	}

	if blob == nil {
		// The phone checks the registers the slot's seal is bound to,
		// unless --pcrs asks for others.
		pcrs := o.PCRs
		sealedAlg := uint16(attest.AlgSHA256)
		if sealed.GetHashAlgo() == PCRHashAlgoSHA1 {
			sealedAlg = attest.AlgSHA1
		}
		if pcrs == "" {
			var parts []string
			for _, i := range sealed.GetPCRIndices() {
				parts = append(parts, strconv.Itoa(i))
			}
			pcrs = strings.Join(parts, ",")
		}
		if pcrs == "" {
			pcrs = "0,2,4,7"
		}
		// SHA-256, unless --sha1 says otherwise: like 'seal', SHA-1 is
		// never picked for the user, not even where nothing else works.
		alg, err := chooseAttestBank(o.SHA1, sealedAlg, func(a PCRHashAlgo) bool { return TPMHasPCRBank(tpmDev, a) })
		if err != nil {
			return err
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
	if sel.Alg == attest.AlgSHA1 {
		warnAboutSHA1Quote()
	}
	// Find out now whether the TPM can quote this selection, not after the
	// radio is taken and a human has compared codes.
	if _, err := readPCRBank(tpmDev, sel); err != nil {
		return fmt.Errorf("this TPM cannot quote %s: %w", sel, err)
	}
	// And whether the slot's blob still fits its NV index with one more
	// phone in it: the TOTP key shares that index.
	if err := checkEnrolmentFits(tpmDev, slotBlob, blob, attestSlot(idx)); err != nil {
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
		fmt.Println()
		fmt.Println("The phone can now attest this machine at boot. To serve attestation")
		fmt.Println("requests at the passphrase prompt, enable the gate in lazy mode:")
		fmt.Println("    echo 'TPM2_KIRA_ATTEST=lazy' | sudo tee /etc/tpm2-kira/attest.conf")
		fmt.Println("and rebuild the initramfs (the Bluetooth hook must find your adapter).")
		fmt.Println("Further phones need no rebuild.")
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
	SignerPath  string // the signing public key in the initramfs; "" = DefaultAttestSignerPath
	Coordinator string // the coordinator's socket; "" = this process holds the TPM itself
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
	step := gateSteps(o.Debug)
	if o.Coordinator != "" {
		// The radio worker: no TPM here. Everything that needs one, and
		// the reading of the phone's receipt, is the coordinator's.
		step("version %s; radio worker, asking the coordinator at %s", AppVersion, o.Coordinator)
		client, err := dialGate(o.Coordinator, gateCoordinatorWait)
		if err != nil {
			gateFail("%v", err)
			return ExitUnavailable
		}
		defer client.Close()
		return runGateRadio(client, o, step, client.Gone())
	}
	// Run by hand, or where no coordinator runs (initramfs-tools): one
	// process does both halves.
	tpmPath := preferResourceManager(o.TPMPath)
	step("version %s; opening the TPM at %s", AppVersion, tpmPath)
	tpmDev, err := transport.OpenTPM(tpmPath)
	if err != nil {
		gateFail("failed to open TPM at %s: %v", tpmPath, err)
		return ExitInternal
	}
	defer tpmDev.Close()
	defer CleanupTPM(tpmDev, o.Debug)
	return runGateRadio(newGateService(tpmDev, o.SealIndex, o.SignerPath, o.Debug), o, step, nil)
}

// chooseAttestBank settles the PCR bank of a new enrolment: SHA-256, or
// SHA-1 when --sha1 was given. The slot's seal (sealedAlg, 0 without one)
// and the TPM must agree; where they do not, the answer is the command to
// run instead, never another bank.
func chooseAttestBank(sha1 bool, sealedAlg uint16, has func(PCRHashAlgo) bool) (uint16, error) {
	const stopgap = "WARNING: SHA-1 is broken against collision attacks and is deprecated for\n" +
		"new deployments. Prefer a TPM with a SHA-256 PCR bank, and treat this as a stopgap."
	alg, hashAlgo := uint16(attest.AlgSHA256), PCRHashAlgoSHA256
	if sha1 {
		alg, hashAlgo = attest.AlgSHA1, PCRHashAlgoSHA1
	}
	if sealedAlg == attest.AlgSHA1 && !sha1 {
		return 0, fmt.Errorf("the slot is sealed against the SHA-1 PCR bank, and its phone enrolment quotes the same registers.\n"+
			"Say so explicitly:\n\n    tpm2-kira attest enrol --sha1\n\n%s", stopgap)
	}
	if sealedAlg == attest.AlgSHA256 && sha1 {
		return 0, errors.New("the slot is sealed against the SHA-256 PCR bank, and its phone enrolment quotes the same registers; drop --sha1")
	}
	if has(hashAlgo) {
		return alg, nil
	}
	if !sha1 && has(PCRHashAlgoSHA1) {
		return 0, fmt.Errorf("this TPM has no SHA-256 PCR bank to quote.\n"+
			"The only remaining option is the SHA-1 bank:\n\n    tpm2-kira attest enrol --sha1\n\n%s", stopgap)
	}
	return 0, fmt.Errorf("this TPM has no %s PCR bank to quote", hashAlgo.DisplayString())
}

// warnAboutSHA1Quote is 'attest enrol's counterpart of WarnAboutHashAlgo.
func warnAboutSHA1Quote() {
	fmt.Println("WARNING: the phone will check the SHA-1 PCR bank.")
	fmt.Println("  SHA-1 is broken against collision attacks and TPMs are not required to")
	fmt.Println("  provide a SHA-1 bank at all. Use it only where the TPM offers no SHA-256")
	fmt.Println("  bank, and treat it as a stopgap.")
	fmt.Println()
}

// gateCoordinatorWait is how long the worker waits for the coordinator's
// socket: both are started at the same moment.
const gateCoordinatorWait = 30 * time.Second

// runGateRadio is the radio half of the gate: advertise, serve the phone,
// print what it said. The TPM half is behind host; when ended is closed,
// that half is gone (the code screen has released the boot) and the radio
// stops.
func runGateRadio(host gateHost, o GateOptions, step func(string, ...any), ended <-chan struct{}) int {
	ident, code, err := host.Identity()
	if code != 0 || err != nil {
		if code == 0 {
			code = ExitInternal
		}
		// A refused record was reported in full by whoever checked it.
		if code != ExitTampered || o.Coordinator != "" {
			gateFail("%v", err)
		}
		return code
	}
	step("serving slot %d (record verified: %v), %d phone(s) enrolled", ident.Slot, ident.RecordVerified, len(ident.Verifiers))
	noise, err := attest.NoiseKeypairFromPrivate(ident.NoisePrivate)
	if err != nil {
		gateFail("%v", err)
		return ExitInternal
	}
	id := &attest.AttestIdentity{
		DeviceID:     ident.DeviceID,
		AKName:       ident.AKName,
		NoiseStatic:  noise,
		AppVersion:   AppVersion,
		Capabilities: attest.CapEventlog,
	}
	for _, v := range ident.Verifiers {
		// No anchors here: the receipt is judged by the host.
		id.Verifiers = append(id.Verifiers, attest.EnrolledVerifier{ID: v.ID, Name: v.Name, NoisePub: v.NoisePub})
	}

	step("opening hci%d (waiting up to %s for it)", o.Adapter, o.AdapterWait)
	p, err := ble.Open(ble.Config{Adapter: o.Adapter, UnblockRFKill: true, Wait: o.AdapterWait, Logf: debugLogf(o.Debug)})
	if err != nil {
		gateFail("%v", err)
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
		ServiceData: attest.BuildServiceData(attest.AdvFlagAttest, randBytes(4), ident.AdvKey),
		Info:        attestInfo(infoModeAttest, id.Capabilities),
	}
	fmt.Printf("tpm2-kira: waiting for attestation of %q (open the app on your phone)\n", ident.FriendlyName)
	host.Report(GateWaiting)

	res, err := waitForReceipt(p, adv, o.Timeout, func(conn *frame.Conn) (*attest.AttestResult, error) {
		host.Report(GateSession)
		res, err := attest.ServeAttestation(conn, id, host, debugProgress(o.Debug))
		if res == nil || res.Receipt == nil {
			host.Report(GateWaiting) // the gate advertises again
		}
		return res, err
	}, os.Stdout, time.Now)
	if errors.Is(err, errNoPhoneReachable) {
		gateFail("phone not reachable: no phone connected over Bluetooth within %s.\n"+
			"tpm2-kira:   This is not a TPM or boot-integrity failure. Check that the phone\n"+
			"tpm2-kira:   is close to this machine, Bluetooth is on and the Kira app is open.", o.Timeout)
		host.Report(GateUnavailable)
		return ExitUnavailable
	}
	if err != nil && isOver() {
		// Lazy mode: the phone check lasts as long as the code screen.
		fmt.Println("tpm2-kira: the code screen has ended; the phone was not asked in time for this boot")
		return ExitUnavailable
	}
	if err != nil {
		gateFail("%v", err)
		host.Report(GateUnavailable)
		return ExitUnavailable
	}
	return reportReceipt(res, ident.RecordVerified)
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

// gateSteps returns the gate's step log for debug runs: one line per step
// with the time since the gate started, so that a boot where the phone was
// never asked shows how far the gate got and where the time went.
func gateSteps(debug bool) func(string, ...any) {
	if !debug {
		return func(string, ...any) {}
	}
	start := time.Now()
	return func(format string, args ...any) {
		fmt.Printf("tpm2-kira: gate +%.1fs: "+format+"\n", append([]any{time.Since(start).Seconds()}, args...)...)
	}
}

func gateFail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "tpm2-kira: FAILED: "+format+"\n", args...)
}

// gateRecordCheck checks the record in the TPM before anything is
// advertised: signed by the key this initramfs carries, and current by the
// TPM's counter. It reports whether the record was verified, or the exit
// status with which the gate gives up.
func gateRecordCheck(tpmDev transport.TPM, idx uint32, signerPath string) (bool, int) {
	if signerPath == "" {
		signerPath = DefaultAttestSignerPath
		// Run by hand on the unlocked system, there is no image around
		// the gate, but the key the image would carry is right here.
		if _, err := os.Stat(signerPath); os.IsNotExist(err) {
			if _, err := os.Stat(DefaultPublicKeyPath); err == nil {
				signerPath = DefaultPublicKeyPath
			}
		}
	}
	raw, err := ReadFromNVRAM(tpmDev, idx)
	if err != nil {
		gateFail("cannot read the attestation record at 0x%08X: %v", idx, err)
		return false, ExitInternal
	}
	if _, err := os.Stat(signerPath); os.IsNotExist(err) {
		fmt.Printf("tpm2-kira: no signing public key at %s to check the attestation record (in an initramfs: rebuild it)\n", signerPath)
		return false, 0
	}
	pub, _, err := LoadSigningPublicKeyFromPEM(signerPath)
	if err != nil {
		gateFail("cannot use the signing public key at %s: %v", signerPath, err)
		return false, ExitInternal
	}
	if err := checkAttestRecord(tpmDev, idx, raw, pub); err != nil {
		gateFail("the attestation record in the TPM (slot %d) is not accepted:\n"+
			"tpm2-kira:   %v.\n"+
			"tpm2-kira:   It was replaced, or an older one was put back: no phone is served, and a\n"+
			"tpm2-kira:   verdict from any phone means nothing for this boot. To start over, run\n"+
			"tpm2-kira:   'tpm2-kira attest unenrol' on the unlocked system and enrol again.",
			attestSlot(idx), err)
		return false, ExitTampered
	}
	return true, 0
}

func reportReceipt(res *attest.AttestResult, recordVerified bool) int {
	// Even a verified record is only as good as the initramfs holding the
	// key it was verified with (SECURITY.md); the phone's screen is the verdict.
	if recordVerified {
		defer fmt.Println("tpm2-kira:   (enrolment record verified: signed by this machine's key and current; your phone's screen is authoritative)")
	} else {
		defer fmt.Println("tpm2-kira:   (not verified on this machine: your phone's screen is authoritative)")
	}
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
		indices = enrolledSlots(tpmDev, debug)
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
		Current      string         `json:"record_current"` // yes | no | unchecked: count equals the TPM counter
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
			Slot:         int(attestSlot(idx)),
			NVRAMIndex:   fmt.Sprintf("0x%08X", idx),
			DeviceID:     hex.EncodeToString(b.DeviceID),
			FriendlyName: b.FriendlyName,
			AKName:       hex.EncodeToString(b.AKName),
			EKAlg:        ekAlgName(b.EKAlg),
			PCRSelection: sel.String(),
			AppVersion:   b.AppVersion,
			Signature:    "unchecked",
			Current:      "unchecked",
		}
		if counter, err := readAttestCounter(tpmDev, AttestCounterIndex(idx)); err == nil && counter == b.Count {
			s.Current = "yes"
		} else {
			s.Current = "no"
			invalid++
		}
		if raw, err := ReadFromNVRAM(tpmDev, idx); err == nil {
			if pub, path, err := attestPublicKey(""); err == nil {
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
	// Enrolments earlier versions kept as NV indices of their own.
	printLegacy := func() {
		for _, legacy := range legacyAttestRecords(tpmDev) {
			slot := legacy - AttestNVRAMStart
			if sealIndex != 0 && legacy != legacyAttestIndex(indices[0]) {
				continue
			}
			fmt.Printf("NOTE: slot #%d has an enrolment in the old, separate format (NV 0x%08X). It is not used any more:\n"+
				"      enrol the phone again ('tpm2-kira attest enrol --nvram %d' removes the old one), or remove it\n"+
				"      with 'tpm2-kira attest unenrol --nvram %d'.\n", slot, legacy, slot, slot)
		}
	}
	if len(out) == 0 {
		fmt.Println("No slot is enrolled for attestation. Run: tpm2-kira attest enrol")
		printLegacy()
		return nil
	}
	defer printLegacy()
	for _, s := range out {
		fmt.Printf("Slot #%d (in the slot's blob, %s)\n", s.Slot, s.NVRAMIndex)
		fmt.Printf("├── Machine:    %s\n", s.FriendlyName)
		fmt.Printf("├── Device ID:  %s\n", s.DeviceID)
		fmt.Printf("├── AK Name:    %s\n", s.AKName)
		fmt.Printf("├── EK:         %s\n", s.EKAlg)
		fmt.Printf("├── PCRs:       %s\n", s.PCRSelection)
		switch s.Signature {
		case "valid":
			fmt.Printf("├── Signature:  valid (%s)\n", s.SigningKey)
		case "invalid":
			fmt.Printf("├── Signature:  INVALID: the slot's blob was not written by this machine's signing key (%s). It was replaced, or is left from another installation; trust only the phone.\n", s.SigningKey)
		default:
			fmt.Printf("├── Signature:  not checked (signing public key not found)\n")
		}
		if s.Current == "yes" {
			fmt.Printf("├── Current:    yes (its count equals the TPM's record counter)\n")
		} else {
			fmt.Printf("├── Current:    NO: its count differs from the TPM's record counter. An older record was put back, or the counter was raised; the gate refuses it. Enrol again.\n")
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
func AttestUnenrol(tpmPath string, sealIndex uint32, privKeyPath string, debug bool) error {
	idx, err := AttestIndexForSlot(sealIndex)
	if err != nil {
		return err
	}
	slot := attestSlot(idx)
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	legacy := legacyAttestIndex(idx)
	hadLegacy := NVRAMIndexExists(tpmDev, legacy)
	if _, err := loadAttestBlob(tpmDev, idx); err != nil {
		if !hadLegacy {
			return fmt.Errorf("slot %d has no phone enrolled", slot)
		}
		// Only an enrolment in the old, separate place: that is an NV
		// index of its own and needs no key to remove.
		if err := undefineIndex(tpmDev, legacy); err != nil {
			return fmt.Errorf("failed to delete the old enrolment at 0x%08X: %w", legacy, err)
		}
		if _, err := bumpAttestCounter(tpmDev, AttestCounterIndex(idx)); err != nil {
			fmt.Printf("Warning: could not raise the record counter: %v\n", err)
		}
		fmt.Printf("Attestation enrolment in the old format removed from slot %d (NV 0x%08X).\n", slot, legacy)
		fmt.Println("The phone still lists this machine; remove it there too.")
		return nil
	}

	// The enrolment is part of the slot's blob: taking it out writes and
	// signs that blob again, which needs the signing key.
	if privKeyPath == "" {
		privKeyPath = DefaultPrivateKeyPath
	}
	priv, err := LoadCheckedSigningPrivateKey(privKeyPath)
	if err != nil {
		return fmt.Errorf("removing the enrolment rewrites the slot's blob and needs the signing key: %w\n"+
			"Without the key, 'tpm2-kira nvram delete --nvram %d' removes the whole slot, TOTP key included", err, slot)
	}
	if err := PrepareSigningKey(priv); err != nil {
		return fmt.Errorf("the signing key is not usable: %w", err)
	}
	// The counter is raised with it, so the blob as it was is stale should
	// anyone put it back.
	if err := writeAttestBlob(tpmDev, idx, nil, priv); err != nil {
		return err
	}
	fmt.Printf("Attestation enrolment removed from slot %d. Its TOTP key is unchanged.\n", slot)
	fmt.Println("The phone still lists this machine; remove it there too.")
	if cfg, err := LoadAttestConfig(DefaultAttestConfigPath); err == nil && cfg.Mode != "off" {
		fmt.Println("The initramfs still carries the Bluetooth gate, which now has nothing to")
		fmt.Println("serve: rebuild it (mkinitcpio -P / update-initramfs -u) to take it out.")
	}
	return nil
}
