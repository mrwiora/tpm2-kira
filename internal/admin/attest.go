package admin

import (
	"bufio"
	"bytes"
	"crypto"
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

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/core/transport/ble"
	"github.com/mrwiora/tpm2-kira/core/transport/frame"
	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// Phone attestation commands: the phone at the machine, over Bluetooth LE
// (PLAN-PHONE.md §12, PLAN-BLE.md).
//
// Attestation stands on its own: the phone verifies the boot and returns a
// signed verdict, which the console shows. Releasing a factor (the phone
// salt, PLAN-PHONESALT.md) is an optional step on top of a trusted
// receipt in the same session; this version of the attester answers such a
// request with "unsupported".

// INFO modes.
const (
	infoModeEnrol = 1
)

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
func writeAttestBlob(tpmDev transport.TPM, idx uint32, b *nvslot.Attestation, priv crypto.Signer) error {
	slot := nvslot.AttestSlot(idx)
	raw, sb, err := phonegate.ReadSlot(tpmDev, idx)
	if err != nil {
		return fmt.Errorf("slot %d holds no sealed TOTP key (%v). A phone enrolment is stored with the slot's key: "+
			"run 'tpm2-kira slot add --nvram %d' first", slot, err, slot)
	}
	if err := nvslot.VerifyBlobSignature(raw, sb, priv.Public()); err != nil {
		return foreignSlotError(slot, err)
	}
	counterIdx := nvslot.AttestCounterIndex(idx)
	current, err := nvslot.ReadAttestCounter(tpmDev, counterIdx)
	if err != nil {
		// No counter yet, or not a counter: this makes one and counts once.
		if current, err = nvslot.BumpAttestCounter(tpmDev, counterIdx); err != nil {
			return err
		}
	}
	if b != nil {
		b.Count = current + 1
	}
	// TOTP is a method of its own, sealed when chosen (slot add --totp).
	// The first phone retires it: the phone's check covers what the code
	// proves. The last phone leaving brings none back by itself.
	retired := false
	hadPhones := sb.PhoneAttested()
	sb.Payload.Attestation = b
	if sb.PhoneAttested() {
		retired = sb.HasTOTPKey()
		sb.Payload.Public, sb.Payload.Private, sb.Payload.TOTPAlgorithm = nil, nil, 0
	}
	unsigned, err := sb.Marshal()
	if err != nil {
		return err
	}
	signed, err := nvslot.SignBlobPayload(unsigned, priv)
	if err != nil {
		return err
	}
	// The record is replaced whole or not at all: on a failure the slot
	// is as it was.
	if err := nvslot.WriteRecord(idx, signed); err != nil {
		var tooLarge *nvslot.RecordTooLargeError
		if errors.As(err, &tooLarge) {
			return blobFull(slot, tooLarge.Size, nvslot.MaxRecordSize, b)
		}
		return fmt.Errorf("could not store the slot's record with the enrolment; the slot is as it was: %w", err)
	}
	if got, err := nvslot.BumpAttestCounter(tpmDev, counterIdx); err != nil {
		return fmt.Errorf("the enrolment is written, but the record counter could not be raised, so it is not accepted yet: %w", err)
	} else if b != nil && got != b.Count {
		return fmt.Errorf("the record counter moved to %d while the enrolment was written with %d; enrol again", got, b.Count)
	}
	if retired {
		fmt.Printf("Slot %d's TOTP code is retired: the phone checks its boots from now on. Remove its\n", slot)
		fmt.Printf("entry from your authenticator app (\"TPM2-KIRA: ... (#%d)\"); it shows no valid code any more.\n", slot)
	}
	if hadPhones && !sb.PhoneAttested() {
		fmt.Printf("Slot %d has no phone any more, and no TOTP code: 'tpm2-kira slot add --nvram %d --totp' seals one.\n", slot, slot)
	}
	return nil
}

// enrolmentSize is the size the slot's record has at least after the
// enrolment. The phone is not known before it answers: it may be one of the
// slot's phones enrolling again, which replaces its entry, and its strings
// may be short. So a phone is added only to a slot without any, with empty
// strings. The exact size is checked when the record is written
// (WriteRecord).
func enrolmentSize(slotBlob *nvslot.SealedBlob, enrolment *nvslot.Attestation) (int, error) {
	grown := *enrolment
	if len(enrolment.Phone.Verifiers) == 0 {
		grown.Phone.Verifiers = []attest.EnrolledVerifier{{AnchorPub: make([]byte, 91), NoisePub: make([]byte, 32)}}
	}
	copyBlob := *slotBlob
	copyBlob.Payload.Attestation = &grown
	// With a phone, the slot's TOTP key goes (writeAttestBlob).
	copyBlob.Payload.Public, copyBlob.Payload.Private, copyBlob.Payload.TOTPAlgorithm = nil, nil, 0
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

// checkEnrolmentFits refuses, before a phone is involved, an enrolment
// that cannot fit the slot's record whatever the phone: only then. What
// the phone adds is checked when the record is written.
func checkEnrolmentFits(slotBlob *nvslot.SealedBlob, enrolment *nvslot.Attestation, slot uint32) error {
	size, err := enrolmentSize(slotBlob, enrolment)
	if err != nil {
		return err
	}
	if size > nvslot.MaxRecordSize {
		return blobFull(slot, size, nvslot.MaxRecordSize, enrolment)
	}
	return nil
}

// checkEnrolmentFitsWithKey refuses, before anything is sent or made, an enrolment
// without a phone (the vault, the TPM salt) whose record would not fit:
// the record as writeAttestBlob writes it, the TOTP key in it as it is.
func checkEnrolmentFitsWithKey(slotBlob *nvslot.SealedBlob, att *nvslot.Attestation, slot uint32) error {
	copyBlob := *slotBlob
	copyBlob.Payload.Attestation = att
	unsigned, err := copyBlob.Marshal()
	if err != nil {
		return err
	}
	sig := len(slotBlob.BlobSignature)
	if sig == 0 {
		sig = 512
	}
	if size := len(unsigned) + 2 + sig; size > nvslot.MaxRecordSize {
		return blobFull(slot, size, nvslot.MaxRecordSize, att)
	}
	return nil
}

// blobFull says that a slot's record would exceed its size, and what the
// slot holds that could make room.
func blobFull(slot uint32, size, limit int, att *nvslot.Attestation) error {
	var holds []string
	advice := "use another slot (--nvram N)"
	if att != nil {
		if n := len(att.Phone.Verifiers); n > 0 {
			holds = append(holds, phonesText(n))
			advice = fmt.Sprintf("its phones share the blob with the TOTP key: remove them with 'tpm2-kira phone unenrol --nvram %d' and enrol the ones you need, or %s", slot, advice)
		}
		if att.Vault.Enabled() {
			holds = append(holds, "the vault method")
		}
		if len(att.TPMSalt.Credential) > 0 {
			holds = append(holds, "a TPM salt")
			advice += ", or take out what no keyslot needs any more (the TPM salt goes with its last keyslot: tpm2-kira luks remove)"
		}
	}
	what := ""
	if len(holds) > 0 {
		what = " It holds " + strings.Join(holds, ", ") + " beside its key."
	}
	return fmt.Errorf("slot %d's record would be %d bytes with this enrolment, and a record holds at most %d; nothing was written.%s To make room: %s", slot, size, limit, what, advice)
}

// imagePCRs names the PCRs of a selection that an initramfs rebuild moves:
// 4 (the unified kernel image as the firmware measured it), 9 (the initrd)
// and 11 (the image's sections, by systemd-stub).
func imagePCRs(sel []uint8) string {
	var out []string
	for _, i := range sel {
		if i == 4 || i == 9 || i == 11 {
			out = append(out, strconv.Itoa(int(i)))
		}
	}
	return strings.Join(out, ", ")
}

// foreignSlotError: the slot's blob was not written by this signing key.
func foreignSlotError(slot uint32, cause error) error {
	return fmt.Errorf("slot %d is not signed by your signing key (%v): it was replaced outside tpm2-kira, "+
		"or is left over from an installation with another signing key. Inspect it with 'tpm2-kira slot info --nvram %d'; "+
		"to start over, run 'tpm2-kira slot delete --nvram %d' and add it again", slot, cause, slot, slot)
}

// checkSamePCRs refuses a --pcrs that differs from an existing blob's
// selection. Further phones share the blob and its selection, so the option
// would otherwise be ignored without a word.
func checkSamePCRs(blob *nvslot.Attestation, pcrs string, slot uint32) error {
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
		"'tpm2-kira phone unenrol' (enrolled phones must then be enrolled again), or\n"+
		"enrol without --pcrs to keep %s", slot, have, pcrs, have)
}

// parseAttestPCRs reads a PCR list for quoting. Quotes always cover the
// live registers, so source suffixes from seal syntax are accepted and ignored.
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

// EnrolOptions configures `phone enrol`.
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
	VerifyTPM   phonegate.HWCheckPolicy
	VerifyPhone phonegate.HWCheckPolicy
}

// AttestEnrol binds a phone to this machine over BLE. It runs on the booted,
// unlocked system: it writes NVRAM and needs the signing key, like `slot add`.
func AttestEnrol(o EnrolOptions) error {
	tpmDev, err := tpmdev.Open(o.TPMPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", o.TPMPath, err)
	}
	defer tpmDev.Close()
	defer tpmdev.Cleanup(tpmDev, o.Debug)

	sealIndex := nvslot.ResolveNVRAMIndex(o.SealIndex)
	idx, err := nvslot.AttestIndexForSlot(sealIndex)
	if err != nil {
		return err
	}
	// The signing key is needed to write the blob at the end; find out now,
	// before the radio is taken and a human has compared codes.
	// --privkey or the default key; the blob names no key file.
	privPath := o.PrivKeyPath
	if privPath == "" {
		privPath = signing.DefaultPrivateKeyPath
	}
	priv, err := signing.LoadCheckedSigningPrivateKey(privPath)
	if err != nil {
		return fmt.Errorf("enrolment needs the signing key to write the attestation blob: %w", err)
	}

	// The enrolment is part of the slot's blob, next to the TOTP key, and
	// adding a phone signs that blob again: there has to be one, and this
	// signing key has to be the one that wrote it.
	raw, slotBlob, err := phonegate.ReadSlot(tpmDev, idx)
	if err != nil {
		return fmt.Errorf("slot %d holds no sealed TOTP key (%v).\n"+
			"A phone enrolment is stored with the slot's key and checks the same boot: seal first with\n\n"+
			"    tpm2-kira slot add --nvram %d", nvslot.AttestSlot(idx), err, nvslot.AttestSlot(idx))
	}
	if err := nvslot.VerifyBlobSignature(raw, slotBlob, priv.Public()); err != nil {
		return foreignSlotError(nvslot.AttestSlot(idx), err)
	}
	blob := slotBlob.Payload.Attestation
	sealed := slotBlob
	if blob != nil && !blob.Phone.Enabled() {
		// The part is there for the vault: the phones join it, with the
		// attestation key, selection and release key it has.
		noise, err := attest.GenerateNoiseKeypair(nil)
		if err != nil {
			return err
		}
		blob.Phone = nvslot.PhoneAttestation{NoisePrivate: noise.Private, AdvKey: phonegate.RandBytes(32)}
	}
	if blob != nil && o.PCRs != "" {
		if err := checkSamePCRs(blob, o.PCRs, nvslot.AttestSlot(idx)); err != nil {
			return err
		}
	}
	if blob != nil && o.SHA1 && blob.PCRAlg != attest.AlgSHA1 {
		return fmt.Errorf("slot %d is already enrolled with the SHA-256 bank, which every phone of the slot shares; "+
			"drop --sha1, or start over with 'tpm2-kira phone unenrol --nvram %d'", nvslot.AttestSlot(idx), nvslot.AttestSlot(idx))
	}

	if blob == nil {
		// The phone checks the registers the slot's seal is bound to,
		// unless --pcrs asks for others.
		pcrs := o.PCRs
		sealedAlg := uint16(attest.AlgSHA256)
		if sealed.GetHashAlgo() == measure.PCRHashAlgoSHA1 {
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
		// SHA-256, unless --sha1 says otherwise: like 'slot add', SHA-1 is
		// never picked for the user, not even where nothing else works.
		alg, err := chooseAttestBank(o.SHA1, sealedAlg, func(a measure.PCRHashAlgo) bool { return measure.TPMHasPCRBank(tpmDev, a) })
		if err != nil {
			return err
		}
		sel, err := parseAttestPCRs(pcrs, alg)
		if err != nil {
			return err
		}
		fmt.Println("Creating an attestation key in the TPM ...")
		akPub, akPriv, akName, err := phonegate.CreateAK(tpmDev)
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
		blob = &nvslot.Attestation{
			DeviceID:     phonegate.RandBytes(attest.DeviceIDSize),
			FriendlyName: name,
			AKPublic:     akPub,
			AKPrivate:    akPriv,
			AKName:       akName,
			PCRAlg:       sel.Alg,
			PCRSelection: sel.Indices,
			Phone:        nvslot.PhoneAttestation{NoisePrivate: noise.Private, AdvKey: phonegate.RandBytes(32)},
		}
	} else if o.Name != "" {
		blob.FriendlyName = o.Name
	}
	sel, err := blob.Selection()
	if err != nil {
		return err
	}
	// Find out now whether the TPM can quote this selection, not after the
	// radio is taken and a human has compared codes.
	if _, err := phonegate.ReadPCRBank(tpmDev, sel); err != nil {
		return fmt.Errorf("this TPM cannot quote %s: %w", sel, err)
	}
	// And whether the slot's blob still fits its NV index with one more
	// phone in it: the TOTP key shares that index.
	if err := checkEnrolmentFits(slotBlob, blob, nvslot.AttestSlot(idx)); err != nil {
		return err
	}
	noise, err := attest.NoiseKeypairFromPrivate(blob.Phone.NoisePrivate)
	if err != nil {
		return err
	}

	// The phone pins this boot as the good one: only a boot that the slot's
	// own check verified may be pinned (verifiedBootRequired).
	matched, err := requireVerifiedBoot(tpmDev, sealed, nvslot.AttestSlot(idx))
	if err != nil {
		return err
	}

	// The header is two lines: what the phone sees in detail is its own
	// screen's job ('phone status' and 'slot info' say it here), and the
	// overview already judges the machine.
	mp := phonegate.PredictMeasurePoint(tpmDev, sealed, sel, o.Debug)
	fmt.Printf("Enrolling %q (slot %d) over hci%d. The adapter is taken over until this\n", blob.FriendlyName, nvslot.SlotNumber(sealIndex), o.Adapter)
	fmt.Println("finishes: its Bluetooth devices disconnect meanwhile (--adapter N for another).")
	fmt.Println()
	if mp.Err != nil {
		// Without a prediction the phone pins the running system's values,
		// which the boot check cannot match. The reason is printed: it is
		// what a bug report needs.
		fmt.Println("NOTE: the values at the boot check could not be predicted: the phone will show")
		fmt.Println("      \"changed\" at the first boot - check and approve it there once. Reason:")
		for _, line := range strings.Split(mp.Err.Error(), "\n") {
			fmt.Printf("      %s\n", line)
		}
		fmt.Println()
	}

	in := o.In
	if in == nil {
		in = os.Stdin
	}
	console := bufio.NewReader(in)
	if ok, err := confirmVerifiedBoot(console, sealed, nvslot.AttestSlot(idx), matched); err != nil {
		return err
	} else if !ok {
		return errors.New("enrolment needs a boot you verified: reboot, compare the code at the code screen (or let an enrolled phone attest the boot), then enrol")
	}
	ok, err := phonegate.ConfirmInitrdCoverage(console, sel, measure.DefaultEventlogPath)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("enrolment cancelled: choose PCRs that cover the initrd with --pcrs")
	}
	if ok, err := phonegate.CheckOwnTPM(tpmDev, o.VerifyTPM, console, os.Stdout); err != nil {
		return err
	} else if !ok {
		return errors.New("enrolment cancelled: this machine's TPM is not verified as genuine (--verify-tpm)")
	}
	fmt.Println()

	p, err := ble.Open(ble.Config{Adapter: o.Adapter, Logf: phonegate.DebugLogf(o.Debug)})
	if err != nil {
		return err
	}
	defer p.Close()
	be := &phonegate.TPMBackend{
		TPM:       tpmDev,
		Blob:      blob,
		SealIndex: sealIndex,
		Sealed:    sealed,
		Debug:     o.Debug,
		Baseline:  mp,
		OnConfirmSAS: func(code string) (bool, error) {
			return confirmCode(console, code)
		},
	}
	be.OnCommit = func(v attest.EnrolledVerifier) error {
		if err := blob.UpsertVerifier(v); err != nil {
			return err
		}
		return writeAttestBlob(tpmDev, idx, blob, priv)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	be.PhoneJudge = &phonegate.PhoneJudge{
		Policy: o.VerifyPhone, Console: console, Out: os.Stdout,
		Revoked: func() (map[string]string, error) { return phonegate.RevokedSerials(client) },
	}

	id := &attest.EnrolIdentity{
		DeviceID:     blob.DeviceID,
		FriendlyName: blob.FriendlyName,
		AKPub:        blob.AKPublic,
		AKName:       blob.AKName,
		NoiseStatic:  noise,
		AdvKey:       blob.Phone.AdvKey,
		Selection:    sel,
		AppVersion:   nvslot.AppVersion,
		Slot:         uint8(nvslot.SlotNumber(sealIndex)),
	}
	adv := ble.Advertisement{
		ServiceData: attest.BuildServiceData(attest.AdvFlagEnrol, phonegate.RandBytes(4), nil),
		Info:        phonegate.AttestInfo(infoModeEnrol, 0),
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
		_, err = attest.ServeEnrolment(conn, id, be, progressf)
		conn.Close()
		if err != nil {
			var em *attest.ErrorMsg
			if errors.As(err, &em) || strings.Contains(err.Error(), "rejected") {
				return fmt.Errorf("enrolment aborted: %w", err)
			}
			fmt.Printf("\033[0;31mSession failed: %v\033[0m\nWaiting for another attempt ...\n\n", err)
			continue
		}
		fmt.Println()
		fmt.Printf("\033[0;32mEnrolled:      phone %d of this slot\033[0m\n", len(blob.Phone.Verifiers))
		fmt.Printf("Stored:        in the blob of slot %d (NV 0x%08X)\n", nvslot.AttestSlot(idx), idx)
		fmt.Println()
		if len(blob.Phone.Verifiers) > 1 {
			fmt.Println("The phone can attest this machine from the next boot on. No rebuild is needed.")
			return nil
		}
		fmt.Println("The phone can now attest this machine at boot. Rebuild the initramfs so")
		fmt.Println("the machine asks it while the code is shown (the hook adds the Bluetooth")
		fmt.Println("adapter it finds). Further phones need no rebuild.")
		if changing := imagePCRs(sel.Indices); len(changing) > 0 {
			fmt.Println()
			fmt.Printf("NOTE: that rebuild changes the boot image, and with it PCR %s, which the phone checks.\n", changing)
			fmt.Println("      At the first boot of the new image the phone will therefore show \"changed\", once.")
			fmt.Println("      Check that it lists only these registers, then approve and remember.")
			fmt.Println("      The TOTP code keeps matching all the same: the approval hook approves the new image")
			fmt.Println("      with your signing key. The phone does not take the machine's word for it.")
		}
		return nil
	}
}

// progressf prints the session's progress plainly, successes green and
// failures red.
func progressf(level attest.ProgressLevel, format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	switch level {
	case attest.ProgressGood:
		line = "\033[0;32m" + line + "\033[0m"
	case attest.ProgressBad:
		line = "\033[0;31m" + line + "\033[0m"
	}
	fmt.Println(line)
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

// chooseAttestBank settles the PCR bank of a new enrolment: SHA-256, or
// SHA-1 when --sha1 was given. The slot's seal (sealedAlg, 0 without one)
// and the TPM must agree; where they do not, the answer is the command to
// run instead, never another bank.
func chooseAttestBank(sha1 bool, sealedAlg uint16, has func(measure.PCRHashAlgo) bool) (uint16, error) {
	const stopgap = "WARNING: SHA-1 is broken against collision attacks and is deprecated for\n" +
		"new deployments. Prefer a TPM with a SHA-256 PCR bank, and treat this as a stopgap."
	alg, hashAlgo := uint16(attest.AlgSHA256), measure.PCRHashAlgoSHA256
	if sha1 {
		alg, hashAlgo = attest.AlgSHA1, measure.PCRHashAlgoSHA1
	}
	if sealedAlg == attest.AlgSHA1 && !sha1 {
		return 0, fmt.Errorf("the slot is sealed against the SHA-1 PCR bank, and its phone enrolment quotes the same registers.\n"+
			"Say so explicitly:\n\n    tpm2-kira phone enrol --sha1\n\n%s", stopgap)
	}
	if sealedAlg == attest.AlgSHA256 && sha1 {
		return 0, errors.New("the slot is sealed against the SHA-256 PCR bank, and its phone enrolment quotes the same registers; drop --sha1")
	}
	if has(hashAlgo) {
		return alg, nil
	}
	if !sha1 && has(measure.PCRHashAlgoSHA1) {
		return 0, fmt.Errorf("this TPM has no SHA-256 PCR bank to quote.\n"+
			"The only remaining option is the SHA-1 bank:\n\n    tpm2-kira phone enrol --sha1\n\n%s", stopgap)
	}
	return 0, fmt.Errorf("this TPM has no %s PCR bank to quote", hashAlgo.DisplayString())
}

// bootThroughKira says whether this boot passed the code screen:
// 'tpm2-kira-boot cap' read-locked a generation index when the initrd was left.
func bootThroughKira(tpmDev transport.TPM) bool {
	for _, idx := range nvslot.FindPopulatedSlots(tpmDev, false) {
		if _, err := nvslot.ReadGeneration(tpmDev, nvslot.GenerationIndex(idx)); errors.Is(err, nvslot.ErrCodesLocked) {
			return true
		}
	}
	return false
}

// verifiedBootRequired: a phone is enrolled only in a boot that was
// verified before it, because enrolment pins this boot as the good one.
// The phone takes the machine's identity on first use and records its
// boot state as the baseline every later boot is compared with; nothing
// the phone can check itself says that this state is clean. The person's
// earlier check says so: for a slot's first phone, its TOTP code at this
// boot's code screen, compared with the authenticator (the code exists
// only while the PCRs are the ones the signing key approved); for a
// further phone, an enrolled phone's verdict on this boot. That is why a
// slot starts with a TOTP key, the setup is two parts with a reboot
// between them, and the TOTP key is retired only by the first phone,
// never before (docs/SECURITY-BACKGROUND.md §3.1).
//
// requireVerifiedBoot refuses a boot that cannot have been verified: one
// that never passed tpm2-kira's code screen (the generation indices are
// not read-locked), and, for a slot with a TOTP key, one whose PCR values
// at the code screen were not the approved ones, so no code was shown for
// the slot. It reports whether that match was established; when the event
// log cannot tell, the person's answer is what is left.
func requireVerifiedBoot(tpmDev transport.TPM, sealed *nvslot.SealedBlob, slot uint32) (bool, error) {
	if !bootThroughKira(tpmDev) {
		return false, fmt.Errorf("this boot did not pass tpm2-kira's code screen, so nothing verified it, and enrolling\n" +
			"would pin an unverified boot on the phone. Reboot through the code screen, compare the\n" +
			"code with your authenticator, then enrol")
	}
	if !sealed.HasTOTPKey() {
		return false, nil // a phone verified the boot, or did not: confirmVerifiedBoot asks
	}
	differ, err := bootMatchesApproval(tpmDev, sealed)
	switch {
	case err != nil:
		fmt.Printf("NOTE: whether this boot was the state slot %d is approved for cannot be told from the\n", slot)
		fmt.Printf("      event log (%v); your answer below decides.\n\n", err)
		return false, nil
	case len(differ) > 0:
		return false, fmt.Errorf("this boot is not the state slot %d's code is approved for (PCR %s differ), so the\n"+
			"code screen showed no code for it and nothing verified this boot. Approve the current\n"+
			"boot chain ('tpm2-kira slot approve', after a kernel update the hook does it), reboot, compare the\n"+
			"code with your authenticator, then enrol", slot, joinInts(differ))
	}
	return true, nil
}

// bootMatchesApproval recomputes, from this boot's event log, the values
// the slot's PCRs had at the code screen (before the OS separator, with
// systemd's enter-initrd on PCR 11, as the seal predicts them) and lists
// the PCRs that differ from the approved ones. A PCR the event log does not
// describe is read from its register, which only works for one that has
// not changed since; for one that has (9, 11, 15 above 12) it cannot tell.
func bootMatchesApproval(tpmDev transport.TPM, sealed *nvslot.SealedBlob) ([]int, error) {
	specs := make([]measure.PCRSpec, 0, len(sealed.Payload.PCRDigests))
	for _, pd := range sealed.Payload.PCRDigests {
		spec := measure.PCRSpec{Index: pd.Index, Source: measure.PCRSourceRegister}
		switch {
		case pd.Index <= 12:
			spec.Source = measure.PCRSourceEventlog
		default:
			if reason, volatile := measure.IsVolatileAfterMeasurePoint(pd.Index); volatile {
				return nil, fmt.Errorf("PCR %d is not in the event log and changes after the code screen: %s", pd.Index, reason)
			}
		}
		specs = append(specs, spec)
	}
	res, err := measure.ReadPCRValues(tpmDev, specs, sealed.GetHashAlgo(), measure.MeasurePointOn, measure.MeasurePointBeforeSeparator, false)
	if err != nil {
		return nil, err
	}
	if res.AfterSeparator != "" {
		return nil, errors.New(res.AfterSeparator)
	}
	var differ []int
	for _, pd := range sealed.Payload.PCRDigests {
		if !bytes.Equal(res.Values[pd.Index], pd.Digest.Buffer) {
			differ = append(differ, pd.Index)
		}
	}
	return differ, nil
}

// warnUncappedBoot says, before a session with the phone, what its boot
// key verdict will read in a boot that never passed the code screen:
// refused, not the designed "locked until the next boot". control blocks
// its steps on this; by hand the note is the warning.
func warnUncappedBoot(tpmDev transport.TPM) {
	if bootThroughKira(tpmDev) {
		return
	}
	fmt.Println("NOTE: this boot did not pass tpm2-kira's code screen, so the TPM cannot answer")
	fmt.Println("      with the boot key and the phone will call it refused. In a boot through")
	fmt.Println("      the wired image it reads \"locked until the next boot\", by design.")
	fmt.Println()
}

// confirmVerifiedBoot asks the person whether they verified this boot: the
// machine knows the code screen ran and, with a TOTP key, that it showed a
// valid code, but not that anyone compared it.
func confirmVerifiedBoot(in *bufio.Reader, sealed *nvslot.SealedBlob, slot uint32, matched bool) (bool, error) {
	fmt.Println()
	if sealed.HasTOTPKey() {
		if matched {
			fmt.Printf("    This boot showed slot %d's code at the code screen (its PCRs were the approved ones).\n", slot)
		}
		fmt.Printf("    Did slot %d's code at this boot's code screen match your authenticator?\n", slot)
		fmt.Println("    The phone takes this boot as the good one; only a boot you verified may be.")
		fmt.Printf("    After the enrolment slot %d has no TOTP code; the phone checks its boots.\n", slot)
	} else {
		fmt.Printf("    Did an enrolled phone attest this boot (\"mobile attestation passed\" for slot %d)?\n", slot)
		fmt.Println("    The new phone takes this boot as the good one; only a verified boot may be.")
	}
	fmt.Println()
	for {
		fmt.Print("    [y] yes, I verified this boot   [n] no — abort: ")
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

// AttestStatus shows the enrolment of one slot or all slots.
func AttestStatus(tpmPath string, sealIndex uint32, jsonOut bool, debug bool) error {
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	var indices []uint32
	if sealIndex != 0 {
		idx, err := nvslot.AttestIndexForSlot(sealIndex)
		if err != nil {
			return err
		}
		indices = []uint32{idx}
	} else {
		indices = phonegate.EnrolledSlots(tpmDev, debug)
	}
	type verifierJSON struct {
		ID           string `json:"id"`
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
		Signature    string         `json:"blob_signature"` // valid | invalid | unchecked
		Current      string         `json:"record_current"` // yes | no | unchecked: count equals the TPM counter
		SigningKey   string         `json:"signing_key,omitempty"`
		Verifiers    []verifierJSON `json:"verifiers"`
	}
	invalid := 0
	var out []slotJSON
	for _, idx := range indices {
		b, err := phonegate.LoadAttestBlob(tpmDev, idx)
		if err != nil {
			if sealIndex != 0 {
				return fmt.Errorf("slot is not enrolled for attestation: %w", err)
			}
			continue
		}
		sel, _ := b.Selection()
		s := slotJSON{
			Slot:         int(nvslot.AttestSlot(idx)),
			NVRAMIndex:   fmt.Sprintf("0x%08X", idx),
			DeviceID:     hex.EncodeToString(b.DeviceID),
			FriendlyName: b.FriendlyName,
			AKName:       hex.EncodeToString(b.AKName),
			EKAlg:        nvslot.EKAlgName(b.EKAlg),
			PCRSelection: sel.String(),
			Signature:    "unchecked",
			Current:      "unchecked",
		}
		if counter, err := nvslot.ReadAttestCounter(tpmDev, nvslot.AttestCounterIndex(idx)); err == nil && counter == b.Count {
			s.Current = "yes"
		} else {
			s.Current = "no"
			invalid++
		}
		if raw, err := nvslot.ReadRecord(idx); err == nil {
			if pub, path, err := phonegate.AttestPublicKey(""); err == nil {
				s.SigningKey = path
				if phonegate.VerifyAttestBlobSignature(raw, pub) == nil {
					s.Signature = "valid"
				} else {
					s.Signature = "invalid"
					invalid++
				}
			}
		}
		for _, v := range b.Phone.Verifiers {
			s.Verifiers = append(s.Verifiers, verifierJSON{ID: v.ID, PolicyID: v.PolicyID, AnchorDigest: hex.EncodeToString(attest.AnchorDigest(v.AnchorPub))})
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
		fmt.Println("No slot is enrolled for attestation. Run: tpm2-kira phone enrol")
		return nil
	}
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
			fmt.Printf("├── Current:    yes (its revision equals the TPM's revision counter)\n")
		} else {
			fmt.Printf("├── Current:    NO: its revision differs from the TPM's revision counter. An older blob was put back, or the counter was raised; the gate refuses it. Enrol again.\n")
		}
		fmt.Printf("└── Verifiers:  %d\n", len(s.Verifiers))
		for i, v := range s.Verifiers {
			branch := "├──"
			if i == len(s.Verifiers)-1 {
				branch = "└──"
			}
			fmt.Printf("    %s phone %d (%s), anchor %s…\n", branch, i+1, v.ID, v.AnchorDigest[:16])
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
// machine and judging there with `phone verify`.
func AttestQuote(tpmPath string, sealIndex uint32, nonceHex, pcrs, outPath string, debug bool) error {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) < 16 || len(nonce) > 64 {
		return fmt.Errorf("--nonce must be 16-64 bytes of hex, chosen by the verifier")
	}
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	defer tpmdev.Cleanup(tpmDev, debug)

	idx, err := nvslot.AttestIndexForSlot(sealIndex)
	if err != nil {
		return err
	}
	blob, err := phonegate.LoadAttestBlob(tpmDev, idx)
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
	be := &phonegate.TPMBackend{TPM: tpmDev, Blob: blob, SealIndex: nvslot.ResolveNVRAMIndex(sealIndex), Sealed: phonegate.ReadSealedSlot(tpmDev, nvslot.ResolveNVRAMIndex(sealIndex)), Debug: debug}
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
		AppVersion:  nvslot.AppVersion,
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
		return false, fmt.Errorf("--nonce must be the 16-64 bytes of hex given to 'phone quote'")
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
	idx, err := nvslot.AttestIndexForSlot(sealIndex)
	if err != nil {
		return err
	}
	slot := nvslot.AttestSlot(idx)
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	att, err := phonegate.LoadAttestBlob(tpmDev, idx)
	if err != nil {
		return fmt.Errorf("slot %d has no phone enrolled", slot)
	}
	// The vault method stays, and the attestation key and release key with
	// it: they are its too.
	var keep *nvslot.Attestation
	if att.Vault.Enabled() {
		att.Phone = nvslot.PhoneAttestation{}
		keep = att
	}

	// The enrolment is part of the slot's blob: taking it out writes and
	// signs that blob again, which needs the signing key.
	if privKeyPath == "" {
		privKeyPath = signing.DefaultPrivateKeyPath
	}
	priv, err := signing.LoadCheckedSigningPrivateKey(privKeyPath)
	if err != nil {
		return fmt.Errorf("removing the enrolment rewrites the slot's blob and needs the signing key: %w\n"+
			"Without the key, 'tpm2-kira slot delete --nvram %d' removes the whole slot, TOTP key included", err, slot)
	}
	if err := signing.PrepareSigningKey(priv); err != nil {
		return fmt.Errorf("the signing key is not usable: %w", err)
	}
	// The counter is raised with it, so the blob as it was is stale should
	// anyone put it back.
	if err := writeAttestBlob(tpmDev, idx, keep, priv); err != nil {
		return err
	}
	fmt.Printf("Attestation enrolment removed from slot %d. Its TOTP key is unchanged.\n", slot)
	fmt.Println("The phone still lists this machine; remove it there too.")
	fmt.Println("The initramfs still carries the Bluetooth gate, which now has nothing to")
	fmt.Println("serve; its next build leaves it out.")
	return nil
}
