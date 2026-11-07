package admin

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/core/transport/ble"
	"github.com/tpm2-trust/tpm2-kira/core/transport/frame"
	"github.com/tpm2-trust/tpm2-kira/internal/measure"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/phonegate"
	"github.com/tpm2-trust/tpm2-kira/internal/signing"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"
)

// Phone attestation commands: the phone at the machine, over Bluetooth LE
// (PLAN-PHONE.md §12, PLAN-BLE.md).
//
// Attestation stands on its own: the phone verifies the boot and returns a
// signed verdict, which the console shows. Releasing the phone salt (with a
// keyboard's seed, docs/DISK-KEY.md) is an optional step on top of a trusted
// receipt in the same session, the gate's (internal/phonegate). The files:
// this one enrols; attest_blob.go writes the enrolment into the slot's blob;
// attest_verifiedboot.go decides whether this boot may be pinned;
// attest_inspect.go is status, quote, verify and unenrol.

// INFO modes.
const (
	infoModeEnrol = 1
)

// EnrolOptions configures `phone enrol`.
type EnrolOptions struct {
	TPMPath     string
	SealIndex   uint32
	Name        string
	PCRs        string
	SHA1        bool // quote the SHA-1 bank; never chosen without it
	Adapter     int
	AdapterWait time.Duration // how long the adapter may take to appear and become free; 0: not at all
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
		}
	} else if o.Name != "" {
		blob.FriendlyName = o.Name
	}
	// The part may be there for the vault alone: the phones join it, with the
	// attestation key, selection and release key it has.
	channel, err := enrolmentChannel(tpmDev, sealed, blob, priv)
	if err != nil {
		return err
	}
	defer channel.Wipe()
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
	noise, err := attest.NoiseKeypairFromPrivate(channel.NoisePrivate)
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

	p, err := ble.Open(ble.Config{Adapter: o.Adapter, Wait: o.AdapterWait, Logf: phonegate.DebugLogf(o.Debug)})
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
		AdvKey:       channel.AdvKey,
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
