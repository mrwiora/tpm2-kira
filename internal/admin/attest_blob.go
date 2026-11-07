package admin

import (
	"crypto"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/phonegate"
	"github.com/tpm2-trust/tpm2-kira/internal/signing"
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

// enrolmentChannel is the channel's secrets for an enrolment. A slot's first
// phone makes them and seals them into enrolment; a further phone gets the ones
// the slot's phones have pinned, which the signing key opens: the boot is closed
// by now.
func enrolmentChannel(t transport.TPM, sealed *nvslot.SealedBlob, enrolment *nvslot.Attestation, signer crypto.Signer) (*nvslot.ChannelSecrets, error) {
	if enrolment.Phone.Enabled() {
		if err := signing.PrepareSigningKey(signer); err != nil {
			return nil, fmt.Errorf("the signing key is not usable: %w", err)
		}
		probe := *sealed
		probe.Payload.Attestation = enrolment
		return nvslot.UnsealChannelSigned(t, &probe, signer)
	}
	noise, err := attest.GenerateNoiseKeypair(nil)
	if err != nil {
		return nil, err
	}
	channel := &nvslot.ChannelSecrets{NoisePrivate: noise.Private, AdvKey: phonegate.RandBytes(32)}
	afterSeparator, err := nvslot.SealChannel(t, sealed, &enrolment.Phone, channel)
	if err != nil {
		channel.Wipe()
		return nil, err
	}
	warnChannelAfterSeparator(afterSeparator)
	return channel, nil
}

// warnChannelAfterSeparator says when the channel's secrets are sealed to registers
// that may already carry the separator: the gate may not open them at the next boot.
func warnChannelAfterSeparator(reason string) {
	if reason == "" {
		return
	}
	fmt.Println()
	fmt.Println("WARNING: the event log cannot be used for this TPM, so the phone channel is sealed to the")
	fmt.Println("         registers as they are. Where systemd's os-separator has moved them, the gate does")
	fmt.Println("         not open it at boot, and the phone finds no machine. Reason:")
	fmt.Printf("         %s\n", reason)
	fmt.Println()
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
