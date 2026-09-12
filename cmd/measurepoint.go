// Reconstruction of PCR values at tpm2-kira's measure point.
//
// The policy is checked against live registers at one instant: when tpm2-kira
// reads the TPM in the initrd, before the passphrase prompt. Neither reference
// a caller might reach for describes that instant:
//
//   - the firmware event log stops at the end of firmware, before systemd's
//     userspace extends (which systemd records in its own separate log);
//   - the live register at seal time is already past the measure point for any
//     PCR that keeps being extended afterwards (9, 11, 15).
//
// So eventlog-derived values get the userspace extends below folded in, and
// only PCRs that stop changing at the measure point may be used to validate
// that decision. See SECURITY-BACKGROUND.md sections 5.6-5.8.
package cmd

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"slices"
	"sort"
	"strings"
)

// Words systemd measures as plain strings before tpm2-kira's measure point.
// The digest is H(word) over the literal bytes: no NUL terminator and no salt
// (systemd src/pcrextend/pcrextend.c passes IOVEC_MAKE(word, strlen(word))
// with secret == NULL), so these are universal constants, not per-host values.
const (
	// OSSeparatorWord is extended by systemd-pcrosseparator.service.
	OSSeparatorWord = "os-separator"
	// EnterInitrdWord is extended by systemd-pcrphase-initrd.service.
	EnterInitrdWord = "enter-initrd"
)

// PCR indices systemd-pcrosseparator.service extends, from its ExecStart.
var osSeparatorPCRs = []int{0, 1, 2, 3, 4, 5, 6, 7, 9, 12, 13, 14}

// PCRs that are extended again after tpm2-kira's measure point, so their live
// register value at seal time is not the value the policy will be checked
// against. They cannot be used to validate a measure-point prediction.
var volatileAfterMeasurePoint = map[int]string{
	9:  "systemd-tpm2-setup NvPCR initialisation (runs after switch-root)",
	11: "systemd-pcrphase (leave-initrd, sysinit, ready)",
	15: "systemd-pcrmachine and cryptsetup volume key measurement",
}

// MeasurePointMode selects how the userspace extends that happen before
// tpm2-kira runs are accounted for when reconstructing PCR values.
type MeasurePointMode int

const (
	// MeasurePointAuto probes the TPM to decide whether the extends are in effect.
	MeasurePointAuto MeasurePointMode = iota
	// MeasurePointOn applies them unconditionally.
	MeasurePointOn
	// MeasurePointOff reconstructs end-of-firmware values only.
	MeasurePointOff
)

// ParseMeasurePointMode converts the --measure-point flag value.
func ParseMeasurePointMode(value string) (MeasurePointMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return MeasurePointAuto, nil
	case "on", "yes", "true":
		return MeasurePointOn, nil
	case "off", "no", "false":
		return MeasurePointOff, nil
	default:
		return MeasurePointAuto, fmt.Errorf("invalid --measure-point value %q (want auto, on or off)", value)
	}
}

func (m MeasurePointMode) String() string {
	switch m {
	case MeasurePointOn:
		return "on"
	case MeasurePointOff:
		return "off"
	default:
		return "auto"
	}
}

// MeasurePointModeSetting is the mode used when sealing or resealing. The CLI
// sets it from --measure-point; verification paths instead reproduce whatever
// the blob recorded, so an existing seal keeps validating after a policy change.
var MeasurePointModeSetting = MeasurePointAuto

func newHashFor(algo PCRHashAlgo) hash.Hash {
	if algo == PCRHashAlgoSHA1 {
		return sha1.New()
	}
	return sha256.New()
}

// DigestOf returns H(data) in the given PCR bank.
func DigestOf(algo PCRHashAlgo, data []byte) []byte {
	h := newHashFor(algo)
	h.Write(data)
	return h.Sum(nil)
}

// ExtendDigest returns the PCR value after extending current with next.
func ExtendDigest(algo PCRHashAlgo, current, next []byte) []byte {
	h := newHashFor(algo)
	h.Write(current)
	h.Write(next)
	return h.Sum(nil)
}

// MeasurePointWords returns the words already measured into the given PCR by
// the time tpm2-kira reads it, for a value reconstructed from the firmware
// event log.
func MeasurePointWords(pcr int) []string {
	var words []string
	if slices.Contains(osSeparatorPCRs, pcr) {
		words = append(words, OSSeparatorWord)
	}
	if pcr == 11 {
		// systemd-pcrphase-initrd is ordered before cryptsetup-pre.target, and
		// tpm2-kira orders itself after it.
		words = append(words, EnterInitrdWord)
	}
	return words
}

// IsVolatileAfterMeasurePoint reports whether a PCR keeps changing after the
// measure point, along with the reason.
func IsVolatileAfterMeasurePoint(pcr int) (string, bool) {
	reason, ok := volatileAfterMeasurePoint[pcr]
	return reason, ok
}

// DetectMeasurePointExtends decides whether the userspace measure-point extends
// are in effect on this system.
//
// It compares the event-log replay of each candidate PCR against the live
// register. Only PCRs that stop changing at the measure point can be used:
// for those, the register must equal either the bare replay or the replay plus
// the expected words. A PCR matching neither means the event log does not
// describe that PCR, which is reported rather than guessed around.
func DetectMeasurePointExtends(replay, registers map[int][]byte, algo PCRHashAlgo, debug bool) (bool, string, error) {
	var probed []int
	applied, skipped := 0, 0

	for _, pcr := range sortedKeys(replay) {
		if _, volatile := volatileAfterMeasurePoint[pcr]; volatile {
			continue
		}
		words := MeasurePointWords(pcr)
		if len(words) == 0 {
			continue
		}
		register, ok := registers[pcr]
		if !ok {
			continue
		}

		expected := replay[pcr]
		for _, word := range words {
			expected = ExtendDigest(algo, expected, DigestOf(algo, []byte(word)))
		}

		switch {
		case bytes.Equal(register, expected):
			applied++
		case bytes.Equal(register, replay[pcr]):
			skipped++
		default:
			return false, "", fmt.Errorf(
				"PCR %d cannot be reconstructed from the event log: the register matches "+
					"neither the replay (%x) nor the replay plus %s (%x), it is %x.\n"+
					"Sealing against PCR %de would bind to a value this system will not produce.\n"+
					"Use the register source (%d) instead, or investigate with verify_os_separator.py",
				pcr, replay[pcr], strings.Join(words, "+"), expected, register, pcr, pcr)
		}
		probed = append(probed, pcr)
	}

	if len(probed) == 0 {
		return false, "", fmt.Errorf(
			"cannot determine whether systemd's measure-point extends are active: no " +
				"eventlog-source PCR is stable enough to probe.\n" +
				"Pass --measure-point=on or --measure-point=off explicitly")
	}
	if applied > 0 && skipped > 0 {
		return false, "", fmt.Errorf(
			"inconsistent measure-point state: %d of the probed PCRs %v show the extends "+
				"and %d do not. Refusing to guess", applied, probed, skipped)
	}

	if debug {
		fmt.Printf("Measure-point probe on PCRs %v: extends %s\n", probed,
			map[bool]string{true: "present", false: "absent"}[applied > 0])
	}
	return applied > 0, fmt.Sprintf("auto (probed PCRs %v)", probed), nil
}

// ApplyMeasurePointExtends rewrites eventlog-reconstructed PCR values so they
// describe the measure point rather than the end of firmware. It returns a
// canonical description of what was applied, for recording in the blob.
func ApplyMeasurePointExtends(values map[int][]byte, indices []int, algo PCRHashAlgo, debug bool) string {
	byWord := map[string][]int{}

	for _, pcr := range indices {
		value, ok := values[pcr]
		if !ok {
			continue
		}
		for _, word := range MeasurePointWords(pcr) {
			value = ExtendDigest(algo, value, DigestOf(algo, []byte(word)))
			byWord[word] = append(byWord[word], pcr)
		}
		values[pcr] = value
		if debug {
			if words := MeasurePointWords(pcr); len(words) > 0 {
				fmt.Printf("  PCR%d + %s -> %x\n", pcr, strings.Join(words, " + "), value)
			}
		}
	}

	return FormatMeasurePointExtends(byWord)
}

// FormatMeasurePointExtends renders the applied extends as "word:1,2;word:3".
func FormatMeasurePointExtends(byWord map[string][]int) string {
	if len(byWord) == 0 {
		return ""
	}
	words := make([]string, 0, len(byWord))
	for word := range byWord {
		words = append(words, word)
	}
	sort.Strings(words)

	parts := make([]string, 0, len(words))
	for _, word := range words {
		pcrs := byWord[word]
		sort.Ints(pcrs)
		text := make([]string, len(pcrs))
		for i, pcr := range pcrs {
			text[i] = fmt.Sprintf("%d", pcr)
		}
		parts = append(parts, word+":"+strings.Join(text, ","))
	}
	return strings.Join(parts, ";")
}

func sortedKeys(m map[int][]byte) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
