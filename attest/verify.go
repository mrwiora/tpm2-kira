package attest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/google/go-tpm/tpm2"
)

// Verify is the whole security decision over one piece of evidence.
//
// It is a pure function: no TPM, no network, no filesystem and no clock
// reads — `now` is passed in. It runs unchanged on the phone (through the
// gomobile binding), on a server and against the golden corpus in tests.
//
// expectedQD is the qualifying data the verifier computed for this session
// (QualifyingData or EnrolQualifyingData). Every check is run and every
// failure is reported; Verify does not stop at the first one, because
// "PCR 4 differs" and "four PCRs and the firmware changed" call for different
// human decisions.
func Verify(ev *Evidence, pol *Policy, pin *PinnedIdentity, expectedQD []byte, now time.Time) *Verdict {
	v := &Verdict{}
	if ev == nil || pol == nil || pin == nil {
		v.hard(ReasonMalformed, "missing evidence, policy or pinned identity")
		return v.finish()
	}

	sel, err := pol.PCRSelection()
	if err != nil {
		v.hard(ReasonPolicyInvalid, err.Error())
		return v.finish()
	}

	if ev.Schema != SchemaVersion {
		v.hard(ReasonMalformed, fmt.Sprintf("evidence schema %d, expected %d", ev.Schema, SchemaVersion))
	}
	if !bytes.Equal(ev.DeviceID, pin.DeviceID) {
		v.hard(ReasonDeviceMismatch, "evidence is for a different device")
	}
	if !bytes.Equal(ev.AKName, pin.AKName) {
		v.hard(ReasonAKMismatch, "evidence names an attestation key other than the pinned one")
	}

	// The signature is checked with the *pinned* AK, never one the evidence supplies.
	akPub, err := ParseAKPublic(pin.AKPub, pin.AKName)
	if err != nil {
		v.hard(ReasonAKMismatch, "pinned AK unusable: "+err.Error())
	} else if err := VerifyTPMSignature(akPub, ev.Quoted, ev.Signature); err != nil {
		v.hard(ReasonBadSignature, err.Error())
	}

	v.QuoteDigest = sha256Sum(ev.Quoted)

	att, err := tpm2.Unmarshal[tpm2.TPMSAttest](ev.Quoted)
	if err != nil {
		v.hard(ReasonMalformed, "quote does not parse as TPMS_ATTEST: "+err.Error())
		return v.finish()
	}
	if att.Magic != tpm2.TPMGeneratedValue {
		v.hard(ReasonBadMagic, fmt.Sprintf("magic 0x%08x is not TPM_GENERATED_VALUE", uint32(att.Magic)))
	}
	if att.Type != tpm2.TPMSTAttestQuote {
		v.hard(ReasonBadType, fmt.Sprintf("attestation type 0x%04x is not a quote", uint16(att.Type)))
		return v.finish()
	}
	if !bytes.Equal(att.ExtraData.Buffer, expectedQD) {
		v.hard(ReasonQDMismatch, "quote is not bound to this session's nonces and channel")
	}

	v.ResetCount = att.ClockInfo.ResetCount
	v.RestartCount = att.ClockInfo.RestartCount
	v.ClockSafe = att.ClockInfo.Safe == tpm2.TPMIYesNo(true)
	v.FirmwareVersion = att.FirmwareVersion

	if att.ClockInfo.ResetCount < pin.ResetCount {
		v.hard(ReasonResetCountDecreased, fmt.Sprintf("TPM reset count went backwards (%d < %d): a replayed quote or a cleared TPM", att.ClockInfo.ResetCount, pin.ResetCount))
	} else if att.ClockInfo.ResetCount > pin.ResetCount && pin.ResetCount != 0 && !pol.AllowResetCountIncrease {
		// Each cold boot increments resetCount; a jump of more than one
		// means boots happened that this verifier never saw.
		if att.ClockInfo.ResetCount-pin.ResetCount > 1 {
			v.warn(WarnResetCountJump, fmt.Sprintf("TPM was reset %d times since the last attestation", att.ClockInfo.ResetCount-pin.ResetCount))
		}
	}
	if !v.ClockSafe {
		if pol.RequireClockSafe {
			v.hard(ReasonClockUnsafe, "TPM reports its clock state is not safe")
		} else {
			v.warn(WarnClockUnsafe, "TPM reports its clock state is not safe")
		}
	}
	if pol.FirmwareVersion != nil && att.FirmwareVersion != *pol.FirmwareVersion {
		v.hard(ReasonFirmwareChanged, fmt.Sprintf("TPM firmware 0x%016x differs from pinned 0x%016x", att.FirmwareVersion, *pol.FirmwareVersion))
	} else if pin.FirmwareVersion != 0 && att.FirmwareVersion != pin.FirmwareVersion {
		v.warn(WarnFirmwareChanged, fmt.Sprintf("TPM firmware changed from 0x%016x to 0x%016x", pin.FirmwareVersion, att.FirmwareVersion))
	}

	quote, err := att.Attested.Quote()
	if err != nil {
		v.hard(ReasonMalformed, "quote info missing: "+err.Error())
		return v.finish()
	}
	quotedSel, err := selectionFromTPM(quote.PCRSelect)
	if err != nil {
		v.hard(ReasonSelectionMismatch, err.Error())
	} else if !quotedSel.Equal(sel) {
		v.hard(ReasonSelectionMismatch, fmt.Sprintf("quote covers %s, policy requires %s", quotedSel, sel))
	}

	// pcr_values travel beside the quote; they are only believed if they
	// reproduce the digest the TPM signed.
	values, err := checkPCRValues(ev, sel)
	if err != nil {
		v.hard(ReasonPCRValuesInvalid, err.Error())
		return v.finish()
	}
	composite := compositeDigest(sel, values)
	if !bytes.Equal(composite, quote.PCRDigest.Buffer) {
		v.hard(ReasonPCRDigestMismatch, "PCR values do not reproduce the quoted digest")
		return v.finish()
	}
	v.Values = values

	if pol.RequireSecureBoot && ev.BootContext.SecureBootState != SecureBootEnabled {
		// Informational context, not TPM-signed: it can only make a
		// verdict stricter, never more lenient.
		v.hard(ReasonSecureBootOff, "Secure Boot is not reported as enabled")
	} else if ev.BootContext.SecureBootState == SecureBootDisabled || ev.BootContext.SecureBootState == SecureBootSetupMode {
		v.warn(WarnSecureBootOff, "Secure Boot is off or in Setup Mode; PCR 7 then attests little")
	}

	if pr, err := pol.MatchProfile(values, now); err == nil {
		v.Profile = pr.Name
	} else {
		v.soft(ReasonNoProfileMatch, "PCR values match no known-good profile")
		if closest := pol.closestProfile(values, now); closest != nil {
			v.DiffAgainst = closest.Name
			for _, idx := range sel.Indices {
				want := closest.Values[idx]
				if !SameBootState(idx, want, values[idx]) {
					v.PCRDiff = append(v.PCRDiff, PCRDiff{
						Index:       idx,
						Expected:    hex.EncodeToString(want),
						Actual:      hex.EncodeToString(values[idx]),
						Description: PCRDescription(idx),
					})
				}
			}
			v.Explanation = ExplainDiff(v.PCRDiff)
		}
	}
	return v.finish()
}

// Reason codes. They are stable strings: the app maps them to text.
const (
	ReasonMalformed           = "malformed"
	ReasonPolicyInvalid       = "policy_invalid"
	ReasonDeviceMismatch      = "device_mismatch"
	ReasonAKMismatch          = "ak_mismatch"
	ReasonBadSignature        = "bad_signature"
	ReasonBadMagic            = "bad_magic"
	ReasonBadType             = "bad_type"
	ReasonQDMismatch          = "qd_mismatch"
	ReasonResetCountDecreased = "reset_count_decreased"
	ReasonClockUnsafe         = "clock_unsafe"
	ReasonFirmwareChanged     = "firmware_changed"
	ReasonBootProofInvalid    = "boot_proof_invalid"
	ReasonSelectionMismatch   = "selection_mismatch"
	ReasonPCRValuesInvalid    = "pcr_values_invalid"
	ReasonPCRDigestMismatch   = "pcr_digest_mismatch"
	ReasonSecureBootOff       = "secureboot_off"
	// ReasonNoProfileMatch is the only soft reason: the evidence is
	// authentic, the state is merely unknown, and a human may approve it.
	ReasonNoProfileMatch = "no_profile_match"

	WarnResetCountJump  = "reset_count_jump"
	WarnClockUnsafe     = "clock_unsafe"
	WarnFirmwareChanged = "firmware_changed"
	WarnSecureBootOff   = "secureboot_off"
)

// Reason is one failed check.
type Reason struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
	Hard   bool   `json:"hard"`
}

// Warning is a passed check worth telling a human about.
type Warning struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// PCRDiff is one register that differs from the closest profile.
type PCRDiff struct {
	Index       uint8  `json:"index"`
	Expected    string `json:"expected"`
	Actual      string `json:"actual"`
	Description string `json:"description"`
}

// Verdict is the result of Verify.
type Verdict struct {
	OK bool `json:"ok"`
	// State is "match", "changed" (authentic but unknown state: a human
	// may approve) or "failed" (a hard check failed).
	State       string           `json:"state"`
	Profile     string           `json:"profile,omitempty"`
	Reasons     []Reason         `json:"reasons,omitempty"`
	Warnings    []Warning        `json:"warnings,omitempty"`
	PCRDiff     []PCRDiff        `json:"pcr_diff,omitempty"`
	DiffAgainst string           `json:"diff_against,omitempty"`
	Explanation string           `json:"explanation,omitempty"`
	Values      map[uint8][]byte `json:"-"`

	ResetCount      uint32 `json:"reset_count"`
	RestartCount    uint32 `json:"restart_count"`
	ClockSafe       bool   `json:"clock_safe"`
	FirmwareVersion uint64 `json:"firmware_version"`
	QuoteDigest     []byte `json:"-"`

	// BootKey is what the machine's TPM made of the boot challenge
	// (bootkey.go): "proved", "refused", "invalid", "failed" or "unused".
	// Code is the code to compare with the machine's screen; present only
	// when the key was proved.
	BootKey string `json:"boot_key"`
	Code    string `json:"code,omitempty"`
}

// Boot key results in a Verdict.
const (
	BootKeyResultProved  = "proved"  // the TPM released the key for this boot state
	BootKeyResultRefused = "refused" // the TPM did not: not a state the signing key approved
	BootKeyResultInvalid = "invalid" // the machine claimed a proof that does not verify
	BootKeyResultFailed  = "failed"  // the machine could not try
	BootKeyResultUnused  = "unused"  // the machine did not try
)

// Verdict states.
const (
	StateMatch   = "match"
	StateChanged = "changed"
	StateFailed  = "failed"
)

func (v *Verdict) hard(code, detail string) {
	v.Reasons = append(v.Reasons, Reason{Code: code, Detail: detail, Hard: true})
}

func (v *Verdict) soft(code, detail string) {
	v.Reasons = append(v.Reasons, Reason{Code: code, Detail: detail})
}

func (v *Verdict) warn(code, detail string) {
	v.Warnings = append(v.Warnings, Warning{Code: code, Detail: detail})
}

// HasHardFailure reports whether any hard check failed.
func (v *Verdict) HasHardFailure() bool {
	for _, r := range v.Reasons {
		if r.Hard {
			return true
		}
	}
	return false
}

func (v *Verdict) finish() *Verdict {
	switch {
	case v.HasHardFailure():
		v.State = StateFailed
	case len(v.Reasons) > 0:
		v.State = StateChanged
	default:
		v.State = StateMatch
		v.OK = true
	}
	return v
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func (s PCRSelection) String() string {
	name := "sha256"
	if s.Alg == AlgSHA1 {
		name = "sha1"
	}
	return fmt.Sprintf("%s:%v", name, s.Indices)
}

// selectionFromTPM converts a TPML_PCR_SELECTION with a single bank.
func selectionFromTPM(l tpm2.TPMLPCRSelection) (PCRSelection, error) {
	var banks []PCRSelection
	for _, s := range l.PCRSelections {
		var idx []int
		for byteI, b := range s.PCRSelect {
			for bit := 0; bit < 8; bit++ {
				if b&(1<<bit) != 0 {
					idx = append(idx, byteI*8+bit)
				}
			}
		}
		if len(idx) == 0 {
			continue
		}
		sel, err := NewPCRSelection(uint16(s.Hash), idx)
		if err != nil {
			return PCRSelection{}, err
		}
		banks = append(banks, sel)
	}
	if len(banks) != 1 {
		return PCRSelection{}, fmt.Errorf("quote covers %d PCR banks, exactly one is supported", len(banks))
	}
	return banks[0], nil
}

// ToTPM converts the selection into a TPML_PCR_SELECTION.
func (s PCRSelection) ToTPM() tpm2.TPMLPCRSelection {
	bitmap := make([]byte, 3)
	for _, i := range s.Indices {
		bitmap[i/8] |= 1 << (i % 8)
	}
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash:      tpm2.TPMIAlgHash(s.Alg),
		PCRSelect: bitmap,
	}}}
}

func checkPCRValues(ev *Evidence, sel PCRSelection) (map[uint8][]byte, error) {
	if ev.PCRAlg != sel.Alg {
		return nil, fmt.Errorf("PCR values are from bank 0x%04x, policy requires 0x%04x", ev.PCRAlg, sel.Alg)
	}
	size := DigestSize(sel.Alg)
	values := make(map[uint8][]byte, len(ev.PCRValues))
	for _, pv := range ev.PCRValues {
		if len(pv.Digest) != size {
			return nil, fmt.Errorf("PCR %d digest is %d bytes, expected %d", pv.Index, len(pv.Digest), size)
		}
		if _, dup := values[pv.Index]; dup {
			return nil, fmt.Errorf("PCR %d listed twice", pv.Index)
		}
		values[pv.Index] = pv.Digest
	}
	if len(values) != len(sel.Indices) {
		return nil, fmt.Errorf("evidence carries %d PCR values, selection has %d", len(values), len(sel.Indices))
	}
	for _, idx := range sel.Indices {
		if _, ok := values[idx]; !ok {
			return nil, fmt.Errorf("PCR %d is selected but has no value", idx)
		}
	}
	return values, nil
}

// compositeDigest reproduces TPM2_Quote's pcrDigest: the signing scheme's
// hash (SHA-256 for every AK this project creates) over the selected PCR
// values concatenated in ascending index order.
func compositeDigest(sel PCRSelection, values map[uint8][]byte) []byte {
	h := sha256.New()
	for _, idx := range sel.Indices {
		h.Write(values[idx])
	}
	return h.Sum(nil)
}

// CompositeDigest is the exported form used by the attester to self-check a quote.
func CompositeDigest(sel PCRSelection, vals []PCRValue) []byte {
	m := map[uint8][]byte{}
	for _, v := range vals {
		m[v.Index] = v.Digest
	}
	return compositeDigest(sel, m)
}

// ParseAKPublic parses a marshalled TPMT_PUBLIC, checks that it is a
// restricted signing key that cannot leave its TPM, and that its Name equals
// wantName (if given).
func ParseAKPublic(pubBytes, wantName []byte) (crypto.PublicKey, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](pubBytes)
	if err != nil {
		return nil, fmt.Errorf("AK public area does not parse: %w", err)
	}
	a := pub.ObjectAttributes
	if !a.Restricted || !a.SignEncrypt || a.Decrypt || !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin {
		return nil, fmt.Errorf("AK attributes are not those of a restricted, non-duplicable signing key")
	}
	if pub.NameAlg != tpm2.TPMAlgSHA256 {
		return nil, fmt.Errorf("AK name algorithm 0x%04x is not SHA-256", uint16(pub.NameAlg))
	}
	if wantName != nil {
		name, err := tpm2.ObjectName(pub)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(name.Buffer, wantName) {
			return nil, fmt.Errorf("AK Name does not match its public area")
		}
	}
	return tpm2.Pub(*pub)
}

// AKName computes the TPM Name of a marshalled TPMT_PUBLIC.
func AKName(pubBytes []byte) ([]byte, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](pubBytes)
	if err != nil {
		return nil, err
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return nil, err
	}
	return name.Buffer, nil
}

// VerifyTPMSignature checks a marshalled TPMT_SIGNATURE over msg. Only
// SHA-256 signatures are accepted: a SHA-1 signature is a downgrade.
func VerifyTPMSignature(pub crypto.PublicKey, msg, sigBytes []byte) error {
	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](sigBytes)
	if err != nil {
		return fmt.Errorf("signature does not parse: %w", err)
	}
	digest := sha256.Sum256(msg)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if sig.SigAlg != tpm2.TPMAlgECDSA {
			return fmt.Errorf("signature algorithm 0x%04x does not match an ECDSA key", uint16(sig.SigAlg))
		}
		s, err := sig.Signature.ECDSA()
		if err != nil {
			return err
		}
		if s.Hash != tpm2.TPMAlgSHA256 {
			return fmt.Errorf("signature hash 0x%04x is not SHA-256", uint16(s.Hash))
		}
		r := new(big.Int).SetBytes(s.SignatureR.Buffer)
		ss := new(big.Int).SetBytes(s.SignatureS.Buffer)
		if !ecdsa.Verify(k, digest[:], r, ss) {
			return fmt.Errorf("quote signature does not verify")
		}
		return nil
	case *rsa.PublicKey:
		if sig.SigAlg != tpm2.TPMAlgRSASSA {
			return fmt.Errorf("signature algorithm 0x%04x does not match an RSASSA key", uint16(sig.SigAlg))
		}
		s, err := sig.Signature.RSASSA()
		if err != nil {
			return err
		}
		if s.Hash != tpm2.TPMAlgSHA256 {
			return fmt.Errorf("signature hash 0x%04x is not SHA-256", uint16(s.Hash))
		}
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], s.Sig.Buffer); err != nil {
			return fmt.Errorf("quote signature does not verify")
		}
		return nil
	}
	return fmt.Errorf("unsupported AK key type %T", pub)
}
