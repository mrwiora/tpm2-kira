package attest

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"
)

// Policy is everything a verifier decides with, expressed as data
// (PLAN-REMOTEATTESTATION.md §8). It is stored on the verifier, in the
// machine record, and never on the attester.
type Policy struct {
	ID                      string    `json:"id"`
	Selection               []uint8   `json:"pcr_selection"`
	PCRAlg                  uint16    `json:"pcr_alg"`
	Profiles                []Profile `json:"profiles"`
	RequireSecureBoot       bool      `json:"require_secureboot"`
	RequireEKCert           bool      `json:"require_ek_cert"`
	AllowResetCountIncrease bool      `json:"allow_reset_count_increase"`
	RequireClockSafe        bool      `json:"require_clock_safe"`
	// FirmwareVersion pins the TPM firmware when set; a change is then a hard
	// failure instead of a warning.
	FirmwareVersion *uint64 `json:"firmware_version,omitempty"`
}

// PCRSelection returns the policy's selection as a validated value.
func (p *Policy) PCRSelection() (PCRSelection, error) {
	s := PCRSelection{Alg: p.PCRAlg, Indices: p.Selection}
	return s, s.Validate()
}

// Profile is one known-good set of PCR values.
type Profile struct {
	Name       string           `json:"name"`
	Values     map[uint8]HexStr `json:"values"`
	ValidFrom  time.Time        `json:"valid_from"`
	ValidUntil *time.Time       `json:"valid_until,omitempty"`
	UsesLeft   *uint32          `json:"uses_left,omitempty"`
	AddedBy    string           `json:"added_by,omitempty"`
	Note       string           `json:"note,omitempty"`
}

// HexStr is a byte string that marshals to JSON as lowercase hex.
type HexStr []byte

// MarshalText implements encoding.TextMarshaler.
func (h HexStr) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(h)), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *HexStr) UnmarshalText(b []byte) error {
	v, err := hex.DecodeString(string(b))
	if err != nil {
		return err
	}
	*h = v
	return nil
}

// usable reports whether the profile may be matched at time now.
func (p *Profile) usable(now time.Time) bool {
	if !p.ValidFrom.IsZero() && now.Before(p.ValidFrom) {
		return false
	}
	if p.ValidUntil != nil && now.After(*p.ValidUntil) {
		return false
	}
	if p.UsesLeft != nil && *p.UsesLeft == 0 {
		return false
	}
	return true
}

// matches reports whether values satisfy the profile for every selected PCR.
func (p *Profile) matches(sel []uint8, values map[uint8][]byte) bool {
	for _, idx := range sel {
		want, ok := p.Values[idx]
		if !ok || !bytes.Equal(want, values[idx]) {
			return false
		}
	}
	return true
}

// diffCount counts selected PCRs whose values differ from the profile.
func (p *Profile) diffCount(sel []uint8, values map[uint8][]byte) int {
	n := 0
	for _, idx := range sel {
		if want, ok := p.Values[idx]; !ok || !bytes.Equal(want, values[idx]) {
			n++
		}
	}
	return n
}

// ProfileFromValues builds a profile from observed values.
func ProfileFromValues(name string, vals []PCRValue, now time.Time, addedBy string) Profile {
	p := Profile{Name: name, Values: map[uint8]HexStr{}, ValidFrom: now, AddedBy: addedBy}
	for _, v := range vals {
		p.Values[v.Index] = append(HexStr(nil), v.Digest...)
	}
	return p
}

// MatchProfile returns the first usable profile the values satisfy.
func (p *Policy) MatchProfile(values map[uint8][]byte, now time.Time) (*Profile, error) {
	for i := range p.Profiles {
		pr := &p.Profiles[i]
		if pr.usable(now) && pr.matches(p.Selection, values) {
			return pr, nil
		}
	}
	return nil, fmt.Errorf("no profile matches")
}

// closestProfile returns the usable profile with the fewest differing PCRs,
// which is what a diff is shown against.
func (p *Policy) closestProfile(values map[uint8][]byte, now time.Time) *Profile {
	var best *Profile
	bestN := -1
	for i := range p.Profiles {
		pr := &p.Profiles[i]
		if !pr.usable(now) {
			continue
		}
		n := pr.diffCount(p.Selection, values)
		if bestN < 0 || n < bestN {
			best, bestN = pr, n
		}
	}
	return best
}

// PinnedIdentity is what the verifier learned at enrolment and has seen since.
type PinnedIdentity struct {
	DeviceID []byte `json:"device_id"`
	EKPub    []byte `json:"ek_pub"`  // marshalled TPMT_PUBLIC
	AKPub    []byte `json:"ak_pub"`  // marshalled TPMT_PUBLIC
	AKName   []byte `json:"ak_name"` // TPM2B_NAME contents (alg ‖ digest)
	// Highest resetCount seen; quotes from before it are replays.
	ResetCount uint32 `json:"reset_count"`
	// FirmwareVersion last seen, reported as a warning when it changes.
	FirmwareVersion uint64 `json:"firmware_version"`
}
