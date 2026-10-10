package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// 'tpm2-kira status' is the one page a person wants before a reboot: the
// slots and what they are sealed to, the phones and the remote salt, the
// unlock mode, the LUKS keyslots that are tpm2-kira's - and the notes
// where these do not fit together (PLAN-LUKS.md §4). It reads; it changes
// nothing. Without the TPM, or without root for the LUKS headers, it says
// so for that part and shows the rest.

// StatusOptions is what status takes.
type StatusOptions struct {
	TPMPath     string
	PrivKeyPath string // the signing key the blobs are checked with
	ConfigPath  string
	JSON        bool
	Debug       bool
}

// StatusSlot is one slot of the report.
type StatusSlot struct {
	Slot       int      `json:"slot_number"`
	NVRAMIndex string   `json:"nvram_index"`
	PCRs       string   `json:"pcrs"`
	Fallback   bool     `json:"fallback"` // sealed to 0 and 7 alone
	Generation uint64   `json:"generation"`
	GenState   string   `json:"generation_state"`
	Signed     bool     `json:"signed"` // by this machine's signing key
	SignReason string   `json:"sign_reason,omitempty"`
	Phones     []string `json:"phones"`
	RemoteSalt bool     `json:"remote_salt"` // the release key is in the blob
}

// StatusReport is the whole report.
type StatusReport struct {
	Version      string             `json:"version"`
	TPM          string             `json:"tpm"`
	TPMError     string             `json:"tpm_error,omitempty"`
	Slots        []StatusSlot       `json:"slots"`
	Config       string             `json:"config"`
	ConfigError  string             `json:"config_error,omitempty"`
	Devices      []LuksDeviceStatus `json:"devices"`
	DevicesError string             `json:"devices_error,omitempty"`
	Notes        []string           `json:"notes"`
}

// Status prints the report.
func Status(o StatusOptions) error {
	r := collectStatus(o)
	if o.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	printStatus(r)
	return nil
}

// collectStatus gathers the report; every part that cannot be read says
// so in its error field, and the notes are the checks across the parts.
func collectStatus(o StatusOptions) StatusReport {
	r := StatusReport{Version: AppVersion, TPM: o.TPMPath, Slots: []StatusSlot{}, Devices: []LuksDeviceStatus{}, Notes: []string{}}
	if r.Version == "" {
		r.Version = "unknown"
	}

	tpmDev, err := OpenTPM(o.TPMPath)
	if err != nil {
		r.TPMError = fmt.Sprintf("the TPM at %s cannot be opened: %v", o.TPMPath, err)
	} else {
		verifier := newBlobVerifier(o.PrivKeyPath)
		for _, idx := range FindPopulatedSlots(tpmDev, o.Debug) {
			raw, sb, err := readSlot(tpmDev, idx)
			if err != nil {
				r.Notes = append(r.Notes, fmt.Sprintf("slot %d (0x%08X) does not read as a blob: %v", SlotNumber(idx), idx, err))
				continue
			}
			s := StatusSlot{Slot: SlotNumber(idx), NVRAMIndex: fmt.Sprintf("0x%08X", idx), Phones: []string{},
				PCRs: PCRSpecsToString(sb.GetPCRSpecs()), Generation: sb.Payload.Generation,
				GenState: generationState(tpmDev, idx, sb.Payload.Generation)}
			s.Fallback = isFallbackSelection(sb.GetPCRSpecs())
			v := verifier.verify(raw, sb)
			s.Signed, s.SignReason = v.Verified, v.Reason
			if att := sb.Payload.Attestation; att != nil && att.Phone.Enabled() {
				for _, p := range att.Phone.Verifiers {
					s.Phones = append(s.Phones, p.Name)
				}
				s.RemoteSalt = len(att.ReleaseKeyPublic) > 0
			}
			r.Slots = append(r.Slots, s)
		}
		tpmDev.Close()
	}

	r.Config = o.ConfigPath
	if _, err := LoadControlConfig(o.ConfigPath); err != nil {
		r.ConfigError = err.Error()
	}

	devices, err := luksDevices()
	if err != nil {
		r.DevicesError = err.Error()
	}
	for _, d := range devices {
		r.Devices = append(r.Devices, readLuksStatus(d))
	}

	r.Notes = append(r.Notes, statusNotes(r)...)
	// The route of the key, for the devices with a keyslot of ours.
	var routed []string
	for _, d := range r.Devices {
		for _, ks := range d.Keyslots {
			if ks.Token != nil {
				routed = append(routed, d.Device)
				break
			}
		}
	}
	if len(routed) > 0 {
		if findings, err := RouteFindings(routed, nil, ""); err == nil {
			for _, f := range findings {
				if !f.Routed {
					r.Notes = append(r.Notes, strings.TrimRight(routeText(f), "\n"))
				}
			}
		}
	}
	return r
}

// isFallbackSelection says whether specs are PCRs 0 and 7 alone.
func isFallbackSelection(specs []PCRSpec) bool {
	if len(specs) != 2 {
		return false
	}
	idx := []int{specs[0].Index, specs[1].Index}
	sort.Ints(idx)
	return idx[0] == 0 && idx[1] == 7
}

// statusNotes are the checks across the parts: what does not fit, and
// what to do about it.
func statusNotes(r StatusReport) []string {
	var notes []string
	if r.TPMError == "" && len(r.Slots) == 0 {
		notes = append(notes, "no slot is sealed: tpm2-kira seal")
	}
	remoteSalt, fallback := false, false
	for _, s := range r.Slots {
		if !s.Signed {
			notes = append(notes, fmt.Sprintf("slot %d is not signed by this machine's key (%s): the hooks will not reseal it and the gate serves no phone for it", s.Slot, s.SignReason))
		}
		if strings.Contains(s.GenState, "NOT") || strings.Contains(s.GenState, "unavailable") {
			notes = append(notes, fmt.Sprintf("slot %d shows no code until it is resealed: tpm2-kira reseal --nvram %d", s.Slot, s.Slot))
		}
		remoteSalt = remoteSalt || s.RemoteSalt
		fallback = fallback || s.Fallback
	}
	if r.TPMError == "" && len(r.Slots) > 0 && !fallback {
		notes = append(notes, fmt.Sprintf("no fallback slot (PCRs %s alone) for a boot whose kernel changed unpredicted: tpm2-kira seal --nvram %d --pcrs %s", FallbackPCRSelection, FallbackSlot, FallbackPCRSelection))
	}

	slotThere := map[int]bool{}
	for _, s := range r.Slots {
		slotThere[s.Slot] = true
	}
	marked := map[string]int{} // mode -> keyslots marked with it, over every device
	headersRead := r.DevicesError == ""
	for _, d := range r.Devices {
		if d.Error != "" {
			headersRead = false // a header not read: the keyslot checks would be guesses
		}
		for _, ks := range d.Keyslots {
			if ks.Token == nil {
				continue
			}
			marked[ks.Token.Mode]++
			if r.TPMError != "" || ks.Token.Slot == nil {
				continue // bound to no slot: nothing of the TPM to check
			}
			if !slotThere[*ks.Token.Slot] {
				notes = append(notes, fmt.Sprintf("%s keyslot %d is bound to slot %d, which is gone - the slot is dirty: 'tpm2-kira control' (the slot's line) deletes what is left, or tpm2-kira luks remove %s --keyslot %d by hand", d.Device, ks.Keyslot, *ks.Token.Slot, d.Device, ks.Keyslot))
				continue
			}
			if ks.Token.Mode == LuksModePasswordRemoteSalt {
				ok := false
				for _, s := range r.Slots {
					if s.Slot == *ks.Token.Slot && s.RemoteSalt {
						ok = true
					}
				}
				if !ok {
					notes = append(notes, fmt.Sprintf("%s keyslot %d needs the remote salt of slot %d, which has none: tpm2-kira luks remove %s --keyslot %d, then luks enrol again", d.Device, ks.Keyslot, *ks.Token.Slot, d.Device, ks.Keyslot))
				}
			}
		}
	}
	if remoteSalt && headersRead && marked[LuksModePasswordRemoteSalt] == 0 {
		notes = append(notes, "a remote salt is enrolled, but no LUKS keyslot is marked password+remotesalt: the phone's salt opens nothing (tpm2-kira luks enrol <device> --mode password+remotesalt)")
	}
	return notes
}

func printStatus(r StatusReport) {
	fmt.Printf("tpm2-kira %s\n\n", r.Version)
	fmt.Printf("Slots (%s)\n", r.TPM)
	if r.TPMError != "" {
		fmt.Printf("  %s\n", r.TPMError)
	} else if len(r.Slots) == 0 {
		fmt.Println("  none sealed")
	}
	for _, s := range r.Slots {
		pcrs := s.PCRs
		if s.Fallback {
			pcrs += " (the fallback)"
		}
		signed := "signed by this machine's key"
		if !s.Signed {
			signed = "NOT signed by this machine's key"
		}
		fmt.Printf("  slot %-2d  sealed to %s; generation %s; %s\n", s.Slot, pcrs, s.GenState, signed)
		switch {
		case len(s.Phones) > 0 && s.RemoteSalt:
			fmt.Printf("           phone: %s; remote salt enrolled\n", quoted(s.Phones))
		case len(s.Phones) > 0:
			fmt.Printf("           phone: %s; no remote salt\n", quoted(s.Phones))
		}
	}
	fmt.Println()
	fmt.Println("Disk unlock (how a key is made is in each device's LUKS header)")
	if r.ConfigError != "" {
		fmt.Printf("  %s: %s\n", r.Config, r.ConfigError)
	}
	if r.DevicesError != "" {
		fmt.Printf("  %s\n", r.DevicesError)
	}
	for _, d := range r.Devices {
		if d.Error != "" {
			fmt.Printf("  %s: %s\n", d.Device, d.Error)
			continue
		}
		var parts []string
		for _, ks := range d.Keyslots {
			parts = append(parts, "keyslot "+strconv.Itoa(ks.Keyslot)+": "+shortKeyslot(ks))
		}
		fmt.Printf("  %s  %s\n", d.Device, strings.Join(parts, "; "))
	}
	if len(r.Notes) > 0 {
		fmt.Println()
		fmt.Println("Notes")
		for _, n := range r.Notes {
			fmt.Printf("  - %s\n", n)
		}
	}
}

// shortKeyslot is describeKeyslot in a few words.
func shortKeyslot(ks KeyslotStatus) string {
	if ks.Token == nil {
		return "not tpm2-kira's"
	}
	if ks.Token.Mode == LuksModePasswordRemoteSalt && ks.Token.Slot != nil {
		return fmt.Sprintf("%s (slot %d, label %q)", ks.Token.Mode, *ks.Token.Slot, ks.Token.Label)
	}
	return ks.Token.Mode
}

func quoted(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = strconv.Quote(n)
	}
	return strings.Join(q, ", ")
}
