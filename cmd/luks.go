package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// tpm2-kira's keyslots in a LUKS2 header (PLAN-LUKS.md §2): a token of
// type "tpm2-kira" bound to the keyslot says how the key in it is made at
// the prompt. No key material is in it; cryptsetup needs no handler for
// it, since the key comes through the socket or the keyscript, not
// through the token. Read with luksDump --dump-json-metadata, written
// with token import.

// LuksTokenType is the token's type in the header.
const LuksTokenType = "tpm2-kira"

// The modes a keyslot's key is made in, as the token and unlock.conf
// name them.
const (
	LuksModePasswordSalt       = UnlockPasswordSalt       // "password+salt"
	LuksModePasswordRemoteSalt = UnlockPasswordRemoteSalt // "password+remotesalt"
)

// LuksToken is the token's JSON.
type LuksToken struct {
	Type     string   `json:"type"`
	Keyslots []string `json:"keyslots"`
	Mode     string   `json:"mode"`
	Slot     *int     `json:"slot,omitempty"` // the tpm2-kira slot of the remote salt
	Label    string   `json:"label,omitempty"`
	Created  string   `json:"created"`
}

// luksMetadata is the part of luksDump --dump-json-metadata this reads.
type luksMetadata struct {
	Keyslots map[string]struct {
		Type string `json:"type"`
	} `json:"keyslots"`
	Tokens map[string]json.RawMessage `json:"tokens"`
}

// cryptsetup runs cryptsetup with stdin and returns its output.
var cryptsetup = func(stdin []byte, args ...string) ([]byte, error) {
	c := exec.Command("cryptsetup", args...)
	c.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("cryptsetup %s: %s", args[0], msg)
	}
	return out.Bytes(), nil
}

// luksDevices lists the crypto_LUKS block devices lsblk knows.
func luksDevices() ([]string, error) {
	out, err := exec.Command("lsblk", "-J", "-o", "PATH,FSTYPE").Output()
	if err != nil {
		return nil, fmt.Errorf("lsblk: %w", err)
	}
	return parseLsblk(out)
}

func parseLsblk(out []byte) ([]string, error) {
	type dev struct {
		Path     string `json:"path"`
		FSType   string `json:"fstype"`
		Children []dev  `json:"children"`
	}
	var top struct {
		Devices []dev `json:"blockdevices"`
	}
	if err := json.Unmarshal(out, &top); err != nil {
		return nil, fmt.Errorf("lsblk: %w", err)
	}
	var found []string
	var walk func([]dev)
	walk = func(ds []dev) {
		for _, d := range ds {
			if d.FSType == "crypto_LUKS" {
				found = append(found, d.Path)
			}
			walk(d.Children)
		}
	}
	walk(top.Devices)
	sort.Strings(found)
	return found, nil
}

// KeyslotStatus is one keyslot of a device as luks status reports it.
type KeyslotStatus struct {
	Keyslot int        `json:"keyslot"`
	Token   *LuksToken `json:"token,omitempty"` // nil: not tpm2-kira's
	TokenID int        `json:"token_id,omitempty"`
}

// LuksDeviceStatus is one device.
type LuksDeviceStatus struct {
	Device   string          `json:"device"`
	Keyslots []KeyslotStatus `json:"keyslots"`
	Error    string          `json:"error,omitempty"`
}

// readLuksStatus reads a device's header and pairs keyslots with tokens.
func readLuksStatus(device string) LuksDeviceStatus {
	st := LuksDeviceStatus{Device: device}
	out, err := cryptsetup(nil, "luksDump", "--dump-json-metadata", device)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	slots, err := parseLuksMetadata(out)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.Keyslots = slots
	return st
}

func parseLuksMetadata(out []byte) ([]KeyslotStatus, error) {
	var md luksMetadata
	if err := json.Unmarshal(out, &md); err != nil {
		return nil, fmt.Errorf("the header's metadata does not parse (LUKS2 only): %w", err)
	}
	byKeyslot := map[string]KeyslotStatus{}
	for num := range md.Keyslots {
		n, _ := strconv.Atoi(num)
		byKeyslot[num] = KeyslotStatus{Keyslot: n}
	}
	for id, raw := range md.Tokens {
		var tok LuksToken
		if err := json.Unmarshal(raw, &tok); err != nil || tok.Type != LuksTokenType {
			continue
		}
		tid, _ := strconv.Atoi(id)
		for _, ks := range tok.Keyslots {
			if s, ok := byKeyslot[ks]; ok {
				t := tok
				s.Token, s.TokenID = &t, tid
				byKeyslot[ks] = s
			}
		}
	}
	var slots []KeyslotStatus
	for _, s := range byKeyslot {
		slots = append(slots, s)
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].Keyslot < slots[j].Keyslot })
	return slots, nil
}

// LuksStatus prints which keyslots of the given devices (all LUKS devices
// when none is given) are tpm2-kira's, and how their key is made.
func LuksStatus(devices []string, jsonOut bool) error {
	if len(devices) == 0 {
		var err error
		if devices, err = luksDevices(); err != nil {
			return err
		}
		if len(devices) == 0 {
			fmt.Println("No LUKS device found.")
			return nil
		}
	}
	var all []LuksDeviceStatus
	for _, d := range devices {
		all = append(all, readLuksStatus(d))
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(all)
	}
	for _, st := range all {
		fmt.Printf("%s\n", st.Device)
		if st.Error != "" {
			fmt.Printf("  %s\n", st.Error)
			continue
		}
		for _, s := range st.Keyslots {
			fmt.Printf("  keyslot %d: %s\n", s.Keyslot, describeKeyslot(s))
		}
	}
	return nil
}

func describeKeyslot(s KeyslotStatus) string {
	if s.Token == nil {
		return "not tpm2-kira's (a passphrase, or a key enrolled by other means)"
	}
	t := s.Token
	switch t.Mode {
	case LuksModePasswordSalt:
		return fmt.Sprintf("tpm2-kira, password+salt: a typed password and a typed salt (token %d, %s)", s.TokenID, t.Created)
	case LuksModePasswordRemoteSalt:
		slot := "?"
		if t.Slot != nil {
			slot = strconv.Itoa(*t.Slot)
		}
		return fmt.Sprintf("tpm2-kira, password+remotesalt: a typed password and the verifier's salt, slot %s, label %q (token %d, %s)", slot, t.Label, s.TokenID, t.Created)
	}
	return fmt.Sprintf("tpm2-kira, mode %q (token %d)", t.Mode, s.TokenID)
}

// LuksMarkOptions is what luks mark takes.
type LuksMarkOptions struct {
	TPMPath   string
	Device    string
	Keyslot   int
	Mode      string
	SealIndex uint32 // password+remotesalt: the slot whose remote salt it is
	Label     string
	Debug     bool
}

// errNoRemoteSalt: password+remotesalt is only ever available with an
// attestation set up: a verifier enrolled for the slot, and the slot's
// remote salt enrolled with it.
var errNoRemoteSalt = errors.New("password+remotesalt needs an attestation: a phone enrolled for the slot ('tpm2-kira attest enrol') and the remote salt enrolled with it ('tpm2-kira remotesalt enrol')")

// checkRemoteSaltReady says whether the slot can release a remote salt at
// all: a verifier is enrolled and the release key exists.
func checkRemoteSaltReady(tpmPath string, sealIndex uint32) error {
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	att, err := loadAttestBlob(tpmDev, sealIndex)
	if err != nil {
		return fmt.Errorf("%w (slot %d has no phone enrolled)", errNoRemoteSalt, attestSlot(sealIndex))
	}
	if len(att.ReleaseKeyPublic) == 0 {
		return fmt.Errorf("%w (slot %d has no release key yet)", errNoRemoteSalt, attestSlot(sealIndex))
	}
	return nil
}

// LuksMark writes the token for an existing keyslot. For
// password+remotesalt the slot must be able to release one (checkRemoteSaltReady).
func LuksMark(o LuksMarkOptions) error {
	device, keyslot, mode, label := o.Device, o.Keyslot, o.Mode, o.Label
	if mode != LuksModePasswordSalt && mode != LuksModePasswordRemoteSalt {
		return fmt.Errorf("--mode must be %s or %s", LuksModePasswordSalt, LuksModePasswordRemoteSalt)
	}
	slot := 0
	if mode == LuksModePasswordRemoteSalt {
		idx, err := AttestIndexForSlot(o.SealIndex)
		if err != nil {
			return err
		}
		if err := checkRemoteSaltReady(o.TPMPath, idx); err != nil {
			return err
		}
		slot = int(attestSlot(idx))
	}
	st := readLuksStatus(device)
	if st.Error != "" {
		return errors.New(st.Error)
	}
	var have *KeyslotStatus
	for i := range st.Keyslots {
		if st.Keyslots[i].Keyslot == keyslot {
			have = &st.Keyslots[i]
		}
	}
	if have == nil {
		return fmt.Errorf("%s has no keyslot %d", device, keyslot)
	}
	if have.Token != nil {
		return fmt.Errorf("keyslot %d is marked already (token %d, %s); remove it first: tpm2-kira luks remove", keyslot, have.TokenID, have.Token.Mode)
	}
	tok := LuksToken{Type: LuksTokenType, Keyslots: []string{strconv.Itoa(keyslot)}, Mode: mode, Created: time.Now().UTC().Format(time.RFC3339)}
	if mode == LuksModePasswordRemoteSalt {
		s := slot
		tok.Slot = &s
		if label == "" {
			label = "luks"
		}
		tok.Label = label
	}
	b, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	if _, err := cryptsetup(b, "token", "import", "--json-file", "-", device); err != nil {
		return err
	}
	fmt.Printf("%s keyslot %d marked: %s\n", device, keyslot, describeKeyslot(KeyslotStatus{Keyslot: keyslot, Token: &tok}))
	return nil
}

// LuksEnrolOptions is what luks enrol takes.
type LuksEnrolOptions struct {
	Device string
	Mode   string
	// ExistingKeyFile authorises luksAddKey instead of cryptsetup's prompt
	// for an existing passphrase (scripts and tests).
	ExistingKeyFile string
	// NoConfig leaves unlock.conf alone.
	NoConfig bool
	Remote   FactorEnrolOptions // password+remotesalt: the slot, the phone, the keys
}

// terminalAsk asks on the terminal; tests replace it.
var terminalAsk = terminalPassword

// LuksEnrol adds a keyslot whose key tpm2-kira makes at boot (PLAN-LUKS.md
// §3): the password (and the salt, or the remote salt's round trip with
// the phone), the derivation, 'cryptsetup luksAddKey' with the key on its
// stdin - cryptsetup asks an existing passphrase to authorise, the
// recovery keyslot the device must have - the token for the new keyslot,
// and the mode in unlock.conf. The key is never on disk.
func LuksEnrol(o LuksEnrolOptions) error {
	if o.Mode != LuksModePasswordSalt && o.Mode != LuksModePasswordRemoteSalt {
		return fmt.Errorf("--mode must be %s or %s", LuksModePasswordSalt, LuksModePasswordRemoteSalt)
	}
	before := readLuksStatus(o.Device)
	if before.Error != "" {
		return errors.New(before.Error)
	}
	recovery := false
	for _, s := range before.Keyslots {
		if s.Token == nil {
			recovery = true
		}
	}
	if !recovery {
		return fmt.Errorf("%s has no keyslot that is not tpm2-kira's: add a recovery passphrase first (cryptsetup luksAddKey %s)", o.Device, o.Device)
	}

	var key []byte
	slot := 0
	label := ""
	switch o.Mode {
	case LuksModePasswordSalt:
		pw, err := terminalAsk("Password: ")
		if err != nil {
			return err
		}
		defer wipe(pw)
		again, err := terminalAsk("The same password again: ")
		if err != nil {
			return err
		}
		defer wipe(again)
		if !bytes.Equal(pw, again) {
			return errors.New("the passwords differ; nothing was added")
		}
		salt, err := terminalAsk("Salt (asked for at boot the same way): ")
		if err != nil {
			return err
		}
		defer wipe(salt)
		fmt.Fprintln(os.Stderr, "Deriving the key (Argon2id, 1 GiB, a few seconds) ...")
		if key, err = Combine(pw, salt); err != nil {
			return err
		}
	case LuksModePasswordRemoteSalt:
		idx, err := AttestIndexForSlot(o.Remote.SealIndex)
		if err != nil {
			return err
		}
		if _, err := checkRemoteSaltReadyOrEnrolable(o.Remote.TPMPath, idx); err != nil {
			return err
		}
		k, s, err := remoteSaltKey(o.Remote)
		if err != nil {
			return err
		}
		key, slot = k, int(s)
		label = o.Remote.Label
		if label == "" {
			label = "luks"
		}
	}
	defer wipe(key)

	args := []string{"luksAddKey", "--batch-mode"}
	if o.ExistingKeyFile != "" {
		args = append(args, "--key-file", o.ExistingKeyFile)
	}
	args = append(args, o.Device, "-")
	if _, err := cryptsetupTTY(key, args...); err != nil {
		return err
	}
	after := readLuksStatus(o.Device)
	if after.Error != "" {
		return errors.New(after.Error)
	}
	had := map[int]bool{}
	for _, s := range before.Keyslots {
		had[s.Keyslot] = true
	}
	newSlot := -1
	for _, s := range after.Keyslots {
		if !had[s.Keyslot] {
			newSlot = s.Keyslot
		}
	}
	if newSlot < 0 {
		return errors.New("cryptsetup added no keyslot")
	}
	tok := LuksToken{Type: LuksTokenType, Keyslots: []string{strconv.Itoa(newSlot)}, Mode: o.Mode, Created: time.Now().UTC().Format(time.RFC3339)}
	if o.Mode == LuksModePasswordRemoteSalt {
		s := slot
		tok.Slot, tok.Label = &s, label
	}
	b, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	if _, err := cryptsetup(b, "token", "import", "--json-file", "-", o.Device); err != nil {
		return fmt.Errorf("the keyslot %d is added, but its token is not: %w (tpm2-kira luks mark %s --keyslot %d --mode %s)", newSlot, err, o.Device, newSlot, o.Mode)
	}
	fmt.Printf("%s keyslot %d added: %s\n", o.Device, newSlot, describeKeyslot(KeyslotStatus{Keyslot: newSlot, Token: &tok}))
	if !o.NoConfig {
		if err := setUnlockMode(DefaultUnlockConfigPath, o.Mode); err != nil {
			return fmt.Errorf("the keyslot is added; the unlock mode is not set: %w", err)
		}
		fmt.Printf("%s: TPM2_KIRA_UNLOCK=%s\n", DefaultUnlockConfigPath, o.Mode)
	}
	fmt.Println("Rebuild the initramfs (mkinitcpio -P / update-initramfs -u) and the next boot asks")
	fmt.Println("at tpm2-kira's prompt. The recovery passphrase stays the way in at cryptsetup's.")
	return nil
}

// checkRemoteSaltReadyOrEnrolable is checkRemoteSaltReady without the
// release key: a phone enrolled is enough, remoteSaltKey makes the key.
func checkRemoteSaltReadyOrEnrolable(tpmPath string, idx uint32) (bool, error) {
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return false, fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	if _, err := loadAttestBlob(tpmDev, idx); err != nil {
		return false, fmt.Errorf("%w (slot %d has no phone enrolled)", errNoRemoteSalt, attestSlot(idx))
	}
	return true, nil
}

// cryptsetupTTY runs cryptsetup with the key on stdin and the terminal for
// its prompts (an existing passphrase to authorise luksAddKey).
var cryptsetupTTY = func(stdin []byte, args ...string) ([]byte, error) {
	c := exec.Command("cryptsetup", args...)
	c.Stdin = bytes.NewReader(stdin)
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("cryptsetup %s: %w", args[0], err)
	}
	return nil, nil
}

// setUnlockMode writes TPM2_KIRA_UNLOCK=mode into unlock.conf, replacing
// the line or adding it; a missing file is created with the line.
func setUnlockMode(path, mode string) error {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	done := false
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "TPM2_KIRA_UNLOCK=") {
			lines[i] = "TPM2_KIRA_UNLOCK=" + mode
			done = true
		}
	}
	if !done {
		if len(data) == 0 {
			lines = nil
		}
		lines = append(lines, "TPM2_KIRA_UNLOCK="+mode)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// LuksRemoveOptions is what luks remove takes.
type LuksRemoveOptions struct {
	Device  string
	Keyslot int
	// ExistingKeyFile authorises luksKillSlot instead of cryptsetup's
	// prompt for a remaining passphrase (scripts and tests).
	ExistingKeyFile string
}

// LuksRemove takes one of tpm2-kira's keyslots out of the header, with its
// token: 'cryptsetup luksKillSlot', authorised by a remaining passphrase
// (the recovery keyslot's, at cryptsetup's prompt), then 'token remove'.
// A keyslot that is not tpm2-kira's is refused - that is cryptsetup's to
// remove by hand - and so is the last keyslot of the device.
func LuksRemove(o LuksRemoveOptions) error {
	st := readLuksStatus(o.Device)
	if st.Error != "" {
		return errors.New(st.Error)
	}
	var have *KeyslotStatus
	for i := range st.Keyslots {
		if st.Keyslots[i].Keyslot == o.Keyslot {
			have = &st.Keyslots[i]
		}
	}
	if have == nil {
		return fmt.Errorf("%s has no keyslot %d", o.Device, o.Keyslot)
	}
	if have.Token == nil {
		return fmt.Errorf("keyslot %d is not tpm2-kira's; tpm2-kira removes only the keyslots it marked (cryptsetup luksKillSlot %s %d by hand)", o.Keyslot, o.Device, o.Keyslot)
	}
	if len(st.Keyslots) == 1 {
		return fmt.Errorf("keyslot %d is the last keyslot of %s; removing it would make the device unopenable", o.Keyslot, o.Device)
	}
	args := []string{"luksKillSlot"}
	if o.ExistingKeyFile != "" {
		args = append(args, "--batch-mode", "--key-file", o.ExistingKeyFile)
	}
	args = append(args, o.Device, strconv.Itoa(o.Keyslot))
	if _, err := cryptsetupTTY(nil, args...); err != nil {
		return err
	}
	if _, err := cryptsetup(nil, "token", "remove", "--token-id", strconv.Itoa(have.TokenID), o.Device); err != nil {
		return fmt.Errorf("keyslot %d is removed, its token %d is not: %w", o.Keyslot, have.TokenID, err)
	}
	fmt.Printf("%s keyslot %d removed (was %s)\n", o.Device, o.Keyslot, describeKeyslot(*have))
	left := 0
	for _, s := range st.Keyslots {
		if s.Token != nil && s.Keyslot != o.Keyslot {
			left++
		}
	}
	if left == 0 {
		fmt.Printf("No keyslot of %s is tpm2-kira's now. If no other device has one, set\n", o.Device)
		fmt.Printf("TPM2_KIRA_UNLOCK=skip in %s and rebuild the initramfs.\n", DefaultUnlockConfigPath)
	}
	return nil
}
