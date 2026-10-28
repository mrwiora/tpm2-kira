package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
	"github.com/mrwiora/tpm2-kira/internal/wipe"

	"golang.org/x/sys/unix"
)

// tpm2-kira's keyslots in a LUKS2 header (PLAN-LUKS.md §2): a token of
// type "tpm2-kira" bound to the keyslot says how the key in it is made at
// the prompt. No key material is in it; cryptsetup needs no handler for
// it, since the key comes through the socket or the keyscript, not
// through the token. Read with luksDump --dump-json-metadata, written
// with token import.

// The token's type carries the keyslot's recipe, so a plain 'cryptsetup
// luksDump' tells the two apart ('+' is not allowed in a LUKS2 token
// type - it may name a plugin file - so the type spells the mode out).
const (
	LuksTokenTypeSalt      = "tpm2-kira-salt"      // password+salt
	LuksTokenTypePhoneSalt = "tpm2-kira-phonesalt" // password+phonesalt
	LuksTokenTypeVault     = "tpm2-kira-vault"     // tpm+vault
	// luksTokenTypeOld is the one type of earlier versions, the mode in a
	// field: recognised only to say what to do now - remove it and mark
	// the keyslot anew (Obsolete).
	luksTokenTypeOld = "tpm2-kira"
)

// tokenTypeOf is the type a mode's token is written with.
func tokenTypeOf(mode string) string {
	switch mode {
	case LuksModePasswordPhoneSalt:
		return LuksTokenTypePhoneSalt
	case LuksModeTPMVault:
		return LuksTokenTypeVault
	}
	return LuksTokenTypeSalt
}

// The modes a keyslot's key is made in, as the token names them. The boot
// reads them from the header itself (luks_header.go): there is no
// configured unlock mode any more.
const (
	LuksModePasswordSalt      = "password+salt"      // a typed password and a typed salt, combined
	LuksModePasswordPhoneSalt = "password+phonesalt" // a typed password and the salt a verifier released
	LuksModeTPMVault          = "tpm+vault"          // a local part from the TPM and a remote part from the vault, nothing typed (vault.go)
)

// boundModes are the modes whose keyslot is bound to a slot: its key needs
// what the slot's enrolment releases.
func boundMode(mode string) bool {
	return mode == LuksModePasswordPhoneSalt || mode == LuksModeTPMVault
}

// knownMode says whether mode is one a keyslot can be marked with.
func knownMode(mode string) bool {
	return mode == LuksModePasswordSalt || mode == LuksModePasswordPhoneSalt || mode == LuksModeTPMVault
}

// errMode is the error for a --mode that is none of them.
var errMode = fmt.Errorf("--mode must be %s, %s or %s", LuksModePasswordSalt, LuksModePasswordPhoneSalt, LuksModeTPMVault)

// LuksToken is the token's JSON. Slot is the binding to a tpm2-kira slot
// and is written for password+phonesalt alone: that key needs the salt
// the slot's enrolment releases, so deleting the slot deletes the keyslot
// with it. A password+salt keyslot depends on no slot - no TPM is in its
// key - and carries no binding: it survives every slot and coexists with
// the phone salt keyslot (at boot the phone's salt is tried first, the
// typed salt is the fallback).
type LuksToken struct {
	Type     string   `json:"type"`
	Keyslots []string `json:"keyslots"`
	Slot     *int     `json:"slot,omitempty"` // password+phonesalt: the slot whose salt it needs
	Label    string   `json:"label,omitempty"`
	Created  string   `json:"created"`
	// Mode is the type's meaning, derived when reading: the type carries it.
	Mode string `json:"-"`
	// Obsolete marks the old one-type form: shown so the keyslot can be
	// re-marked, used for nothing else.
	Obsolete bool `json:"-"`
}

// parseKiraToken reads one token's JSON when it is ours: the type carries
// the mode, and the old one-type form is recognised as obsolete.
func parseKiraToken(raw json.RawMessage) (LuksToken, bool) {
	var tok LuksToken
	if err := json.Unmarshal(raw, &tok); err != nil {
		return tok, false
	}
	switch tok.Type {
	case LuksTokenTypeSalt:
		tok.Mode = LuksModePasswordSalt
	case LuksTokenTypePhoneSalt:
		tok.Mode = LuksModePasswordPhoneSalt
	case LuksTokenTypeVault:
		tok.Mode = LuksModeTPMVault
	case luksTokenTypeOld:
		tok.Obsolete = true
	default:
		return tok, false
	}
	return tok, true
}

// BoundTo says whether the keyslot is bound to the given tpm2-kira slot.
// An obsolete token binds nothing: it is re-marked, never acted on.
func (t *LuksToken) BoundTo(slot int) bool {
	return !t.Obsolete && t.Slot != nil && *t.Slot == slot
}

// luksMetadata is the part of luksDump --dump-json-metadata this reads.
type luksMetadata struct {
	Keyslots map[string]struct {
		Type string `json:"type"`
		KDF  struct {
			Salt string `json:"salt"`
		} `json:"kdf"`
	} `json:"keyslots"`
	Tokens map[string]json.RawMessage `json:"tokens"`
}

// cryptsetupPath finds cryptsetup, in the sbin directories too when they
// are not on an unprivileged PATH (Debian).
func cryptsetupPath() string {
	if p, err := exec.LookPath("cryptsetup"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/cryptsetup", "/sbin/cryptsetup"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "cryptsetup"
}

// cryptsetup runs cryptsetup with stdin and returns its output.
var cryptsetup = func(stdin []byte, args ...string) ([]byte, error) {
	c := exec.Command(cryptsetupPath(), args...)
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

// listLuksDevices is luksDevices; tests replace it.
var listLuksDevices = luksDevices

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

// OrphanToken is a token of ours whose keyslots are gone: a leftover.
type OrphanToken struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
}

// KeyslotStatus is one keyslot of a device as luks status reports it.
type KeyslotStatus struct {
	Keyslot int        `json:"keyslot"`
	Token   *LuksToken `json:"token,omitempty"` // nil: not tpm2-kira's
	TokenID int        `json:"token_id,omitempty"`
	Salt    string     `json:"-"` // the KDF's salt: new with every passphrase the keyslot gets
}

// LuksDeviceStatus is one device.
type LuksDeviceStatus struct {
	Device   string          `json:"device"`
	Keyslots []KeyslotStatus `json:"keyslots"`
	Orphans  []OrphanToken   `json:"orphan_tokens,omitempty"` // tokens of ours whose keyslots are gone
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
	slots, orphans, err := parseLuksMetadata(out)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.Keyslots, st.Orphans = slots, orphans
	return st
}

func parseLuksMetadata(out []byte) ([]KeyslotStatus, []OrphanToken, error) {
	var md luksMetadata
	if err := json.Unmarshal(out, &md); err != nil {
		return nil, nil, fmt.Errorf("the header's metadata does not parse (LUKS2 only): %w", err)
	}
	byKeyslot := map[string]KeyslotStatus{}
	for num, ks := range md.Keyslots {
		n, _ := strconv.Atoi(num)
		byKeyslot[num] = KeyslotStatus{Keyslot: n, Salt: ks.KDF.Salt}
	}
	var orphans []OrphanToken
	for id, raw := range md.Tokens {
		tok, ok := parseKiraToken(raw)
		if !ok {
			continue
		}
		tid, _ := strconv.Atoi(id)
		assigned := false
		for _, ks := range tok.Keyslots {
			if s, ok := byKeyslot[ks]; ok {
				t := tok
				s.Token, s.TokenID = &t, tid
				byKeyslot[ks] = s
				assigned = true
			}
		}
		if !assigned {
			// A token whose keyslots are gone: a leftover of a kill that
			// skipped the token, to be removed by name.
			orphans = append(orphans, OrphanToken{ID: tid, Type: tok.Type})
		}
	}
	var slots []KeyslotStatus
	for _, s := range byKeyslot {
		slots = append(slots, s)
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].Keyslot < slots[j].Keyslot })
	sort.Slice(orphans, func(i, j int) bool { return orphans[i].ID < orphans[j].ID })
	return slots, orphans, nil
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
	if t.Obsolete {
		return fmt.Sprintf("tpm2-kira, an old token (type %s): remove it and mark the keyslot anew - cryptsetup token remove --token-id %d <device>, then tpm2-kira luks mark", luksTokenTypeOld, s.TokenID)
	}
	switch t.Mode {
	case LuksModePasswordSalt:
		return fmt.Sprintf("tpm2-kira, password+salt: a typed password and a typed salt, bound to no slot (token %d, %s)", s.TokenID, t.Created)
	case LuksModePasswordPhoneSalt:
		slot := "?"
		if t.Slot != nil {
			slot = strconv.Itoa(*t.Slot)
		}
		return fmt.Sprintf("tpm2-kira, password+phonesalt: a typed password and the verifier's salt, bound to slot %s, label %q (token %d, %s)", slot, t.Label, s.TokenID, t.Created)
	case LuksModeTPMVault:
		slot := "?"
		if t.Slot != nil {
			slot = strconv.Itoa(*t.Slot)
		}
		return fmt.Sprintf("tpm2-kira, tpm+vault: the TPM's local part and the vault's remote part, nothing typed, bound to slot %s, label %q (token %d, %s)", slot, t.Label, s.TokenID, t.Created)
	}
	return fmt.Sprintf("tpm2-kira, mode %q (token %d)", t.Mode, s.TokenID)
}

// LuksMarkOptions is what luks mark takes.
type LuksMarkOptions struct {
	TPMPath   string
	Device    string
	Keyslot   int
	Mode      string
	SealIndex uint32 // the slot the keyslot is bound to (password+phonesalt: the slot whose phone salt it is)
	Label     string
	Debug     bool
}

// errNoPhoneSalt: password+phonesalt is only ever available with an
// attestation set up: a verifier enrolled for the slot, and the slot's
// phone salt enrolled with it.
var errNoPhoneSalt = errors.New("password+phonesalt needs an attestation: a phone enrolled for the slot ('tpm2-kira phone enrol') and the phone salt enrolled with it ('tpm2-kira phonesalt enrol')")

// boundSlotIndex resolves the slot a keyslot is bound to - a slot number or
// a blob index - to the blob index, refusing anything outside the sixteen
// slots: a keyslot is deleted with its slot, so it must name one.
func boundSlotIndex(sealIndex uint32) (uint32, error) {
	idx := nvslot.ResolveNVRAMIndex(sealIndex)
	if idx < nvslot.NVRAMSlotStart || idx > nvslot.NVRAMSlotEnd {
		return 0, fmt.Errorf("a keyslot is bound to one of the sixteen slots (0-15), got 0x%08X", idx)
	}
	return idx, nil
}

// checkRemoteSaltReady says whether the slot can release a phone salt at
// all: a verifier is enrolled and the release key exists.
func checkRemoteSaltReady(tpmPath string, sealIndex uint32) error {
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	att, err := loadAttestBlob(tpmDev, sealIndex)
	if err != nil {
		return fmt.Errorf("%w (slot %d has no phone enrolled)", errNoPhoneSalt, nvslot.AttestSlot(sealIndex))
	}
	if len(att.ReleaseKeyPublic) == 0 {
		return fmt.Errorf("%w (slot %d has no release key yet)", errNoPhoneSalt, nvslot.AttestSlot(sealIndex))
	}
	return nil
}

// checkVaultReady says whether the slot is enrolled with a vault, and
// returns the label its key is derived with.
func checkVaultReady(tpmPath string, sealIndex uint32) (string, error) {
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return "", fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	_, sb, err := readSlot(tpmDev, sealIndex)
	if err != nil || sb.Payload.Attestation == nil || !sb.Payload.Attestation.Vault.Enabled() {
		return "", fmt.Errorf("slot %d is not enrolled with a vault: tpm2-kira vault enrol first, or luks enrol --mode %s", nvslot.AttestSlot(sealIndex), LuksModeTPMVault)
	}
	return sb.Payload.Attestation.Vault.Label, nil
}

// LuksMark writes the token for an existing keyslot. A password+phonesalt
// or tpm+vault keyslot is bound to the slot whose release it needs
// (--nvram, slot 0 unless named), which must be able to give one
// (checkRemoteSaltReady, checkVaultReady); a password+salt keyslot is
// bound to nothing.
func LuksMark(o LuksMarkOptions) error {
	device, keyslot, mode, label := o.Device, o.Keyslot, o.Mode, o.Label
	if !knownMode(mode) {
		return errMode
	}
	slot := 0
	if boundMode(mode) {
		idx, err := boundSlotIndex(o.SealIndex)
		if err != nil {
			return err
		}
		slot = nvslot.SlotNumber(idx)
		if mode == LuksModeTPMVault {
			// The label is the vault method's: the key was derived with it.
			if label, err = checkVaultReady(o.TPMPath, idx); err != nil {
				return err
			}
		} else if err := checkRemoteSaltReady(o.TPMPath, idx); err != nil {
			return err
		}
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
	if have.Token != nil && have.Token.Obsolete {
		return fmt.Errorf("keyslot %d carries the old token type %s: cryptsetup token remove --token-id %d %s, then mark it anew", keyslot, luksTokenTypeOld, have.TokenID, device)
	}
	if have.Token != nil {
		return fmt.Errorf("keyslot %d is marked already (token %d, %s); remove it first: tpm2-kira luks remove", keyslot, have.TokenID, have.Token.Mode)
	}
	tok := LuksToken{Type: tokenTypeOf(mode), Keyslots: []string{strconv.Itoa(keyslot)}, Mode: mode, Created: time.Now().UTC().Format(time.RFC3339)}
	if boundMode(mode) {
		tok.Slot = &slot
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
	Remote          FactorEnrolOptions // password+phonesalt: the slot, the phone, the keys
	Vault           VaultEnrolOptions  // tpm+vault: the slot, the vault, the keys
}

// terminalAsk asks on the terminal; tests replace it.
var terminalAsk = terminalPassword

// terminalAskExisting asks for a passphrase the device has already, which
// may be empty: a disk encrypted with an empty passphrase is authorised by
// Enter alone (control flags such a disk as a risk). Tests replace it.
var terminalAskExisting = func(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := readPassphrase(os.Stdin, int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return pw, err
}

// LuksEnrol adds a keyslot whose key tpm2-kira makes at boot (PLAN-LUKS.md
// §3): the password (and the salt, or the phone salt's round trip with
// the phone), the derivation, 'cryptsetup luksAddKey' with the key on its
// stdin and an existing passphrase, asked at the prompt, in a memfd - the
// recovery keyslot the device must have, its passphrase empty or not - the
// token for the new keyslot. The key is never on disk.
func LuksEnrol(o LuksEnrolOptions) error {
	if !knownMode(o.Mode) {
		return errMode
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
		defer wipe.Bytes(pw)
		again, err := terminalAsk("The same password again: ")
		if err != nil {
			return err
		}
		defer wipe.Bytes(again)
		if !bytes.Equal(pw, again) {
			return errors.New("the passwords differ; nothing was added")
		}
		salt, err := terminalAsk("Salt (asked for at boot the same way): ")
		if err != nil {
			return err
		}
		defer wipe.Bytes(salt)
		fmt.Fprintln(os.Stderr, "Deriving the key (Argon2id, 1 GiB, a few seconds) ...")
		if key, err = Combine(pw, salt); err != nil {
			return err
		}
	case LuksModePasswordPhoneSalt:
		idx, err := boundSlotIndex(o.Remote.SealIndex)
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
	case LuksModeTPMVault:
		k, s, err := vaultEnrolKey(o.Vault)
		if err != nil {
			return err
		}
		key, slot = k, int(s)
		label = o.Vault.Label
		if label == "" {
			label = "luks"
		}
	}
	defer wipe.Bytes(key)

	existing, err := existingPassphrase(o.Device, o.ExistingKeyFile)
	if err != nil {
		return err
	}
	defer wipe.Bytes(existing)
	if _, err := cryptsetupAuth(key, existing, "luksAddKey", "--batch-mode", "--key-file", existingFD, o.Device, "-"); err != nil {
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
	tok := LuksToken{Type: tokenTypeOf(o.Mode), Keyslots: []string{strconv.Itoa(newSlot)}, Mode: o.Mode, Created: time.Now().UTC().Format(time.RFC3339)}
	if boundMode(o.Mode) {
		tok.Slot, tok.Label = &slot, label
	}
	b, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	if _, err := cryptsetup(b, "token", "import", "--json-file", "-", o.Device); err != nil {
		return fmt.Errorf("the keyslot %d is added, but its token is not: %w (tpm2-kira luks mark %s --keyslot %d --mode %s)", newSlot, err, o.Device, newSlot, o.Mode)
	}
	fmt.Printf("%s keyslot %d added: %s\n", o.Device, newSlot, describeKeyslot(KeyslotStatus{Keyslot: newSlot, Token: &tok}))
	// Nothing is configured: at boot the key provider reads the token just
	// written and asks accordingly. Only the route must be in place.
	if advice := RouteAdvice(o.Device); advice != "" {
		fmt.Print(advice)
	}
	if o.Mode == LuksModeTPMVault && o.Vault.Pepper {
		fmt.Println("Every boot waits until an operator approves it on the vault with the pepper;")
		fmt.Println("without that, the recovery passphrase stays the way in at cryptsetup's own prompt.")
		return nil
	}
	if o.Mode == LuksModeTPMVault {
		fmt.Println("The next boot opens it unattended, with the vault's remote part; without it, the")
		fmt.Println("recovery passphrase stays the way in at cryptsetup's own prompt.")
		return nil
	}
	fmt.Println("The next boot asks at tpm2-kira's prompt; the recovery passphrase stays the")
	fmt.Println("way in at cryptsetup's own.")
	return nil
}

// checkRemoteSaltReadyOrEnrolable is checkRemoteSaltReady without the
// release key: a phone enrolled is enough, remoteSaltKey makes the key.
func checkRemoteSaltReadyOrEnrolable(tpmPath string, idx uint32) (bool, error) {
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return false, fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	if _, err := loadAttestBlob(tpmDev, idx); err != nil {
		return false, fmt.Errorf("%w (slot %d has no phone enrolled)", errNoPhoneSalt, nvslot.AttestSlot(idx))
	}
	return true, nil
}

// existingFD is where cryptsetupAuth puts the existing passphrase: a
// memfd on descriptor 3, named by --key-file. cryptsetup reads a
// passphrase from stdin when stdin is not a terminal, and stdin carries
// the new key ('-'), so the two must not share it. A memfd and not a pipe:
// cryptsetup refuses an empty pipe ("Nothing to read on input") but reads
// an empty regular file as the empty passphrase, and the memfd is one that
// lives in memory alone.
const existingFD = "/dev/fd/3"

// existingPassphrase is a passphrase of one of the device's other
// keyslots, which cryptsetup wants before it changes the header: from the
// file named (scripts), else asked on the terminal. Without a trailing
// newline, which --key-file would take as part of it. Empty is a
// passphrase too: cryptsetup takes an empty one from the pipe.
func existingPassphrase(device, file string) ([]byte, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	return terminalAskExisting("An existing passphrase of " + device + " (the recovery passphrase; Enter alone for an empty one), to authorise: ")
}

// existingFile is the existing passphrase as a memfd read from its start
// (existingFD says why not a pipe).
func existingFile(existing []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate("tpm2-kira-existing", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	f := os.NewFile(uintptr(fd), "existing")
	if _, err := f.Write(existing); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// emptyPassphraseOpens says whether a keyslot of the device opens with an
// empty passphrase - cryptsetup's own test, one key derivation, the empty
// passphrase in the memfd, as existingPassphrase hands it.
var emptyPassphraseOpens = func(device string, keyslot int) (bool, error) {
	r, err := existingFile(nil)
	if err != nil {
		return false, err
	}
	defer r.Close()
	c := exec.Command(cryptsetupPath(), "open", "--test-passphrase", "--key-slot", strconv.Itoa(keyslot), "--key-file", existingFD, device)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	c.ExtraFiles = []*os.File{r}
	err = c.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &exit) && exit.ExitCode() == 2: // no key with this passphrase
		return false, nil
	}
	return false, fmt.Errorf("cryptsetup open --test-passphrase: %v: %s", err, strings.TrimSpace(stderr.String()))
}

// cryptsetupAuth runs cryptsetup with key on stdin (nil: nothing) and
// existing on descriptor 3 (existingFD), its messages on stderr.
var cryptsetupAuth = func(key, existing []byte, args ...string) ([]byte, error) {
	r, err := existingFile(existing)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	c := exec.Command(cryptsetupPath(), args...)
	c.Stdin = bytes.NewReader(key)
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	c.ExtraFiles = []*os.File{r}
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("cryptsetup %s: %w", args[0], err)
	}
	return nil, nil
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
// (the recovery keyslot's, asked at the prompt), then 'token remove'.
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
	existing, err := existingPassphrase(o.Device, o.ExistingKeyFile)
	if err != nil {
		return err
	}
	defer wipe.Bytes(existing)
	if err := killKeyslot(o.Device, *have, existing); err != nil {
		return err
	}
	fmt.Printf("%s keyslot %d removed (was %s)\n", o.Device, o.Keyslot, describeKeyslot(*have))
	left := 0
	for _, s := range st.Keyslots {
		if s.Token != nil && s.Keyslot != o.Keyslot {
			left++
		}
	}
	if left == 0 {
		fmt.Printf("No keyslot of %s is tpm2-kira's now: the next boot goes to cryptsetup's own\n", o.Device)
		fmt.Println("prompt for it - the provider reads that from the header, nothing to set.")
	}
	return nil
}

// killKeyslot takes one keyslot of tpm2-kira's out of the header with its
// token: 'cryptsetup luksKillSlot', authorised by a remaining passphrase on
// existing, then 'token remove'.
func killKeyslot(device string, ks KeyslotStatus, existing []byte) error {
	if _, err := cryptsetupAuth(nil, existing, "luksKillSlot", "--batch-mode", "--key-file", existingFD, device, strconv.Itoa(ks.Keyslot)); err != nil {
		return err
	}
	if _, err := cryptsetup(nil, "token", "remove", "--token-id", strconv.Itoa(ks.TokenID), device); err != nil {
		return fmt.Errorf("keyslot %d is removed, its token %d is not: %w", ks.Keyslot, ks.TokenID, err)
	}
	return nil
}
