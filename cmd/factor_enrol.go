package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mrwiora/tpm2-kira/attest"
)

// FactorEnrolOptions is what 'remote-salt enrol' takes.
type FactorEnrolOptions struct {
	TPMPath     string
	SealIndex   uint32 // slot (0-15) or its NVRAM index; 0 is slot 0
	Rotate      bool   // a new factor for a slot that has one: the old keyslot is to go
	Label       string // the factor's label, default "luks"
	Out         string // where the derived key goes: a file on tmpfs
	PrivKeyPath string // the signing key: every hand-over needs it
	PubKeyPath  string // the signing public key, for the gate's record check
	Adapter     int
	Timeout     time.Duration
	AdapterWait time.Duration
	Yes         bool // the recovery keyslot exists, no question asked
	Debug       bool
}

// FactorEnrol gives the enrolled phone a factor to keep and derives the
// disk's key from it and the password, once, for 'cryptsetup luksAddKey'
// (PLAN-FACTORRELEASE.md §6). The release key is made for the slot when it
// has none; F is drawn and wrapped for this TPM's EK and that key; the
// phone is asked to keep the credential in an ordinary check (the verdict
// screen says so); the phone returns it after the accepted receipt, the
// TPM opens it, and only if what came back is F does anything go on. The
// machine keeps nothing: not F, not the credential, not the key.
func FactorEnrol(o FactorEnrolOptions) error {
	if o.Out == "" {
		return errors.New("--out PATH is required: the derived key is written there, on tmpfs, for cryptsetup luksAddKey")
	}
	if err := checkKeyOut(o.Out); err != nil {
		return err
	}
	if !o.Yes && !confirmRecoveryKeyslot() {
		return errors.New("add a recovery passphrase to a second LUKS keyslot first (cryptsetup luksAddKey <device>), then run this again")
	}
	key, _, err := remoteSaltKey(o)
	if err != nil {
		return err
	}
	defer wipe(key)
	if err := writeKeyOut(o.Out, key); err != nil {
		return err
	}

	fmt.Printf("\nKey written to %s\n\n", o.Out)
	fmt.Println("Next steps - tpm2-kira does not touch your keyslots:")
	fmt.Printf("    cryptsetup luksAddKey <device> %s\n", o.Out)
	fmt.Printf("    cryptsetup open --test-passphrase <device> --key-file %s\n", o.Out)
	fmt.Printf("    rm %s\n", o.Out)
	fmt.Println()
	if o.Rotate {
		fmt.Println("The phone now keeps the new remote salt and no longer has the old one. Remove the")
		fmt.Println("old keyslot once the new one is in place (cryptsetup luksKillSlot <device> N;")
		fmt.Println("'cryptsetup luksDump' lists them), or the old key stays valid for whoever")
		fmt.Println("captured the old salt.")
		fmt.Println()
	}
	fmt.Println("Then: tpm2-kira luks mark <device> --keyslot N --mode password+remotesalt, set")
	fmt.Println("TPM2_KIRA_UNLOCK=password+remotesalt in /etc/tpm2-kira/control.conf and rebuild the")
	fmt.Println("initramfs. At boot, once the phone has verified the machine, tpm2-kira asks for")
	fmt.Println("the password and derives this key. The recovery passphrase in its own keyslot")
	fmt.Println("stays the way in without the phone: at cryptsetup's prompt (Ctrl-C at tpm2-kira's).")
	return nil
}

// remoteSaltKey does the enrolment up to the derived key: the release key
// if the slot has none, F wrapped for this TPM, the phone asked to keep
// it and handing it back, the TPM opening it, then the password and the
// derivation. Returns the key (the caller wipes it) and the slot number.
func remoteSaltKey(o FactorEnrolOptions) ([]byte, uint32, error) {
	label := o.Label
	if label == "" {
		label = "luks"
	}

	idx, err := AttestIndexForSlot(o.SealIndex)
	if err != nil {
		return nil, 0, err
	}
	slot := attestSlot(idx)
	tpmDev, err := OpenTPM(o.TPMPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open TPM at %s: %w", o.TPMPath, err)
	}
	defer tpmDev.Close()
	CleanupTPM(tpmDev, o.Debug)

	att, err := loadAttestBlob(tpmDev, idx)
	if err != nil {
		return nil, 0, fmt.Errorf("slot %d has no phone enrolled: run 'tpm2-kira attest enrol' first", slot)
	}
	_, sealed, err := readSlot(tpmDev, idx)
	if err != nil {
		return nil, 0, err
	}

	if o.Rotate && len(att.ReleaseKeyPublic) == 0 {
		return nil, 0, fmt.Errorf("slot %d has no remote salt to rotate; use 'remote-salt enrol'", slot)
	}

	// Every hand-over needs the signing key, as reseal does: with the key
	// on a YubiKey, the token and its PIN; with local key files, root. The
	// first one also puts the release key into the slot's blob, which is
	// signed; a later one replaces what the phone keeps, which is the
	// owner's act, not root's alone.
	privKeyPath := o.PrivKeyPath
	if privKeyPath == "" {
		privKeyPath = DefaultPrivateKeyPath
	}
	priv, err := LoadCheckedSigningPrivateKey(privKeyPath)
	if err != nil {
		return nil, 0, fmt.Errorf("a remote salt is given to the phone with the signing key only: %w", err)
	}
	if err := PrepareSigningKey(priv); err != nil {
		return nil, 0, fmt.Errorf("the signing key is not usable: %w", err)
	}
	if len(att.ReleaseKeyPublic) == 0 {
		pub, privArea, err := createReleaseKey(tpmDev, sealed)
		if err != nil {
			return nil, 0, err
		}
		att.ReleaseKeyPublic, att.ReleaseKeyPrivate = pub, privArea
		if err := writeAttestBlob(tpmDev, idx, att, priv); err != nil {
			return nil, 0, err
		}
		fmt.Printf("Release key created for slot %d, under the slot's policy\n", slot)
	}

	f, w, err := wrapFactor(tpmDev, att, nil)
	if err != nil {
		return nil, 0, err
	}
	defer wipe(f)
	want := FactorSalt(f, label)
	defer wipe(want)

	// The phone keeps the credential in an ordinary check of the booted
	// system (the quote says which boot this is; the boot key is locked
	// until the next boot, so there is no code), and returns it after the
	// accepted receipt. The TPM opens it at the next boot, in the initrd,
	// where the slot's policy holds; here the salt is known in the clear.
	pubKeyPath := o.PubKeyPath
	if pubKeyPath == "" {
		pubKeyPath = DefaultPublicKeyPath
	}
	svc := newGateService(tpmDev, idx, pubKeyPath, o.Debug)
	svc.Keep(&attest.FactorBlob{CredentialBlob: w.Credential, EncryptedSecret: w.EncryptedSecret, Label: label})
	fmt.Println("Open Marify on the phone and verify this machine: the verdict screen asks")
	fmt.Println("to keep the remote salt (no code: after boot the boot key is locked). Continue")
	fmt.Println("to keep it.")
	code := runGateRadio(svc, GateOptions{TPMPath: o.TPMPath, Adapter: o.Adapter, Timeout: o.Timeout, AdapterWait: o.AdapterWait, Debug: o.Debug}, gateSteps(o.Debug), nil)
	defer svc.Forget()
	if code != 0 || !svc.Returned() {
		return nil, 0, fmt.Errorf("the phone did not return the remote salt (gate exit %d); nothing was enrolled. Check the phone's screen and run this again", code)
	}
	fmt.Println("The phone keeps the remote salt and gave it back unchanged. This TPM opens it at")
	fmt.Println("the next boot, under the slot's policy; the boot log says so.")

	pw, err := terminalPassword("Password for the disk (the factor's other half): ")
	if err != nil {
		return nil, 0, err
	}
	defer wipe(pw)
	again, err := terminalPassword("The same password again: ")
	if err != nil {
		return nil, 0, err
	}
	defer wipe(again)
	if !bytes.Equal(pw, again) {
		return nil, 0, errors.New("the passwords differ; nothing was written")
	}
	fmt.Fprintln(os.Stderr, "Deriving the key (Argon2id, 1 GiB, a few seconds) ...")
	key, err := Combine(pw, want)
	if err != nil {
		return nil, 0, err
	}
	return key, slot, nil
}

// confirmRecoveryKeyslot asks, on the terminal, whether the recovery
// passphrase is in place; the factor's keyslot must never be the only one.
func confirmRecoveryKeyslot() bool {
	fmt.Print("Does the volume have a recovery passphrase in a second LUKS keyslot,\n" +
		"one that is not this password? Without it, a lost phone locks you out. [y/N]: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}

// terminalPassword asks on the terminal, echo off.
func terminalPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := readPassphrase(os.Stdin, int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		return nil, errors.New("an empty password is not a password")
	}
	return pw, nil
}

// checkKeyOut refuses a key file anywhere but on tmpfs or ramfs, in a
// directory root owns that others cannot enter.
func checkKeyOut(path string) error {
	dir := filepath.Dir(path)
	var fs unix.Statfs_t
	if err := unix.Statfs(dir, &fs); err != nil {
		return fmt.Errorf("--out: %s: %w", dir, err)
	}
	if fs.Type != unix.TMPFS_MAGIC && fs.Type != unix.RAMFS_MAGIC {
		return fmt.Errorf("--out: %s is not on tmpfs or ramfs; the key must not touch a disk (use /run)", dir)
	}
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 || st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("--out: %s must be owned by root and not group- or world-accessible (mkdir -m 700)", dir)
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("--out: %s exists; remove it first", path)
	}
	return nil
}

// writeKeyOut writes the key to a temporary file and renames it into place.
func writeKeyOut(path string, key []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// FactorStatus reports, per slot, whether a factor is enrolled on the
// machine's side: the release key in the slot's blob. The factor itself
// is the phone's; the machine keeps nothing of it, so nothing more can be
// said here. --json for scripts.
func FactorStatus(tpmPath string, sealIndex uint32, jsonOut bool, debug bool) error {
	tpmDev, err := OpenTPM(tpmPath)
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
	type slotJSON struct {
		Slot       int    `json:"slot_number"`
		NVRAMIndex string `json:"nvram_index"`
		ReleaseKey bool   `json:"release_key"`
		Phones     int    `json:"phones"`
	}
	var out []slotJSON
	for _, idx := range indices {
		b, err := loadAttestBlob(tpmDev, idx)
		if err != nil {
			if sealIndex != 0 {
				return fmt.Errorf("slot %d has no phone enrolled", attestSlot(idx))
			}
			continue
		}
		out = append(out, slotJSON{Slot: int(attestSlot(idx)), NVRAMIndex: fmt.Sprintf("0x%08X", idx),
			ReleaseKey: len(b.ReleaseKeyPublic) > 0, Phones: len(b.Phone.Verifiers)})
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if out == nil {
			out = []slotJSON{}
		}
		return enc.Encode(out)
	}
	if len(out) == 0 {
		fmt.Println("No slot has a phone enrolled; a remote salt needs one ('tpm2-kira attest enrol').")
		return nil
	}
	for _, s := range out {
		if s.ReleaseKey {
			fmt.Printf("Slot %d (%s): remote salt enrolled - the release key is in the slot's blob; the\n"+
				"  factor itself is kept by the phone (%d enrolled) and opened by this TPM at boot\n", s.Slot, s.NVRAMIndex, s.Phones)
		} else {
			fmt.Printf("Slot %d (%s): no remote salt ('tpm2-kira remote-salt enrol --out /run/tpm2-kira/luks.key')\n", s.Slot, s.NVRAMIndex)
		}
	}
	return nil
}

// FactorUnenrol takes the release key out of the slot's blob: what the
// phone keeps can then not be opened by any TPM, and the factor's keyslot
// is dead weight the user removes by hand. Needs the signing key, like
// every rewrite of the blob.
func FactorUnenrol(tpmPath string, sealIndex uint32, privKeyPath string, debug bool) error {
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
	att, err := loadAttestBlob(tpmDev, idx)
	if err != nil {
		return fmt.Errorf("slot %d has no phone enrolled", slot)
	}
	if len(att.ReleaseKeyPublic) == 0 {
		return fmt.Errorf("slot %d has no remote salt enrolled", slot)
	}
	if privKeyPath == "" {
		privKeyPath = DefaultPrivateKeyPath
	}
	priv, err := LoadCheckedSigningPrivateKey(privKeyPath)
	if err != nil {
		return fmt.Errorf("removing the remote salt rewrites the slot's blob and needs the signing key: %w", err)
	}
	if err := PrepareSigningKey(priv); err != nil {
		return fmt.Errorf("the signing key is not usable: %w", err)
	}
	att.ReleaseKeyPublic, att.ReleaseKeyPrivate = nil, nil
	if err := writeAttestBlob(tpmDev, idx, att, priv); err != nil {
		return err
	}
	fmt.Printf("Remote salt removed from slot %d: the release key is gone, so what the phone keeps\n", slot)
	fmt.Println("cannot be opened any more (it answers \"takes no remote salt\" at the next check).")
	fmt.Println("Remove the salt's keyslot by hand: cryptsetup luksKillSlot <device> N")
	fmt.Println("('cryptsetup luksDump' lists them). The recovery passphrase stays.")
	return nil
}
