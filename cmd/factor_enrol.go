package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/matthias/tpm2-kira/attest"
)

// FactorEnrolOptions is what 'factor enrol' takes.
type FactorEnrolOptions struct {
	TPMPath     string
	SealIndex   uint32 // 0 = first enrolled slot
	Label       string // the factor's label, default "luks"
	Out         string // where the derived key goes: a file on tmpfs
	PrivKeyPath string // the signing key, for the release key's first enrolment
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
	label := o.Label
	if label == "" {
		label = "luks"
	}

	idx, err := AttestIndexForSlot(o.SealIndex)
	if err != nil {
		return err
	}
	slot := attestSlot(idx)
	tpmDev, err := OpenTPM(o.TPMPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", o.TPMPath, err)
	}
	defer tpmDev.Close()
	CleanupTPM(tpmDev, o.Debug)

	att, err := loadAttestBlob(tpmDev, idx)
	if err != nil {
		return fmt.Errorf("slot %d has no phone enrolled: run 'tpm2-kira attest enrol' first", slot)
	}
	_, sealed, err := readSlot(tpmDev, idx)
	if err != nil {
		return err
	}

	if len(att.ReleaseKeyPublic) == 0 {
		// The release key goes into the slot's blob, which is signed.
		privKeyPath := o.PrivKeyPath
		if privKeyPath == "" {
			privKeyPath = DefaultPrivateKeyPath
		}
		priv, err := LoadCheckedSigningPrivateKey(privKeyPath)
		if err != nil {
			return fmt.Errorf("the first factor enrolment adds the release key to the slot's blob and needs the signing key: %w", err)
		}
		if err := PrepareSigningKey(priv); err != nil {
			return fmt.Errorf("the signing key is not usable: %w", err)
		}
		pub, privArea, err := createReleaseKey(tpmDev, sealed)
		if err != nil {
			return err
		}
		att.ReleaseKeyPublic, att.ReleaseKeyPrivate = pub, privArea
		if err := writeAttestBlob(tpmDev, idx, att, priv); err != nil {
			return err
		}
		fmt.Printf("Release key created for slot %d, under the slot's policy\n", slot)
	}

	f, w, err := wrapFactor(tpmDev, att, nil)
	if err != nil {
		return err
	}
	defer wipe(f)
	want := FactorSalt(f, label)
	defer wipe(want)

	// The phone keeps the credential in an ordinary check, and returns it
	// after the accepted receipt; the coordinator opens it in the TPM.
	pubKeyPath := o.PubKeyPath
	if pubKeyPath == "" {
		pubKeyPath = DefaultPublicKeyPath
	}
	svc := newGateService(tpmDev, idx, pubKeyPath, o.Debug)
	svc.Keep(&attest.FactorBlob{CredentialBlob: w.Credential, EncryptedSecret: w.EncryptedSecret, Label: label})
	fmt.Println("Open Marify on the phone and verify this machine: the verdict screen asks")
	fmt.Println("to keep the disk factor. Accept the verdict to keep it.")
	code := runGateRadio(svc, GateOptions{TPMPath: o.TPMPath, Adapter: o.Adapter, Timeout: o.Timeout, AdapterWait: o.AdapterWait, Debug: o.Debug}, gateSteps(o.Debug), nil)
	defer svc.Forget()
	got := svc.Salt()
	defer wipe(got)
	if code != 0 || got == nil {
		return fmt.Errorf("the phone did not return the factor (gate exit %d); nothing was enrolled. Check the phone's screen and run this again", code)
	}
	if !bytes.Equal(got, want) {
		return errors.New("the factor the phone returned is not the one it was given; nothing was enrolled")
	}
	fmt.Println("The phone keeps the factor, and this TPM opened it: the round trip works.")

	pw, err := terminalPassword("Password for the disk (the factor's other half): ")
	if err != nil {
		return err
	}
	defer wipe(pw)
	again, err := terminalPassword("The same password again: ")
	if err != nil {
		return err
	}
	defer wipe(again)
	if !bytes.Equal(pw, again) {
		return errors.New("the passwords differ; nothing was written")
	}
	fmt.Fprintln(os.Stderr, "Deriving the key (Argon2id, 1 GiB, a few seconds) ...")
	key, err := Combine(pw, want)
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
	fmt.Println("At boot, once the phone has verified the machine, tpm2-kira asks for the")
	fmt.Println("password and derives this key. The recovery passphrase in its own keyslot")
	fmt.Println("stays the way in without the phone: at systemd's prompt (Ctrl-C at tpm2-kira's).")
	return nil
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
