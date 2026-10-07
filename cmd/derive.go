package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

// DeriveCommand is hashpwd2 by hand: the password and the salt asked on
// the terminal, their combination written to a file on tmpfs for
// 'cryptsetup luksAddKey', so a keyslot can be enrolled for the password+salt
// mode of unlock.conf without a phone. The same bytes hashpwd2 itself
// would print; nothing is kept.
func DeriveCommand(out string) error {
	if out == "" {
		return errors.New("--out PATH is required: the derived key is written there, on tmpfs, for cryptsetup luksAddKey")
	}
	if err := checkKeyOut(out); err != nil {
		return err
	}
	pw, err := terminalPassword("Password: ")
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
	salt, err := terminalPassword("Salt (asked for at boot the same way): ")
	if err != nil {
		return err
	}
	defer wipe(salt)
	fmt.Fprintln(os.Stderr, "Deriving the key (Argon2id, 1 GiB, a few seconds) ...")
	key, err := Combine(pw, salt)
	if err != nil {
		return err
	}
	defer wipe(key)
	if err := writeKeyOut(out, key); err != nil {
		return err
	}
	fmt.Printf("Key written to %s\n\n", out)
	fmt.Println("Next steps - tpm2-kira does not touch your keyslots:")
	fmt.Printf("    cryptsetup luksAddKey <device> %s\n", out)
	fmt.Printf("    cryptsetup open --test-passphrase <device> --key-file %s\n", out)
	fmt.Printf("    rm %s\n", out)
	fmt.Println()
	fmt.Println("Then mark the keyslot (tpm2-kira luks mark <device> --keyslot N --mode password+salt),")
	fmt.Println("set TPM2_KIRA_UNLOCK=password+salt in /etc/tpm2-kira/unlock.conf and rebuild the")
	fmt.Println("initramfs: at boot tpm2-kira asks for the password and the salt and derives this")
	fmt.Println("key. Keep a recovery passphrase in another keyslot; it works at cryptsetup's prompt.")
	return nil
}
