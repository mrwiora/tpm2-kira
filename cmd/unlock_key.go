package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

// The Debian side of the key provider (initramfs-tools, cryptsetup's
// local-top/cryptroot). There systemd-cryptsetup does not run; a
// keyscript= in crypttab does, and its stdout is the key. The keyscript
// /lib/cryptsetup/scripts/tpm2-kira runs 'tpm2-kira unlock-key <volume>',
// which asks the same socket the same way systemd-cryptsetup would - from
// an abstract address named /cryptsetup/<volume> - and writes the answer
// to stdout. Without the socket (no TPM, 'once' mode, a failure) it
// becomes cryptsetup's own prompt, /lib/cryptsetup/askpass, so the boot
// is never worse than without tpm2-kira. cryptroot's tries= re-runs the
// keyscript after a wrong key, which asks at tpm2-kira's prompt again.

// askpass is cryptsetup-initramfs's prompt, in every Debian initramfs.
const askpass = "/lib/cryptsetup/askpass"

// UnlockKeyCommand writes the key for volume to stdout, from the socket
// (waited for up to wait), or execs askpass in its place.
func UnlockKeyCommand(socket, volume string, wait time.Duration) error {
	if volume == "" {
		return errors.New("unlock-key needs the volume's name (cryptroot sets CRYPTTAB_NAME)")
	}
	key, err := askUnlockSocket(socket, volume, wait)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm2-kira: %v; asking at cryptsetup's prompt\n", err)
		return execAskpass(volume)
	}
	defer wipe(key)
	if _, err := os.Stdout.Write(key); err != nil {
		return err
	}
	return nil
}

// askUnlockSocket connects to the key socket as systemd-cryptsetup does and
// reads the key until EOF. No data is "no key".
func askUnlockSocket(socket, volume string, wait time.Duration) ([]byte, error) {
	deadline := time.Now().Add(wait)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no key socket at %s", socket)
		}
		time.Sleep(100 * time.Millisecond)
	}
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	laddr := &net.UnixAddr{Name: "@" + hex.EncodeToString(r[:]) + "/cryptsetup/" + volume, Net: "unix"}
	c, err := net.DialUnix("unix", laddr, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	key, err := io.ReadAll(c)
	if err != nil {
		return nil, err
	}
	if len(key) == 0 {
		return nil, errors.New("no key for " + volume)
	}
	return key, nil
}

// execAskpass replaces this process with cryptsetup's prompt. askpass
// writes its prompt to stderr and reads the console; the keyscript sends
// this process's stderr to the boot log, so both are pointed at the
// console again first, or the question would be asked unseen.
func execAskpass(volume string) error {
	if _, err := os.Stat(askpass); err != nil {
		return fmt.Errorf("no key, and %s is not there either", askpass)
	}
	if con, err := os.OpenFile("/dev/console", os.O_RDWR, 0); err == nil {
		syscall.Dup2(int(con.Fd()), 0)
		syscall.Dup2(int(con.Fd()), 2)
	}
	return syscall.Exec(askpass, []string{askpass, "Please unlock disk " + volume + ": "}, os.Environ())
}
