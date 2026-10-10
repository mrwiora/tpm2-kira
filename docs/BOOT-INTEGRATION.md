# Boot integration in depth

What the hooks put into the initramfs on Arch and Debian, the units and their conditions, the display mode, and how PCR 8/9 are predicted on a GRUB system. The setup steps are in the README.

## What is installed where

The package puts four unit files into `/usr/lib/systemd/system` on the
host, because the mkinitcpio hook takes them from there. None of them is
enabled on the host, and each carries
`ConditionPathExists=/etc/initrd-release`, so enabling one there by mistake
does nothing.

| Unit | In the initramfs image | Does something when |
|------|------------------------|---------------------|
| `tpm2-kira.service` (the code at the prompt, the gate's coordinator, and the key provider for `systemd-cryptsetup`) | always, once `sd-tpm2-kira` is in `HOOKS` | a TOTP key is sealed. With nothing sealed it says so once and releases the boot; a later `seal` needs no rebuild. The gate ends when the boot is released; the process stays to answer the volumes' key requests and ends at switch-root |
| `tpm2-kira-unlock.socket` (the key socket) | always, with the display | `systemd-cryptsetup` activates a volume whose key file is the socket |
| `tpm2-kira-cap.service` (locks codes when the initrd is left) | always, with the display | the initrd is left. Without sealed keys there is nothing to lock |
| `tpm2-kira-attest.service` (Bluetooth gate, radio worker) | only if a phone is enrolled, **and** its record is signed by this machine's key and current, **and** the adapter was found when the image was built. The signing public key goes into the image with it. Otherwise neither the unit nor any Bluetooth module or firmware is in the image; `mkinitcpio` says which condition failed | a phone connects |

One case leaves a unit in the image with nothing to do: `attest unenrol`
without rebuilding the initramfs. The gate then starts at boot, reports that no
phone is enrolled and fails; `unenrol` tells you to rebuild.

The radio worker is the only process that takes input from outside the
machine before the disk is unlocked, so its unit confines it: Bluetooth and
Unix sockets only, the capabilities for the adapter and no others, rfkill and
the console as its only devices and no TPM, a read-only file system, and a
system call filter (`systemd-analyze security` rates the unit 2.2, from 9.4
without).

On Debian there are no units in the image: the initramfs-tools scripts start
the display and, under the same three conditions, the gate, and run `cap` when
the initramfs is left. The split into coordinator and radio worker and the
confinement above apply to systemd-based images only; there the gate is one
process with the TPM, and the phone's verdict does not release the display.

## Display mode

`/etc/tpm2-kira/initramfs.conf` selects what happens at boot:

| `TPM2_KIRA_INITRAMFS_MODE` | Behaviour |
|---|---|
| `run` (default) | Keeps showing codes until the disk is unlocked |
| `once` | Prints a single code and carries on booting |

In `run` mode the display refreshes once per 30-second TOTP window, writing to
the same console as the passphrase prompt. The prompt scrolls up as codes
arrive; typing is unaffected, since the passphrase is not echoed anyway. The
`init-bottom` script stops the process before `run-init` replaces the initramfs,
so nothing is left holding it open, and then runs `tpm2-kira cap`.

Edit the file and run `sudo update-initramfs -u` to apply a change.

## PCR 8 and 9 are predicted for the next boot

GRUB measures every command it runs into PCR 8 and every file it reads
into PCR 9, and the kernel's EFI stub adds its load options and the initrd
to PCR 9. The event log of the running boot is the complete script of
that. After an update only the entries of what changed differ, so
`reseal` replays this boot's log with those entries replaced by what is
on disk now - the way SUSE's `pcr-oracle` does it; neither Debian nor
`systemd-pcrlock` (which knows no GRUB) offers this:

| changed on disk | what is put into the replay |
|---|---|
| the initrd (`update-initramfs`) | its SHA-256, in GRUB's file event and the stub's `Linux initrd` tag |
| a new kernel | the version string in GRUB's `linux`/`initrd`/`echo` commands, the kernel command line and the stub's load options; the kernel's and initrd's SHA-256 |
| `grub.cfg` (`update-grub`) | its SHA-256, and the `menuentry`/`submenu` commands rebuilt from it - GRUB measures them with their whole body |
| `grubenv`, GRUB modules, `.lst` files | their SHA-256 |

The hooks run it: `/etc/initramfs/post-update.d/tpm2-kira` after every
`update-initramfs`, and `/etc/kernel/postinst.d/zzz-tpm2-kira` (also
`postrm.d`) after `zz-update-grub` has written the final `grub.cfg` of a
kernel install or removal. `reseal` prints what it substituted, for
example `PCR9 /initrd.img-6.12.111+deb13-amd64: now /boot/initrd.img-…`.
The next boot then shows a code at once; no boot without one, no second
reseal.

What the prediction cannot know, and what then happens: a different menu
entry chosen at the GRUB menu, a command line edited there, a `grubenv`
the boot rewrites (`GRUB_SAVEDEFAULT`, `recordfail`), or a GRUB package
update that changes the module set. Such a boot shows no code - expected,
not a compromise - and `sudo tpm2-kira reseal` after it binds to the
state you booted, as the reseal always did. The prediction is checked
against this machine's real log in the test suite
(`cmd/grub_predict_test.go`, Debian 13, GRUB 2.12).

Resealing is still never automatic at *boot*: a tampered kernel does not
become a trusted baseline by being booted once. The hooks run on the
unlocked system, after a change you made.
