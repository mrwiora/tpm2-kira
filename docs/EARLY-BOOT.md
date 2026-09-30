# Early boot integration

tpm2-kira earns its keep before the disk is unlocked: it shows a TOTP code while
the passphrase prompt is on screen, so the boot chain can be checked before the
passphrase is typed. That means getting the binary into the initramfs and running
it at the right moment, which differs between the two initramfs generators.

The two platforms diverge in more than plumbing. Arch's systemd initramfs has the
measure-point units and usually a unified kernel image, so PCR 11 is available and
a reseal can happen before rebooting. Debian's initramfs has no systemd and no
UKI, GRUB carries the equivalent measurements in PCRs 8 and 9, and every PCR
source is read from the running system — so a reseal there has to follow the
reboot, not precede it.

See [PCR-SELECTION.md](PCR-SELECTION.md) for what to seal against, and
[SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md) §5.6 for why the measure point
matters.

---

## Arch Linux (mkinitcpio)

tpm2-kira can display TOTP codes during early boot — before you enter your disk encryption passphrase. This way you can verify the system hasn't been tampered with before typing your LUKS password.

### Install the hooks

```bash
sudo make install-mkinitcpio
```

This installs:
- `sd-tpm2-kira` — mkinitcpio install hook (systemd-based initramfs)
- A **post-generation hook** that automatically runs `tpm2-kira reseal` after every initramfs rebuild

### Configure mkinitcpio

Edit `/etc/mkinitcpio.conf` and add the hook **before** your encrypt hook:

```bash
# Systemd-based initramfs (recommended):
HOOKS=(base systemd autodetect modconf block keyboard sd-tpm2-kira sd-encrypt filesystems fsck)
```

Then rebuild:

```bash
sudo mkinitcpio -P
```

The post-generation hook will automatically reseal so the next boot matches.

### How it works at boot

A systemd service (`tpm2-kira.service`) starts before the disk unlock prompt and runs `tpm2-kira run`, which continuously displays TOTP codes. Compare what's on screen with your authenticator app. If they match, your boot chain is clean — go ahead and type your LUKS passphrase.

See [initramfs/mkinitcpio/mkinitcpio.conf.example](../initramfs/mkinitcpio/mkinitcpio.conf.example) for more HOOKS configurations (LVM, multiple encrypted devices, etc.).

## Debian and Ubuntu (initramfs-tools)

Debian's stock initramfs has no systemd in it, so the systemd unit used on Arch
does not apply. The `.deb` installs two scripts instead:

| Path | Role |
|---|---|
| `/usr/share/initramfs-tools/hooks/tpm2-kira` | copies the binary into the image |
| `/usr/share/initramfs-tools/scripts/init-premount/tpm2-kira` | starts the display at boot |
| `/usr/share/initramfs-tools/scripts/init-bottom/tpm2-kira` | stops it before the real root takes over |
| `/etc/tpm2-kira/initramfs.conf` | display mode |

`/init` runs `init-premount` before `local-top/cryptroot` asks for the
passphrase, which is what puts the code on screen first.

### Display mode

`/etc/tpm2-kira/initramfs.conf` selects what happens at boot:

| `TPM2_KIRA_INITRAMFS_MODE` | Behaviour |
|---|---|
| `run` (default) | Keeps showing codes until the disk is unlocked |
| `once` | Prints a single code and carries on booting |

In `run` mode the display refreshes once per 30-second TOTP window, writing to
the same console as the passphrase prompt. The prompt scrolls up as codes
arrive; typing is unaffected, since the passphrase is not echoed anyway. The
`init-bottom` script stops the process before `run-init` replaces the initramfs,
so nothing is left holding it open.

Edit the file and run `sudo update-initramfs -u` to apply a change.

### Choosing PCRs on Debian

There is no UKI, so PCR 11 is empty and the `11u` and `11e` sources do not
apply. GRUB carries the equivalent measurements instead:

| PCR | Measures | Changes when |
|---|---|---|
| 0, 2 | firmware code and option ROMs | firmware update |
| 4 | the GRUB EFI binary the firmware loaded | `grub-install`, shim/GRUB package update |
| 7 | Secure Boot state and policy | key rotation, enabling/disabling Secure Boot |
| 8 | every command GRUB runs (`grub_cmd: ...`) | `update-grub`, kernel version change |
| 9 | contents of every file GRUB reads (grub.cfg, modules, kernel, initrd) + EFI LoadOptions | **every kernel or initramfs update** |

```bash
# Stable across kernel updates - a good default
tpm2-kira seal --pcrs "0e,2e,4e,7e"

# Adds kernel and initrd integrity, at the cost of the workflow below
tpm2-kira seal --pcrs "0e,2e,4e,7e,8e,9e"
```

### If you seal PCR 8 or 9: reseal *after* the reboot

Every PCR source on Debian is read from the **running** system. `reseal` binds
to the kernel and initrd you booted, so running it right after
`update-initramfs` would bind to the image you are about to leave. Only a reseal
after the next boot is correct:

```
update-initramfs / kernel update
        |
        v
    reboot  ->  no TOTP code shown        <- expected, not a compromise
        |
        v
  unlock with your passphrase as usual
        |
        v
  sudo tpm2-kira reseal                    <- re-binds to the new state
```

`/etc/initramfs/post-update.d/tpm2-kira` prints this reminder after a rebuild,
but only when the sealed policy actually contains PCR 8 or 9. It deliberately
does **not** reseal.

This is a genuine trade-off rather than an oversight. Auto-resealing on every
boot would remove the churn, but it would also turn a tampered kernel into a
trusted baseline after a single reboot: unlock once, and the new state is
sealed. Keeping a human in the loop is the point.
