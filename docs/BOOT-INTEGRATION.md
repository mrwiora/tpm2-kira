# Boot integration in depth

What the hooks put into the initramfs on Arch and Debian, the units and their conditions, the display mode, and how PCR 8/9 are predicted on a GRUB system. The setup steps are in the README.

## What is installed where

The package puts four unit files into `/usr/lib/systemd/system` on the
host, because the mkinitcpio hook takes them from there. None of them is
enabled on the host, and each carries
`ConditionPathExists=/etc/initrd-release`, so enabling one there by mistake
does nothing.

The image carries one binary, `/usr/bin/tpm2-kira-boot`: the code screen
and the parts of the plan, the cap, the keyscript, the phone's radio worker
and the SSH server's unprivileged half. `tpm2-kira`, the administration,
stays on the installed system; the hooks run it to decide the plan.

What goes in is the **boot plan**'s (`tpm2-kira initramfs plan`,
`tpm2-kira help initramfs`): the disk unlock always, every other part only
while something uses it, and what needs the TPM only with one. The image
names its parts in `/etc/tpm2-kira/plan/`; `tpm2-kira-boot run --plan` and the
Debian scripts start only those.

| Unit | In the initramfs image | Does something when |
|------|------------------------|---------------------|
| `tpm2-kira.service` (`run`: the code at the prompt, the gate's coordinator, the SSH server, and the key provider for `systemd-cryptsetup`) | always, once `sd-tpm2-kira` is in `HOOKS`. `run` waits for the TPM's device (at most 5 s) only when a part of the plan needs it | a volume asks for its key; with the codes in the plan, a TOTP key is shown. Without them the TPM is not asked, and the boot is released at once. The first `slot add` makes the image out of date (`control` rebuilds it when left). The gate ends when the boot is released; the process stays to answer the volumes' key requests and ends at switch-root |
| `tpm2-kira-unlock.socket` (the key socket) | always, with the display | `systemd-cryptsetup` activates a volume whose key file is the socket |
| `tpm2-kira-cap.service` (locks codes when the initrd is left) | with the codes in the plan: a slot is sealed | the initrd is left |
| `tpm2-kira-machine-id.service` (releases the sealed machine-id, `tpm2-kira-boot machine-id`) | with the image's network | before systemd-networkd starts: slot 0's policy holds, `KIRAmachineID` unseals ([SSH.md](SSH.md) §2.1) |

The phone's gate is no unit: with the phone in the plan, `run` starts its
radio worker itself. The phone is in the plan with a TPM, a phone enrolled
(or `TPM2_KIRA_ATTEST_BLUETOOTH=always`), its record signed by this
machine's key and current, **and** the adapter found when the image was
built; the signing public key and the adapter's modules and firmware go
into the image with it. Otherwise no Bluetooth module or firmware is in the
image, and the build says which condition failed. `phone unenrol` without
rebuilding the image leaves the gate in it with nothing to do: it reports
at boot that no phone is enrolled, and the next build leaves it out.

### The child processes of run

Two parts parse what arrives from outside before the disk is unlocked,
and `run` starts each as a process of its own - the same on Arch and
Debian, with nothing of it in a unit or a script:

| | `ssh-child` (the SSH server) | `gate-child` (the phone's radio worker) |
|---|---|---|
| user | nobody | nobody, with `CAP_NET_ADMIN` and `CAP_NET_RAW` alone (the HCI user channel) |
| namespaces of its own | network, IPC, PID, mount, UTS | IPC, PID, mount, UTS (Bluetooth sockets exist only in the first network namespace) |
| open files | the listening socket, a socket pair to `run` | two socket pairs to `run`, `/dev/rfkill` |
| files it can reach (Landlock) | none | reads beneath `/sys` (the adapter's and rfkill's state) |
| TPM | none: `run` signs | none: `run` quotes, opens the boot key and the phone salt, reads the receipt |

Each then confines itself with aSSH's `sandbox`, on every thread (Go runs
a program on several threads, and prctl, Landlock and seccomp act on the
thread that asks): no new privileges, no executable memory, Landlock as
above (no TCP bind or connect either), and none of the system calls that
administer the machine - mounts, modules, the clock, other processes'
memory, namespaces, user IDs, keyrings, BPF, running a program (seccomp,
EPERM; another architecture's ABI ends the process). `tpm2-kira help
ssh-child`, `tpm2-kira help gate-child`.

### Arch and Debian

The boot is one process tree on both: `run` and its children, started
with the same arguments. What differs is what the distribution's boot
does around it:

| | Arch (mkinitcpio, systemd) | Debian (initramfs-tools) |
|---|---|---|
| `run` is started by | `tpm2-kira.service` | `scripts/init-premount/tpm2-kira`, in the background |
| the disk's key | `systemd-cryptsetup` reads `tpm2-kira-unlock.socket` (`rd.luks.key=`, crypttab(5) AF_UNIX key files) | cryptroot runs the keyscript `unlock-key`, which asks the socket `run --unlock` made |
| the adapter's modules | loaded by `systemd-modules-load` (`modules-load.d`) | loaded by the image's init (`conf/modules`, the hook's `force_load`) |
| the image's network | `systemd-networkd`, the plan's `.network` file; the sealed machine-id released before it (`tpm2-kira-machine-id.service`), from which networkd derives its default DUID (a copied identity wins) | the script: initramfs-tools' `configure_networking`, or busybox' `udhcpc` / `ip` (`remote.conf`) with the copied identity; the machine-id is released all the same, before it |
| the narrative | the journal: `journalctl -b -u tpm2-kira.service` | `/run/initramfs/tpm2-kira.log` |
| stopped, and the codes locked | at `initrd-switch-root`: the units' stop, `cap` in `tpm2-kira-cap.service` | `scripts/init-bottom/tpm2-kira`: TERM to `run` (5 s), then `cap` |
| the measure point | ordered before systemd's PCR separators | before cryptroot (no separator) |

The display refreshes once per 30-second TOTP window, writing to the same
console as the passphrase prompt. The prompt scrolls up as codes arrive;
typing is unaffected, since the passphrase is not echoed anyway.

## PCR 8 and 9 are predicted for the next boot

GRUB measures every command it runs into PCR 8 and every file it reads
into PCR 9, and the kernel's EFI stub adds its load options and the initrd
to PCR 9. The event log of the running boot is the complete script of
that. After an update only the entries of what changed differ, so
`slot approve` replays this boot's log with those entries replaced by what is
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
kernel install or removal. `slot approve` prints what it substituted, for
example `PCR9 /initrd.img-6.12.111+deb13-amd64: now /boot/initrd.img-…`.
The next boot then shows a code at once; no boot without one, no second
approve.

What the prediction cannot know, and what then happens: a different menu
entry chosen at the GRUB menu, a command line edited there, a `grubenv`
the boot rewrites (`GRUB_SAVEDEFAULT`, `recordfail`), or a GRUB package
update that changes the module set. Such a boot shows no code - expected,
not a compromise - and `sudo tpm2-kira slot approve` after it binds to the
state you booted, as the approval always did. The prediction is checked
against this machine's real log in the test suite
(`internal/measure/grub_predict_test.go`, Debian 13, GRUB 2.12).

Approving is still never automatic at *boot*: a tampered kernel does not
become a trusted baseline by being booted once. The hooks run on the
unlocked system, after a change you made.
