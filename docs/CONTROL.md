# Guided: `tpm2-kira control`

For a person rather than a script, in two steps. It starts by checking
`/etc/tpm2-kira/control.conf`: a file that does not load is not worked on
- control lists every line it refuses, with its number and what to do, and
quits before anything is asked or written. Otherwise control writes the
file itself, every setting it keeps; you do not edit it.

**Step 1, the boot chain**, is the first screen until it is in place. On
top the **prerequisites**, each a line, green when met and red with what
to do when not: a usable TPM, mkinitcpio or initramfs-tools, tpm2-kira's
hook files installed, systemd and sd-encrypt in HOOKS, the LUKS devices,
a recovery passphrase (a keyslot that is not tpm2-kira's) on each, and
no keyslot that opens with an **empty passphrase** - such a disk is
encrypted, yet anybody with it opens it, so it is red; tpm2-kira still
takes the empty passphrase where it asks for the recovery one. Under it
the steps: **mkinitcpio adoption** (sd-tpm2-kira into HOOKS),
**kernel command line adoption** (the key's route: `rd.luks.key=`
naming the socket, crypttab on Debian) - each shows the line as it
should read and writes it only when you say so. **Continue to step 2**
opens once both are in place. The boot image is built when you leave
`control`, once, after you say yes.

**Step 2** is what the machine combines, in submenus; every option is
open, done, or greyed with the reason this machine cannot have it - no
TPM, no Bluetooth adapter, no wired network interface, no recovery
passphrase, an option it builds on still missing:

| Submenu | Options |
|---|---|
| Signing key and TOTP codes | the signing key (and a YubiKey's PIN, stored); the standard sealing - slot 0 to the evaluated PCR selection, acknowledged or custom, and slot 1 the fallback; every slot a line, **picking it deletes the slot whole** |
| Attestation by phone | enrol a phone; Bluetooth in every boot image |
| Disk unlock | password + salt; password + phone salt (the phone); this TPM + a vault, or the password + the vault's salt and a pepper typed through its one-time keyboard; password + phone salt + a pepper typed through the phone's one-time keyboard - each a keyslot of its own, enrolled it offers the removal |
| Network and SSH at boot | the image's network (DHCP or static, proposed from the running system); the SSH server with the code screen |

An option that needs another one control can set up offers it on the
way: the vault and SSH set up the image's network first. The vault is
asked before the enrolment - does it answer, verified against its root
and its pinned key - and
at every later look at the machine whether it still knows this device;
one that does not is red.

**Why the TOTP code comes first, and the phone only after a reboot.**
Enrolling a phone pins the boot it happens in as the good one: every later
boot is compared with it, and nothing the phone can check itself says that
this first state is clean. So the phone is enrolled only in a boot you
verified: slot 0 is sealed with a TOTP code, the reboot goes through the
code screen, you compare the code with your authenticator, and in that boot
the phone is enrolled, which then retires slot 0's code. `phone enrol`
holds to it whichever way it is started: it refuses a boot that did not
pass the code screen, and one whose PCRs at the code screen were not the
ones slot 0's code is approved for (no code was shown, nothing verified
it); then it asks whether you compared the code. A further phone needs a
boot an enrolled phone attested (SECURITY-BACKGROUND §3.1).

On top of step 2, the machine's status, judged line by line - the TPM and
its banks, the endorsement key's vendor, Secure Boot, how it booted, the
slots, the signing key, the initramfs, a Bluetooth adapter, the LUKS
devices, the boot image's network, the vault -
**green what is good, orange what is open, red what is not good, with
the risk in brackets**: the
SHA-1 bank in use (orange: a warning on a machine with nothing better), Secure Boot disabled or in Setup Mode, a slot sealed
without the kernel measured, a TPM whose endorsement key no known vendor
vouches for (a phone then trusts it on first use, as it would a software
TPM), a loose file holding the PIN, an empty passphrase, a vault that
does not answer. `tpm2-kira status`, `slot add`, `slot approve`, the image's hooks and,
at boot, the code screen, every SSH session and the boot's log say the same of Secure
Boot on their own (a `WARNING:` line, never a stop). Beside the firmware's variable
stands the **proof**: the phone's and the vault's own check on the live PCR 7 and the event
log, which the variable proves nothing to; when the log does not make the register it says
whether systemd's log accounts for the rest, for a person and never as proof. The header carries the version. Because the status
already says what is not good, the steps repeat none of the commands'
advisory warnings. A slot whose deletion stopped halfway shows as dirty,
marked `[!]` and recommended first, until a run removes the rest (see
[Deleting a slot](SLOT.md#deleting-a-slot)).

The boot image is built once, **when you quit `control`**, after
everything is set up - a build takes its time. It is out of date when a
file of the boot chain (`mkinitcpio.conf` and its `.d` files,
`/etc/kernel/cmdline`, `crypttab.initramfs`) changed after it, or when
the **boot plan** says so: the image carries the disk unlock always, and
each other part - the TOTP codes, the phone's Bluetooth gate, the vault,
the network, the SSH server - only while something uses it (a sealed
slot, an enrolled phone, the settings in `control.conf`), and names its
parts with the digest of their settings (`tpm2-kira help initramfs`). A
part in use now and not in the image - the first sealed slot, the first
phone, SSH switched on - or in it with other settings - another port,
another login key - makes the image out of date; the status' "Boot
image" line says which. New TOTP codes for a slot that has some, a
approve, a further phone, a LUKS keyslot or the YubiKey's PIN never do.
The SSH server or the network switched off while the image still carries
it makes the image out of date too: the next boot must not start them.
Another part the image carries and nothing uses any more is no reason to
rebuild: the next build leaves it out. Quitting then shows the reasons
and what the build puts in, and runs `mkinitcpio -P` (`update-initramfs
-u`) when you say yes. The image looked at is the first preset's default
(its UKI, else its initramfs) - fallback and further profiles are not
checked yet. **Ready to reboot** leads step 2 when the image is current
but this boot did not go through it, and picking it reboots, after a
confirmation.

Every step runs with the same functions the commands use; run
`control` again later and it shows the state and what is left. The
commands are for specific settings, and they touch no configuration
file: `control` alone writes the two configuration files.
`/etc/tpm2-kira/control.conf` is tpm2-kira's - the radio settings and the
image's network and SSH server, what the image is built with and nothing
else (nothing of it goes into the image but the network and SSH settings,
as files of their own). `/etc/tpm2-kira/assh.conf` beside it is
[aSSH](../assh/README.md)'s: the SSH CA and its slots, the port, the keys
that may log in ([SSH.md](SSH.md)).
Beside it `control` keeps the YubiKey's PIN, checked on the token, in
`/etc/tpm2-kira/pin` (root's alone, never in the image), and the keys
that may log in at boot in `/etc/tpm2-kira/authorized_keys` (root's
keys copied there when asked; edit it for others). A command that signs
takes the PIN from `--pin-fd N` if a script gives it (a systemd unit: its
credential, `--pin-fd 3 3<"$CREDENTIALS_DIRECTORY/pin"`, through a shell; a bad
descriptor exits 2 on every command, and a regular file others can read is one), else from
that file, else from the terminal; never from argv or the environment. The two wiring steps of step 1
are checks, green and no longer pickable once in place. Every other file
is advised, never edited, with three exceptions, each asked for every
time: the PCR key's lines in `/etc/kernel/uki.conf`, the mkinitcpio step writes sd-tpm2-kira into the HOOKS of
`/etc/mkinitcpio.conf` when you say so (editing it yourself works just as
well), and the route step writes the line it shows into
`/etc/kernel/cmdline` (or the cmdline.d file, a boot entry's options
line, a crypttab line) the same way. The disk keys are toggles: enrolled,
picking one offers the keyslot's removal instead of a second enrolment.
Everything but the help needs root; `control` says so on its own screen,
the commands in a line.
Each screen is a page of its own, cleared each time it is shown; what a
step prints stays until "Back to ..." is answered. Sealing both slots,
each QR code gets a cleared screen of its own, held until you confirm it
is in your authenticator. The screens are numbered text menus: the arrow keys
and Enter, or a number and Enter (Enter alone takes what is named above the menu,
never a step; a greyed entry says why when the cursor is on it);
Ctrl-C, Ctrl-D or Esc leaves, in a submenu back to step 2. The arrows work inline,
in plain ANSI: what stays in the scrollback is the question and `> 2. ...`, the answer.
With `TERM=dumb`, or a terminal that does not say its width, the same menu is
a number and Enter alone. Colours are ANSI,
none with `NO_COLOR` or on a non-terminal. Without a terminal, `control`
prints both steps and exits.

```
  [ KIRA ] control 0.5.0-rc1 - the protections of this machine, step by step
  Step 1 of 2: the boot chain

  Prerequisites
    ✓ TPM: /dev/tpmrm0, SHA-256 bank
    ✓ Initramfs: mkinitcpio
    ✓ Boot integration: tpm2-kira's hook files are installed
    ✓ systemd in the initrd: systemd and sd-encrypt in HOOKS
    ✓ LUKS: /dev/sda2
    ✓ Recovery passphrase: a keyslot that is not tpm2-kira's on every device
    ✗ Passphrase: keyslot 0 of /dev/sda2 opens with an empty passphrase (risk: ...)
    ✓ Secure Boot: enabled
    ✓ Secure Boot's proof: on: PCR 7 and the event log show it, as a phone and the vault will see it
    1 not met: the steps that need them say so.
  The boot chain
  Recommended next: Kernel command line adoption (the key's route)
  systemd-cryptsetup takes a volume's key from tpm2-kira when its rd.luks.key= names the socket. ...
  Up, down and Enter, or a number and Enter; Esc cancels.
  1. ✓ mkinitcpio adoption  - sd-tpm2-kira in HOOKS of /etc/mkinitcpio.conf
  2. • Kernel command line adoption (the key's route)
  3. - Continue to step 2  - first: Kernel command line adoption (the key's route)
  4.   Quit
  Enter a number between 1 and 4:
```
