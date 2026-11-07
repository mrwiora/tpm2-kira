# Guided: `tpm2-kira control`

For a person rather than a script. It starts by checking
`/etc/tpm2-kira/control.conf`: a file that does not load is not worked on
- control lists every line it refuses, with its number and what to do, and
quits before anything is asked or written. Otherwise control writes the
file itself, every setting it keeps; you do not edit it.

## The screen

On a terminal that says its size, control takes the whole screen (the
alternate screen; the terminal is given back as it was on every way out -
q, Ctrl-C, a signal). It is up at once and fills in while it looks at the
machine; the slow part - asking each vault, trying each passphrase empty -
says "checking" until it is done.

```
[ KIRA ] control 0.5.0 · host · Secure Boot on · image out of date (1)
─────────────────────────────────────────────────────────────────────
  Overview        │ Keys & slots
  Boot chain      │ ✓ Signing key  - YubiKey 5 (serial 123), its PIN stored
▶ Keys & slots    │ ✓ Slot 0 ⚠  - sealed to 0e,2e,4u,7e,11s, a TOTP code
  Phone           │ ✓ Slot 1 ⚠  - the fallback, sealed to 7e,11s, a TOTP code
  Disk unlock     │ • Seal another slot (2-15) to PCRs you choose
  Network & SSH   │ • Approve the slots for the next boot now
  Boot image      │ • Delete everything of tpm2-kira's in the TPM ⚠
  Tools           │ ───────────────────────────────────────────────────
  Reference       │ Slot 0
                  │ Done: sealed to 0e,2e,4u,7e,11s, a TOTP code
                  │ ⚠ Destroys: slot 0 whole: its TOTP key, its phones, ...
                  │ The command: tpm2-kira slot delete --nvram 0
─────────────────────────────────────────────────────────────────────
↑↓ move  ←→ in/out  Enter run  / search  ? keys  r again  q quit
```

The sections on the left; the selected section's steps on the right, each
with its mark - green ✓ done, orange • open, grey - not possible here (the
reason beside it), red ✗ needs attention - and ⚠ on a step that destroys.
Below them the selected step's detail: what it does, how it stands, what
it destroys, and **the command it equals**, so whatever control does can be
done by hand too. On the sections themselves the detail is the section's
intro, on the Overview with the machine's status, on the Boot chain with
the prerequisites. Narrower than 72 columns the sections and a section's
steps take the screen in turn.

| Keys | |
|---|---|
| ↑ ↓ (j k) | move |
| → Tab (l), ← (h) | into a section's steps, back to the sections |
| Enter | open a section; run a step (a blocked one says why instead) |
| PgUp PgDn | scroll the detail |
| / | search every step of every section, by its title first |
| r | look at the machine again |
| ? | the keys |
| Ctrl-L | draw again |
| q, Esc, Ctrl-C | leave |

A step runs in the terminal below the screen, as it always has: its
questions, its QR code, its output; then a key, and the screen is back
with the machine looked at again.

**Destroying asks for its word.** Deleting a slot, removing a keyslot, a
slot's phones or phone salt, the vault, the SSH CA, or everything of
tpm2-kira's in the TPM shows what goes and asks for the slot's or the
keyslot's number, or `delete`, to be typed. Enter alone, `y` or a typo
keep it.

**The line menus.** `control --lines`, and on their own without a terminal
size, on `TERM=dumb` and with `--debug` (whose output would run through the
frame): the same steps as numbered menus, a number and Enter. Without a
terminal control prints everything and leaves (a script's look).

## The sections

**Boot chain** - what tpm2-kira needs of the machine to be in its boot at
all. The **prerequisites**, each a line, green when met and red with what
to do when not: a usable TPM, mkinitcpio or initramfs-tools, tpm2-kira's
hook files installed, systemd and sd-encrypt in HOOKS, the LUKS devices, a
recovery passphrase (a keyslot that is not tpm2-kira's) on each, and no
keyslot that opens with an **empty passphrase** - such a disk is
encrypted, yet anybody with it opens it, so it is red; tpm2-kira still
takes the empty passphrase where it asks for the recovery one. The steps:
**mkinitcpio adoption** (sd-tpm2-kira into HOOKS), **kernel command line
adoption** (the key's route: `rd.luks.key=` naming the socket, crypttab on
Debian), the **PCR key** in uki.conf - each shows the line as it should
read and writes it only when you say so. The other sections open once the
chain is in place.

The others hold every option of the machine, each open, done, or greyed
with the reason this machine cannot have it - no TPM, no Bluetooth
adapter, no wired network interface, no recovery passphrase, an option it
builds on still missing:

| Section | Steps |
|---|---|
| Keys & slots | the signing key (and a YubiKey's PIN, stored); the standard sealing - slot 0 to the evaluated PCR selection, acknowledged or custom, and slot 1 the fallback; every slot a line, **picking it deletes the slot whole**; another slot (2-15) to PCRs you choose; approve the slots now; delete everything |
| Phone | enrol a phone; Bluetooth in every boot image; remove a slot's phones |
| Disk unlock | password + salt; password + phone salt (the phone); this TPM + a vault, or the password + the vault's salt and a pepper typed through its one-time keyboard; password + phone salt + a pepper typed through the phone's one-time keyboard - each a keyslot of its own, enrolled it offers the removal; remove a slot's phone salt |
| Network & SSH | the image's network (DHCP or static, proposed from the running system; whether the boot announces its address, on by default); the SSH server with the code screen |
| Boot image | what is out of date in it and why; build it now; debug at boot |
| Tools | the commands that read the machine, run as they are: status, slot list and info, luks, vault, phone and phone salt status, the EK certificate, the YubiKeys, the next image's plan, pcrtips |
| Reference | every help page: what control does not do by itself (luks mark and derive, phone salt rotate, phone quote and verify, the boot's commands) is done by hand, as they say |

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

On the Overview, the machine's status, judged line by line - the TPM and
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
checked yet. **Ready to reboot** leads the Overview when the image is current
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
that file, else from the terminal; never from argv or the environment. The two wiring steps of the
boot chain are checks, green and no longer pickable once in place. Every other file
is advised, never edited, with three exceptions, each asked for every
time: the PCR key's lines in `/etc/kernel/uki.conf`, the mkinitcpio step writes sd-tpm2-kira into the HOOKS of
`/etc/mkinitcpio.conf` when you say so (editing it yourself works just as
well), and the route step writes the line it shows into
`/etc/kernel/cmdline` (or the cmdline.d file, a boot entry's options
line, a crypttab line) the same way. The disk keys are toggles: enrolled,
picking one offers the keyslot's removal instead of a second enrolment.
Everything but the help needs root; `control` says so on its own screen,
the commands in a line.
Sealing both slots, each QR code gets a cleared screen of its own, held
until you confirm it is in your authenticator. Colours are ANSI, none with
`NO_COLOR` or on a non-terminal; the glyphs are Unicode on a UTF-8 locale
and ASCII elsewhere (`+`, `x`, `!`, `|`).

The line menus (`--lines`, or on their own as above) show the same steps,
the boot chain first and then the Overview with a line per section, a
number and Enter or the arrows; Esc goes back from a section, and leaves
from the Overview:

```
  [ KIRA ] control 0.5.0-rc1 - the protections of this machine, step by step
  Step 1 of 2: the boot chain

  Prerequisites
    ✓ TPM: /dev/tpmrm0, SHA-256 bank
    ✓ Initramfs: mkinitcpio
    ✓ LUKS: /dev/sda2
    ✗ Passphrase: keyslot 0 of /dev/sda2 opens with an empty passphrase (risk: ...)
    1 not met: the steps that need them say so.
  The boot chain
  Recommended next: Kernel command line adoption (the key's route)
  1. ✓ mkinitcpio adoption  - sd-tpm2-kira in HOOKS of /etc/mkinitcpio.conf
  2. • Kernel command line adoption (the key's route)
  3. - Continue to step 2  - first: Kernel command line adoption (the key's route)
  4.   Quit
  Enter a number between 1 and 4:
```
