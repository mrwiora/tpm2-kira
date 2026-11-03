# The code: a TOTP code only the approved boot can show

A way to check the boot before you type anything, chosen when the slot is
sealed: `tpm2-kira slot add --totp` (or `control`'s "A TOTP code at boot?")
creates a TOTP key **inside the TPM**, as an HMAC key
that never leaves it, sealed to the slot ([SLOT.md](SLOT.md)). The TPM
computes every code; the key is shown exactly once, as the QR code you
enrol in your authenticator app (Marify, or any TOTP app). Once a phone is
enrolled for a slot, the phone checks the boot in its place and the slot's
code is retired ([PHONE.md](PHONE.md)).

## When the TPM computes a code

Only under a policy your signing key approved:

| Condition | What it checks |
|-----------|----------------|
| **PCR values** | Boot measurements match the values approved by `slot add` or `slot approve` |
| **Generation** | The approval is the latest one: every approval revokes the older ones |
| **Not closed** | The close (PCR 15) has not run in this boot - it runs at the end of the code screen, so the running system cannot compute codes |

When an update changes the PCR values, the TPM refuses until `slot
approve` approves the new boot state with your signing key (the hooks run
it after every image rebuild). The key itself stays the same, so there is
nothing to enrol again.

## At boot: the code screen

`tpm2-kira-boot run` (on Arch `tpm2-kira.service`, on Debian the init-premount
script) shows a fresh code of every slot every 30 seconds, before the
disk's passphrase is asked. Compare it with your authenticator: if it
matches, the boot chain is the one you approved - press Enter, and the
disk's key is asked ([DISK-KEY.md](DISK-KEY.md)). Without Enter the boot
continues by itself after 90 seconds. The same screen can be had over SSH
([SSH.md](SSH.md)).

On the running system, `tpm2-kira reveal` (`reveal-plain` without colour)
shows a slot's code - only before the close, so in practice only in the
initrd.

## The close

`tpm2-kira-boot close` extends PCR 15 (an event, "assh-close", in every
bank). Every slot object - the TOTP key, the sealed machine-id, the phone's
boot key, the release key - is created under the slot's policy
`PolicyAuthorize(signing key) ; PolicyPCR(15 == 0)`: the PCR 15 check is
the object's own, fixed at creation, beyond any approval. The SSH CA's
policy reads PCR 15 too. Once it is extended, until the next reboot the TPM
computes no codes and opens no slot's part, for anyone, root included,
whatever the signing key approves.

- `run` closes at the end of the code screen, after the parts have opened
  what they hold (the vault's part, the phone's salt, the TPM salt).
- The image closes again, whatever `run` did, before any volume is opened:
  on Arch `tpm2-kira-close.service`, on Debian local-top's script before
  cryptroot, and its init-bottom once more. A close tries a refused extend
  once more; a TPM that answers and refuses every way of it, or does not
  answer for the first time, is a hard reboot: no shell with PCR 15 at zero
  ([SSH.md](SSH.md), "The close: what it can come to").
- Right before a resume from hibernation, which starts the TPM afresh and
  runs no code screen: on Arch a drop-in on
  `systemd-hibernate-resume.service`, on Debian
  `scripts/local-top/tpm2-kira-close` (`--resume`: a failure clears `resume=`).

`tpm2-kira reveal` in the running system reports "Closed until the next
boot". `slot approve` still works; the next boot opens the slots again.
A slot sealed from the registers (post-separator values, the event log not
usable) shows no code at boot: the close comes before the separator.

## The clock

A matching code is evidence only if the clock was not tampered with: the
codes depend on the real-time clock, which nothing measures. Someone with
the machine can boot it untouched with the clock set forward, note the
codes for the time you will next boot, then tamper with it. A firmware
setup password and a locked boot order make that much harder; see
[SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md) §8 and
[SLOT.md](SLOT.md#hardening-the-boot-path).
