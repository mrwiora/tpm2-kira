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
| **Not capped** | `tpm2-kira-boot cap` has not run in this boot - it runs when the initrd is left, so the running system cannot compute codes |

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
shows a slot's code - only before the cap, so in practice only in the
initrd.

## The cap

When the initrd hands over to the real root, `tpm2-kira-cap.service`
(Debian: the init-bottom script) runs `tpm2-kira-boot cap`. From then until the
next reboot the TPM computes no codes, for anyone, root included -
`tpm2-kira reveal` in the running system reports "Locked until reboot".
`slot approve` still works.

## The clock

A matching code is evidence only if the clock was not tampered with: the
codes depend on the real-time clock, which nothing measures. Someone with
the machine can boot it untouched with the clock set forward, note the
codes for the time you will next boot, then tamper with it. A firmware
setup password and a locked boot order make that much harder; see
[SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md) §8 and
[SLOT.md](SLOT.md#hardening-the-boot-path).
