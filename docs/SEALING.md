# Sealing in depth

The parts of sealing that matter once the basic selection is chosen: the measure point, TPMs without SHA-256 event logs, your own signing keys, several slots. The short form is in the README.

## The measure point

tpm2-kira checks its policy in the initrd, between two systemd extends that
both happen before `cryptsetup-pre.target`: *after*
`systemd-pcrphase-initrd.service` has extended `enter-initrd` into PCR 11,
and *before* `systemd-pcrosseparator.service` extends `os-separator` into
PCRs 0–7, 9, 12, 13, 14. `tpm2-kira.service` is ordered between the two and
is `Type=notify`: while it holds READY back, the PCRs still hold the sealed
values, so it shows a fresh code every 30 seconds and asks whether it
matches your authenticator. Enter continues to the passphrase, and so does
the end of the hold (90 seconds by default, `tpm2-kira run --hold`), so a
boot nobody watches goes on by itself. READY is sent then, the separator
runs, and no code can be computed until the next boot.

A slot that is enrolled with a phone (see *Remote attestation*) is verified
by the phone instead: the Bluetooth gate runs next to the display from the
start, and the phone's verdict continues to the passphrase like Enter does.
The code stays on the screen for when the phone is not at hand. While the
phone checks, the screen also shows a second code, eight letters and digits,
that the phone made up and sealed to a key in this machine's TPM; the TPM
gives it up only in a boot state your signing key approved. The phone shows
the same code and asks you to compare the two before it signs anything. The phone
check lasts as long as the code screen: when that ends (Enter, the phone's
verdict, or the end of the hold), the gate ends too, and nothing listens to
the radio at the passphrase prompt. A phone that is in the middle of its
answer when the hold runs out gets up to a minute more.

The gate is two processes of the one `tpm2-kira` binary. The display is also
its *coordinator* (`tpm2-kira run --gate`): it holds the TPM, issues the
quotes and reads the phone's signed receipt. The *radio worker*
(`tpm2-kira attest gate --coordinator`, in `tpm2-kira-attest.service`) talks
to the phone and has no TPM at all; it asks the coordinator over a socket in
`/run/tpm2-kira`. What listens to the radio can therefore neither have a
TOTP code computed nor make up a verdict.

That order is what locks the key for the rest of the boot. PCR extends are
one-way, so once the separator has run, nothing in the booted system can
satisfy the key's policy again — not root, not malware — until the next boot.
The key never leaves the TPM; the display holds nothing but the code it is
showing, good for 30 seconds. `tpm2-kira reveal` on a running system reports the
slot as *locked until the next boot*, which is the intended state, and
`tpm2-kira cap` read-locks the generation index at `initrd-switch-root` on
top of that. (The signing key is outside the lock: whoever can use it can
approve a new policy — keep it on a YubiKey, or at least off the machine.)

Because the live registers at seal time already carry the separator, PCRs
0–7, 9, 12–14 are sealed to values replayed from the firmware event log even
when given as register source. Where the log cannot be replayed, `seal` warns
and falls back to the registers: the key's policy then holds only after the
separator, the display computes codes live after the boot has been released
(until `cap`), and marks them accordingly.

Eventlog-derived values describe the *end of firmware*, so tpm2-kira adds
`enter-initrd` on PCR 11 to reach the measure point. `--measure-point`
controls this:

| Value | Behaviour |
|-------|-----------|
| `auto` (default) | Probes stable PCRs against the TPM to decide whether systemd's extends are active, and refuses if the result is ambiguous |
| `on` | Always apply |
| `off` | Reconstruct end-of-firmware values only (and read registers as they are) |

The mkinitcpio install hook inspects the image being built and passes the right
value to `reseal`, which is what makes the first rebuild after these units
appear behave correctly.

## TPMs whose event log has no SHA-256 digests

Some firmware writes a SHA-1-only event log even when the TPM has a SHA-256 PCR
bank. The `e` source then has nothing to replay in the selected bank, and
tpm2-kira refuses rather than sealing the resulting all-zero value:

```
Error: PCR 0 has no SHA-256 digests in the event log ... (digests present for this PCR: SHA-1).
Replaying it would yield an all-zero value that this system will never produce.
```

Two ways forward:

```bash
# Preferred: keep SHA-256, drop eventlog reconstruction for these PCRs.
# PCRs 0-7 do not change between the measure point and seal time, so the
# register source produces exactly the same value.
tpm2-kira seal --pcrs "0,7"

# Or reconstruct from the SHA-1 log. Requires a SHA-1 PCR bank on the TPM,
# and binds the policy to SHA-1 PCR values.
tpm2-kira seal --sha1 --pcrs "0e,7e"
```

The SHA-256 value cannot be derived from a SHA-1 log — different banks hold
different values, and several event types have digests that are not a plain
hash of the logged payload, so re-hashing the payloads would be wrong.

## Custom signing keys

By default, `setup` generates keys at `/etc/tpm2-kira/keys/`. You can supply your own (RSA-2048, ECDSA P-256, or ECDSA P-384):

```bash
tpm2-kira seal --pubkey /path/to/key.pub --privkey /path/to/key.pem
```

Both key files must be mode `0400`, owned by root (or by the user running
tpm2-kira), not symlinks, and in a directory nobody else can write to; `seal`
and `reseal` refuse them otherwise.

Both key paths are recorded in the sealed blob for `info`, but `reseal` never
uses them to find the key: anyone with TPM access can replace the blob, and a
planted one would name a key its author holds. `reseal` uses `--privkey`, or
the default key from `setup`. With a custom key, always pass `--privkey`.

## Multiple slots

tpm2-kira supports up to 16 NVRAM slots (0–15). Useful if you need separate secrets for different purposes:

```bash
tpm2-kira seal --nvram 0
tpm2-kira seal --nvram 1 --pcrs "0e,2e,7e"

tpm2-kira reveal --nvram 0
tpm2-kira reveal --nvram 1
```
