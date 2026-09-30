# Choosing PCRs

Which Platform Configuration Registers a secret is sealed against decides what a
matching TOTP code actually attests, and how often you have to reseal. `tpm2-kira
seal` with no `--pcrs` suggests a selection for the machine it is running on and
explains the trade-offs; this is the reference behind that.

See also `tpm2-kira pcrtips` for what each register measures, and
[SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md) §5.6–5.8 for the reconstruction
rules in full.

---

## Custom PCRs

Each PCR index can have a **source suffix** that controls where the value comes from:

| Suffix | Source | Example | Notes |
|--------|--------|---------|-------|
| *(none)* or `r` | TPM register | `0`, `7r` | Reads current live value from the TPM |
| `e` | Eventlog | `0e`, `7e` | Calculates from `/sys/kernel/security/tpm0/binary_bios_measurements` (PCRs 0–12) |
| `u[:PATH]` | Unified kernel image | `11u`, `11u:/boot/EFI/Linux/arch-linux.efi` | Replays systemd-stub's section measurements natively (PCR 11 only) |

You can mix sources freely:

```bash
# PCR 0 and 7 from eventlog, PCR 2 from register
tpm2-kira seal --pcrs "0e,2,7e"

# Add a UKI-computed PCR 11
tpm2-kira seal --pcrs "0e,2e,7e,11u"
```

The `u` source parses the unified kernel image directly and reproduces what
systemd-stub measures: for each section, `H(name + NUL)` followed by
`H(section bytes)`, then the `enter-initrd` boot phase. It needs neither
`objcopy` nor `systemd-measure`, and nothing is executed as a subprocess.

`seal` checks that computation against the current boot's firmware event log,
measurement by measurement. What happens on a mismatch depends on what kind it
is:

| Mismatch | Meaning | Result |
|---|---|---|
| Section set or order differs | tpm2-kira models systemd-stub wrongly | **fails** |
| Section content differs, image rebuilt after boot | cannot be checked yet | warns, proceeds |
| Section content differs, image unchanged since boot | the computation is wrong | **fails** |

The middle case is the normal one right after a kernel or initramfs update: the
image on disk is not the one that booted, so there is nothing to verify against.
PCR 11 becomes correct once you boot that image. Pass `--verify-uki=false` to
skip the check entirely.

## Warnings about weak selections

`seal` and `reseal` report selections that attest less than they appear to.
These are advisory — the secret is still sealed.

**PCR 0 on its own** identifies a firmware *build*, not a machine. It measures
firmware code only (configuration lives in PCR 1), so every device running the
same firmware version holds the same value and an attacker can reproduce it on
their own hardware.

**PCR 7 while Secure Boot is off or the platform is in Setup Mode.** PCR 7
records the Secure Boot state and policy. With Secure Boot disabled it faithfully
records "disabled" and nothing verifies which bootloader or kernel runs, so a
matching PCR 7 does not mean the boot chain was checked. In Setup Mode the keys
can be replaced without physical presence, so the policy it attests is one any
root user can rewrite. The state is read from
`/sys/firmware/efi/efivars`; if that is unavailable, tpm2-kira says so rather
than staying silent.

## The measure point

tpm2-kira reads PCRs in the initrd, *after* systemd has already extended some
of them. `systemd-pcrosseparator.service` extends `os-separator` into PCRs
0–7, 9, 12, 13, 14, and `systemd-pcrphase-initrd.service` extends
`enter-initrd` into PCR 11 — both before `cryptsetup-pre.target`.

Eventlog-derived values describe the *end of firmware*, so tpm2-kira adds those
extends to reach the measure point. `--measure-point` controls this:

| Value | Behaviour |
|-------|-----------|
| `auto` (default) | Probes stable PCRs against the TPM to decide, and refuses if the result is ambiguous |
| `on` | Always apply |
| `off` | Reconstruct end-of-firmware values only |

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
