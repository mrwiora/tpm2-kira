# Choosing PCRs

Which Platform Configuration Registers a secret is sealed against decides what a
matching TOTP code actually attests, and how often you have to reseal. `tpm2-kira
seal` with no `--pcrs` suggests a selection for the machine it is running on and
explains the trade-offs; this is the reference behind that.

See also `tpm2-kira pcrtips` for what each register measures, and
[SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md) §5.6–5.8 for the reconstruction
rules in full.

---

## What `seal` works out for itself

Run `tpm2-kira seal` with no `--pcrs` from a terminal and it probes the machine
before suggesting anything, then explains the choice. What it establishes:

| Probe | Decides |
|---|---|
| Secure Boot state, from efivars | whether PCR 7 attests a verified chain, and so whether anything else has to measure the kernel |
| PCR banks the TPM provides | whether SHA-256 is available at all, or `--sha1` is forced |
| Which banks the event log carries digests in | whether the `e` sources are usable |
| Live registers **compared against an event log replay** | whether `r` and `e` actually agree on this machine |
| A unified kernel image, or GRUB | which PCR measures the kernel here: `11u`, or `8,9`, or `4` |
| Whether the mkinitcpio reseal hook is installed | whether a kernel-measuring PCR costs you a reseal per update, or none |

The last two are why the same machine can get different advice than another with
the same Secure Boot state. With Secure Boot enforcing, PCRs 0 and 7 are already a
sound policy that survives kernel updates — so measuring the kernel as well is
suggested only when the reseal it costs is automated. Without the hook it is
offered rather than imposed.

## The three sources, and when each is used

A PCR selection names registers *and* where their expected value comes from. The
source is not a matter of taste: it follows from whether the register has finished
changing by the time tpm2-kira reads the TPM at boot — the **measure point**, in
the initrd just before the passphrase prompt.

| Suffix | Source | Reads | Produces |
|---|---|---|---|
| none, or `r` | register | the live TPM register, now | whatever the register holds at seal time |
| `e` | eventlog | `/sys/kernel/security/tpm0/binary_bios_measurements`, replayed, then the measure-point extends applied | the value the *measure point* presents |
| `u` | uki | the unified kernel image on disk, replaying systemd-stub's section measurements | the value the *next boot* will present |

### Which one each register needs

| PCRs | Use | Why, and what goes wrong otherwise |
|---|---|---|
| 0–7, 8, 12, 13, 14 | **register** | They stop changing at the measure point, so the live value read now is what the next boot presents. It needs no event log, which makes it the more robust of the two. |
| 9 | **`9e`** | `systemd-tpm2-setup` extends four NvPCRs *after* the disk is unlocked. The register read at seal time is therefore polluted; the replay gives the measure-point value. Sealing `9` produces a policy that can never match. |
| 11 | **`11u`**, else `11e` | The boot phases `leave-initrd`, `sysinit` and `ready` land after the measure point, so the register is polluted the same way. `u` is better than `e` because it reads the image on disk and so predicts the *next* boot — which is what lets a reseal happen before rebooting rather than after. |
| 15 | **nothing works** | machine-id and the volume key, and neither is in the firmware event log. It cannot be sealed by any source. Leave it out. |
| 1, 5 | register, but rarely worth it | Firmware *configuration* and boot order. They change when UEFI settings or the boot order change, including harmless ones, so they produce false alarms. |

Measured rather than assumed: the arithmetic for PCR 9 and 11 is in
[SYSTEMD-PCROSSEPARATOR.issue](SYSTEMD-PCROSSEPARATOR.issue) §7.3.

### What each source is good for

**register** — the default, and right for almost everything. Simple, needs no
event log, and self-correcting: if a component changes, one reseal from the
running system captures the new value and the next boot matches.

**`e` eventlog** — two jobs. It is *mandatory* for PCR 9, whose register is
polluted after unlock. And it is the diagnostic tool: comparing `0e` against `0`
is how a divergence gets found, because the two answer different questions — a
calculation versus a measurement. That comparison is what uncovered
`systemd-pcrosseparator.service` silently changing PCRs 0–7.

**`u` uki** — the only source that predicts a state the machine has not yet been
in. It reads the image on disk, so after a kernel update you can reseal *before*
rebooting and the next boot matches immediately. The mkinitcpio post hook relies
on exactly that.

### Why `0e` is not a better `0`

For PCRs 0–7 the two are equivalent, and the register is the sturdier choice: it
depends neither on the event log carrying SHA-256 digests nor on the
measure-point extends being reconstructed correctly. That reconstruction is
precisely what broke when `systemd-pcrosseparator.service` appeared — the replay
went one extend short and **stayed** wrong, because the calculation itself was
now incomplete, while register-based policies needed one reseal and were fine
afterwards.

So `seal` picks the source per register for you: a bare `tpm2-kira seal` on a
GRUB system produces `0,7,8,9e`, not a uniform suffix, and says why 9 differs. The
suffix remains available in `--pcrs` because the blob records it per PCR, `reseal`
preserves it, and the comparison is a diagnostic — but it is no longer something
you have to decide.

Asking for a volatile register explicitly is warned about rather than refused,
since an explicit selection may know something this code does not:

```
WARNING: PCR 9 is being sealed from the live register, which cannot work.
  It keeps changing after tpm2-kira reads the TPM at boot: systemd-tpm2-setup
  NvPCR initialisation (runs after switch-root).
  Use the event log source instead:  --pcrs "...,9e"
```

### A fourth source, considered and not adopted

`systemd-pcrlock` predicts future PCR values and could in principle be a source
of its own. The investigation, and why it is not one, is in
[PLAN-PCRLOCK.md](PLAN-PCRLOCK.md).

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
