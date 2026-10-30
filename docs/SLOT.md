# The slot: a boot state your signing key approved

A slot is what everything else of tpm2-kira stands on: a policy of PCR
values and a generation, approved by your signing key, in one of the
slots 0-15 - a record in the EFI variable `KIRAslotN`, with its
generation index and record counter in the TPM (*Deleting a slot*,
below). Its methods work only in a boot whose PCRs match the approval:

- a TOTP key, when chosen (`slot add --totp`): the code on the screen
  ([CODE.md](CODE.md)) - or, once a phone is enrolled, the phone's
  enrolment in its place ([PHONE.md](PHONE.md));
- the TPM salt ([DISK-KEY.md](DISK-KEY.md));
- the phone salt's release key ([DISK-KEY.md](DISK-KEY.md#password-typed-salt-from-the-phone-0x1300));
- the vault's local part ([VAULT.md](VAULT.md));
- the SSH CA in the TPM approves its own slots the same way ([SSH.md](SSH.md)).

`slot add` makes a slot, `slot approve` approves the boot state anew after
an update (the hooks run it), `slot info` shows it, `slot list | status |
delete` show and remove it. The signing key comes from
`tpm2-kira setup` (a file, or a YubiKey: [PLAN-YUBIKEY.md](PLAN-YUBIKEY.md));
the details of sealing - the measure point, SHA-1, your own keys, several
slots - are in [SEALING.md](SEALING.md).

## Adding a slot: `slot add`

```bash
tpm2-kira slot add            # the boot state alone: the methods are enrolled into it
tpm2-kira slot add --totp     # and a TOTP code at boot, with slot 1 the fallback
```

`--totp` seals a TOTP key too: a code at boot, compared with your
authenticator before you type anything, which proves the boot is one your
signing key approved. Without it nothing is shown at boot for the slot;
its other methods - the vault, the TPM salt, a phone - check the boot.
`tpm2-kira control` asks.

Without `--pcrs`, the selection is what this boot measured, read from the
event log:

| This boot | Slot 0 is sealed to | Why |
|---|---|---|
| a unified kernel image (systemd-stub) | `0e,2e,7e,11u` | firmware, option ROMs, Secure Boot state, and PCR 11 computed from the image - a kernel update is predicted from the new image |
| GRUB | `0e,2e,7e,8e,9e` | the same, and GRUB's commands and the files it read, predicted from `grub.cfg` for the next boot |
| neither | `0e,2e,7e` | firmware, option ROMs, Secure Boot state |
| no event log to read (a software TPM, a run without root) | `0,2,7` | the same registers as they are now: nothing can be replayed |

Without `--pcrs` and `--nvram`, and with `--totp`, a second slot is sealed as
well: **slot 1, the fallback, to `0e,7e` alone** (`0,7` without an event log). When a kernel or boot loader change was
not predicted, slot 0 shows no code, but slot 1 still does as long as the
firmware and the Secure Boot state are what they were: the machine is not
simply lost, and the first slot is resealed once the boot is understood.
Pair both with your authenticator.

With `--pcrs`, or `--nvram`, one slot is sealed: the one named (else 0),
to the PCRs named (else the selection above).

### Custom PCRs

Each PCR index can have a **source suffix** that controls where the value comes from:

| Suffix | Source | Example | Notes |
|--------|--------|---------|-------|
| *(none)* or `r` | TPM register | `0`, `7r` | Reads current live value from the TPM |
| `e` | Eventlog | `0e`, `7e` | Calculates from `/sys/kernel/security/tpm0/binary_bios_measurements` (PCRs 0–12) |
| `u[:PATH]` | Unified kernel image | `11u`, `11u:/boot/EFI/Linux/arch-linux.efi` | Replays systemd-stub's section measurements natively (PCR 11 only) |

You can mix sources freely:

```bash
# PCR 0 and 7 from eventlog, PCR 2 from register
tpm2-kira slot add --pcrs "0e,2,7e"

# Add a UKI-computed PCR 11
tpm2-kira slot add --pcrs "0e,2e,7e,11u"
```

The `u` source parses the unified kernel image directly and reproduces what
systemd-stub measures: for each section, `H(name + NUL)` followed by
`H(section bytes)`, then the `enter-initrd` boot phase. It needs neither
`objcopy` nor `systemd-measure`, and nothing is executed as a subprocess.

`slot add` checks that computation against the current boot's firmware event log,
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

### Choosing PCRs

A code on screen means "nothing that the selected PCRs measure has changed".
Anything they do not measure can be replaced without changing the code. Most
important is what runs before the passphrase prompt: the kernel, the initrd
and the kernel command line.

| Boot setup | Selection | Measures kernel, initrd and command line through |
|---|---|---|
| Unified kernel image (systemd-stub) | `0,7,11u` | PCR 11, computed from the image on disk |
| GRUB | `0e,2e,4e,7e,8e,9e` | PCR 8 (GRUB commands, incl. the command line) and PCR 9 (files GRUB reads) |
| systemd-boot, separate kernel and initrd | add `9`, `12` | PCR 9 (initrd loaded by the EFI stub) and PCR 12 (command line) |

Firmware-only selections such as `0,7` or `0e,2e,4e,7e` survive kernel updates
untouched, but a replaced initrd, or a shell from an edited command line, then
still gets a valid code — and from such a shell the TPM can be made to compute
codes for any future time. PCRs 8 and 9 change on every kernel or initramfs
update; `slot approve` predicts them from the files on disk, see
[BOOT-INTEGRATION.md](BOOT-INTEGRATION.md#pcr-8-and-9-are-predicted-for-the-next-boot).

### Hardening the boot path

A selection is only as good as the ways into a shell that it measures. Also:

- **Disable the boot-menu editor.** systemd-boot: `editor no` in
  `loader.conf`. GRUB: set a superuser password. Otherwise `rd.break` or
  `break=` on the command line drops to a root shell in the genuine initrd
  (and if the command line is not measured, the code still matches).
- **No shell after a failed unlock.** On Debian, add `panic=0` (reboot) so
  initramfs-tools does not drop to its fallback shell.
- **Firmware setup password and locked boot order**, so no other medium can be
  booted, and the clock cannot be changed (see [the clock](CODE.md#the-clock)).
- **Your own Secure Boot keys** (e.g. with sbctl), so any medium signed for
  other systems changes PCR 7.

### Warnings about weak selections

`slot add` and `slot approve` report selections that attest less than they appear to.
These are advisory — the secret is still sealed.

**No PCR for the kernel, initrd or command line.** See
[Choosing PCRs](#choosing-pcrs). The warning names what is missing and, on a
system booted from a unified kernel image, the selection that adds it.

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

### The measure point

The display runs before systemd's OS separator, so the seal predicts the PCR values of that point; `--measure-point` and what it means: [SEALING.md](SEALING.md#the-measure-point).

### TPMs whose event log has no SHA-256 digests

A TPM without a SHA-256 PCR bank needs `--sha1` throughout: [SEALING.md](SEALING.md#tpms-whose-event-log-has-no-sha-256-digests).

### Custom signing keys

Your own key pair instead of `setup`'s (`--privkey`, `--pubkey`; P-256, the default and the smallest in the TPM, P-384 or RSA-2048): [SEALING.md](SEALING.md#custom-signing-keys).

### Multiple slots

Up to sixteen slots, `--nvram N`: [SEALING.md](SEALING.md#multiple-slots).

## Approving a new boot state: `slot approve`

When PCR values change (kernel update, initramfs rebuild, firmware update), the TPM no longer computes codes and `reveal` shows a PCR mismatch. Reseal to approve the new values with your signing key; the key in the TPM, and so your authenticator, stay the same:

```bash
# Uses the default signing key from setup
tpm2-kira slot approve

# Or specify the key explicitly
tpm2-kira slot approve --privkey /etc/tpm2-kira/keys/seal.key
```

You can also change the PCR selection during reseal:

```bash
tpm2-kira slot approve --pcrs "0e,2,4,7e"
```

## Inspecting a slot: `slot info`

```bash
tpm2-kira slot info
tpm2-kira slot info --nvram 0
tpm2-kira slot info --json          # machine-readable
tpm2-kira slot info --privkey /path/to/key.pem   # verify with a custom key
```

`slot info` first checks each blob's signature with the signing key (`--privkey`,
or the default key). The result is the first line of the output, and
`signature_verified` in JSON. A blob that does not verify is still shown, but
marked untrusted: its strings are printed escaped, and the files it names are
not opened.

`--json` always emits an array of slot objects, one per populated slot, even
when there is only one. Each entry carries `slot_number`, `nvram_index` and the
blob itself, so consumers never have to branch on the slot count.

## Deleting a slot

**Deleting a slot is one act**: `tpm2-kira control`, the slot's own line. It
deletes everything the slot is made of - its record (the EFI variable
`KIRAslotN`: the TOTP key, the phones, the phone salt's release key, the
vault's part, the TPM salt), its two companion indices in the TPM, the
keyslots bound to the slot by their token (every recipe but the recovery
recipe, which is bound to nothing and stays). If any part fails to go (no
remaining passphrase for `luksKillSlot`, a TPM that refuses), the rest is
still removed, and the slot is **dirty**: parts of it exist while it is
not whole. `control` shows a dirty slot with `[!]` and the cause, and
recommends the removal first; `status` notes it, until a run removes what
is left.

A slot is also left incomplete without anybody deleting it:

| What is left | Cause | Means |
|---|---|---|
| the record, without the slot's indices | the TPM was cleared (or the slot removed without the record) | its keys are the old TPM's and open nothing |
| the indices, without the record | the variable removed, or the firmware's variables reset | its methods fail at boot; the fallbacks unlock (password and salt typed, the OS recovery passphrase) |

The pieces can still be taken by hand - these leave the slot dirty the
same way where something of it remains:

```bash
tpm2-kira slot delete              # everything tpm2-kira keeps (slots, TPM indices, the SSH CA): asks to type 'yes'
tpm2-kira slot delete --yes        # the same, without asking
tpm2-kira slot delete --nvram 0    # one slot: its record and its indices in the TPM
tpm2-kira luks remove /dev/sda2 --keyslot 1   # one LUKS keyslot of tpm2-kira's, with its token
tpm2-kira phone unenrol --nvram 0  # only the phones of one slot (needs the signing key)
```

A slot is one record, under one signature: the EFI variable `KIRAslotN`,
holding its sealed boot state and its methods - a TOTP key when chosen
(`slot add --totp`), the phones, the vault, the TPM salt. Two small
companions belong to it in the TPM, because they are mechanisms of the TPM
and not data: an index the TPM can lock for the rest of the boot, and a
counter the TPM only lets count up. Nothing else of it is in the TPM: the
record needs no protection of the TPM's (its signature and the counter
are its protection; nothing in it is secret in clear) and has room an NV
index has not (SECURITY-BACKGROUND §3.1, *Why an EFI variable*). `slot
list` shows the slots and their parts, and the machine's boot settings:

| Where (slot *n*) | What it holds | Written by |
|---|---|---|
| EFI variable `KIRAslot`*n* | the slot's record: the boot state, its approval, its methods | `slot add`, `slot approve`, `phone enrol`/`unenrol`, `vault enrol`, `luks enrol` (TPM salt, vault) |
| NV `0x01803810` + *n* | the generation index of the slot's policy (the slot exists while it does) | `slot add`, `slot approve` |
| NV `0x01803820` + *n* | the record counter of the attestation part | the enrolments |
| NV `0x01803000` | the boot settings: "Debug at boot" (one per machine, only while it is on) | `control` |

Because the phones live in the slot's record,

- `phone enrol` needs a sealed slot, and checks the PCRs that slot is sealed
  to unless `--pcrs` says otherwise;
- `slot approve` (after every kernel update) and sealing a slot again keep its
  phones. A slot sealed by *another* signing key does not take over the
  phones the old key vouched for;
- the first phone retires the slot's TOTP code: the boot screen then shows
  "mobile attestation locked - please connect" for the slot until the phone
  is in. Remove the slot's entry from your authenticator; slot 1, the
  fallback, keeps its code for a boot without the phone;
- `phone unenrol` rewrites the record without the phones, and therefore
  needs the signing key; no TOTP key comes back by itself (`slot add
  --totp` seals one). `slot delete --nvram N` removes the slot whole and
  needs none;
- every further phone makes the record larger (about 170 bytes); a record
  holds at most 8 KiB, checked for the record as it would be written.

`slot delete` without `--nvram` removes everything of tpm2-kira's outside
the disk: every slot, what belongs to no slot any more (a counter whose
slot is gone, a record left by a cleared TPM), the boot settings, the sealed machine-id (`KIRAmachineID`,
docs/SSH.md §2.1; it goes with slot 0 too), and the SSH CA - its EFI
variable `KIRAasshCA` and `/etc/tpm2-kira/ssh_ca.pub` (docs/SSH.md §4).
What it never touches is the LUKS header: a keyslot bound to a deleted
slot is named as dirty, and `control` (or `luks remove`) takes it.

Every removal - `slot delete`, `control`'s, the SSH CA's - goes the one way
aSSH removes what it keeps (its `persist` package): an NV index goes only
when it has the public area tpm2-kira defines at that place, and anything
else at a handle of tpm2-kira's range is left and named; what is not there
is no error.

### If a rewrite of the slot fails

The firmware writes an EFI variable whole or not at all and keeps the
old one until the new one is there: a `slot approve` or an enrolment that
fails leaves the slot as it was.

