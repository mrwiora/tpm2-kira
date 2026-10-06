# tpm2-kira (Known Integrity Recognition Agent)

<p align="center">
  <img src=".github/tpm2-kira_300x300.png" alt="tpm2-kira logo" />
</p>

A TPM2 based tool to recognize modifications on your system !before! entering passphrases to unlock your disk.
Time-Based One-Time-Password Tokens calculated on Secrets, that the TPM2 reveals only when the device is in an unmodified state.

<p align="center">
  <img src=".github/ssh.gif" alt="tpm2-kira demo" />
</p>

**Successor/Extension to [tpm2-totp](https://github.com/tpm2-software/tpm2-totp).**

> [!CAUTION]
> tpm2-kira is currently in **alpha**. Expect breaking changes between versions.

## How It Works

tpm2-kira creates the TOTP key **inside the TPM**, as an HMAC key that never
leaves it: the TPM computes every code, and the key is shown exactly once, as
the QR code you enrol in your authenticator app.

The TPM computes a code only under a policy your signing key has approved:

| Condition | What it checks |
|-----------|----------------|
| **PCR values** | Boot measurements match the values approved at seal or reseal time |
| **Generation** | The approval is the latest one: every reseal revokes the older ones |
| **Not capped** | `tpm2-kira cap` has not run in this boot — it runs when the initrd is left, so the running system cannot compute codes |

On every boot, tpm2-kira asks the TPM for the current code before the
passphrase prompt. Compare it with the code in your authenticator app — if
they match, your boot chain is intact.

When a system update changes PCR values (kernel update, initramfs rebuild,
Secure Boot key rotation, etc.), the TPM refuses until you approve the new
values with `reseal` and your signing key. The key itself stays the same, so
there is nothing to re-enrol.

For more details on the cryptographic design, see [SECURITY-BACKGROUND.md](docs/SECURITY-BACKGROUND.md).

## Requirements

**Hardware:**
- TPM 2.0 (discrete or firmware TPM)

**Software:**
- Linux with TPM 2.0 kernel support (`/dev/tpmrm0`; `/dev/tpm0` is used only when
  the kernel provides no resource manager)
- Go ≥ 1.24 (build only)

**Supported architectures:** x86_64, aarch64

## Quick Start

```bash
# Build
git clone https://github.com/mrwiora/tpm2-kira.git
cd tpm2-kira
make build

# Install
sudo make install

# First-time setup: generates the signing keys
sudo tpm2-kira setup

# Seal a TOTP secret bound to firmware, Secure Boot state and the
# unified kernel image (kernel, initrd, command line)
sudo tpm2-kira seal --pcrs 0,7,11u

# Show the current TOTP code
tpm2-kira reveal
```

`setup` creates an ECDSA P-256 key pair at `/var/lib/tpm2-kira/keys/` and nothing else. `seal` creates a TOTP key inside the TPM, here approved for PCRs 0, 7 and 11; scan the QR code it prints with your authenticator app. Without a unified kernel image, see [Choosing PCRs](#choosing-pcrs): a selection that leaves out the kernel, initrd and command line lets a modified initrd show a valid code. `seal` refuses to run until `setup` has created the keys (or you pass your own with `--privkey` / `--pubkey`).

## Installation

### Build from Source

```bash
sudo pacman -S base-devel go git    # Arch
# or
sudo apt install build-essential golang git    # Debian/Ubuntu

git clone https://github.com/mrwiora/tpm2-kira.git
cd tpm2-kira
make build
sudo make install
```

### Arch Linux (AUR)

```bash
paru -S tpm2-kira      # or your preferred AUR helper
```

The PKGBUILD in [packaging/aur/](packaging/aur/) is a template: it builds a
checksummed release tarball, and its `pkgver` is filled in at publish time, so
it cannot be built straight from a clone. See
[packaging/aur/README.md](packaging/aur/README.md) to build one locally.

After installing, run setup and seal once, then rebuild the initramfs:

```bash
sudo tpm2-kira setup
sudo tpm2-kira seal --pcrs 0,7,11u    # with a unified kernel image
sudo mkinitcpio -P
```

### Debian / Ubuntu (.deb)

```bash
sudo apt install build-essential debhelper dpkg-dev golang-go
make deb
sudo apt install ../tpm2-kira_*_amd64.deb
```

`make deb` derives the package version from `git describe`, so an untagged
checkout produces something like `0.2.3+9.g9d32210`.

The package installs the binary, the initramfs-tools hook and boot scripts, and
rebuilds the initramfs. It does **not** run `setup` or `seal`, because sealing
generates a new TOTP secret and prints a QR code you need to scan:

```bash
sudo tpm2-kira setup
sudo tpm2-kira seal --pcrs "0e,2e,4e,7e,8e,9e"
sudo update-initramfs -u
```

The binary is built statically (`CGO_ENABLED=0`), so the initramfs needs no
libraries and the package has no shared-library dependencies.

### Verify

```bash
tpm2-kira version
```

## Commands

If called without a command, tpm2-kira defaults to `reveal`.

| Command | Description |
|---------|-------------|
| `setup` | One-time initial setup: generate the signing keys (run before `seal`) |
| `seal` | Generate and seal a new TOTP secret with custom PCR selection (requires `setup` or your own keys) |
| `reseal` | Approve new PCR values for the existing key (revokes older approvals) |
| `reveal` | Show the current TOTP code (colored output) |
| `reveal-plain` | Show the current TOTP code (plain text, for scripts) |
| `run` | Show a fresh code at boot until Enter (or 90 s), then release the boot |
| `cap` | Lock code computation until the next reboot (run by the boot integration when leaving the initrd) |
| `info` | Display metadata about the sealed key, its approval and its generation (`--json` for machine-readable output) |
| `nvram list` | List NVRAM indices |
| `nvram status` | Show NVRAM index status |
| `nvram delete` | Delete a slot (TOTP key and phones), or everything tpm2-kira keeps in the TPM |
| `attest enrol` | Bind a phone to this machine over Bluetooth LE (see [Remote attestation](#remote-attestation-with-a-phone-experimental)) |
| `attest gate` | Serve attestation requests until a phone returns a signed verdict |
| `attest status` | Show which phones are enrolled per slot, and whether the blob is signed by this machine's key (`--json`) |
| `attest signer` | Print this machine's signing public key for the initramfs, after checking the enrolled records against it and the TPM's record counter (used by the hooks; exit 6 if a record does not pass) |
| `attest quote` / `attest verify` | Produce evidence without a phone / judge it offline |
| `attest unenrol` | Remove a slot's phones from its blob (needs the signing key; the TOTP key stays) |
| `pcrtips` | PCR reference guide — what each register measures |
| `version` | Print version |

## Global Options

```
--tpm PATH       TPM device path (default: /dev/tpmrm0)
--nvram INDEX    NVRAM slot: 0-15 maps to 0x01803010-0x0180301F,
                 or specify a full hex index like 0x01803010.
                 When omitted, commands auto-discover populated slots.
--debug          Verbose output
```

## Sealing Secrets

### Basic seal

```bash
# Uses default PCRs 0,2,7 read from TPM registers
tpm2-kira seal
```

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
codes for any future time. PCRs 8 and 9 change on every kernel or initramfs update;
see [If you seal PCR 8 or 9](#if-you-seal-pcr-8-or-9-reseal-after-the-reboot).

### Hardening the boot path

A selection is only as good as the ways into a shell that it measures. Also:

- **Disable the boot-menu editor.** systemd-boot: `editor no` in
  `loader.conf`. GRUB: set a superuser password. Otherwise `rd.break` or
  `break=` on the command line drops to a root shell in the genuine initrd
  (and if the command line is not measured, the code still matches).
- **No shell after a failed unlock.** On Debian, add `panic=0` (reboot) so
  initramfs-tools does not drop to its fallback shell.
- **Firmware setup password and locked boot order**, so no other medium can be
  booted, and the clock cannot be changed (see [How it works at
  boot](#how-it-works-at-boot)).
- **Your own Secure Boot keys** (e.g. with sbctl), so any medium signed for
  other systems changes PCR 7.

### Warnings about weak selections

`seal` and `reseal` report selections that attest less than they appear to.
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
The code stays on the screen for when the phone is not at hand. The phone
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
(until `cap`), and marks them accordingly. Blobs sealed by earlier versions
(which ran after the separator) work the same way until they are resealed.

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

### TPMs whose event log has no SHA-256 digests

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

### Custom signing keys

By default, `setup` generates keys at `/var/lib/tpm2-kira/keys/`. You can supply your own (RSA-2048, ECDSA P-256, or ECDSA P-384):

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

### Multiple slots

tpm2-kira supports up to 16 NVRAM slots (0–15). Useful if you need separate secrets for different purposes:

```bash
tpm2-kira seal --nvram 0
tpm2-kira seal --nvram 1 --pcrs "0e,2e,7e"

tpm2-kira reveal --nvram 0
tpm2-kira reveal --nvram 1
```

## Resealing After Updates

When PCR values change (kernel update, initramfs rebuild, firmware update), the TPM no longer computes codes and `reveal` shows a PCR mismatch. Reseal to approve the new values with your signing key; the key in the TPM, and so your authenticator, stay the same:

```bash
# Uses the default signing key from setup
tpm2-kira reseal

# Or specify the key explicitly
tpm2-kira reseal --privkey /var/lib/tpm2-kira/keys/seal.key
```

You can also change the PCR selection during reseal:

```bash
tpm2-kira reseal --pcrs "0e,2,4,7e"
```

## Inspecting Sealed Data

```bash
tpm2-kira info
tpm2-kira info --nvram 0
tpm2-kira info --json          # machine-readable
tpm2-kira info --privkey /path/to/key.pem   # verify with a custom key
```

`info` first checks each blob's signature with the signing key (`--privkey`,
or the default key). The result is the first line of the output, and
`signature_verified` in JSON. A blob that does not verify is still shown, but
marked untrusted: its strings are printed escaped, and the files it names are
not opened.

`--json` always emits an array of slot objects, one per populated slot, even
when there is only one. Each entry carries `slot_number`, `nvram_index` and the
blob itself, so consumers never have to branch on the slot count.

## Deleting Sealed Data

```bash
tpm2-kira nvram delete              # everything tpm2-kira keeps in the TPM: asks to type 'yes'
tpm2-kira nvram delete --yes        # the same, without asking
tpm2-kira nvram delete --nvram 0    # one slot, whole: TOTP key and phones
tpm2-kira attest unenrol --nvram 0  # only the phones of one slot (needs the signing key)
```

A slot is one blob in the TPM: it holds the slot's TOTP key and, once a phone
is enrolled, the phones too, under one signature. Two small companions belong
to it, because they are mechanisms of the TPM and not data: an index the TPM
can lock for the rest of the boot, and a counter the TPM only lets count up.
`nvram list` labels all three:

| NV index (slot *n*) | What it holds | Written by |
|---|---|---|
| `0x01803010` + *n* | the slot's blob: TOTP key and phone enrolment | `seal`, `reseal`, `attest enrol`, `attest unenrol` |
| `0x01803810` + *n* | the generation index of the TOTP key's policy | `seal`, `reseal` |
| `0x01803820` + *n* | the record counter of the phone enrolment | `attest enrol`, `attest unenrol` |

Because the phones live in the slot's blob,

- `attest enrol` needs a sealed slot, and checks the PCRs that slot is sealed
  to unless `--pcrs` says otherwise;
- `reseal` (after every kernel update) and sealing a slot again keep its
  phones. A slot sealed by *another* signing key does not take over the
  phones the old key vouched for;
- `attest unenrol` rewrites the blob without the phones and therefore needs
  the signing key; `nvram delete --nvram N` removes the slot whole and needs
  none;
- every phone makes the blob larger (about 200 bytes), and a TPM limits the
  size of an NV index (2048 bytes on many). `attest enrol` checks before it
  starts whether another phone still fits.

`nvram delete` without `--nvram` removes every slot and what belongs to no
slot any more: a companion whose slot is gone, or a phone enrolment that an
earlier version kept as an index of its own (`0x01803020` + *n*; no longer
read - enrol the phone again).

## Remote attestation with a phone (experimental)

Instead of comparing six digits by eye, a phone app can verify the boot: the
machine's TPM signs a quote over its PCRs, the phone checks it against what it
recorded at enrolment and shows **match**, **changed** (with an explanation of
which part of the boot chain moved) or **failed**. After a kernel update the
machine is not silent as with the OTP: it attests its new state and you approve
the change on the phone. The OTP path stays and remains the fallback.

```bash
# Once, on the booted system (needs the signing key and a Bluetooth adapter):
sudo tpm2-kira attest enrol --name "Thinkpad-X1"
#   compare the 6-digit code on the console with the app, confirm on both
#   A TPM without a SHA-256 PCR bank, or a slot sealed with --sha1, needs
#   --sha1 here as well: SHA-1 is never chosen without being asked for.

# Serve an attestation (lazy mode: shows the verdict, never blocks):
sudo tpm2-kira attest gate
sudo tpm2-kira attest status

```

**Both sides check each other's hardware at enrolment.** The phone checks
that this machine's TPM is genuine (its EK certificate against vendor roots
built into the app); `attest enrol` runs the same check on itself first
(`--verify-tpm`). The machine checks the phone's key attestation against
Google's attestation roots and revocation list: key in StrongBox or the TEE,
an unlock for every use, a locked and verified phone (`--verify-phone`).
Both default to `warn`: the result is shown and, if not verified, you are
asked (custom ROMs such as LineageOS boot "self-signed" and fail the last
check). `require` refuses, `off` skips.

**Choose PCRs that cover the initrd.** The initrd is where a passphrase
logger would sit; if no quoted PCR measures it, a modified initrd attests as
unchanged. `attest enrol` reads this boot's event log, says which PCRs
measured the initrd, and asks before enrolling a selection that misses them:

| Boot path | Initrd measured into | For example |
|---|---|---|
| GRUB, separate initrd | PCR 9 (the file) | `--pcrs 0,2,4,7,9` |
| systemd-boot / EFI stub, separate initrd (kernel ≥ 5.17) | PCR 9 (tagged "Linux initrd") | `--pcrs 0,2,4,7,9` |
| Unified kernel image (UKI) | PCR 11 (`.initrd` section) and PCR 4 (the whole image) | the default `0,2,4,7` |

PCR 9 also changes with every kernel or initrd update; the phone then shows
*changed* with the diff, and you approve the new state once.

The phone enrolment lives in the slot's blob in TPM NV storage, next to the
TOTP key: readable and — through the owner hierarchy — replaceable by anyone
who can talk to the TPM, including another OS booted on this machine. So the gate checks it before the passphrase prompt:
the record must be signed by your signing key, whose public half the hook puts
into the image, and its count must equal a counter the TPM keeps for the slot,
which cannot be turned back. A foreign record fails the first check, an older
one put back the second. Enrolling or removing a phone needs no rebuild. The
check is as strong as the protection of the initramfs itself (a Secure
Boot-signed unified kernel image, or PCRs that cover the initrd); the verdict
on the console stays advisory: **only the phone's screen counts.**

While enrolling or attesting, tpm2-kira takes the Bluetooth adapter
exclusively through an HCI user channel (no BlueZ needed); other Bluetooth
devices on that adapter disconnect until it finishes. `--adapter N` selects
another adapter.

### At the passphrase prompt

Enable lazy mode in `/etc/tpm2-kira/attest.conf` and rebuild the initramfs:

```bash
sudo sed -i 's/^TPM2_KIRA_ATTEST=.*/TPM2_KIRA_ATTEST=lazy/' /etc/tpm2-kira/attest.conf
sudo mkinitcpio -P            # or: sudo update-initramfs -u
```

The hooks ask `tpm2-kira attest initramfs-deps` what the configured adapter
needs and copy exactly that: its driver modules and the firmware files the
kernel loaded for it in the current boot (about 1.1 MB on an Intel adapter).
Nothing is added while attestation is off, no phone is enrolled, or the
adapter is missing. At boot the gate runs beside the TOTP display, waits for
the adapter, serves the phone, prints the verdict, and never holds the boot.

The new modules and firmware change the initramfs and therefore PCR 11 (UKI)
or PCR 9 (GRUB): on Arch the post hook reseals automatically; on Debian with
PCR 9 sealed, reseal after the next boot as described below.

The same session will later also release the salt for
[hashpwd2](https://github.com/mrwiora/hashpwd2) when the LUKS key is derived
from a password plus a phone-held factor
([docs/PLAN-FACTORRELEASE.md](docs/PLAN-FACTORRELEASE.md)).

Status: the machine side, Bluetooth inside the initramfs (lazy mode) and the
phone's verification core are implemented but not yet tested on real
Bluetooth hardware; enforced mode and salt release are not implemented yet.
The phone apps are specified in [docs/mobile/](docs/mobile/). The protocol is
defined in [docs/PROTOCOL-BLE.md](docs/PROTOCOL-BLE.md), the design in
[docs/PLAN-REMOTEATTESTATION.md](docs/PLAN-REMOTEATTESTATION.md) and
[docs/PLAN-BLE.md](docs/PLAN-BLE.md).

## Early Boot Integration (Arch Linux / mkinitcpio)

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

A systemd service (`tpm2-kira.service`) starts before the disk unlock prompt and runs `tpm2-kira run`, which shows a fresh TOTP code every 30 seconds. Compare what's on screen with your authenticator app. If they match, your boot chain is clean — press Enter and type your LUKS passphrase. Without Enter the boot continues by itself after 90 seconds; once it has continued, no code can be computed until the next boot.

When the initrd hands over to the real root, `tpm2-kira-cap.service` runs
`tpm2-kira cap`. From then until the next reboot the TPM computes no codes,
for anyone, root included — `tpm2-kira reveal` in the running system reports
"Locked until reboot". `reseal` still works.

A matching code is evidence only if the clock was not tampered with: the
codes depend on the real-time clock, which nothing measures. Someone with the
machine can boot it untouched with the clock set forward, note the codes for
the time you will next boot, then tamper with it. A firmware setup password
and a locked boot order make that much harder; see
[SECURITY-BACKGROUND.md](docs/SECURITY-BACKGROUND.md) §8.

See [initramfs/mkinitcpio/mkinitcpio.conf.example](initramfs/mkinitcpio/mkinitcpio.conf.example) for more HOOKS configurations (LVM, multiple encrypted devices, etc.).

### What is installed where

The package puts three unit files into `/usr/lib/systemd/system` on the
host, because the mkinitcpio hook takes them from there. None of them is
enabled on the host, and each carries
`ConditionPathExists=/etc/initrd-release`, so enabling one there by mistake
does nothing.

| Unit | In the initramfs image | Does something when |
|------|------------------------|---------------------|
| `tpm2-kira.service` (the code at the prompt, and the gate's coordinator) | always, once `sd-tpm2-kira` is in `HOOKS` | a TOTP key is sealed. With nothing sealed it says so once, releases the boot and exits; a later `seal` needs no rebuild. It ends when the boot is released, and the gate with it |
| `tpm2-kira-cap.service` (locks codes when the initrd is left) | always, with the display | the initrd is left. Without sealed keys there is nothing to lock |
| `tpm2-kira-attest.service` (Bluetooth gate, radio worker) | only if `/etc/tpm2-kira/attest.conf` says `lazy`, **and** a phone is enrolled, **and** its record is signed by this machine's key and current, **and** the adapter was found when the image was built. The signing public key goes into the image with it. Otherwise neither the unit nor any Bluetooth module or firmware is in the image; `mkinitcpio` says which condition failed | a phone connects |

One case leaves a unit in the image with nothing to do: `attest unenrol`
without rebuilding the initramfs. The gate then starts at boot, reports that no
phone is enrolled and fails; `unenrol` tells you to rebuild.

The radio worker is the only process that takes input from outside the
machine before the disk is unlocked, so its unit confines it: Bluetooth and
Unix sockets only, the capabilities for the adapter and no others, rfkill and
the console as its only devices and no TPM, a read-only file system, and a
system call filter (`systemd-analyze security` rates the unit 2.2, from 9.4
without).

On Debian there are no units in the image: the initramfs-tools scripts start
the display and, under the same three conditions, the gate, and run `cap` when
the initramfs is left. The split into coordinator and radio worker and the
confinement above apply to systemd-based images only; there the gate is one
process with the TPM, and the phone's verdict does not release the display.

## Early Boot Integration (Debian / initramfs-tools)

Debian's stock initramfs has no systemd in it, so the systemd unit used on Arch
does not apply. The `.deb` installs two scripts instead:

| Path | Role |
|---|---|
| `/usr/share/initramfs-tools/hooks/tpm2-kira` | copies the binary into the image |
| `/usr/share/initramfs-tools/scripts/init-premount/tpm2-kira` | starts the display at boot |
| `/usr/share/initramfs-tools/scripts/init-bottom/tpm2-kira` | stops it and runs `tpm2-kira cap` before the real root takes over |
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
so nothing is left holding it open, and then runs `tpm2-kira cap`.

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
# Measures kernel, initrd and command line; needs the workflow below
tpm2-kira seal --pcrs "0e,2e,4e,7e,8e,9e"

# Stable across kernel updates, but a modified initrd or command line
# still shows a valid code (seal prints a warning)
tpm2-kira seal --pcrs "0e,2e,4e,7e"
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

## Eventlog PCR Calculator

`tools/pcrtool.py` independently reconstructs PCR values, which is the first
thing to reach for when a sealed policy stops matching. It reads the live
firmware event log directly, or a `tpm2_eventlog` YAML dump:

```bash
# All PCRs from the running system's event log
sudo python3 tools/pcrtool.py replay

# A specific PCR, showing every extension step
sudo python3 tools/pcrtool.py replay --pcr 7 --verbose

# From a dump, which needs neither root nor a TPM
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements > evlog.yaml
python3 tools/pcrtool.py --eventlog evlog.yaml replay

# The SHA-1 bank
sudo python3 tools/pcrtool.py --bank sha1 replay
```

The `extends` column counts how many events actually extended each PCR. A zero
there means the log carries no digests for that PCR **in the selected bank**, so
the value shown is only the reset value — the tool warns and exits non-zero
rather than letting that pass as a measurement.

Requires PyYAML (`pip install pyyaml`) and tpm2-tools.

## Testing

```bash
# Unit tests (no TPM required)
make test-unit

# Integration tests (requires swtpm + socat)
# Install: sudo apt install swtpm swtpm-tools socat
#      or: sudo pacman -S swtpm socat
make test-integration

# Everything
make test-all
```

## Troubleshooting

**TPM device not found:**
```bash
ls -la /dev/tpm*
sudo dmesg | grep -i tpm
```
Ensure TPM 2.0 is enabled in your BIOS/UEFI settings.

**Permission denied on `/dev/tpmrm0`:**
```bash
# Check current permissions
ls -la /dev/tpmrm0

# Your user needs access — either run as root or add a udev rule
```

**TOTP code doesn't match after update:**
```bash
tpm2-kira reseal
```
If reseal also fails, check `tpm2-kira info` to see which PCRs changed and verify you have the correct signing key available.

**Debug output:**
```bash
tpm2-kira --debug reveal
```

**Check current PCR values vs. sealed values:**
```bash
tpm2-kira info            # shows what was sealed
tpm2-kira pcrtips         # explains what each PCR measures
```

## Uninstall

```bash
# Remove sealed data first
tpm2-kira nvram delete --yes

# Remove binary
sudo make uninstall

# Remove mkinitcpio hooks (if installed)
sudo make uninstall-mkinitcpio
sudo mkinitcpio -P

# Optionally remove signing keys
sudo rm -rf /var/lib/tpm2-kira
```

On Arch:
```bash
tpm2-kira nvram delete --yes
sudo pacman -R tpm2-kira
```

On Debian:
```bash
tpm2-kira nvram delete --yes
sudo apt remove tpm2-kira
```

Purging the Debian package deliberately leaves `/var/lib/tpm2-kira` in place:
the signing key is the only way to approve new PCR values for a key that may
still be sealed in the TPM. Delete the slot first, then the directory.

## Project Structure

```
├── main.go                  # CLI entrypoint and command routing
├── attest/                  # Remote attestation core: protocol, Noise, Verify(); no device access
│   └── attesttest/          # Software TPM, in-memory pipe and simulated phone for tests
├── transport/
│   ├── frame/               # Record fragmentation for BLE (shared with the phone)
│   └── ble/                 # Pure-Go BLE peripheral over an HCI user channel
├── mobile/
│   ├── kiracore/            # gomobile binding: the phone's verifier core
│   └── kiratest/            # gomobile binding: a simulated machine for app tests
├── cmd/                     # Command implementations
│   ├── seal.go              # Create the TOTP key in the TPM and approve PCR values
│   ├── reseal.go            # Approve new PCR values, revoke older approvals
│   ├── setup.go             # First-time setup (keygen)
│   ├── info.go              # Inspect sealed blob metadata
│   ├── scan.go              # Multi-slot NVRAM scanning
│   ├── blob.go              # Sealed blob serialization format
│   ├── totpkey.go           # TOTP key object, PolicyAuthorize, generation, cap
│   ├── signingkey.go        # Signing key loading, PolicySigned for NV writes
│   ├── keyfile.go           # Key file checks (owner, mode, symlinks)
│   ├── untrusted.go         # Printing strings from unverified blobs
│   ├── eventlog_utils.go    # TPM eventlog parsing
│   ├── measurepoint.go      # Userspace extends before tpm2-kira reads PCRs
│   ├── ukipredict.go        # Native PCR 11 computation from a UKI
│   ├── pcr.go               # PCR spec parsing, reading and comparison
│   ├── pcrwarn.go           # Warnings for PCR selections that attest little
│   ├── attest.go            # attest enrol/gate/status/quote/verify/unenrol
│   ├── attest_blob.go       # Per-slot attestation blob (AK, pinned phones)
│   ├── attest_tpm.go        # AK/EK, TPM2_Quote, ActivateCredential
│   ├── nvram.go             # NVRAM read/write/scan operations
│   ├── totp_utils.go        # Code truncation, QR code and display
│   ├── tpm_utils.go         # Low-level TPM operations
│   ├── pcrtips.go           # PCR reference information
│   └── constants.go         # Default paths and constants
├── tools/
│   ├── pcrtool.py            # PCR replay and full-chain diagnosis
│   └── tpm2-pcr11predict     # Independent cross-check of the built-in PCR 11 computation
├── docs/
│   ├── PROTOCOL-BLE.md           # Phone <-> machine protocol: the interface definition
│   ├── PLAN-*.md                 # Designs: remote attestation, BLE, remote unlocking, factor release
│   ├── mobile/                   # Agent prompts for the Android and iOS apps
│   ├── PLATFORM-OBSERVATIONS.md  # Measured facts about Arch and Debian boots
│   ├── pentest1/, pentest2/      # Security review findings and mitigations
│   └── *.issue                   # Write-ups of specific bugs
├── initramfs/               # Everything that goes into, or builds, an initramfs
│   ├── common/attest.conf          # Attestation mode for the initramfs (off / lazy)
│   ├── systemd/tpm2-kira.service   # Shows the code in systemd-based images
│   ├── systemd/tpm2-kira-cap.service  # Runs 'cap' when leaving the initrd
│   ├── systemd/tpm2-kira-attest.service  # Lazy Bluetooth attestation gate
│   ├── mkinitcpio/                 # Arch
│   │   ├── install/sd-tpm2-kira    # Build hook: puts the binary in the image
│   │   ├── post/sd-tpm2-kira       # Reseal after the image is written
│   │   └── mkinitcpio.conf.example
│   └── initramfs-tools/            # Debian
│       ├── hooks/tpm2-kira         # Build hook: copies the static binary
│       ├── scripts/init-premount/tpm2-kira  # Shows the code before unlock
│       ├── scripts/init-bottom/tpm2-kira    # Stops it and caps before switching root
│       ├── post-update.d/tpm2-kira          # Reseal reminder
│       └── initramfs.conf          # Display mode (run / once)
├── debian/                  # Debian package definition (must sit at the root)
├── packaging/
│   ├── aur/                 # Arch Linux PKGBUILD
│   └── deb-version.sh       # git describe -> a Debian-valid version
└── Makefile
```

## Diagnosing PCR mismatches

If the displayed PCR values differ from what was sealed, reconstruct the whole
chain before changing anything:

```bash
# Replays the firmware event log AND systemd's own measurement log,
# then explains every difference against the live registers.
sudo python3 tools/pcrtool.py verify
```

Each PCR is reported as `unchanged since firmware`, `os-separator (x1)`,
`explained: <words>`, or `UNEXPLAINED`. Anything unexplained on a sealed PCR is
a real finding.

Two things to keep in mind while reading any PCR output:

- `tpm2_eventlog`'s trailing `pcrs:` block is a **replay of the log**, not a
  read of the TPM. Comparing it against `tpm2_pcrread` is comparing a
  calculation against a measurement — and that difference is usually the answer.
- The **post-boot register is not the measure-point value** for PCRs 9, 11 and
  15. They keep being extended after the initrd, so a mismatch there is expected
  and not evidence of tampering.

See [SECURITY-BACKGROUND.md](docs/SECURITY-BACKGROUND.md) §5.6–5.8 for the full
reconstruction rules and constants.

## Exit status

**tpm2-kira always exits 0, including on failure.** This is deliberate: it is
meant to be chainable in a boot sequence, so a TPM or NVRAM problem must not
stop the commands after it.

```bash
tpm2-kira && cryptsetup open /dev/nvme0n1p2 cryptroot
```

Scripts must therefore judge success from the **output**, not the exit status.
Failures are printed to stderr with a fixed marker:

```
tpm2-kira: FAILED: <reason>
tpm2-kira: (exit status is 0 by design; this command did NOT succeed)
```

The mkinitcpio post hook does exactly this — it greps the output for the success
line rather than testing `$?`.

**Exception: the attestation commands.** `attest gate`, `attest verify`,
`attest quote` and `attest enrol` gate or judge something, and a gate that
exits 0 on failure is not a gate. They exit non-zero on failure: `1` internal
error, `2` usage, `3` no phone or no adapter, `4` the phone rejected this boot
(do not type a passphrase before checking further), `5` the receipt was not
signed by the enrolled phone.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy and [SECURITY-BACKGROUND.md](docs/SECURITY-BACKGROUND.md) for an in-depth description of the cryptographic design, threat model, and trust boundaries.

## History

[HISTORY.md](HISTORY.md) records superseded formats, removed features and the
reasoning behind them, so the source can describe what it is rather than what it
used to be. This project is in development: **no backwards compatibility is
maintained**, and blob formats, on-disk layouts and CLI flags may change without
a migration path.

## License

BSD 3-Clause — see [LICENSE](LICENSE).
