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

# Seal a TOTP key to what this boot measured: firmware and Secure Boot
# state, plus the unified kernel image or GRUB's PCRs - and a fallback
# slot sealed to firmware and Secure Boot state alone
sudo tpm2-kira seal

# Show the current TOTP code
tpm2-kira reveal
```

`setup` makes the signing key that approves every PCR policy, and nothing else. It looks for a YubiKey first: with one plugged in it offers to take the key from a PIV slot (`--yubikey`, optionally `=SERIAL`, `--slot`, default 9a) so the private key never exists on the machine; without one, or with `--local`, it creates an ECDSA P-256 key pair at `/etc/tpm2-kira/keys/` (`seal.pub`, `seal.key`, root-only). `tpm2-kira yubikey list` shows the candidates; the trade-offs are in [docs/PLAN-YUBIKEY.md](docs/PLAN-YUBIKEY.md). `seal` creates a TOTP key inside the TPM, approved for what this boot measured (see [Basic seal](#basic-seal)); scan the QR codes it prints with your authenticator app, the fallback slot's too. A selection that leaves out the kernel, initrd and command line lets a modified initrd show a valid code, see [Choosing PCRs](#choosing-pcrs). `seal` refuses to run until `setup` has created the keys (or you pass your own with `--privkey` / `--pubkey`).

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

## Guided: `tpm2-kira control`

One screen for a person rather than a script: what the machine has (the
TPM and its banks, how it booted and so which PCRs to seal to, the
initramfs kind, a Bluetooth adapter, the LUKS devices), what is configured
(the signing key, the slots, the phone, the keyslots, the unlock mode,
the route of the key), the five protections in the order they build on
each other - each done, possible, or blocked with the reason - and the
recommended next step. Pick a number and it runs that step with the same
functions the commands below use; run it again later and it shows the
state and what is left. The commands below are for specific settings.

```
[ KIRA ] control - the protections of this machine, step by step

What this machine has
  TPM         /dev/tpmrm0, SHA-256 bank and event log
  Boot        a unified kernel image booted: ...: PCRs 0e,2e,7e,11u
  Initramfs   mkinitcpio
  Bluetooth   hci0 (attestation by phone possible)
  LUKS        /dev/sda2: keyslots 0 not tpm2-kira's; not routed through tpm2-kira
  Unlock      mode skip

Protections
  [x] 1  Signing key  - local key files in /etc/tpm2-kira/keys
  [x] 2  TOTP code at boot  - slot 0 sealed to 0e,2e,7e,11u; the fallback in place
  [ ] 3  Attestation by phone (Marify, Bluetooth LE)
  [ ] 4  Disk key from password + salt (hashpwd2)
  [-] 5  Disk key from password + remote salt (the phone)  - needs the attestation by phone

Recommended next: 3  Attestation by phone (Marify, Bluetooth LE)
  The phone checks the boot state against what it pinned and shows a code the machine must show too; ...

Choose a step by number, or q to leave:
```

## Commands

`tpm2-kira help` is one screen, the commands grouped by what you are doing;
`tpm2-kira help <command>` (or `<command> --help`) is that command's page
with its subcommands, options and examples. Called without a command,
tpm2-kira runs `reveal`.

| | Commands |
|---|---|
| Guided | `control`: one screen, the protections step by step |
| Setting up the machine | `setup` the signing key · `seal` a new TOTP key to the boot state · `reseal` approve the current boot state (the hooks run it) · `status` the overview · `info` a slot's blob · `nvram list\|status\|delete\|restore` |
| The phone (Marify, Bluetooth LE) | `attest enrol\|unenrol\|status\|gate\|signer\|ekcert\|quote\|verify\|config-check` · `remote-salt enrol\|rotate\|status\|unenrol` |
| The disk's key | `luks status\|enrol\|remove\|mark\|route` · `derive` (hashpwd2 by hand) · the mode in `/etc/tpm2-kira/unlock.conf` |
| At boot (the units and hooks) | `run` · `cap` · `unlock-key` (Debian keyscript) |
| By hand | `reveal` / `reveal-plain` · `yubikey list` · `pcrtips` · `version` |

Global options come before the command: `--tpm PATH` (default `/dev/tpmrm0`),
`--nvram INDEX` (a slot 0-15 or a full index such as `0x01803010`; without
it most commands take every populated slot), `--debug`.

## Sealing Secrets

### Basic seal

```bash
tpm2-kira seal
```

Without `--pcrs`, the selection is what this boot measured, read from the
event log:

| This boot | Slot 0 is sealed to | Why |
|---|---|---|
| a unified kernel image (systemd-stub) | `0e,2e,7e,11u` | firmware, option ROMs, Secure Boot state, and PCR 11 computed from the image - a kernel update is predicted from the new image |
| GRUB | `0e,2e,7e,8e,9e` | the same, and GRUB's commands and the files it read, predicted from `grub.cfg` for the next boot |
| neither | `0e,2e,7e` | firmware, option ROMs, Secure Boot state |

Without `--pcrs` and `--nvram`, a second slot is sealed as well: **slot 1,
the fallback, to `0e,7e` alone**. When a kernel or boot loader change was
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
codes for any future time. PCRs 8 and 9 change on every kernel or initramfs
update; `reseal` predicts them from the files on disk, see
[docs/BOOT-INTEGRATION.md](docs/BOOT-INTEGRATION.md#pcr-8-and-9-are-predicted-for-the-next-boot).

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

The display runs before systemd's OS separator, so the seal predicts the PCR values of that point; `--measure-point` and what it means: [docs/SEALING.md](docs/SEALING.md#the-measure-point).

### TPMs whose event log has no SHA-256 digests

A TPM without a SHA-256 PCR bank needs `--sha1` throughout: [docs/SEALING.md](docs/SEALING.md#tpms-whose-event-log-has-no-sha-256-digests).

### Custom signing keys

Your own key pair instead of `setup`'s (`--privkey`, `--pubkey`; RSA-2048, P-256, P-384): [docs/SEALING.md](docs/SEALING.md#custom-signing-keys).

### Multiple slots

Up to sixteen slots, `--nvram N`: [docs/SEALING.md](docs/SEALING.md#multiple-slots).

## Resealing After Updates

When PCR values change (kernel update, initramfs rebuild, firmware update), the TPM no longer computes codes and `reveal` shows a PCR mismatch. Reseal to approve the new values with your signing key; the key in the TPM, and so your authenticator, stay the same:

```bash
# Uses the default signing key from setup
tpm2-kira reseal

# Or specify the key explicitly
tpm2-kira reseal --privkey /etc/tpm2-kira/keys/seal.key
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
slot any more: a companion index whose slot is gone.

### If a rewrite of the slot fails

A TPM cannot replace an NV index in place: `reseal`, `attest enrol` and
`attest unenrol` undefine the slot and write it again, and for a moment
the TPM holds no blob. Everything that can fail without touching the TPM
(loading the key, the token's PIN, the signer) is exercised before that
moment. If a step after it fails anyway — the TPM refuses the define, a
chunk does not write, the read-back differs — the blob that was about to
be written is saved to `/etc/tpm2-kira/recovery/slot-0x<index>-<time>.blob`
and the command says so. The file holds the sealed object as this TPM
wrapped it, which only this TPM can load, so the secret is not lost with
the index. Once the cause is fixed:

```bash
tpm2-kira nvram restore /etc/tpm2-kira/recovery/slot-0x01803010-1759823456.blob
```

verifies the blob with the signing key, needs the slot to be empty (it
is, after such a failure), approves the blob again for the PCRs it was
sealed to, writes it, and removes the file. The codes are the ones from
before; nothing has to be re-enrolled.

## Remote attestation with a phone (experimental)

Instead of comparing six digits by eye, a phone app can verify the boot: the
machine's TPM signs a quote over its PCRs, the phone checks it against what it
recorded at enrolment and shows **match**, **changed** (with an explanation of
which part of the boot chain moved) or **failed**, together with a code that
the machine's screen must show (see *The measure point*) and whether the
machine's TPM released its *boot key* for this boot state. Nothing is signed
until you have compared the code and pressed the button. After a kernel update the
machine is not silent as with the OTP: it attests its new state and you approve
the change on the phone. The OTP path stays and remains the fallback.

```bash
# Once, on the booted system (needs the signing key and a Bluetooth adapter):
sudo tpm2-kira attest enrol --name "Thinkpad-X1"
#   compare the 6-digit code on the console with the app, confirm on both
#   A TPM without a SHA-256 PCR bank, or a slot sealed with --sha1, needs
#   --sha1 here as well: SHA-1 is never chosen without being asked for.

# Serve an attestation by hand (shows the verdict, never blocks):
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

### At the code screen

Once a phone is enrolled, rebuild the initramfs:

```bash
sudo mkinitcpio -P            # or: sudo update-initramfs -u
```

There is no mode to switch on: the hooks ask `tpm2-kira attest
initramfs-deps` what the adapter needs (`TPM2_KIRA_ATTEST_ADAPTER` in
`/etc/tpm2-kira/attest.conf`, hci0 by default) and copy exactly that: its
driver modules and the firmware files the kernel loaded for it in the
current boot (about 1.1 MB on an Intel adapter). Nothing is added while no
phone is enrolled or the adapter is missing. At boot the gate runs beside
the TOTP display, waits for the adapter, serves the phone, prints the
verdict, and never holds the boot.

The new modules and firmware change the initramfs and therefore PCR 11 (UKI)
or PCR 9 (GRUB): on both, the post hook reseals automatically, on Debian
with PCR 8/9 predicted for the next boot (below).

The same session will later also release the salt for
[hashpwd2](https://github.com/mrwiora/hashpwd2) when the LUKS key is derived
from a password plus a phone-held factor
([docs/PLAN-FACTORRELEASE.md](docs/PLAN-FACTORRELEASE.md)).

Status: the machine side, Bluetooth inside the initramfs and the phone's
verification core are implemented but not yet tested on real Bluetooth
hardware; salt release is not implemented yet. The phone's verdict informs;
the passphrase can always be entered by hand
([UNLOCK-DISK.md](docs/UNLOCK-DISK.md) §4).
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

Edit `/etc/mkinitcpio.conf` and add the hook next to `sd-encrypt`:

```bash
# Systemd-based initramfs (recommended):
HOOKS=(base systemd autodetect modconf block keyboard sd-tpm2-kira sd-encrypt filesystems fsck)
```

The order of the two hooks does not matter for the boot: what runs when is
decided by the units (`tpm2-kira.service` before `systemd-pcrosseparator`,
the key socket before `cryptsetup-pre.target`, the disk after both), not
by the position in `HOOKS`, and neither hook reads what the other wrote.
`sd-tpm2-kira sd-encrypt` is the order to use, because it reads like the
boot: the code screen, then the disk.

What the image does at boot depends on two things, both optional:

| In the image / on the command line | At boot |
|---|---|
| nothing but the hook | the code screen, then `sd-encrypt`'s own passphrase prompt (systemd's), as if tpm2-kira were not there once the code is confirmed |
| `rd.luks.key=<UUID>=/run/tpm2-kira/unlock.sock` on the kernel command line | the code screen, then tpm2-kira's passphrase prompt; a typo falls back to systemd's prompt |
| a phone enrolled (`attest enrol`) and the adapter found at build time | the code screen also asks the phone and shows its verdict; the passphrase prompt is never held |

### Configure the disk unlock

The passphrase is asked at tpm2-kira's prompt, after the code screen, for
every volume whose *key file* is tpm2-kira's socket,
`/run/tpm2-kira/unlock.sock`. That is `crypttab(5)`'s own way of taking a
key from a service ("AF_UNIX key files"): `systemd-cryptsetup` connects
to the socket and reads the key when it activates the volume. tpm2-kira
is meant for the main disk, which on a systemd initrd is named on the
kernel command line; name its key file there too, next to
`rd.luks.name=`:

```
rd.luks.name=<UUID>=cryptroot rd.luks.key=<UUID>=/run/tpm2-kira/unlock.sock
```

`<UUID>` is the LUKS UUID (`cryptsetup luksUUID /dev/<partition>`), the
same in both. `rd.luks.key=` is honoured in the initrd only
(`systemd-cryptsetup-generator(8)`), so the running system sees no
change. With a UKI the command line is the file in your preset
(`/etc/kernel/cmdline` or `/etc/cmdline.d/`); with a boot loader it is
the entry's `options` line. `rd.luks.key=/run/tpm2-kira/unlock.sock`
without a UUID routes every volume named on the command line.

Both parameters stay; a second `rd.luks.name=` with the socket as its
"name" makes systemd set up a volume called `/run/tpm2-kira/unlock.sock`
and no `cryptroot` ("Failed to start Cryptography Setup for
/run/tpm2-kira/unlock.sock").

**tpm2-kira does not edit the command line, it tells you what it should
read**: `tpm2-kira luks route` reads the files the command line comes from
(`/etc/cmdline.d/*.conf`, else `/etc/kernel/cmdline`; boot loader
entries; `/etc/crypttab`), names what is wrong for every device with a
keyslot of tpm2-kira's - the parameter missing, a doubled `rd.luks.name=`,
the socket as the volume's name, another key file - and prints the line
as it should read. `luks enrol` ends with it, `tpm2-kira status` notes it,
and `mkinitcpio -P` runs it (the hook's `the volume <UUID> is unlocked
through tpm2-kira's prompt`, or a warning with the lines to change).

### What tpm2-kira does with the disk's key: `unlock.conf`

`/etc/tpm2-kira/unlock.conf` names it, in three modes, the same on Arch
and Debian; the hooks copy the file into the image, so rebuild after a
change:

| `TPM2_KIRA_UNLOCK=` | at boot, after the code screen |
|---|---|
| `skip` (default) | tpm2-kira stays out of it: cryptsetup's own prompt asks for the LUKS passphrase |
| `password+salt` | tpm2-kira asks for a **password** and a **salt** and hands over [hashpwd2](https://github.com/mrwiora/hashpwd2)'s derivation of the two - the same bytes hashpwd2 prints, so a keyslot enrolled with hashpwd2 opens as it is |
| `password+remotesalt` | tpm2-kira asks for the **password**; the salt is the one the phone released after verifying the machine and this TPM opened (next section). Only with an attestation set up. Without a salt from the phone (no phone in range, nothing released) it asks for a typed salt as in `password+salt`, which opens a keyslot enrolled that way; Ctrl-C then leads to cryptsetup's own prompt |

In every mode a wrong answer, or Ctrl-C at tpm2-kira's prompt, goes to
cryptsetup's own prompt, where the recovery passphrase works - keep one
in its own keyslot. The derivation needs 1 GiB of memory in the initramfs
and takes some seconds; the keyboard layout in the initramfs must be the
one the password was typed with (`sd-vconsole` on Arch, the `keymap`
hook on Debian).

A keyslot for `password+salt`, made on the unlocked system:

```bash
sudo mkdir -m 700 -p /run/tpm2-kira
sudo tpm2-kira derive --out /run/tpm2-kira/luks.key     # asks password (twice) and salt
sudo cryptsetup luksAddKey /dev/nvme0n1p2 /run/tpm2-kira/luks.key
sudo cryptsetup open --test-passphrase /dev/nvme0n1p2 --key-file /run/tpm2-kira/luks.key
sudo rm /run/tpm2-kira/luks.key
sudo tpm2-kira luks mark /dev/nvme0n1p2 --keyslot 1 --mode password+salt
```

The last line marks the keyslot as tpm2-kira's with a LUKS2 token in the
header (no key material; `cryptsetup luksDump` lists it as
`tpm2-kira`), so that `tpm2-kira luks status` can say which keyslot is
whose and how its key is made. The plan for `luks enrol`, which will do
all of the above in one step, is [docs/PLAN-LUKS.md](docs/PLAN-LUKS.md).

### The remote salt: your password and the phone, together

With a phone enrolled, the disk can need **both** your password and a
salt the phone keeps - the *remote salt*
([PLAN-FACTORRELEASE.md](docs/PLAN-FACTORRELEASE.md)): a value only this
machine's TPM can open, and only in a boot your signing key approved. It
is released by the attestation and by nothing else: the phone enrolled
with `attest enrol`, over Bluetooth LE, hands it back after a verdict you
accept. The key in the LUKS keyslot is hashpwd2's derivation of password
and salt, as in `password+salt` - only that nobody types the salt.
Whoever has the disk and the password still needs the phone and this
machine; whoever has the phone and the machine still needs the password.

1. **Recovery passphrase first**, in its own keyslot, typed at
   cryptsetup's prompt - long, not the password below, written down
   somewhere safe. It is the way in without the phone, at cryptsetup's
   own prompt. `remote-salt enrol` asks whether it exists.

   ```bash
   sudo cryptsetup luksAddKey /dev/nvme0n1p2
   ```

2. **Enrol the remote salt.** On the unlocked system, with Marify open on
   the phone:

   ```bash
   sudo mkdir -m 700 -p /run/tpm2-kira
   sudo tpm2-kira remote-salt enrol --out /run/tpm2-kira/luks.key
   ```

   The phone shows the ordinary verdict screen with a card "Keep this
   machine's remote salt"; accepting the verdict keeps it. The phone
   hands it straight back, the TPM opens it, and only if the round trip
   gives back what was sent does tpm2-kira ask for your password and
   write the derived key - once, to tmpfs. The first enrolment of a slot
   also adds the release key to its blob (needs the signing key).

3. **Add the derived key**, remove the file, mark the keyslot, switch the
   mode, rebuild:

   ```bash
   sudo cryptsetup luksAddKey /dev/nvme0n1p2 /run/tpm2-kira/luks.key
   sudo cryptsetup open --test-passphrase /dev/nvme0n1p2 --key-file /run/tpm2-kira/luks.key
   sudo rm /run/tpm2-kira/luks.key
   sudo tpm2-kira luks mark /dev/nvme0n1p2 --keyslot 2 --mode password+remotesalt
   sudo sed -i 's/^TPM2_KIRA_UNLOCK=.*/TPM2_KIRA_UNLOCK=password+remotesalt/' /etc/tpm2-kira/unlock.conf
   sudo mkinitcpio -P            # Debian: update-initramfs -u
   ```

At boot: code screen, the phone verifies and hands the salt back, the
TPM opens it before the OS separator, and tpm2-kira's prompt says `The
verifier released the disk's salt` and asks for the *password*. It
derives the key (1 GiB of memory, some seconds) and gives it to
`systemd-cryptsetup`. No phone, no verdict, or a TPM that refused: no
answer from tpm2-kira, cryptsetup's own prompt, the recovery passphrase.
`remote-salt status` says which slots have one (`--json` for scripts);
`remote-salt rotate` gives the phone a new salt and derives the new key,
after which the old keyslot is removed by hand (`cryptsetup luksKillSlot`);
`remote-salt unenrol` takes the release key out of the slot, so what the
phone keeps can never be opened again, and the keyslot is removed by
hand. The phone side runs on Android; the iOS app is tested separately.

`/etc/crypttab` is not touched and does not need to be: only if a volume
is kept there with `x-initrd.attach` instead of on the command line, the
same socket goes into that line's key field
(`cryptroot UUID=… /run/tpm2-kira/unlock.sock x-initrd.attach`), and
`sd-encrypt` copies it into the image as it is. Volumes with `none` or
`-` as key file are still asked for by systemd's own console prompt;
volumes with a key file or a token (`tpm2-device=`, `fido2-device=`,
`pkcs11-uri=`) are not tpm2-kira's.

Then rebuild:

```bash
sudo mkinitcpio -P
```

The post-generation hook will automatically reseal so the next boot matches.

### How it works at boot

A systemd service (`tpm2-kira.service`) starts before the disk unlock and runs `tpm2-kira run`, which shows a fresh TOTP code every 30 seconds. Compare what's on screen with your authenticator app. If they match, your boot chain is clean — press Enter and type your LUKS passphrase. Without Enter the boot continues by itself after 90 seconds; once it has continued, no code can be computed until the next boot.

The passphrase prompt that follows is tpm2-kira's: `systemd-cryptsetup`
activates the volume with every option in your `crypttab`, connects to
`/run/tpm2-kira/unlock.sock` for the key, tpm2-kira asks `Passphrase
for disk <volume>:` and answers with what you type. tpm2-kira
never opens the disk itself; it only provides the key. A typo is not
fatal: `systemd-cryptsetup` then asks on its own prompt for the remaining
two tries, as it does for a wrong key file, and a recovery passphrase in
another LUKS keyslot works at either prompt. This is also where
the key will come from other sources than your fingers: a factor the
phone releases after a successful attestation
([PLAN-FACTORRELEASE.md](docs/PLAN-FACTORRELEASE.md)). There is no mode
in which tpm2-kira withholds the prompt: the passphrase can always be
entered by hand. How systemd's unlock works, why this is the way to plug
in, and what happens after a typo: [UNLOCK-DISK.md](docs/UNLOCK-DISK.md).

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

Which unit runs when, and under which conditions the gate is in the image: [docs/BOOT-INTEGRATION.md](docs/BOOT-INTEGRATION.md#what-is-installed-where).

## Early Boot Integration (Debian / initramfs-tools)

Debian's stock initramfs has no systemd in it, so the systemd unit used on Arch
does not apply. The `.deb` installs two scripts instead:

| Path | Role |
|---|---|
| `/usr/share/initramfs-tools/hooks/tpm2-kira` | copies the binary into the image |
| `/usr/share/initramfs-tools/scripts/init-premount/tpm2-kira` | starts the display at boot |
| `/usr/share/initramfs-tools/scripts/init-bottom/tpm2-kira` | stops it and runs `tpm2-kira cap` before the real root takes over |
| `/lib/cryptsetup/scripts/tpm2-kira` | cryptsetup keyscript: the volume's key from tpm2-kira's prompt |
| `/etc/tpm2-kira/initramfs.conf` | display mode |

`/init` runs `init-premount` before `local-top/cryptroot` asks for the
passphrase, which is what puts the code on screen first.

### Configure the disk unlock (Debian)

There is no `systemd-cryptsetup` in a Debian initramfs; `cryptroot` runs
a `keyscript=` from `/etc/crypttab` instead and reads the key from its
stdout. Add tpm2-kira's to the root volume's line:

```
vda3_crypt UUID=… none luks,discard,keyscript=/lib/cryptsetup/scripts/tpm2-kira
```

and `sudo update-initramfs -u`. The keyscript asks the same socket
`systemd-cryptsetup` would on Arch (`tpm2-kira unlock-key`): the display
started by `init-premount` answers once the code screen is confirmed,
with what you type at `🔐 Passphrase for disk vda3_crypt:`
(or, with a phone and a factor, the key derived from your password).
`cryptroot` re-runs the keyscript for each of its tries (`tries=`, 3 by
default): the first ones are tpm2-kira's prompt, the last is cryptsetup's
own, for the recovery passphrase; Ctrl-C at tpm2-kira's prompt goes
there at once. Without the socket (no TPM, `once` mode) the keyscript is
cryptsetup's own prompt, as before tpm2-kira. (On Arch, `systemd-cryptsetup`
tries a key file once: after a wrong answer at tpm2-kira's prompt its own
prompt follows.)

What the display reported at boot - when the volume asked, when the hold
ended, when the prompt opened and answered - is in
`/run/initramfs/tpm2-kira.log` after the boot (on Arch:
`journalctl -b -u tpm2-kira.service`). Tested on Debian 13 with
initramfs-tools 0.148 and cryptsetup 2.7.

### Display mode

`/etc/tpm2-kira/initramfs.conf`, `run` or `once`: [docs/BOOT-INTEGRATION.md](docs/BOOT-INTEGRATION.md#display-mode).

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
# Measures kernel, initrd and command line; predicted across updates (below)
tpm2-kira seal --pcrs "0e,2e,4e,7e,8e,9e"

# Stable across kernel updates, but a modified initrd or command line
# still shows a valid code (seal prints a warning)
tpm2-kira seal --pcrs "0e,2e,4e,7e"
```

### PCR 8 and 9 are predicted for the next boot

`reseal` predicts PCR 8 and 9 from this boot's event log and the files on disk, so an update needs no boot without a code; the hooks run it. What it cannot foresee, and the state of the art: [docs/BOOT-INTEGRATION.md](docs/BOOT-INTEGRATION.md#pcr-8-and-9-are-predicted-for-the-next-boot).

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
sudo rm -rf /etc/tpm2-kira/keys
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

Purging the Debian package deliberately leaves `/etc/tpm2-kira/keys` in place:
the signing key is the only way to approve new PCR values for a key that may
still be sealed in the TPM. Delete the slot first, then the directory.

## Troubleshooting, diagnosis, exit status

The event-log calculator, what to do when a code stops matching, the common errors and the exit status table are in [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md); the repository layout and how the tests are run in [docs/PROJECT-STRUCTURE.md](docs/PROJECT-STRUCTURE.md).

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
