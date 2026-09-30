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

tpm2-kira generates a TOTP secret and seals it inside TPM NVRAM, protected by a **PolicyOR** with two branches:

| Branch | When it works | Purpose |
|--------|--------------|---------|
| **PCR** | Boot measurements match the values recorded at seal time | Normal daily use — no keys or passwords needed |
| **PolicySigned** | You have the signing private key | Recovery after firmware/kernel/bootloader updates change PCR values |

On every boot, tpm2-kira asks the TPM to unseal the secret. If PCRs still match, you get a valid TOTP code. Compare it with the code in your authenticator app — if they match, your boot chain is intact.

When a system update changes PCR values (kernel update, initramfs rebuild, Secure Boot key rotation, etc.), the PCR branch fails. You use `reseal` with your signing key to re-seal the secret against the new PCR values.

For more details on the cryptographic design, see [SECURITY-BACKGROUND.md](docs/SECURITY-BACKGROUND.md).

## Requirements

**Hardware:**
- TPM 2.0 (discrete or firmware TPM)

**Software:**
- Linux with TPM 2.0 kernel support (`/dev/tpm0` or `/dev/tpmrm0`)
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

# Create the signing key (one step)
sudo tpm2-kira setup

# Seal a TOTP secret against PCRs 0 and 7 (the other step)
sudo tpm2-kira seal --pcrs "0,7"

# Show the current TOTP code
tpm2-kira reveal
```

`setup` creates an ECDSA P-256 key pair at `/var/lib/tpm2-kira/keys/` and stops
there. `seal` generates the TOTP secret, binds it to the PCRs you name, and
prints a QR code to scan with your authenticator app.

The two are deliberately separate. Creating a key is cheap and repeatable;
sealing writes to TPM NVRAM and mints a secret you have to enrol, and it is the
step where the PCR choice is made. Keeping them apart means you can re-run
either without having to think about the other.

If a YubiKey is plugged in, `setup` notices and offers to put the signing key on
it instead — a key file remains the default, so pressing Enter keeps the
behaviour above. See [Signing key on a YubiKey](#signing-key-on-a-yubikey).

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

After installing, create the key, seal a secret, and rebuild the initramfs:

```bash
sudo tpm2-kira setup
sudo tpm2-kira seal --pcrs "0,7"
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
rebuilds the initramfs. It runs neither `setup` nor `seal`: sealing generates a
new TOTP secret and prints a QR code you need to scan, which must not happen as
a side effect of installing a package.

```bash
sudo tpm2-kira setup
sudo tpm2-kira seal --pcrs "0,7"
sudo update-initramfs -u
```

The binary is built statically (`CGO_ENABLED=0`), so the initramfs needs no
libraries and the package has no shared-library dependencies. That holds for
every build path — `make build`, the `.deb`, the AUR package and the release
artefacts — because the installed binary is what the initramfs hooks copy.
`make verify-static` asserts it: no `NEEDED` entries and no `PT_INTERP`, so
neither a shared library nor the dynamic loader is required.

### Verify

```bash
tpm2-kira version
```

## Commands

If called without a command, tpm2-kira defaults to `reveal`.

| Command | Description |
|---------|-------------|
| `setup` | One-time initial setup: generate signing keys + seal a secret (PCRs 0,7) |
| `seal` | Generate and seal a new TOTP secret with custom PCR selection |
| `reseal` | Re-seal the existing secret against current PCR values |
| `reveal` | Show the current TOTP code (colored output) |
| `reveal-plain` | Show the current TOTP code (plain text, for scripts) |
| `run` | Continuously display TOTP codes (useful during boot) |
| `info` | Display metadata about the sealed secret (`--json` for machine-readable output) |
| `nvram list` | List NVRAM indices |
| `nvram status` | Show NVRAM index status |
| `nvram delete` | Delete sealed data from NVRAM (`--nvram N` or `--all`) |
| `nvram restore` | Write back a blob that a failed NVRAM write left on disk |
| `yubikey list` | Show connected YubiKeys, their PIV slots and policies |
| `yubikey adopt` | Register an existing PIV slot key and cache its public key |
| `yubikey status` | Check whether the enrolled token is present |
| `yubikey export-pubkey` | Write a slot's public key to a PEM file |
| `pcrtips` | PCR reference guide — what each register measures |
| `version` | Print version |

## Global Options

```
--tpm PATH       TPM device path (default: /dev/tpm0)
--nvram INDEX    NVRAM slot: 0-15 maps to 0x01803010-0x0180301F,
                 or specify a full hex index like 0x01803010.
                 When omitted, commands auto-discover populated slots.
--debug          Verbose output
```

Environment:

```
TPM2_KIRA_PIN    PIN for a signing key held in a YubiKey PIV slot.
                 Only read when the key reference names a token.
```

## Sealing Secrets

### Basic seal

Run `seal` with no `--pcrs` from a terminal and it looks at the machine first,
then suggests a selection to match:

```bash
sudo tpm2-kira seal
```

```
What was found:
  Firmware: UEFI
  Secure Boot: enabled
  Event log: present, with SHA-256 digests
  Unified kernel image: /boot/EFI/Linux/arch-linux.efi

Suggested NVRAM slot: #0 (0x01803010), which is free

Suggested selection: 0,7
  PCR 0  firmware code — changes when you update the firmware
  PCR 7  Secure Boot policy — changes if the keys are rotated or Secure Boot is turned off

Also possible here:
  11u  the unified kernel image. The strongest measurement of the exact kernel that
       will run, but it changes on every kernel update, so each one needs a reseal.
  ...

Worth knowing:
  - PCR 0 on its own would identify a firmware build, not this machine — every device
    running the same firmware version holds the same value. ...

  [Enter]      seal slot #0 (0x01803010) with PCRs 0,7
  <selection>  type your own, for example "0,2,7" or "0e,7e,11u"
  [?]          show the full PCR reference and stop
  [q]          quit without sealing
```

The advice tracks the machine rather than being boilerplate. With Secure Boot
enabled, PCRs 0 and 7 are enough and need no reseal after a kernel update. With
Secure Boot **off**, nothing verifies which kernel runs, so the suggestion adds
whatever this system measures the boot components with — `11u` for a unified
kernel image, `8,9` for GRUB, `4` otherwise — and says what that costs in
resealing. A free NVRAM slot is suggested, and slots already in use are listed so
an enrolled secret is not overwritten by accident.

**Passing `--pcrs` skips all of it** and seals exactly what you asked for:

```bash
tpm2-kira seal --pcrs "0,2,7"
```

So does running without a terminal — a package hook or script gets the
documented default (`0,2,7`) silently, with no prompt to hang on.

### Going further

| Topic | Where |
|---|---|
| PCR sources (`r`, `e`, `u`), weak selections, the measure point, event logs without SHA-256 digests | [docs/PCR-SELECTION.md](docs/PCR-SELECTION.md) |
| Using your own key, sharing one with sbctl, holding it on a YubiKey | [docs/SIGNING-KEYS.md](docs/SIGNING-KEYS.md) |
| What each register measures | `tpm2-kira pcrtips` |

### Multiple slots

tpm2-kira supports up to 16 NVRAM slots (0–15). Useful if you need separate secrets for different purposes:

```bash
tpm2-kira seal --nvram 0
tpm2-kira seal --nvram 1 --pcrs "0e,2e,7e"

tpm2-kira reveal --nvram 0
tpm2-kira reveal --nvram 1
```

## Resealing After Updates

When PCR values change (kernel update, initramfs rebuild, firmware update), the PCR branch will fail and `reveal` won't produce a valid code. Reseal to bind the secret to the new values:

```bash
# Auto-discovers the signing key from the stored blob metadata
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
```

`--json` always emits an array of slot objects, one per populated slot, even
when there is only one. Each entry carries `slot_number`, `nvram_index` and the
blob itself, so consumers never have to branch on the slot count.

## Deleting Sealed Data

```bash
sudo tpm2-kira nvram delete --nvram 0    # one slot
sudo tpm2-kira nvram delete --all        # every populated slot
```

Deleting a sealed secret cannot be undone: the secret is gone and the
authenticator has to be re-enrolled. So there is no default — `nvram delete`
with neither option refuses and shows both, and `--all` lists the slots and asks
for confirmation when run from a terminal.

Options are named, and a stray argument is refused rather than ignored.
`tpm2-kira nvram delete 0` does **not** mean slot 0; it is rejected with a
suggestion, because the flag package would otherwise drop the `0` and leave the
command meaning "every slot".

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

# Everything, plus a real pcscd and a virtual YubiKey, in a container.
# This is the only way to exercise the token path end to end without hardware.
# BASE selects the pcsc-lite generation: 2.x by default, 1.9.x for bookworm.
make test-docker
make test-docker-all
```

`internal/virtualpiv` emulates a YubiKey PIV application and attaches to the
vsmartcard virtual reader, so `pcscd` sees an ordinary card. See
[docs/YUBIKEY.md](docs/YUBIKEY.md#testing-without-hardware).

## Troubleshooting

**TPM device not found:**
```bash
ls -la /dev/tpm*
sudo dmesg | grep -i tpm
```
Ensure TPM 2.0 is enabled in your BIOS/UEFI settings.

**Permission denied, or "needs root":**

The TPM device is root-only, deliberately: anything able to open it can ask the
TPM to unseal the secret while the PCR values still match, so the threat model
places non-root userspace outside the trust boundary
([SECURITY-BACKGROUND.md §8](docs/SECURITY-BACKGROUND.md)). **Do not loosen the
permissions on `/dev/tpm0`** — that moves the boundary rather than working around
it, and is not a supported configuration.

So every command that talks to the TPM needs `sudo`, and says so rather than
reporting a bare syscall error:

```
tpm2-kira: FAILED: /dev/tpm0 is a TPM device, which only root may open.
  Run the command with sudo:
      sudo tpm2-kira reveal ...
  Current user has UID 1000.
```

The requirement comes from the **device**, not from the verb. A software TPM
reached over a unix socket — `--tpm /path/to/swtpm.sock`, which is how the test
suite runs — belongs to whoever started it and needs no privilege at all.

`setup` needs root regardless, because it writes the signing key under
`/var/lib/tpm2-kira`. `version`, `help`, `pcrtips` and the `yubikey` subcommands
that only inspect a token through `pcscd` need nothing.

As always the exit status is 0, so judge success from the output.

**TOTP code doesn't match after an update:**
```bash
sudo tpm2-kira reseal
```
Expected after a firmware, kernel or bootloader change. If reseal also fails, or
if nothing explains the change, work through
[docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md) — it covers reconstructing the whole
measurement chain and recovering an NVRAM write that did not complete.

**Debug output:**
```bash
tpm2-kira --debug reveal
```

**Check current PCR values vs. sealed values:**
```bash
tpm2-kira info            # shows what was sealed
tpm2-kira pcrtips         # explains what each PCR measures
```

## Early Boot Integration

tpm2-kira can display TOTP codes during early boot, before the disk encryption
passphrase is entered, so the boot chain can be checked before the passphrase is
typed.

```bash
sudo make install-mkinitcpio     # Arch: mkinitcpio hooks
                                 # Debian: the .deb installs its hooks already
```

On Arch, add the hook to `/etc/mkinitcpio.conf` **before** your encrypt hook and
rebuild:

```bash
HOOKS=(base systemd autodetect modconf block keyboard sd-tpm2-kira sd-encrypt filesystems fsck)
sudo mkinitcpio -P
```

The two platforms differ in more than plumbing — Debian has no systemd in its
initramfs and no unified kernel image, so GRUB's measurements land in PCRs 8 and 9
and a reseal has to follow the reboot rather than precede it.

**See [docs/EARLY-BOOT.md](docs/EARLY-BOOT.md)** for both procedures in full: the
hooks each platform installs, the display modes, choosing PCRs per platform, and
the reseal ordering rule.

## Uninstall

```bash
# Remove sealed data first
sudo tpm2-kira nvram delete --all

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
sudo tpm2-kira nvram delete --all
sudo pacman -R tpm2-kira
```

On Debian:
```bash
sudo tpm2-kira nvram delete --all
sudo apt remove tpm2-kira
```

Purging the Debian package deliberately leaves `/var/lib/tpm2-kira` in place:
the signing key is the only recovery path for a secret that may still be sealed
in the TPM. Delete the slot first, then the directory.

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
```

The mkinitcpio post hook does exactly this — it greps the output for the success
line rather than testing `$?`.

## Documentation

| Document | Covers |
|---|---|
| [docs/PCR-SELECTION.md](docs/PCR-SELECTION.md) | Choosing PCRs: sources, weak selections, the measure point, event logs without SHA-256 digests |
| [docs/SIGNING-KEYS.md](docs/SIGNING-KEYS.md) | Using your own key, sharing one with sbctl, holding it on a YubiKey |
| [docs/YUBIKEY.md](docs/YUBIKEY.md) | The hardware token in full: preparing a slot, PIN handling, polkit, backups, testing |
| [docs/EARLY-BOOT.md](docs/EARLY-BOOT.md) | Showing a code before the disk is unlocked, on Arch and on Debian |
| [docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md) | Diagnosing a PCR mismatch, the eventlog calculator, recovering an interrupted write |
| [docs/PLAN-PCRLOCK.md](docs/PLAN-PCRLOCK.md) | Whether systemd-pcrlock should be a fourth PCR source, and why it is not one |
| [docs/SECURITY-BACKGROUND.md](docs/SECURITY-BACKGROUND.md) | The cryptographic design, threat model and trust boundaries |
| [docs/CODE-LAYOUT.md](docs/CODE-LAYOUT.md) | Where things live in the source, and the rule that decides it |
| [docs/PLATFORM-OBSERVATIONS.md](docs/PLATFORM-OBSERVATIONS.md) | Measured facts about Arch and Debian boots |
| [HISTORY.md](HISTORY.md) | Superseded formats and removed features, with the reasoning |

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy and
[docs/SECURITY-BACKGROUND.md](docs/SECURITY-BACKGROUND.md) for an in-depth
description of the cryptographic design, threat model, and trust boundaries.

## History

[HISTORY.md](HISTORY.md) records superseded formats, removed features and the
reasoning behind them, so the source can describe what it is rather than what it
used to be. This project is in development: **no backwards compatibility is
maintained**, and blob formats, on-disk layouts and CLI flags may change without
a migration path.

## License

BSD 3-Clause — see [LICENSE](LICENSE).
