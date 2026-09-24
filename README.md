# tpm2-kira (Known Integrity Recognition Agent)

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

For more details on the cryptographic design, see [SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md).

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

# First-time setup: generates signing keys + seals a TOTP secret (PCRs 0,7)
sudo tpm2-kira setup

# Show the current TOTP code
tpm2-kira reveal
```

`setup` creates an ECDSA P-256 key pair at `/var/lib/tpm2-kira/keys/` and seals a TOTP secret bound to PCRs 0 and 7. Scan the QR code it prints with your authenticator app.

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

After installing, run setup once and rebuild the initramfs:

```bash
sudo tpm2-kira setup
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
rebuilds the initramfs. It does **not** run `setup`, because that generates a
new TOTP secret and prints a QR code you need to scan:

```bash
sudo tpm2-kira setup
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
| `setup` | One-time initial setup: generate signing keys + seal a secret (PCRs 0,7) |
| `seal` | Generate and seal a new TOTP secret with custom PCR selection |
| `reseal` | Re-seal the existing secret against current PCR values |
| `reveal` | Show the current TOTP code (colored output) |
| `reveal-plain` | Show the current TOTP code (plain text, for scripts) |
| `run` | Continuously display TOTP codes (useful during boot) |
| `info` | Display metadata about the sealed secret (`--json` for machine-readable output) |
| `nvram list` | List NVRAM indices |
| `nvram status` | Show NVRAM index status |
| `nvram delete` | Delete sealed data from NVRAM |
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

### Warnings about weak selections

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

### The measure point

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

Both key paths are stored in the sealed blob so that `reseal` can find them automatically.

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
tpm2-kira nvram delete              # deletes all populated slots
tpm2-kira nvram delete --nvram 0    # deletes a specific slot
```

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

A systemd service (`tpm2-kira.service`) starts before the disk unlock prompt and runs `tpm2-kira run`, which continuously displays TOTP codes. Compare what's on screen with your authenticator app. If they match, your boot chain is clean — go ahead and type your LUKS passphrase.

See [mkinitcpio/mkinitcpio.conf.example](mkinitcpio/mkinitcpio.conf.example) for more HOOKS configurations (LVM, multiple encrypted devices, etc.).

## Early Boot Integration (Debian / initramfs-tools)

Debian's stock initramfs has no systemd in it, so the systemd unit used on Arch
does not apply. The `.deb` installs two scripts instead:

| Path | Role |
|---|---|
| `/usr/share/initramfs-tools/hooks/tpm2-kira` | copies the binary into the image |
| `/usr/share/initramfs-tools/scripts/init-premount/tpm2-kira` | starts the display at boot |
| `/usr/share/initramfs-tools/scripts/init-bottom/tpm2-kira` | stops it before the real root takes over |
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
so nothing is left holding it open.

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
# Stable across kernel updates - a good default
tpm2-kira seal --pcrs "0e,2e,4e,7e"

# Adds kernel and initrd integrity, at the cost of the workflow below
tpm2-kira seal --pcrs "0e,2e,4e,7e,8e,9e"
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

**Permission denied on `/dev/tpm0`:**
```bash
# Check current permissions
ls -la /dev/tpm0

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
tpm2-kira nvram delete

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
tpm2-kira nvram delete
sudo pacman -R tpm2-kira
```

On Debian:
```bash
tpm2-kira nvram delete
sudo apt remove tpm2-kira
```

Purging the Debian package deliberately leaves `/var/lib/tpm2-kira` in place:
the signing key is the only recovery path for a secret that may still be sealed
in the TPM. Delete the slot first, then the directory.

## Project Structure

```
├── main.go                  # CLI entrypoint and command routing
├── cmd/                     # Command implementations
│   ├── seal.go              # Seal TOTP secret into TPM
│   ├── reseal.go            # Re-seal with new PCR values
│   ├── setup.go             # First-time setup (keygen + seal)
│   ├── info.go              # Inspect sealed blob metadata
│   ├── scan.go              # Multi-slot NVRAM scanning
│   ├── blob.go              # Sealed blob serialization format
│   ├── policy_or.go         # PolicyOR digest computation
│   ├── eventlog_utils.go    # TPM eventlog parsing
│   ├── measurepoint.go      # Userspace extends before tpm2-kira reads PCRs
│   ├── ukipredict.go        # Native PCR 11 computation from a UKI
│   ├── pcr.go               # PCR spec parsing, reading and comparison
│   ├── pcrwarn.go           # Warnings for PCR selections that attest little
│   ├── nvram.go             # NVRAM read/write/scan operations
│   ├── totp_utils.go        # TOTP generation and display
│   ├── tpm_utils.go         # Low-level TPM operations
│   ├── pcrtips.go           # PCR reference information
│   └── constants.go         # Default paths and constants
├── tools/
│   ├── pcrtool.py            # PCR replay and full-chain diagnosis
│   └── tpm2-pcr11predict     # Independent cross-check of the built-in PCR 11 computation
├── docs/
│   ├── PLATFORM-OBSERVATIONS.md  # Measured facts about Arch and Debian boots
│   ├── pentest1/, pentest2/      # Security review findings and mitigations
│   └── *.issue                   # Write-ups of specific bugs
├── mkinitcpio/              # Early boot hooks for Arch Linux
│   ├── install/sd-tpm2-kira # mkinitcpio install hook
│   ├── post/sd-tpm2-kira    # Post-generation reseal hook
│   └── mkinitcpio.conf.example
├── initramfs-tools/         # Early boot scripts for Debian
│   ├── hooks/tpm2-kira              # Copies the binary into the image
│   ├── scripts/init-premount/tpm2-kira  # Starts the display before disk unlock
│   ├── scripts/init-bottom/tpm2-kira    # Stops it before switching root
│   ├── post-update.d/tpm2-kira      # Reseal reminder after a rebuild
│   └── initramfs.conf               # Display mode (run / once)
├── systemd/system/          # systemd service for boot-time TOTP display
├── debian/                  # Debian package definition
├── packaging/aur/           # Arch Linux PKGBUILD
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

See [SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md) §5.6–5.8 for the full
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

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy and [SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md) for an in-depth description of the cryptographic design, threat model, and trust boundaries.

## History

[HISTORY.md](HISTORY.md) records superseded formats, removed features and the
reasoning behind them, so the source can describe what it is rather than what it
used to be. This project is in development: **no backwards compatibility is
maintained**, and blob formats, on-disk layouts and CLI flags may change without
a migration path.

## License

BSD 3-Clause — see [LICENSE](LICENSE).
